from Cookie import SimpleCookie
from liteauth import LiteAuthStorage
from swift.common.swob import Request, HTTPUnauthorized, HTTPNotFound, HTTPForbidden
from swift.common.utils import get_logger, split_path
from swift.common.middleware.acl import clean_acl


def parse_lite_acl(acl_string):
    """
    Parses Litestack ACL string into an account list.

    :param acl_string: The standard Swift ACL string to parse.
    :returns: list of user accounts
    """
    accounts = []
    if acl_string:
        for value in acl_string.split(','):
            accounts.append(value)
    return accounts


def extract_auth_token(req):
    auth_token = None
    try:
        auth_token = SimpleCookie(req.environ.get('HTTP_COOKIE', ''))['session'].value
        if auth_token:
            req.headers['x-auth-token'] = auth_token
            req.headers['x-storage-token'] = auth_token
    except KeyError:
        pass
    if not auth_token:
        auth_token = req.headers.get('x-auth-token', None)
    return auth_token


class LiteAuthToken(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='lite-auth')
        self.storage_driver = conf.get('storage_driver', LiteAuthStorage)
        provider = conf.get('oauth_provider', 'google_oauth')
        mod = __import__('providers.' + provider, fromlist=['Client'])
        self.provider = getattr(mod, 'Client')
        self.prefix = self.provider.PREFIX

    def __call__(self, env, start_response):
        req = Request(env)
        token = extract_auth_token(req)
        if token:
            account_id, _junk = \
                self.storage_driver(env, self.prefix).get_id(token)
            if account_id:
                req.environ['REMOTE_USER'] = account_id
        req.environ['swift.authorize'] = self.authorize
        req.environ['swift.clean_acl'] = clean_acl
        return self.app(env, start_response)

    def authorize(self, req):
        try:
            version, account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            self.logger.increment('errors')
            return HTTPNotFound(request=req)
        if not account:
            return self.denied_response(req)
        user_data = (req.remote_user or '')
        if req.method in 'POST' and 'x-zerovm-execute' in req.headers \
                and account == user_data:
            return None
        if account == user_data and \
                (req.method not in ('DELETE', 'PUT', 'POST') or container):
            req.environ['swift_owner'] = True
            return None
        if container:
            accounts = parse_lite_acl(getattr(req, 'acl', None))
            # * is a full public access (Everybody)
            if '*' in accounts or user_data in accounts:
                return None
            # ** is a limited public access (Authorized Users)
            if '**' in accounts and user_data:
                return None
        return self.denied_response(req)

    def denied_response(self, req):
        if req.remote_user:
            self.logger.increment('forbidden')
            return HTTPForbidden(request=req)
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return LiteAuthToken(app, conf)
    return auth_filter
