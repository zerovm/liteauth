from Cookie import SimpleCookie
import datetime
from liteauth import LiteAuthStorage
from providers.abstract_oauth import load_provider
from swift.common.swob import Request, HeaderKeyDict
from swift.common.utils import get_logger, urlparse


def create_auth_cookie(cookie_name, auth_domain,
                       token='', path='/', expires_in=0,
                       secure=False, httponly=False):
    cookie = SimpleCookie()
    cookie[cookie_name] = token
    cookie[cookie_name]['path'] = path
    if not auth_domain.startswith('localhost'):
        cookie[cookie_name]['domain'] = auth_domain
    expiration = datetime.datetime.utcnow() + \
        datetime.timedelta(seconds=expires_in)
    cookie[cookie_name]['expires'] = expiration.strftime(
        '%a, %d %b %Y %H:%M:%S GMT')
    if secure:
        cookie[cookie_name]['secure'] = True
    if httponly:
        cookie[cookie_name]['HttpOnly'] = True
    return cookie[cookie_name].output(header='').strip()


def extract_from_cookie_to_header(req, cookie_key, header_names):
    value = None
    try:
        value = SimpleCookie(req.environ.get('HTTP_COOKIE', ''))[cookie_key].value
        if value:
            for name in header_names:
                req.headers[name] = value
    except KeyError:
        pass
    if not value:
        for name in header_names:
            value = req.headers.get(name, None)
            if value:
                break
    return value


class LiteAuthToken(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='lite-auth')
        self.storage_driver = conf.get('storage_driver', LiteAuthStorage)
        provider = load_provider(conf.get('oauth_provider', 'google_oauth'))
        self.prefix = provider.PREFIX
        self.cookie_key = conf.get('cookie_key', 'session')

    def __call__(self, env, start_response):
        req = Request(env)
        token = extract_from_cookie_to_header(req,
                                              self.cookie_key,
                                              ('x-auth-token', 'x-storage-token'))
        if token:
            account_id, _junk = \
                self.storage_driver(env, self.prefix).get_id(token)
            if account_id:
                req.environ['REMOTE_USER'] = account_id

        def cookie_resp(status, response_headers, exc_info=None):
            resp_headers = HeaderKeyDict(response_headers)
            if 'x-auth-token' in resp_headers:
                auth_token = resp_headers['x-auth-token']
                expires_in = int(resp_headers.get('x-auth-token-expires', 0))
                storage_url = resp_headers.get('x-storage-url', '')
                path_parts = urlparse(storage_url)
                domain = path_parts.netloc
                secure = False
                if path_parts.scheme == 'https':
                    secure = True
                if auth_token and domain:
                    new_cookie = create_auth_cookie('session',
                                                    domain,
                                                    token=auth_token,
                                                    expires_in=expires_in,
                                                    secure=secure,
                                                    httponly=True)
                    # response_headers.append(('Set-Cookie', new_cookie))
                    new_cookie += create_auth_cookie('storage',
                                                     domain,
                                                     token=storage_url,
                                                     expires_in=expires_in,
                                                     secure=secure)
                    response_headers.append(('Set-Cookie', new_cookie))
            return start_response(status, response_headers, exc_info)

        return self.app(env, cookie_resp)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return LiteAuthToken(app, conf)
    return auth_filter
