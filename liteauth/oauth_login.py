from uuid import uuid4
from liteauth import LiteAuthStorage
from providers import load_oauth_provider
from swift.common.swob import wsgify, HTTPUnauthorized, HTTPForbidden, Response, HTTPFound
from swift.common.utils import get_logger, urlparse


class OauthLogin(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='liteauth')
        self.provider = load_oauth_provider(
            conf.get('oauth_provider', 'google_oauth'))
        self.auth_endpoint = conf.get('auth_endpoint', '')
        if not self.auth_endpoint:
            raise ValueError('auth_endpoint not set in config file')
        if isinstance(self.auth_endpoint, unicode):
            self.auth_endpoint = self.auth_endpoint.encode('utf-8')
        parsed_path = urlparse(self.auth_endpoint)
        if not parsed_path.netloc:
            raise ValueError('auth_endpoint is invalid in config file')
        self.auth_domain = parsed_path.netloc
        self.login_path = parsed_path.path
        self.scheme = parsed_path.scheme
        if self.scheme != 'https':
            raise ValueError('auth_endpoint must have https:// scheme')
        # by default service_domain can be extracted from the endpoint
        # in case where auth domain is different from service domain
        # you need to set up the service domain separately
        # Example:
        # auth_endpoint = https://auth.example.com/login
        # service_domain = https://www.example.com
        self.service_domain = conf.get('service_domain',
                                       '%s://%s'
                                       % (self.scheme, self.auth_domain))
        self.storage_driver = None
        self.oauth_login_timeout = 3600

    @wsgify
    def __call__(self, req):
        self.storage_driver = LiteAuthStorage(req.environ)
        if req.path == self.login_path:
            state = None
            if req.params:
                code = req.params.get('code')
                state = req.params.get('state')
                if code:
                    return self.handle_login(req, code, state)
            return self.handle_oauth(state)
        token = req.headers.get('x-auth-token', None)
        if token:
            account_id, _junk = self.storage_driver.get_id(token)
            if account_id:
                req.environ['REMOTE_USER'] = account_id
        return self.app

    def handle_login(self, req, code, state):
        stored_state = self.storage_driver.get_id(state)
        if not stored_state:
            req.response = HTTPUnauthorized(request=req,
                                            body='Login time expired')
            return req.response
        oauth_client = self.provider.create_for_token(self.conf,
                                                      self.auth_endpoint,
                                                      code)
        token = oauth_client.access_token
        if not token:
            req.response = HTTPUnauthorized(request=req)
            return req.response
        user_info = oauth_client.userinfo
        if not user_info:
            req.response = HTTPForbidden(request=req)
            return req.response
        account_id = '%s:%s' % (self.provider.PREFIX + user_info.get('id'),
                                user_info.get('email'))
        self.storage_driver.store_id(account_id,
                                     token,
                                     oauth_client.expires_in)
        return Response(request=req, status=302,
                        headers={
                            'x-auth-token': token,
                            'x-storage-token': token,
                            'x-auth-token-expires': oauth_client.expires_in,
                            'x-storage-url': self.auth_endpoint,
                            'location': '%s%s?account=%s' %
                                        (self.service_domain,
                                         stored_state or '/',
                                         account_id)})

    def handle_oauth(self, state=None, approval_prompt='auto'):
        uid = uuid4().hex
        self.storage_driver.store_id(uid, state or '/',
                                     self.oauth_login_timeout)
        oauth_client = self.provider.create_for_redirect(
            self.conf,
            self.auth_endpoint,
            state=uid,
            approval_prompt=approval_prompt)
        return HTTPFound(location=oauth_client.redirect)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return OauthLogin(app, conf)
    return auth_filter
