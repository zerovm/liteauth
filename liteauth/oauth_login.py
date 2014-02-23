from Cookie import SimpleCookie
import datetime
import urlparse
from liteauth import LiteAuthStorage
from swift.common.swob import wsgify, HTTPUnauthorized, HTTPForbidden, Response, HTTPFound
from swift.common.utils import get_logger


class OauthLogin(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='liteauth')
        try:
            provider = conf.get('oauth_provider', 'google_oauth')
            mod = __import__('liteauth.providers.' + provider, fromlist=['Client'])
            self.provider = getattr(mod, 'Client')
            self.prefix = self.provider.PREFIX
        except Exception:
            raise ValueError('oauth_provider is invalid in config file')
        self.service_endpoint = conf.get('service_endpoint', '')
        if not self.service_endpoint:
            raise ValueError('service_endpoint not set in config file')
        if isinstance(self.service_endpoint, unicode):
            self.service_endpoint = self.service_endpoint.encode('utf-8')
        parsed_path = urlparse.urlparse(self.service_endpoint)
        if not parsed_path.netloc:
            raise ValueError('service_endpoint is invalid in config file')
        self.service_domain = parsed_path.netloc
        self.login_path = parsed_path.path
        self.scheme = parsed_path.scheme
        self.storage_driver = None

    @wsgify
    def __call__(self, req):
        if req.path == self.login_path:
            state = None
            if req.params:
                code = req.params.get('code')
                state = req.params.get('state')
                if code:
                    return self.handle_login(req, code, state)
            return self.handle_oauth(state)
        return self.app

    def handle_login(self, req, code, state):
        self.storage_driver = LiteAuthStorage(req.environ, self.prefix)
        oauth_client = self.provider.create_for_token(self.conf,
                                                      self.service_endpoint,
                                                      code)
        token = oauth_client.access_token
        if not token:
            req.response = HTTPUnauthorized(request=req)
            return req.response
        user_info = oauth_client.userinfo
        if not user_info:
            req.response = HTTPForbidden(request=req)
            return req.response
        account_id = '%s:%s' % (self.prefix + user_info.get('id'),
                                user_info.get('email'))
        self.storage_driver.store_id(account_id,
                                     token,
                                     oauth_client.expires_in)
        cookie = self.create_session_cookie(token=token, expires_in=oauth_client.expires_in)
        return Response(request=req, status=302,
                        headers={
                            'set-cookie': cookie,
                            'location': '%s://%s%s?account=%s' %
                                        (self.scheme,
                                         self.service_domain,
                                         state or '/',
                                         account_id)})

    def handle_oauth(self, state=None, approval_prompt='auto'):
        oauth_client = self.provider.create_for_redirect(self.conf,
                                                         self.service_endpoint,
                                                         state,
                                                         approval_prompt)
        return HTTPFound(location=oauth_client.redirect)

    def create_session_cookie(self, token='', path='/', expires_in=0):
        cookie = SimpleCookie()
        cookie['session'] = token
        cookie['session']['path'] = path
        if not self.service_domain.startswith('localhost'):
            cookie['session']['domain'] = self.service_domain
        expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        cookie['session']['expires'] = expiration.strftime('%a, %d %b %Y %H:%M:%S GMT')
        return cookie['session'].output(header='').strip()


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return OauthLogin(app, conf)
    return auth_filter
