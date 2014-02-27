from liteauth.providers.abstract_oauth import OauthClientInterface
from oauth import Client as OauthClient


def _parser(msg):
    return dict([pair.strip().split('=', 1) for pair in msg.split('&')])


class Client(OauthClientInterface):

    PREFIX = 'fb_'

    def __init__(self, conf, redirect_url):
        super(Client, self).__init__(redirect_url)
        self.facebook_client_id = conf.get('facebook_client_id')
        if not self.facebook_client_id:
            raise ValueError('facebook_client_id not set in config file')
        self.facebook_client_secret = conf.get('facebook_client_secret')
        if not self.facebook_client_secret:
            raise ValueError('facebook_client_secret not set in config file')
        self.facebook_scope = conf.get('facebook_scope')
        if not self.facebook_scope:
            raise ValueError('facebook_scope not set in config file')
        self.refresh_token = None

    @classmethod
    def create_for_redirect(cls, conf, redirect_url, state=None, approval_prompt='auto'):
        gclient = cls(conf, redirect_url)
        c = OauthClient(auth_endpoint='https://www.facebook.com/dialog/oauth',
                        client_id=gclient.facebook_client_id,
                        redirect_uri=gclient.redirect_url)
        loc = c.auth_uri(scope=gclient.facebook_scope.split(','),
                         state=state or '/')
        gclient.redirect = loc
        return gclient

    @classmethod
    def create_for_token(cls, conf, redirect_url, code):
        gclient = cls(conf, redirect_url)
        c = OauthClient(token_endpoint='https://graph.facebook.com/oauth/access_token',
                        resource_endpoint='https://graph.facebook.com',
                        redirect_uri=gclient.redirect_url,
                        client_id=gclient.facebook_client_id,
                        client_secret=gclient.facebook_client_secret)
        c.request_token(code=code, parser=_parser)
        gclient.access_token = c.access_token
        gclient.expires_in = int(c.expires)
        gclient.userinfo = c.request('/me')
        return gclient
