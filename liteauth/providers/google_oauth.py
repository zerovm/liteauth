from liteauth.providers.abstract_oauth import OauthClientInterface
from oauth import Client as OauthClient


class Client(OauthClientInterface):

    PREFIX = 'g_'

    def __init__(self, conf, redirect_url):
        super(Client, self).__init__(redirect_url)
        self.google_client_id = conf.get('google_client_id')
        if not self.google_client_id:
            raise ValueError('google_client_id not set in config file')
        self.google_client_secret = conf.get('google_client_secret')
        if not self.google_client_secret:
            raise ValueError('google_client_secret not set in config file')
        self.google_scope = conf.get('google_scope')
        if not self.google_scope:
            raise ValueError('google_scope not set in config file')
        self.refresh_token = None

    @classmethod
    def create_for_redirect(cls, conf, redirect_url, state=None, approval_prompt='auto'):
        gclient = cls(conf, redirect_url)
        c = OauthClient(auth_endpoint='https://accounts.google.com/o/oauth2/auth',
                        client_id=gclient.google_client_id,
                        redirect_uri=gclient.redirect_url)
        loc = c.auth_uri(scope=gclient.google_scope.split(','), access_type='offline',
                         state=state or '/', approval_prompt=approval_prompt)
        gclient.redirect = loc
        return gclient

    @classmethod
    def create_for_token(cls, conf, redirect_url, code):
        gclient = cls(conf, redirect_url)
        c = OauthClient(token_endpoint='https://accounts.google.com/o/oauth2/token',
                        resource_endpoint='https://www.googleapis.com/oauth2/v1',
                        redirect_uri=gclient.redirect_url,
                        client_id=gclient.google_client_id,
                        client_secret=gclient.google_client_secret)
        c.request_token(code=code)
        gclient.access_token = c.access_token
        gclient.expires_in = c.expires_in
        if hasattr(c, 'refresh_token'):
            gclient.refresh_token = c.refresh_token
            new_client = cls.create_for_refresh(conf, c.refresh_token)
            gclient.access_token = new_client.access_token
            gclient.expires_in = new_client.expires_in
        gclient.userinfo = c.request('/userinfo')
        return gclient

    @classmethod
    def create_for_refresh(cls, conf, redirect_url, rtoken):
        gclient = cls(conf, redirect_url)
        c = OauthClient(token_endpoint='https://accounts.google.com/o/oauth2/token',
                        resource_endpoint='https://www.googleapis.com/oauth2/v1',
                        client_id=gclient.google_client_id,
                        client_secret=gclient.google_client_secret)
        error = c.request_token(grant_type='refresh_token',
                                refresh_token=rtoken)
        if not error:
            gclient.access_token = c.access_token
            gclient.expires_in = c.expires_in
        return gclient
