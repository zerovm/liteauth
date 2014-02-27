class OauthClientInterface(object):
    # describes abstract client interface for generic Oauth2 clients

    # prefix for user id (account id)
    # each client must supply a unique one
    PREFIX = None

    # after getting a new client some of these properties will be set
    def __init__(self, redirect_url):
        self.access_token = None
        self.expires_in = None
        self.userinfo = None
        self.redirect = None
        self.redirect_url = redirect_url

    @classmethod
    def create_for_redirect(cls, conf, redirect_url):
        """
        get Oauth2 Client suitable for redirect

        :param conf: configuration dict
        :return: Client instance with attr `redirect` set
        """
        raise NotImplementedError

    @classmethod
    def create_for_token(cls, conf, redirect_url, code):
        """
        get Oauth2 Client suitable for getting token and user info

        :param conf: configuration dict
        :param code: Oauth2 code from the redirected request
        :return: Client instance with attr `access_token`,
                                 `expires_in` and `userinfo` set
        """
        raise NotImplementedError

    @classmethod
    def create_for_refresh(cls, conf, redirect_url, rtoken):
        """
        get Oauth2 Client suitable for refreshing short term tokens

        :param conf: configuration dict
        :param rtoken: refresh token
        :return: Client instance with attr `access_token`
                                       and `expires_in`  set
        """
        raise NotImplementedError


def load_provider(name):
    try:
        mod = __import__('liteauth.providers.' + name, fromlist=['Client'])
        provider = getattr(mod, 'Client')
        return provider
    except Exception:
        raise ValueError('oauth_provider is invalid in config file')
