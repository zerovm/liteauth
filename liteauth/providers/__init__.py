def load_provider(name, klass, err_msg):
    try:
        mod = __import__('liteauth.providers.' + name, fromlist=[klass])
        provider = getattr(mod, klass)
        return provider
    except Exception:
        raise ValueError(err_msg)


def load_oauth_provider(name):
    load_provider(name, 'Client', 'oauth_provider is invalid in config file')
