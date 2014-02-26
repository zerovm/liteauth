from urllib import quote
from time import time
from hashlib import md5
from providers.abstract_oauth import load_provider

from swift.common.constraints import MAX_META_VALUE_LENGTH
from swift.common.middleware.acl import clean_acl

try:
    import simplejson as json
except ImportError:
    import json

from swift.common.swob import HTTPFound, Response, Request, \
    HTTPUnauthorized, HTTPForbidden, HTTPInternalServerError, HTTPNotFound
from swift.common.utils import cache_from_env, get_logger, TRUE_VALUES, \
    split_path


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


def retrieve_metadata(app, version, account_id, name, env):
    account_req = Request.blank('/%s/%s' % (version, account_id))
    account_req.method = 'HEAD'
    account_req.environ['swift.cache'] = env['swift.cache']
    resp = account_req.get_response(app)
    if resp.status_int >= 300:
        return None
    meta = assemble_from_partial('x-account-meta-%s' % name, resp.headers)
    try:
        user_data = json.loads(meta)
    except:
        return None
    return user_data


def assemble_from_partial(key_name, key_dict):
    result = ''
    i = 0
    key = '%s%s' % (key_name, i)
    while key in key_dict:
        result += key_dict[key]
        i += 1
        key = '%s%s' % (key_name, i)
    return result or None


def store_metadata(app, version, account_id, name, user_data, env):
    try:
        user_data = json.dumps(user_data)
    except:
        return False
    userdata_req = Request.blank('/%s/%s' % (version, account_id))
    userdata_req.method = 'POST'
    userdata_req.environ['swift.cache'] = env['swift.cache']
    i = 0
    while user_data:
        userdata_req.headers['x-account-meta-%s%d' % (name, i)] = \
            user_data[:MAX_META_VALUE_LENGTH]
        user_data = user_data[MAX_META_VALUE_LENGTH:]
        i += 1
    resp = userdata_req.get_response(app)
    if resp.status_int >= 300:
        return False
    return True


def get_account_from_whitelist(whitelist_url, app, email, logger, env):
    if not whitelist_url or not email:
        return None
    req = Request.blank('%s/%s' % (whitelist_url, quote(email)))
    req.method = 'GET'
    req.environ['swift.cache'] = env['swift.cache']
    resp = req.get_response(app)
    if resp.status_int >= 300:
        logger.info('Whitelist response for %s is %s %s'
                    % (req.path, resp.status, resp.body))
        return None
    return resp.body.strip()


def store_account_in_whitelist(whitelist_url, app, email, account_id, env):
    if not whitelist_url or not email:
        return False
    req = Request.blank('%s/%s' % (whitelist_url, quote(email)))
    req.method = 'PUT'
    req.headers['content-type'] = 'text/plain'
    req.body = str(account_id)
    req.environ['swift.cache'] = env['swift.cache']
    req.environ['liteauth.new_service'] = \
        env.get('liteauth.new_service', None)
    resp = req.get_response(app)
    if resp.status_int >= 300:
        return False
    return True


class LiteAuthStorage(object):
    def __init__(self, env, prefix):
        self.cache = cache_from_env(env)
        if not self.cache:
            raise Exception('Memcache required')
        self.prefix = prefix

    def get_id(self, token):
        account_id = None
        expires = None
        memcache_token_key = '%s/token/%s' % (self.prefix, token)
        data = self.cache.get(memcache_token_key)
        if data:
            expires, account_id = data
        print ['get', memcache_token_key, account_id, expires]
        return account_id, expires

    def del_id(self, token):
        memcache_token_key = '%s/token/%s' % (self.prefix, token)
        self.cache.delete(memcache_token_key)
        print ['del', memcache_token_key]

    def store_id(self, account_id, token, expires_in):
        expires = time() + expires_in
        memcache_token_key = '%s/token/%s' % (self.prefix, token)
        print ['set', memcache_token_key, str(account_id), expires]
        self.cache.set(memcache_token_key, (expires, account_id),
                       time=float(expires - time()))


class LiteAuth(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.version = 'v1'
        self.service_domain = conf.get('service_domain')
        if not self.service_domain:
            raise ValueError('service_domain not set in config file')
        self.service_endpoint = conf.get('service_endpoint',
                                         'https://' + self.service_domain)
        self.auth_path = '/login/google/'
        self.logger = get_logger(conf, log_route='lite-auth')
        self.log_headers = conf.get('log_headers', 'false').lower() \
            in TRUE_VALUES
        # try to refresh token
        # when less than this amount of seconds left
        self.refresh_before = conf.get('token_refresh_before', 60 * 29)
        # url for whitelist objects
        # Example: /v1/liteauth/whitelist
        self.whitelist_url = conf.get('whitelist_url', '').lower().rstrip('/')
        self.storage_driver = None
        self.metadata_key = conf.get('metadata_key', 'userdata').lower()
        self.redirect_url = '%s%s' % (self.service_endpoint, self.auth_path)
        self.provider = load_provider(conf.get('oauth_provider', 'google_oauth'))
        self.prefix = self.provider.PREFIX

    def __call__(self, env, start_response):
        req = Request(env)
        self.storage_driver = LiteAuthStorage(env, self.prefix)
        if req.path.startswith(self.auth_path):
            state = None
            if req.params:
                code = req.params.get('code')
                state = req.params.get('state')
                if code:
                    return self.do_google_login(req, code, state)(env, start_response)
            return self.do_google_oauth(state)(env, start_response)
        token = req.headers.get('x-auth-token')
        _start_response = start_response
        if token:
            account_id, expires = self.storage_driver.get_id(token)
            req.environ['swift.authorize'] = self.authorize
            req.environ['swift.clean_acl'] = clean_acl
            if account_id and expires:
                new_headers = self.refresh_token(env, account_id, expires)
                if new_headers:

                    def refresh_resp(status, response_headers, exc_info=None):
                        for k, v in new_headers.iteritems():
                            response_headers.append((k, v))
                        return start_response(status, response_headers, exc_info)

                    _start_response = refresh_resp
        return self.app(env, _start_response)

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

    def do_google_oauth(self, state=None, approval_prompt='auto'):
        oauth_client = self.provider.create_for_redirect(
            self.conf,
            state=state,
            approval_prompt=approval_prompt)
        return HTTPFound(location=oauth_client.redirect)

    def do_google_login(self, req, code, state=None):
        if 'logout' in code:
            resp = Response(request=req, status=302,
                            headers={
                                'x-auth-token': 'logout',
                                'x-auth-token-expires': 0,
                                'x-storage-url': '%s/%s'
                                                 % (self.service_endpoint,
                                                    self.version),
                                'location': '%s%s?account=logout'
                                            % (self.service_endpoint, state)})
            req.response = resp
            return resp
        oauth_client = self.provider.create_for_token(self.conf, code)
        token = oauth_client.access_token
        if not token:
            req.response = HTTPUnauthorized()
            return req.response
        user_info = oauth_client.userinfo
        if not user_info:
            req.response = HTTPForbidden()
            return req.response
        account_id = self.prefix + user_info.get('id')
        self.storage_driver.store_id(account_id,
                                     oauth_client.access_token,
                                     oauth_client.expires_in)
        if self.whitelist_url:
            email = user_info.get('email', None)
            if not email:
                return HTTPForbidden()
            whitelist_id = get_account_from_whitelist(
                self.whitelist_url, self.app, email, self.logger, req.environ)
            self.logger.info('Whitelist is %s for user: %s' % (whitelist_id, email))
            if not whitelist_id:
                return Response(request=req, status=402,
                                body='Account not in whitelist')
            if whitelist_id.startswith('service_'):
                req.environ['liteauth.new_service'] = \
                    whitelist_id.replace('service_', '', 1)
                if not store_account_in_whitelist(self.whitelist_url,
                                                  self.app, email, account_id,
                                                  req.environ):
                        return HTTPInternalServerError()
            # elif whitelist_id.startswith(self.prefix):
            #     pass
            # else:
            #     self.logger.warning('Whitelist for user %s '
            #                         'contains wrong data: %s' % (email, whitelist_id))
            #     return HTTPInternalServerError()
        stored_info = retrieve_metadata(self.app,
                                        self.version,
                                        account_id,
                                        self.metadata_key,
                                        req.environ)
        if not stored_info:
            rtoken = oauth_client.refresh_token
            if not rtoken:
                return self.do_google_oauth(state=state, approval_prompt='force')
            user_info['rtoken'] = rtoken
            user_info['hash__'] = md5(json.dumps(sorted(user_info.items()))).hexdigest()
            if not store_metadata(self.app,
                                  self.version,
                                  account_id,
                                  self.metadata_key,
                                  user_info,
                                  req.environ):
                req.response = HTTPInternalServerError()
                return req.response
        else:
            rtoken = stored_info.pop('rtoken')
            stored_hash = stored_info.pop('hash__', None)
            user_hash = md5(json.dumps(sorted(user_info.items()))).hexdigest()
            if user_hash != stored_hash:
                # user changed profile data
                # we need to update our stored userinfo
                user_info['rtoken'] = rtoken
                user_info['hash__'] = user_hash
                if not store_metadata(self.app,
                                      self.version,
                                      account_id,
                                      self.metadata_key,
                                      user_info,
                                      req.environ):
                    req.response = HTTPInternalServerError()
                    return req.response
        resp = Response(request=req, status=302,
                        headers={
                            'x-auth-token': token,
                            'x-storage-token': token,
                            'x-storage-url': '%s/%s/%s'
                                             % (self.service_endpoint,
                                                self.version,
                                                account_id),
                            'location': '%s%s?account=%s'
                                        % (self.service_endpoint,
                                           state or '/',
                                           account_id)})
        #print resp.headers
        req.response = resp
        return resp

    def refresh_token(self, env, account_id, expires):
        if expires - time() < self.refresh_before:
            user_data = retrieve_metadata(self.app,
                                          self.version,
                                          account_id,
                                          self.metadata_key,
                                          env)
            if not user_data:
                return None
            rtoken = user_data.get('rtoken', None)
            if not rtoken:
                return None
            oauth_client = self.provider.create_for_refresh(self.conf, rtoken)
            headers = {
                'X-Auth-Token': oauth_client.access_token,
                'X-Auth-Token-Expires': oauth_client.expires_in,
                'X-Storage-Token': oauth_client.access_token,
                'X-Storage-Url': '%s/%s/%s'
                                 % (self.service_endpoint,
                                    self.version,
                                    account_id),
            }
            self.storage_driver.store_id(account_id,
                                         oauth_client.access_token,
                                         oauth_client.expires_in)
            return headers
        return None


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return LiteAuth(app, conf)
    return auth_filter