from Cookie import SimpleCookie
from urllib import quote, unquote
from time import gmtime, strftime, time
import datetime
from swift.common.constraints import MAX_META_VALUE_LENGTH

try:
    import simplejson as json
except ImportError:
    import json

from swift.common.http import HTTP_CLIENT_CLOSED_REQUEST
from swift.common.swob import HTTPFound, Response, Request, HTTPUnauthorized, HTTPForbidden, HTTPNotFound, wsgify, HTTPInternalServerError
from swift.common.utils import cache_from_env, get_logger, TRUE_VALUES, split_path
from swift.common.middleware.acl import clean_acl
from oauth import Client


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


def retrieve_metadata(app, version, account_id, name):
    account_req = Request.blank('/%s/%s' % (version, account_id))
    account_req.method = 'HEAD'
    resp = account_req.get_response(app)
    if resp.status_int >= 300:
        return None
    i = 0
    meta = ''
    key = 'x-account-meta-%s0' % name
    while key in resp.headers:
        meta += resp.headers[key]
        i += 1
        key = 'x-account-meta-%s%d' % (name, i)
    try:
        user_data = json.loads(meta)
    except:
        return None
    return user_data


def store_metadata(app, version, account_id, name, user_data):
    try:
        user_data = json.dumps(user_data)
    except:
        return False
    userdata_req = Request.blank('/%s/%s' % (version, account_id))
    userdata_req.method = 'POST'
    i = 0
    while user_data:
        userdata_req.headers['x-account-meta-%s%d' % (name, i)] = user_data[:MAX_META_VALUE_LENGTH]
        user_data = user_data[MAX_META_VALUE_LENGTH:]
        i += 1
    resp = userdata_req.get_response(app)
    if resp.status_int >= 300:
        return False
    return True


def get_account_from_whitelist(whitelist_url, app, email, logger):
    if not whitelist_url or not email:
        return None
    req = Request.blank('%s/%s' % (whitelist_url, quote(email)))
    req.method = 'GET'
    resp = req.get_response(app)
    if resp.status_int >= 300:
        logger.info('Whitelist response for %s is %s %s' % (req.path, resp.status, resp.body))
        return None
    return resp.body.strip()


def store_account_in_whitelist(whitelist_url, app, email, account_id):
    if not whitelist_url or not email:
        return False
    req = Request.blank('%s/%s' % (whitelist_url, quote(email)))
    req.method = 'PUT'
    req.headers['content-type'] = 'text/plain'
    req.body = str(account_id)
    resp = req.get_response(app)
    if resp.status_int >= 300:
        return False
    return True


class LiteAuth(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.version = 'v1'
        self.google_client_id = conf.get('google_client_id')
        if not self.google_client_id:
            raise ValueError('google_client_id not set in config file')
        self.google_client_secret = conf.get('google_client_secret')
        if not self.google_client_secret:
            raise ValueError('google_client_secret not set in config file')
        self.service_domain = conf.get('service_domain')
        if not self.service_domain:
            raise ValueError('service_domain not set in config file')
        self.service_endpoint = conf.get('service_endpoint', 'https://' + self.service_domain)
        self.google_scope = conf.get('google_scope')
        if not self.google_scope:
            raise ValueError('google_scope not set in config file')
        self.google_auth = '/login/google/'
        self.google_prefix = 'g_'
        self.logger = get_logger(conf, log_route='lite-auth')
        self.log_headers = conf.get('log_headers', 'false').lower() in TRUE_VALUES
        self.system_accounts = conf.get('system_accounts', '').split()
        # try to refresh token
        # when less than this amount of seconds left
        self.refresh_before = conf.get('token_refresh_before', 60 * 29)
        # url for whitelist objects
        # Example: /v1/liteauth/whitelist
        self.whitelist_url = conf.get('whitelist_url', '').lower().rstrip('/')
        # if set to 'true' will allow getting whitelist data even for un-authorized clients
        self.whitelist_is_public = conf.get('whitelist_public', 'false').lower() in TRUE_VALUES

    def extract_auth_token(self, env):
        auth_token = None
        try:
            auth_token = SimpleCookie(env.get('HTTP_COOKIE', ''))['session'].value
        except KeyError:
            pass
        return auth_token

    def is_whitelist_request(self, req):
        if self.whitelist_url \
                and req.path.startswith(self.whitelist_url) \
                and req.method in ['GET', 'HEAD']:
            return True
        return False

    def __call__(self, env, start_response):
        req = Request(env)
        if self.whitelist_is_public and self.is_whitelist_request(req):
            return self.app(env, start_response)
        if req.path.startswith(self.google_auth):
            state = None
            if req.params:
                code = req.params.get('code')
                state = req.params.get('state')
                if code:
                    if not 'eventlet.posthooks' in req.environ:
                        req.bytes_transferred = '-'
                        req.client_disconnect = False
                        req.start_time = time()
                        response = self.do_google_login(req, code, state)
                        req.response = response
                        self.posthooklogger(req.environ, req)
                        return response(env, start_response)
                    else:
                        return self.do_google_login(
                            req, code, state)(env, start_response)
            return self.do_google_oauth(state)(env, start_response)
        token = self.extract_auth_token(req.environ)
        if token:
            req.headers['x-auth-token'] = token
            req.headers['x-storage-token'] = token
            account_id = self.get_cached_account_id(req.environ, token)
            if not account_id:
                return HTTPUnauthorized()(env, start_response)
            req.environ['REMOTE_USER'] = account_id
            req.headers['x-auth-token'] = '%s,%s' % (account_id, token)
            if self.is_whitelist_request(req):
                return self.app(env, start_response)
        req.environ['swift.authorize'] = self.authorize
        req.environ['swift.clean_acl'] = clean_acl
        new_cookie = req.environ.get('refresh_cookie', None)
        if new_cookie:
            del req.environ['refresh_cookie']

            def cookie_resp(status, response_headers, exc_info=None):
                response_headers.append(('Set-Cookie', new_cookie))
                return start_response(status, response_headers, exc_info)

            return self.app(env, cookie_resp)
        return self.app(env, start_response)

    def do_google_oauth(self, state=None, approval_prompt='auto'):
        c = Client(auth_endpoint='https://accounts.google.com/o/oauth2/auth',
                   client_id=self.google_client_id,
                   redirect_uri='%s%s' % (self.service_endpoint, self.google_auth))
        loc = c.auth_uri(scope=self.google_scope.split(','), access_type='offline',
                         state=state or '/', approval_prompt=approval_prompt)
        return HTTPFound(location=loc)

    def do_google_login(self, req, code, state=None):
        if 'eventlet.posthooks' in req.environ:
            req.bytes_transferred = '-'
            req.client_disconnect = False
            req.start_time = time()
            req.environ['eventlet.posthooks'].append(
                (self.posthooklogger, (req,), {}))
        if 'logout' in code:
            auth_token = self.extract_auth_token(req.environ)
            if auth_token:
                self.del_cached_account_id(req.environ, auth_token)
            cookie = self.create_session_cookie()
            resp = Response(request=req, status=302,
                            headers={
                                'set-cookie': cookie,
                                'location': '%s%s?account=logout' % (self.service_endpoint, state)})
            req.response = resp
            return resp
        c = Client(token_endpoint='https://accounts.google.com/o/oauth2/token',
                   resource_endpoint='https://www.googleapis.com/oauth2/v1',
                   redirect_uri='%s%s' % (self.service_endpoint, self.google_auth),
                   client_id=self.google_client_id,
                   client_secret=self.google_client_secret)
        c.request_token(code=code)
        token = c.access_token
        if hasattr(c, 'refresh_token'):
            rc = Client(token_endpoint=c.token_endpoint,
                        client_id=c.client_id,
                        client_secret=c.client_secret,
                        resource_endpoint=c.resource_endpoint)
            rc.request_token(grant_type='refresh_token',
                             refresh_token=c.refresh_token)
            token = rc.access_token
        if not token:
            req.response = HTTPUnauthorized()
            return req.response
        user_info = self.get_new_user_info(req.environ, c)
        if not user_info:
            req.response = HTTPForbidden()
            return req.response
        account_id = self.get_account_id(user_info)
        if self.whitelist_url:
            email = user_info.get('email', None)
            if not email:
                return HTTPForbidden()
            whitelist_id = get_account_from_whitelist(self.whitelist_url, self.app, email, self.logger)
            self.logger.info('Whitelist is %s for user: %s' % (whitelist_id, json.dumps(user_info)))
            if not whitelist_id:
                return Response(request=req, status=402, body='Account not in whitelist')
            if 'new' in whitelist_id:
                if not store_account_in_whitelist(self.whitelist_url, self.app, email, account_id):
                    return HTTPInternalServerError()
        stored_info = retrieve_metadata(self.app, self.version, account_id, 'userdata')
        if not stored_info:
            if not hasattr(c, 'refresh_token'):
                return self.do_google_oauth(state=state, approval_prompt='force')
            user_info['rtoken'] = c.refresh_token
            if not store_metadata(self.app, self.version, account_id, 'userdata', user_info):
                req.response = HTTPInternalServerError()
                return req.response
        cookie = self.create_session_cookie(token=token, expires_in=c.expires_in)
        resp = Response(request=req, status=302,
                        headers={
                            'x-auth-token': token,
                            'x-storage-token': token,
                            'x-storage-url': '%s/%s/%s' % (self.service_endpoint, self.version, account_id),
                            'set-cookie': cookie,
                            'location': '%s%s?account=%s' % (self.service_endpoint, state or '/', account_id)})
        #print resp.headers
        req.response = resp
        return resp

    def create_session_cookie(self, token='', path='/', expires_in=0):
        cookie = SimpleCookie()
        cookie['session'] = token
        cookie['session']['path'] = path
        if not self.service_domain.startswith('localhost'):
            cookie['session']['domain'] = self.service_domain
        expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        cookie['session']['expires'] = expiration.strftime('%a, %d %b %Y %H:%M:%S GMT')
        return cookie['session'].output(header='').strip()

    def del_cached_account_id(self, env, token):
        memcache_client = cache_from_env(env)
        if not memcache_client:
            raise Exception('Memcache required')
        memcache_token_key = '%s/token/%s' % (self.google_prefix, token)
        memcache_client.delete(memcache_token_key)

    def cache_account_id(self, env, account_id, token, expires_in):
        expires = time() + expires_in
        memcache_client = cache_from_env(env)
        memcache_token_key = '%s/token/%s' \
                             % (self.google_prefix, token)
        memcache_client.set(memcache_token_key, (expires, account_id),
                            time=float(expires - time()))

    def get_cached_account_id(self, env, token):
        account_id = None
        memcache_client = cache_from_env(env)
        if not memcache_client:
            raise Exception('Memcache required')
        memcache_token_key = '%s/token/%s' % (self.google_prefix, token)
        cached_auth_data = memcache_client.get(memcache_token_key)
        if cached_auth_data:
            expires, account_id = cached_auth_data
            if expires - time() < self.refresh_before:
                user_data = retrieve_metadata(self.app, self.version, account_id, 'userdata')
                if not user_data:
                    return self.do_google_oauth(state=None, approval_prompt='force')
                rtoken = user_data.get('rtoken', None)
                if not rtoken:
                    return self.do_google_oauth(state=None, approval_prompt='force')
                client = Client(token_endpoint='https://accounts.google.com/o/oauth2/token',
                                resource_endpoint='https://www.googleapis.com/oauth2/v1',
                                client_id=self.google_client_id,
                                client_secret=self.google_client_secret)
                error = client.request_token(grant_type='refresh_token',
                                             refresh_token=rtoken)
                if error:
                    self.logger.info('%s' % str(error))
                cookie = self.create_session_cookie(token=client.access_token,
                                                    expires_in=client.expires_in)
                env['refresh_cookie'] = cookie
                self.cache_account_id(env, account_id,
                                      client.access_token, client.expires_in)
        return account_id

    def get_account_id(self, user_info):
        account_id = self.google_prefix + user_info.get('id')
        return account_id

    def get_new_user_info(self, env, client):
        user_info = client.request('/userinfo')
        if user_info:
            account_id = self.get_account_id(user_info)
            self.cache_account_id(env, account_id, client.access_token, client.expires_in)
        return user_info

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
                and account in user_data:
            return None
        if account in user_data and \
                (req.method not in ('DELETE', 'PUT', 'POST') or container):
            req.environ['swift_owner'] = True
            return None
        if container:
            accounts = parse_lite_acl(getattr(req, 'acl', None))
            if '*' in accounts or user_data in accounts:
                return None
        return self.denied_response(req)

    def denied_response(self, req):
        if req.remote_user:
            self.logger.increment('forbidden')
            return HTTPForbidden(request=req)
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized(request=req)

    def posthooklogger(self, env, req):
        if not req.path.startswith(self.google_auth):
            return
        response = getattr(req, 'response', None)
        if not response:
            return
        trans_time = '%.4f' % (time() - req.start_time)
        the_request = quote(unquote(req.path))
        if req.query_string:
            the_request = the_request + '?' + req.query_string
            # remote user for zeus
        client = req.headers.get('x-cluster-client-ip')
        if not client and 'x-forwarded-for' in req.headers:
            # remote user for other lbs
            client = req.headers['x-forwarded-for'].split(',')[0].strip()
        logged_headers = None
        if self.log_headers:
            logged_headers = '\n'.join('%s: %s' % (k, v)
                                       for k, v in req.headers.items())
        status_int = response.status_int
        if getattr(req, 'client_disconnect', False) or \
                getattr(response, 'client_disconnect', False):
            status_int = HTTP_CLIENT_CLOSED_REQUEST
        self.logger.info(
            ' '.join(quote(str(x)) for x in (client or '-',
                                             req.remote_addr or '-', strftime('%d/%b/%Y/%H/%M/%S', gmtime()),
                                             req.method, the_request, req.environ['SERVER_PROTOCOL'],
                                             status_int, req.referer or '-', req.user_agent or '-',
                                             req.headers.get('x-auth-token',
                                                             req.headers.get('x-auth-admin-user', '-')),
                                             getattr(req, 'bytes_transferred', 0) or '-',
                                             getattr(response, 'bytes_transferred', 0) or '-',
                                             req.headers.get('etag', '-'),
                                             req.environ.get('swift.trans_id', '-'), logged_headers or '-',
                                             trans_time)))


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return LiteAuth(app, conf)
    return auth_filter