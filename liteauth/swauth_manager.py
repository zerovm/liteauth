from urllib import quote
from uuid import uuid4
from swift.common.swob import Request, HTTPUnauthorized, \
    HTTPForbidden, wsgify, Response, HTTPInternalServerError, HTTPConflict
from swift.common.utils import get_logger
from swift.common.wsgi import make_pre_authed_request


def get_data_from_url(url, app, key, logger, env):
    if not url or not key:
        return None
    req = make_pre_authed_request(env,
                                  method='GET',
                                  path='%s/%s' % (url, quote(key)),
                                  swift_source='liteauth',
                                  agent='Liteauth')
    resp = req.get_response(app)
    if resp.status_int >= 300:
        logger.info('get_data response for %s is %s %s'
                    % (req.path, resp.status, resp.body))
        return None
    return resp.body.strip()


def store_data_in_url(url, app, key, data, env):
    if not url or not key:
        return False
    req = make_pre_authed_request(env,
                                  method='PUT',
                                  path='%s/%s' % (url, quote(key)),
                                  body=str(data),
                                  headers={'content-type': 'text/plain'},
                                  swift_source='liteauth',
                                  agent='Liteauth')
    req.environ['liteauth.new_service'] = \
        env.get('liteauth.new_service', None)
    resp = req.get_response(app)
    if resp.status_int >= 300:
        return False
    return True


def copy_env(src_req, dest_req):
    for key in ('swift.cache', 'swift.source', 'swift.trans_id',
                    'eventlet.posthooks'):
            if key in src_req.environ:
                dest_req.environ[key] = src_req.environ[key]


class SwauthManager(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='lite-swauth')
        self.profile_path = 'profile'
        self.super_admin_key = conf.get('super_admin_key')
        if not self.super_admin_key:
            msg = 'No super_admin_key set in conf file; ' \
                  'Swauth administration features will be disabled.'
            try:
                self.logger.warn(msg)
            except Exception:
                pass
        self.auth_prefix = conf.get('auth_prefix', '/auth/')
        if not self.auth_prefix:
            self.auth_prefix = '/auth/'
        if self.auth_prefix[0] != '/':
            self.auth_prefix = '/' + self.auth_prefix
        if self.auth_prefix[-1] != '/':
            self.auth_prefix += '/'
        self.version = 'v2'
        # url for whitelist objects
        # Example: /v1/liteauth/whitelist
        self.whitelist_url = conf.get('whitelist_url', '').lower().rstrip('/')
        if not self.whitelist_url:
            raise ValueError('whitelist_url not set in config file')
        # url for invite objects
        # Example: /v1/liteauth/invites
        self.invite_url = conf.get('invite_url', '').lower().rstrip('/')
        if not self.invite_url:
            raise ValueError('invite_url not set in config file')

    @wsgify
    def __call__(self, req):
        if not self.super_admin_key:  # profile management is disabled
            return self.denied_response(req)
        try:
            (endpoint, _rest) = req.split_path(1, 2, True)
        except ValueError:
            return self.denied_response(req)
        if endpoint == self.profile_path:
            new_service = None
            account_id = req.environ.get('REMOTE_USER', '')
            if not account_id:
                return HTTPUnauthorized(request=req)
            user_id, user_email = account_id.split(':')
            whitelist_id = get_data_from_url(self.whitelist_url,
                                             self.app,
                                             user_email,
                                             self.logger,
                                             req.environ)
            invite_code = req.headers.get('x-auth-invite-code', None)
            if invite_code and req.method == 'PUT':
                invite_id = get_data_from_url(self.invite_url,
                                              self.app,
                                              invite_code,
                                              self.logger,
                                              req.environ)
                if not invite_id:
                    return self.denied_response(req)
                service = None
                if not invite_id.startswith('email:'):
                    if not store_data_in_url(self.invite_url,
                                             self.app,
                                             invite_code,
                                             'email:%s:%s' % (user_email, invite_id),
                                             req.environ):
                        return HTTPInternalServerError(request=req)
                    service = invite_id
                elif 'email:%s:' % user_email in invite_id:
                    service = invite_id.split(':', 3)[2]
                if service and not whitelist_id:
                    if not store_data_in_url(self.whitelist_url,
                                             self.app,
                                             user_email,
                                             service,
                                             req.environ):
                        return HTTPInternalServerError(request=req)
                    whitelist_id = service
            if not whitelist_id:
                return Response(request=req, status=402,
                                body='Account not in whitelist')
            if whitelist_id.startswith('service_'):
                new_service = \
                    whitelist_id.replace('service_', '', 1)
                if not store_data_in_url(self.whitelist_url,
                                         self.app,
                                         user_email,
                                         user_id,
                                         req.environ):
                    return HTTPInternalServerError(request=req)
            elif whitelist_id != user_id:
                # user subscribed to the service already
                # but using a different auth provider
                return HTTPConflict(request=req)
            if req.method == 'GET':
                return self.get_swauth(req, user_id, user_email)
            elif req.method == 'PUT':
                return self.put_swauth(req, user_id, user_email, new_service)
        return self.denied_response(req)

    def get_swauth(self, req, user_id, user_email):
        swauth_req = Request.blank('%s%s/%s/%s' % (self.auth_prefix,
                                                   self.version,
                                                   user_email,
                                                   user_id),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key})
        copy_env(req, swauth_req)
        resp = swauth_req.get_response(self.app)
        return resp

    def put_swauth(self, req, user_id, user_email, service=None):
        user_key = req.headers.get('x-auth-user-key', str(uuid4()))
        swauth_req = Request.blank('%s%s/%s' % (self.auth_prefix,
                                                self.version,
                                                user_email),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key})
        swauth_req.method = 'PUT'
        copy_env(req, swauth_req)
        resp = swauth_req.get_response(self.app)
        if not resp.status_int // 100 == 2:
            return resp
        swauth_req = Request.blank('%s%s/%s/%s' % (self.auth_prefix,
                                                   self.version,
                                                   user_email,
                                                   user_id),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key,
                                            'x-auth-user-key': user_key,
                                            'x-auth-user-admin': 'true'})
        swauth_req.method = 'PUT'
        copy_env(req, swauth_req)
        if service:
            swauth_req.environ['liteauth.new_service'] = service
        resp = swauth_req.get_response(self.app)
        return resp

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
        return SwauthManager(app, conf)
    return auth_filter
