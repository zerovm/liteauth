from uuid import uuid4
from swift.common.swob import Request
from swift.common.utils import get_logger
try:
    import simplejson as json
except ImportError:
    import json


def copy_env(src_req, dest_req):
    for key in ('swift.cache', 'swift.source', 'swift.trans_id',
                    'eventlet.posthooks'):
            if key in src_req.environ:
                dest_req.environ[key] = src_req.environ[key]


class SwauthClient(object):
    def __init__(self, conf):
        self.logger = get_logger(conf, log_route='lite-auth')
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

    def get_account(self, app, req, user_email):
        swauth_req = Request.blank('%s%s/%s' % (self.auth_prefix,
                                                self.version,
                                                user_email),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key})
        copy_env(req, swauth_req)
        resp = swauth_req.get_response(app)
        if not resp.status_int // 100 == 2:
            return None
        try:
            data = json.loads(resp.body)
        except Exception:
            return None
        return data

    def get_user(self, app, req, user_id, user_email):
        swauth_req = Request.blank('%s%s/%s/%s' % (self.auth_prefix,
                                                   self.version,
                                                   user_email,
                                                   user_id),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key})
        copy_env(req, swauth_req)
        resp = swauth_req.get_response(app)
        return resp

    def put_user(self, app, req, user_id, user_email, service=None):
        user_key = req.headers.get('x-auth-user-key', str(uuid4()))
        swauth_req = Request.blank('%s%s/%s' % (self.auth_prefix,
                                                self.version,
                                                user_email),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key})
        swauth_req.method = 'PUT'
        copy_env(req, swauth_req)
        resp = swauth_req.get_response(app)
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
        resp = swauth_req.get_response(app)
        return resp

    def is_disabled(self):
        if self.super_admin_key:
            return False
        return True