from urllib import quote
from providers import load_provider
from swift.common.swob import HTTPUnauthorized, \
    HTTPForbidden, wsgify, Response, HTTPInternalServerError, HTTPConflict
from swift.common.utils import get_logger
from swift.common.wsgi import make_pre_authed_request
try:
    import simplejson as json
except ImportError:
    import json


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
        self.provider = load_provider('swauth',
                                      'SwauthClient',
                                      'could not load SwauthClient')(conf)
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
        self.cors_allow_origin = [
            a.strip()
            for a in conf.get('cors_allow_origin', '').split(',')
            if a.strip()]

    @wsgify
    def __call__(self, req):
        req_origin = req.headers.get('origin', None)
        resp = self.handle(req)
        if req_origin and req_origin in self.cors_allow_origin:
                resp.headers['access-control-allow-origin'] = req_origin
        return resp

    def denied_response(self, req):
        if req.remote_user:
            self.logger.increment('forbidden')
            return HTTPForbidden(request=req)
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized(request=req)

    def handle(self, req):
        if self.provider.is_disabled():  # profile management is disabled
            return self.denied_response(req)
        try:
            (endpoint, _rest) = req.split_path(1, 2, True)
        except ValueError:
            return self.denied_response(req)
        if endpoint == self.profile_path:
            account_id = req.environ.get('REMOTE_USER', '')
            if not account_id:
                return HTTPUnauthorized(request=req)
            user_id, user_email = account_id.split(':')
            whitelist_data = get_data_from_url(self.whitelist_url,
                                               self.app,
                                               user_email,
                                               self.logger,
                                               req.environ)
            invite_code = req.headers.get('x-auth-invite-code', None)
            if invite_code and req.method == 'PUT':
                invite_data = get_data_from_url(self.invite_url,
                                                self.app,
                                                invite_code,
                                                self.logger,
                                                req.environ)
                if not invite_data or isinstance(invite_data, dict):
                    return self.denied_response(req)
                try:
                    invite_data = json.loads(invite_data)
                except Exception:
                    return HTTPInternalServerError(request=req)
                if not invite_data.get('service', None):
                    return HTTPInternalServerError(request=req)
                if not invite_data.get('email', None):
                    invite_data['email'] = user_email
                    invite_data['user_id'] = user_id
                    if not store_data_in_url(self.invite_url,
                                             self.app,
                                             invite_code,
                                             json.dumps(invite_data),
                                             req.environ):
                        return HTTPInternalServerError(request=req)
                    if not store_data_in_url(self.whitelist_url,
                                             self.app,
                                             user_email,
                                             json.dumps(invite_data),
                                             req.environ):
                        return HTTPInternalServerError(request=req)
                elif not whitelist_data and invite_data['email'] == user_email:
                    if not store_data_in_url(self.whitelist_url,
                                             self.app,
                                             user_email,
                                             json.dumps(invite_data),
                                             req.environ):
                        return HTTPInternalServerError(request=req)
            else:
                if whitelist_data:
                    try:
                        whitelist_data = json.loads(whitelist_data)
                    except Exception:
                        return HTTPInternalServerError(request=req)
                if not whitelist_data or not isinstance(whitelist_data, dict):
                    return Response(request=req, status=402,
                                    body='Account not in whitelist')
                if not whitelist_data.get('service', None):
                    return HTTPInternalServerError(request=req)
                current_user = whitelist_data.get('user_id', None)
                if not current_user:
                    whitelist_data['email'] = user_email
                    whitelist_data['user_id'] = user_id
                    if not store_data_in_url(self.whitelist_url,
                                             self.app,
                                             user_email,
                                             json.dumps(whitelist_data),
                                             req.environ):
                        return HTTPInternalServerError(request=req)
                elif current_user != user_id:
                    # user subscribed to the service already
                    # but used a different auth provider
                    return HTTPConflict(request=req)
            if req.method == 'GET':
                return self.provider.get_user(self.app,
                                              req,
                                              user_id,
                                              user_email)
            elif req.method == 'PUT':
                return self.provider.put_user(self.app,
                                              req,
                                              user_id,
                                              user_email)
        return self.denied_response(req)

def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return SwauthManager(app, conf)
    return auth_filter
