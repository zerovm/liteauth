from liteauth import assemble_from_partial
from swauth_manager import get_data_from_url
from swift.common.constraints import MAX_META_VALUE_LENGTH
from swift.common.http import is_success
from swift.common.swob import Request, HTTPRequestEntityTooLarge, HTTPInternalServerError
from swift.common.utils import get_logger, TRUE_VALUES
from swift.common.wsgi import make_pre_authed_request
from swift.proxy.controllers.base import get_account_info, get_container_info, get_object_info

try:
    import simplejson as json
except ImportError:
    import json


def check_acl(req, container_info, acl_type):
    if 'swift.authorize' in req.environ:
        req.acl = container_info[acl_type]
        return req.environ['swift.authorize'](req)
    return None


def bad_response(req, container_info, msg):
    # 401 if the user couldn't have PUT this object in the first place.
    # This prevents leaking the container's existence to unauthed users.
    if container_info:
        aresp = check_acl(req, container_info, 'write_acl')
        if aresp:
            return aresp
    return HTTPRequestEntityTooLarge(request=req, body=msg)


class LiteQuota(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='lite-quota')
        self.version = 'v1'
        self.metadata_key = conf.get('metadata_key', 'serviceplan').lower()
        # url for service objects
        self.services_url = conf.get('services_url', '').lower().rstrip('/')
        # url for whitelist objects
        # Example: /v1/liteauth/whitelist
        self.whitelist_url = conf.get('whitelist_url', '').lower().rstrip('/')
        if not self.whitelist_url:
            raise ValueError('whitelist_url not set in config file')
        self.enforce_quota = conf.get('enforce_quota', 't').lower() in TRUE_VALUES

    def __call__(self, env, start_response):
        req = Request(env)
        # We want to check POST here
        # it can possibly have content_length > 0
        if not self.enforce_quota or req.method not in ("POST", "PUT", "COPY"):
            return self.app(env, start_response)
        account_info = get_account_info(req.environ, self.app,
                                        swift_source='litequota')
        if not account_info:
            return self.app(env, start_response)
        service_plan = assemble_from_partial(self.metadata_key,
                                             account_info['meta'])
        try:
            ver, account, container, obj = \
                req.split_path(2, 4, rest_with_last=True)
        except ValueError:
            return self.app(env, start_response)
        if not service_plan and req.method == 'PUT' and not obj:
            service_plan = self.set_serviceplan(req, account)
        if not service_plan:
            return self.app(env, start_response)
        try:
            service_plan = json.loads(service_plan)
        except ValueError:
            return self.app(env, start_response)

        if service_plan.get('storage', None):
            resp = self.apply_storage_quota(req, service_plan['storage'],
                                            account_info,
                                            ver, account, container, obj)
            if resp:
                return resp(env, start_response)
        return self.app(env, start_response)

    def set_serviceplan(self, req, account_id):
        groups = req.remote_user
        if not groups:
            return None
        user_email = None
        for group in groups.split(','):
            if ':' in group:
                user_email, user_id = group.split(':')
                break
        if not user_email:
            return None
        # We do not want to accidentally set service plan
        # of one user on another user account
        if groups.split(',')[-1] != account_id:
            return None
        whitelist_data = get_data_from_url(self.whitelist_url,
                                           self.app,
                                           user_email,
                                           self.logger,
                                           req.environ)
        if not whitelist_data:
            return None
        try:
            service = json.loads(whitelist_data).get('service', None)
        except Exception:
            return HTTPInternalServerError(request=req)
        service_plan_data = {}
        for service_type, service_name in service.iteritems():
            if not self.services_url:
                self.logger.warning('No services url found in config, '
                                    'and user requests service: %s'
                                    % service_name)
                return None
            req = make_pre_authed_request(req.environ,
                                          method='GET',
                                          path='%s/%s'
                                               % (self.services_url, service_name),
                                          swift_source='litequota')
            resp = req.get_response(self.app)
            if not is_success(resp.status_int):
                self.logger.error('Error getting service object: %s %s %s'
                                  % (req.path, resp.status, resp.body))
                return None
            try:
                service_data = json.loads(resp.body)
            except Exception:
                self.logger.error('Error loading service object: %s %s %s'
                                  % (req.path, resp.status, resp.body))
                return None
            service_plan_data[service_type] = service_data
        print service_plan_data
        req = make_pre_authed_request(req.environ,
                                      method='POST',
                                      path='/%s/%s' % (self.version, account_id),
                                      swift_source='litequota')
        config = json.dumps(service_plan_data)
        i = 0
        while config:
            req.headers['x-account-meta-%s%d' % (self.metadata_key, i)] = \
                config[:MAX_META_VALUE_LENGTH]
            config = config[MAX_META_VALUE_LENGTH:]
            i += 1
        resp = req.get_response(self.app)
        if not is_success(resp.status_int):
            self.logger.error('Error storing service object in account: %s %s %s'
                              % (req.path, resp.status, resp.body))
            return None
        return json.dumps(service_plan_data)

    def apply_storage_quota(self, req, service_plan, account_info,
                            ver, account, container, obj):
        if not obj:
            quota = service_plan['containers']
            # If "number of containers" = (quota + 1): deny PUT
            # We don't want to deny overwrite of the last container
            new_size = int(account_info['container_count'])
            if 0 <= quota < new_size:
                return bad_response(
                    req, None, 'Over quota: containers')
            return None

        content_length = (req.content_length or 0)
        if req.method == 'COPY':
            copy_from = container + '/' + obj
        else:
            copy_from = req.headers.get('X-Copy-From')
        container_info = None
        if copy_from:
            copy_account = req.headers.get('X-Copy-From-Account', account)
            path = '/' + ver + '/' + copy_account + '/' + copy_from.lstrip('/')
            # We are copying from another account
            # Let's not leak the existence of the remote object
            # to the unauthorized user
            if copy_account != account:
                container_info = get_container_info(req.environ, self.app,
                                                    swift_source='litequota')
                aresp = check_acl(req, container_info, 'read_acl')
                if aresp:
                    return aresp
            object_info = get_object_info(req.environ, self.app, path)
            if not object_info or not object_info['length']:
                content_length = 0
            else:
                content_length = int(object_info['length'])
        new_size = int(account_info['bytes']) + content_length
        quota = service_plan['bytes']
        if 0 <= quota < new_size:
            if not container_info:
                container_info = get_container_info(req.environ, self.app,
                                                    swift_source='litequota')
            return bad_response(req, container_info, 'Over quota: bytes')
        # If "number of objects" == (quota + 1): deny PUT
        # We don't want to deny overwrite of the last object
        new_size = int(account_info['total_object_count'])
        quota = service_plan['objects']
        if 0 <= quota < new_size:
            if not container_info:
                container_info = get_container_info(req.environ, self.app,
                                                    swift_source='litequota')
            return bad_response(req, container_info, 'Over quota: objects')


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def accounting_filter(app):
        return LiteQuota(app, conf)
    return accounting_filter