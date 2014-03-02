from liteauth import assemble_from_partial, store_metadata
from swift.common.http import is_success
from swift.common.swob import Request, HTTPRequestEntityTooLarge, HTTPInternalServerError
from swift.common.utils import get_logger, TRUE_VALUES
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
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
        if self.reseller_prefix and self.reseller_prefix[-1] != '_':
            self.reseller_prefix += '_'
        self.auth_account = '%s.auth' % self.reseller_prefix
        self.enforce_quota = conf.get('enforce_quota', 't').lower() in TRUE_VALUES

    def __call__(self, env, start_response):
        req = Request(env)
        new_service = env.get('liteauth.new_service', None)
        if new_service:
            account_name = req.split_path(2, 4, rest_with_last=True)[2]
            if not self.activate_service(account_name, new_service, req.environ):
                    return HTTPInternalServerError()
            del env['liteauth.new_service']
            return self.app(env, start_response)
        # We want to check POST here also
        # it can possibly have content_length > 0
        if not self.enforce_quota or req.method not in ("POST", "PUT", "COPY"):
            return self.app(env, start_response)
        account_info = get_account_info(req.environ, self.app,
                                        swift_source='litequota')
        if not account_info:
            return self.app(env, start_response)
        service_plan = assemble_from_partial(self.metadata_key,
                                             account_info['meta'])
        if not service_plan:
            return self.app(env, start_response)
        try:
            service_plan = json.loads(service_plan)
            ver, account, container, obj = \
                req.split_path(2, 4, rest_with_last=True)
        except ValueError:
            return self.app(env, start_response)

        if not obj:
            quota = service_plan['storage']['containers']
            # If "number of containers" = (quota + 1): deny PUT
            # We don't want to deny overwrite of the N-th container
            new_size = int(account_info['container_count'])
            if 0 <= quota < new_size:
                return bad_response(
                    req, None, 'Over quota: containers')(env, start_response)
            return self.app(env, start_response)

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
        quota = service_plan['storage']['bytes']
        if 0 <= quota < new_size:
            if not container_info:
                container_info = get_container_info(req.environ, self.app,
                                                    swift_source='litequota')
            return bad_response(req, container_info, 'Over quota: bytes')
        # If "number of objects" == (quota + 1): deny PUT
        # We don't want to deny overwrite of the N-th object
        new_size = int(account_info['total_object_count'])
        quota = service_plan['storage']['objects']
        if 0 <= quota < new_size:
            if not container_info:
                container_info = get_container_info(req.environ, self.app,
                                                    swift_source='litequota')
            return bad_response(req, container_info, 'Over quota: objects')
        return self.app(env, start_response)

    def activate_service(self, account_name, service, env):
        if not self.services_url:
            self.logger.warning('No services url found in config, '
                                'and user requests service %s'
                                % service)
            return False
        req = Request.blank('%s/%s' % (self.services_url, service))
        req.method = 'GET'
        req.environ['swift.cache'] = env['swift.cache']
        resp = req.get_response(self.app)
        if not is_success(resp.status_int):
            self.logger.error('Error getting service object: %s %s %s'
                              % (req.path, resp.status, resp.body))
            return False
        try:
            config = json.loads(resp.body)
        except Exception:
            self.logger.error('Error loading service object: %s %s %s'
                              % (req.path, resp.status, resp.body))
            return False
        req = Request(env)
        req.path_info = '/%s/%s/%s' \
                        % (self.version, self.auth_account, account_name)
        container_info = get_container_info(req.environ, self.app,
                                            swift_source='litequota')
        account_id = container_info['meta']['account-id']
        if not store_metadata(self.app, self.version, account_id,
                              self.metadata_key, config, env):
            return False
        return True


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def accounting_filter(app):
        return LiteQuota(app, conf)
    return accounting_filter