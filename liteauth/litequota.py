from liteauth import assemble_from_partial, store_metadata
from swift.common.http import is_success
from swift.common.swob import Request, HTTPRequestEntityTooLarge, HTTPInternalServerError
from swift.common.utils import get_logger
from swift.proxy.controllers.base import get_account_info

try:
    import simplejson as json
except ImportError:
    import json


class LiteQuota(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='lite-quota')
        self.version = 'v1'
        self.metadata_key = conf.get('metadata_key', 'serviceplan').lower()
        # url for service objects
        self.services_url = conf.get('services_url', '').lower().rstrip('/')

    def __call__(self, env, start_response):
        req = Request(env)
        new_service = env.get('liteauth.new_service', None)
        if new_service:
            account_id = env.get('REMOTE_USER', '')
            if not account_id:
                return HTTPInternalServerError()
            if not self.activate_service(account_id, new_service, req.environ):
                    return HTTPInternalServerError()
        if req.method in ['PUT', 'POST'] and not 'x-zerovm-execute' in req.headers:
            account_info = get_account_info(req.environ, self.app,
                                            swift_source='litequota')
            service_plan = assemble_from_partial(self.metadata_key,
                                                 account_info['meta'])
            if service_plan:
                try:
                    service_plan = json.loads(service_plan)
                    path_parts = req.split_path(2, 4, rest_with_last=True)
                except ValueError:
                    return self.app(env, start_response)
                if len(path_parts) == 3:
                    quota = service_plan['storage']['containers']
                    new_size = int(account_info['container_count'])
                    if 0 <= quota < new_size:
                        return HTTPRequestEntityTooLarge(
                            body='Over quota: containers')(env, start_response)
                else:
                    new_size = int(account_info['bytes']) + (req.content_length or 0)
                    quota = service_plan['storage']['bytes']
                    if 0 <= quota < new_size:
                        return HTTPRequestEntityTooLarge(
                            body='Over quota: bytes')(env, start_response)
                    quota = service_plan['storage']['objects']
                    new_size = int(account_info['total_object_count'])
                    if 0 <= quota < new_size:
                        return HTTPRequestEntityTooLarge(
                            body='Over quota: objects')(env, start_response)
        return self.app(env, start_response)

    def activate_service(self, account_id, service, env):
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