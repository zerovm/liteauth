from liteauth.liteauth import retrieve_metadata, store_metadata
from liteauth.swauth_manager import copy_env
from swift.common.swob import wsgify, HTTPBadRequest, HTTPUnauthorized, HTTPNotFound, Response, Request
from swift.common.utils import get_logger


class SharedContainersMiddleware(object):

    def __init__(self, app, conf):
        self.app = app
        self.shared_container_add = 'load-share'
        self.shared_container_remove = 'drop-share'
        self.version = 'v1'
        self.logger = get_logger(conf, log_route='lite-auth')
        self.metadata_key = conf.get('metadata_key', 'shared').lower()

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

    @wsgify
    def __call__(self, request):
        try:
            (version, account, container, obj) = request.split_path(2, 4, True)
        except ValueError:
            return self.app
        if version in (self.shared_container_add, self.shared_container_remove):
            if container:
                return self.handle_shared(version,
                                          request,
                                          account,
                                          container)
            return HTTPBadRequest(body='Cannot parse url path %s%s'
                                       % (request.environ.get('SCRIPT_NAME', ''),
                                          request.environ['PATH_INFO']))
        return self.app

    def handle_shared(self, version, request, shared_account, shared_container):
        groups = request.remote_user
        if not groups:
            return HTTPUnauthorized(request=request)
        remote_user_name = 'shared'

        account_id = groups[-1]
        shared = retrieve_metadata(self.app, self.version,
                                   account_id, self.metadata_key,
                                   request.environ)
        if not shared:
            shared = {}
        if version in self.shared_container_add:
            shared['%s/%s' % (shared_account, shared_container)] = remote_user_name
        elif version in self.shared_container_remove:
            try:
                del shared['%s/%s' % (shared_account, shared_container)]
            except KeyError:
                return HTTPNotFound(body='Could not remove shared container %s/%s'
                                         % (shared_account, shared_container))
        if store_metadata(self.app, self.version,
                          account_id, self.metadata_key,
                          shared, request.environ):
            return Response(body='Successfully handled shared container %s/%s'
                                 % (shared_account, shared_container))
        return HTTPNotFound(body='Could not handle shared container %s/%s'
                                 % (shared_account, shared_container))

    def get_swauth(self, req, user_id, user_email):
        swauth_req = Request.blank('%s%s/%s/%s' % (self.auth_prefix,
                                                   self.version,
                                                   user_id,
                                                   user_email),
                                   headers={'x-auth-admin-user': '.super_admin',
                                            'x-auth-admin-key': self.super_admin_key})
        copy_env(req, swauth_req)
        resp = swauth_req.get_response(self.app)
        return resp


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def shared_containers_filter(app):
        return SharedContainersMiddleware(app, conf)

    return shared_containers_filter