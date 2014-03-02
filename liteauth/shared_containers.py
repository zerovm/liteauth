from liteauth import retrieve_metadata, store_metadata
from providers import load_provider
from swift.common.swob import wsgify, HTTPBadRequest, HTTPUnauthorized, HTTPNotFound, Response, Request, \
    HTTPRequestEntityTooLarge
from swift.common.utils import get_logger
try:
    import simplejson as json
except ImportError:
    import json


class SharedContainersMiddleware(object):

    def __init__(self, app, conf):
        self.app = app
        self.shared_container_add = 'load-share'
        self.shared_container_remove = 'drop-share'
        self.version = 'v1'
        self.logger = get_logger(conf, log_route='lite-auth')
        self.metadata_key = conf.get('metadata_key', 'shared').lower()
        self.provider = load_provider('swauth', 'SwauthClient',
                                      'could not load SwauthClient')(conf)
        self.shared_max = int(conf.get('max_shared_containers', 20))

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
        user_data = self.provider.get_account(self.app, request, shared_account)
        if user_data:
            remote_user_name = shared_account
            shared_account = user_data['account_id']
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
        if len(shared) > self.shared_max:
            return HTTPRequestEntityTooLarge(request=request,
                                             body='Max number of shared containers reached')
        if store_metadata(self.app, self.version,
                          account_id, self.metadata_key,
                          shared, request.environ):
            return Response(body='Successfully handled shared container %s/%s'
                                 % (shared_account, shared_container))
        return HTTPNotFound(body='Could not handle shared container %s/%s'
                                 % (shared_account, shared_container))


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def shared_containers_filter(app):
        return SharedContainersMiddleware(app, conf)

    return shared_containers_filter