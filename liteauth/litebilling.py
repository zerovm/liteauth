from urlparse import parse_qs
from swift.common.swob import Response, Request, HTTPForbidden, HTTPNotFound
from swift.common.utils import get_logger
try:
    import simplejson as json
except ImportError:
    import json

class LiteBilling(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.billing_prefix = '/checkout'
        self.notification_prefix = '/notify'
        self.logger = get_logger(conf, log_route='lite-billing')
        self.item_prices = [i.strip() for i in conf.get('checkout_item_prices', '').split(';') if i.strip()]
        self.item_names = [i.strip() for i in conf.get('checkout_item_names', '').split(';') if i.strip()]
        self.item_descriptions = [i.strip() for i in conf.get('checkout_item_descriptions', '').split(';') if i.strip()]
        if len(self.item_prices) and len(self.item_names) and len(self.item_descriptions):
            if len(self.item_prices) == len(self.item_names) == len(self.item_descriptions):
                pass
            else:
                raise
        else:
            raise
        self.item_currency = 'USD'
        self.item_quantity = '1'
        self.service_domain = conf.get('service_domain')
        self.service_endpoint = conf.get('service_endpoint', 'https://' + self.service_domain)
        self.service_metadata_key = 'x-account-meta-services'

    def __call__(self, env, start_response):
        qs = env.get('QUERY_STRING', None)
        if env.get('PATH_INFO', '').startswith(self.billing_prefix):
            if qs:
                account = parse_qs(qs).get('account', None)
                if account:
                    return self.google_checkout(env, parse_qs(qs))(env, start_response)
        elif env.get('PATH_INFO', '').startswith(self.notification_prefix):
            if qs:
                type = parse_qs(qs).get('type', None)
                if type:
                    type = type[0]
                    if 'new-order-notification' in type:
                        return self.new_order(env)(env, start_response)
                    elif 'risk-information-notification' in type:
                        return self.risk_info(env)(env, start_response)
                    elif 'order-state-change-notification' in type:
                        return self.order_changed(env)(env, start_response)
                    elif 'charge-amount-notification' in type:
                        return self.charge_amount(env)(env, start_response)
                    else:
                        return self.unhandled(env)(env, start_response)
        return HTTPForbidden()

    def google_checkout(self, env, query_dict):
        type = query_dict.get('type', None)
        if not type is None:
            type = type[0]
            try:
                self.item_names[type]
            except IndexError:
                return HTTPForbidden()
            account = query_dict['account'][0]
            state = query_dict['state'][0]
            req = Request.blank('/v1/%s' % account)
            req.method = 'HEAD'
            resp = req.get_response(self.app)
            if resp.status_int >= 300:
                return HTTPNotFound()
            services = {}
            if self.service_metadata_key in resp.headers:
                try:
                    services = json.loads(resp.headers[self.service_metadata_key])
                    existing_service = services.get(self.item_names[type], None)
                    if existing_service:
                        return Response(status=302, headers={
                            'location': '%s%s?account=%s&msg=service_exists' % (self.service_endpoint, state, account)
                        })
                except Exception:
                    self.logger.exception('Exception when parsing x-account-meta-services for %s' % account)
                    return HTTPForbidden()
            services[self.item_names[type]] = 'pending'
            req = Request.blank('/v1/%s' % account)
            req.method = 'POST'
            req.headers[self.service_metadata_key] = json.dumps(services)
            req.get_response(self.app)
            loc = self.create_checkout_uri(
                self.item_names[type],
                self.item_descriptions[type],
                self.item_prices[type],
                self.item_quantity,
                self.item_currency
            )
            if loc:
                return Response(status=302, headers={
                    'location': loc
                })
        req = Request(env)
        return Response(request=req)

    def new_order(self, env):
        req = Request(env)
        return Response(request=req)

    def risk_info(self, env):
        req = Request(env)
        return Response(request=req)

    def order_changed(self, env):
        req = Request(env)
        return Response(request=req)

    def charge_amount(self, env):
        req = Request(env)
        return Response(request=req)

    def unhandled(self, env):
        self.logger.info('Unhandled notification: %s' % str(parse_qs(env.get('QUERY_STRING', None))))
        req = Request(env)
        return Response(request=req)

    def create_checkout_uri(self, param, param1, param2, item_quantity, item_currency):
        pass


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return LiteBilling(app, conf)
    return auth_filter
