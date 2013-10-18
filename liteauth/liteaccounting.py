from eventlet import Queue, spawn_n, Timeout, sleep
import random
import time
from eventlet.green.Queue import Empty
from swift.common.http import is_success
from swift.common.middleware.memcache import MemcacheMiddleware
from swift.common.swob import Request
from swift.common.utils import get_logger
from swift.common.wsgi import WSGIContext
try:
    import simplejson as json
except ImportError:
    import json

CACHE_KEYS = [{'key': 'systime', 'factor': 1000},
              {'key': 'usertime', 'factor': 1000},
              {'key': 'dskreads', 'factor': (1.0 / 1000 / 1000)},
              {'key': 'dskrdbytes', 'factor': (1.0 / 1024 / 1024)},
              {'key': 'dskwrites', 'factor': (1.0 / 1000 / 1000)},
              {'key': 'dskwrbytes', 'factor': (1.0 / 1024 / 1024)},
              {'key': 'netreads', 'factor': (1.0 / 1000 / 1000)},
              {'key': 'netrdbytes', 'factor': (1.0 / 1024 / 1024)},
              {'key': 'netwrites', 'factor': (1.0 / 1000 / 1000)},
              {'key': 'netwrbytes', 'factor': (1.0 / 1024 / 1024)}]


class LiteAccountingContext(WSGIContext):
    def __init__(self, wsgi_app, logger, liteacc):
        super(LiteAccountingContext, self).__init__(wsgi_app)
        self.logger = logger
        self.liteacc = liteacc

    def handle_request(self, env, start_response):
        resp = self._app_call(env)
        account_id = env['REMOTE_USER']
        print self._response_headers
        print account_id
        if 'X-Nexe-Cdr-Line' in self._response_headers:
            total_time, line = self._response_headers['X-Nexe-Cdr-Line'].split(', ', 1)
            node_lines = line.split(',')
            for line in node_lines:
                rtime, line = line.split(', ', 1)
                accounting_info = line.split(' ')
                total = self.liteacc.cache_accounting_info(account_id, rtime, accounting_info)
                self._response_headers['X-Nexe-Cdr-Total'] = ' '.join(total)
                self.liteacc.queue.put(account_id)
        start_response(self._response_status, self._response_headers,
                       self._response_exc_info)
        return resp


class LiteAccounting(object):

    def __init__(self, app, conf):
        """
        Should be placed after liteauth but before proxy-query

        """
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='lite-accounting')
        # interval between accounting data dumps
        self.interval = int(conf.get('liteacc_interval', 60))
        # how long to keep in memcache, there should be: self.interval << self.timeout
        # maybe we need: self.timeout = 100 * self.interval
        self.timeout = int(conf.get('liteacc_cache_time', 30 * 60))
        # url for accounting objects
        # Example: /v1/liteacc/accounting
        self.accounting_url = conf.get('liteacc_url', '').lower().rstrip('/')
        self.queue = Queue()
        # braindead hack to get memcache pointer :)
        memcache_filter = MemcacheMiddleware(None, conf)
        self.memcache = memcache_filter.memcache
        self.logger.info('Got memcache servers: %s' % memcache_filter.memcache_servers)
        # let's spawn the accounting thread
        spawn_n(self.accounting_server)

    def __call__(self, env, start_response):
        context = LiteAccountingContext(self.app, self.logger, self)
        return context.handle_request(env, start_response)

    def accounting_server(self):
        sleep(random.random() * self.interval)  # start with some entropy
        accounts = {}
        start = time.time()
        while True:
            try:
                try:
                    account_id = self.queue.get(block=False)
                    accounts[account_id] = True
                except Empty:
                    account_id = None
                    pass
                if (time.time() - start) > self.interval:
                    try:
                        with Timeout(self.interval):
                            self.dump_accounting_data(accounts)
                    except Timeout:
                        pass
                    start = time.time()
                    continue
                if not account_id:
                    sleep(self.interval / 100)
            except Exception:
                self.logger.exception('Exception occurred when dumping accounting data')
                sleep(self.interval)
                start = time.time()
                accounts = {}
                continue

    def dump_accounting_data(self, accounts):
        if not self.accounting_url:
            self.logger.warning('No accounting url, dump cannot complete')
            return
        while len(accounts):
            for acc_id in accounts.keys():
                if not self.add_semaphore(acc_id):
                    # cannot lock the accounting data, will try again
                    continue
                try:
                    totals = self.retrieve_accounting_info(acc_id)
                    if sum(totals) > 0:  # sum(totals) == 0 if all executions failed, no need to add it
                        req = Request.blank('%s/%s' % (self.accounting_url, acc_id))
                        req.method = 'GET'
                        resp = req.get_response(self.app)
                        if is_success(resp.status_int):
                            try:
                                acc_totals = json.loads(resp.body)
                                for key in acc_totals.keys():
                                    acc_totals[key] += totals[key]
                            except Exception:
                                self.logger.warning('Accounting response for GET %s is %s %s'
                                                    % (req.path, resp.status, resp.body))
                                acc_totals = totals
                        else:
                            self.logger.warning('Accounting response for GET %s is %s %s'
                                                % (req.path, resp.status, resp.body))
                            acc_totals = totals
                        req = Request.blank('%s/%s' % (self.accounting_url, acc_id))
                        req.method = 'PUT'
                        req.body = json.dumps(acc_totals)
                        resp = req.get_response(self.app)
                        if not is_success(resp.status_int):
                            self.logger.warning('Accounting response for PUT %s is %s %s'
                                                % (req.path, resp.status, resp.body))
                    del accounts[acc_id]
                finally:
                    self.remove_semaphore(acc_id)

    def cache_accounting_info(self, account_id, rtime, accounting_info):
        total_acc = []
        run_key = 'liteacc/%s/run' % account_id
        total = self.memcache.incr(run_key, delta=1, timeout=self.timeout)
        total_acc.append(total)
        rtime_key = 'liteacc/%s/rtime' % account_id
        total = self.memcache.incr(rtime_key, delta=int(rtime * 1000), timeout=self.timeout)
        total_acc.append(total)
        for k, value in zip(CACHE_KEYS, accounting_info):
            key = 'liteacc/%s/%s' % (account_id, k['key'])
            val = value * k['factor']
            total = self.memcache.incr(key, delta=int(val), timeout=self.timeout)
            total_acc.append(total)
        return total_acc

    def retrieve_accounting_info(self, account_id):
        total_acc = {}
        run_key = 'liteacc/%s/run' % account_id
        total = self.memcache.get(run_key) or 0
        if total:
            self.memcache.decr(run_key, delta=total, timeout=self.timeout)
        total_acc['runs'] = total
        rtime_key = 'liteacc/%s/rtime' % account_id
        total = self.memcache.get(rtime_key) or 0
        if total:
            self.memcache.decr(rtime_key, delta=total, timeout=self.timeout)
        total_acc['realtime'] = total
        for k in CACHE_KEYS:
            key = 'liteacc/%s/%s' % (account_id, k['key'])
            total = self.memcache.get(key) or 0
            if total:
                self.memcache.decr(key, delta=total, timeout=self.timeout)
            total_acc[k['key']] = total
        return total_acc

    def add_semaphore(self, account_id):
        sem_key = 'liteacc_sem/%s' % account_id
        try:
            value = self.memcache.incr(sem_key, delta=1, timeout=self.timeout)
            if value > 1:
                self.remove_semaphore(account_id)
                return False
        except Exception:
            return False
        return True

    def remove_semaphore(self, account_id):
        sem_key = 'liteacc_sem/%s' % account_id
        try:
            self.memcache.decr(sem_key, delta=1, timeout=self.timeout)
        except Exception:
            pass


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def accounting_filter(app):
        return LiteAccounting(app, conf)
    return accounting_filter