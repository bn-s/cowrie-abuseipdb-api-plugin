import pickle
from collections import deque
from datetime import datetime
from pathlib import Path
from time import time

from treq import post

from twisted.internet import defer, reactor
from twisted.python import log
from twisted.web import http

from cowrie.core import output
from cowrie.core.config import CowrieConfig


class Output(output.Output):
    def start(self):
        self.tollerance_attempts = CowrieConfig().getint('output_abuseipdb', 'tollerance_attempts', fallback=10)
        self.state_path = CowrieConfig().get('output_abuseipdb', 'dump_path')
        self.state_dump = Path(self.state_path, 'aipdb.dump')

        self.logbook = LogBook(self.tollerance_attempts)

        self.reporter = Reporter(self.logbook, self.tollerance_attempts)

        try:
            with open(self.state_dump, 'rb') as f:
                self.logbook.update(pickle.load(f))

        except FileNotFoundError:
            pass

        try:
            if self.logbook['sleeping']:
                t_wake = self.logbook['sleep_until']
                t_now = time()
                if t_wake > t_now:
                    self.logbook.sleeping = True
                    self.logbook.sleepuntil = t_wake
                    reactor.callLater(t_wake - t_now, self.logbook.wakeup)
            del self.logbook['sleeping']
            del self.logbook['sleep_until']
        except KeyError:
            pass

        self.logbook.full_cleanup()

        log.msg(
            eventid='cowrie.abuseipdb.start',
            format='AbuseIPDB Plugin has started. Alpha version! Untested!',
        )

    def stop(self):
        self.logbook.full_cleanup()

        dump = {
            'sleeping': self.logbook.sleeping,
            'sleep_until': self.logbook.sleepuntil
        }

        for k, v in self.logbook.items():
            dump[k] = v

        try:
            Path(self.state_path).mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError:
            pass

        with open(self.state_dump, 'wb') as f:
            pickle.dump(dump, f, protocol=pickle.HIGHEST_PROTOCOL)

    def write(self, ev):
        if self.logbook.sleeping:
            return

        if ev['eventid'].rsplit('.', 1)[0] == 'cowrie.login':
            t = time()
            ip = ev['src_ip']

            if ip in self.logbook:

                try:
                    if self.logbook[ip][0]:
                        self.logbook[ip].append(t)
                        self.logbook.clean_expired_timestamps(ip, t)

                        if len(self.logbook[ip]) >= self.tollerance_attempts:
                            self.reporter.report_ip(ip)

                    elif self.logbook.can_rereport(ip, t):
                        self.logbook[ip] = deque([t], maxlen=self.tollerance_attempts)

                    else:
                        return

                except IndexError:
                    self.logbook[ip].append(t)

            else:
                self.logbook[ip] = deque([t], maxlen=self.tollerance_attempts)


class LogBook(dict):
    def __init__(self, tollerance_attempts):
        self.sleeping = False
        self.sleepuntil = 0
        self.tollerance_attempts = tollerance_attempts
        self.tollerance_window = 60 * CowrieConfig().getint('output_abuseipdb', 'tollerance_window', fallback=30)
        self.rereport_after = 3600 * CowrieConfig().getint('output_abuseipdb', 'rereport_after', fallback=24)
        super().__init__()

    def wakeup(self):
        self.sleeping = False
        self.sleepuntil = 0
        log.msg(
            eventid='cowrie.abuseipdb.wakeup',
            format='AbuseIPDB plugin resuming activity after receiving '
                   'Retry-After header in previous response.',
        )

    def clean_expired_timestamps(self, ip_key, current_time):
        while self[ip_key]:
            if not self[ip_key][0]:
                self.can_rereport(ip_key, current_time)
                break
            elif self[ip_key][0] < current_time - self.tollerance_window:
                self[ip_key].popleft()
            else:
                break

    def find_and_delete_empty_entries(self):
        delete_me = []
        for k in self:
            if not self[k]:
                delete_me.append(k)
        self.delete_entries(delete_me)

    def delete_entries(self, delete_me):
        for i in delete_me:
            del self[i]

    def can_rereport(self, ip_key, current_time):
        try:
            if current_time > self[ip_key][1] + self.rereport_after:
                return True
            else:
                return False
        except IndexError:
            return True

    def full_cleanup(self):
        t = time()
        delete_me = []
        for k in self:
            if self.can_rereport(k, t):
                delete_me.append(k)
            self.clean_expired_timestamps(k, t)
        self.delete_entries(delete_me)
        self.find_and_delete_empty_entries()
        reactor.callLater(3600, self.full_cleanup)


class Reporter:
    def __init__(self, logbook, attempts):
        self.logbook = logbook
        self.attempts = attempts

    def report_ip(self, ip):
        t_last = self.logbook[ip].pop()
        t_first = self.epoch_to_string_utc(self.logbook[ip].popleft())

        self.logbook[ip] = (None, t_last)

        t_last = self.epoch_to_string_utc(t_last)

        params = {
            'ip': ip,
            'categories': '18,22',
            'comment': '{} failed SSH/Telnet login attempts between {} '
                       'and {}'.format(self.attempts, t_first, t_last)
        }

        self.http_request(params)

    def epoch_to_string_utc(self, t):
        t_utc = datetime.utcfromtimestamp(t)
        return t_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

    @defer.inlineCallbacks
    def http_request(self, params):
        ABUSEIP_URL = 'https://api.abuseipdb.com/api/v2/report'
        api_key = CowrieConfig().get('output_abuseipdb', 'api_key')

        headers = {
            'User-Agent': 'Cowrie Honeypot AbuseIPDB plugin',
            'Accept': 'application/json',
            'Key': api_key
        }

        try:
            response = yield post(
                url=ABUSEIP_URL,
                headers=headers,
                params=params,
                )

        except Exception as e:
            log.msg(
                eventid='cowrie.abuseipdb.reportfail',
                format='AbuseIPDB plugin failed to report IP %(IP)s. '
                       'Exception raised: %(exception)s.',
                IP=params['ip'],
                exception=repr(e),
            )
            return

        if response.code != http.OK:
            log.msg(
                eventid='cowrie.abuseipdb.reportfail',
                format='AbuseIPDB plugin failed to report IP %(IP)s. Received HTTP '
                       'status code in response: %(response)s; Reason: %(reason)s.',
                IP=params['ip'],
                response=response.code,
                reason=http.RESPONSES[response.code].decode('utf-8'),
            )

            retry_after = yield response.headers.hasHeader('Retry-After')

            if retry_after:
                retry = yield response.headers.getRawHeaders('Retry-After')
                retry = int(retry.pop())

                log.msg(
                    eventid='cowrie.abuseipdb.ratelimit',
                    format='AbuseIPDB plugin received Retry-After header in response. '
                           'Reporting activity will resume in %(retry_after)s seconds.',
                    retry_after=retry,
                )

                self.logbook.sleeping = True
                self.logbook.sleepuntil = time() + retry
                reactor.callLater(retry, self.logbook.wakeup)

            return

        j = yield response.json()

        log.msg(
            eventid='cowrie.abuseipdb.success',
            format='AbuseIPDB plugin successfully reported %(IP)s. Current '
                   'AbuseIPDB confidence score for this IP is %(confidence)s',
            IP=params['ip'],
            confidence=j['data']['abuseConfidenceScore']
        )
