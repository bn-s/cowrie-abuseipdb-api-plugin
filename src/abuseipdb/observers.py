from collections import deque
from time import time
from threading import Lock

from twisted.internet import reactor

from cowrie.output.abuseipdb import utils


class DogeBook:
    class __dogeBook(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._lock = Lock()

        def __enter__(self):
            self._lock.acquire()
            return self

        def __exit__(self, type, value, traceback):
            self._lock.release()

        def clean_stale(self, ip_key, current_time):
            while self[ip_key]:
                if not self[ip_key][0]:
                    self.can_rereport(ip_key, current_time)
                    break
                elif self[ip_key][0] < current_time - utils.cfg.tollerance_window:
                    self[ip_key].popleft()
                else:
                    break

        def delete_empty(self):
            delete_me = []
            for k in self:
                if not self[k]:
                    delete_me.append(k)
            for i in delete_me:
                del self[i]

        def can_rereport(self, ip_key, current_time):
            if current_time > self[ip_key][1] + utils.cfg.rereport_after:
                self[ip_key] = deque(maxlen=utils.cfg.tollerance_attempts)
                return True
            else:
                return False

        def all_clean(self):
            t = time()
            for k in self:
                self.can_rereport(k, t)
                self.clean_stale(k, t)
            self.delete_empty()
            reactor.callLater(3600, self.all_clean)

    __instance = None

    def __new__(cls):
        # Doge don't need more than one dogebook hanging around
        if not DogeBook.__instance:
            DogeBook.__instance = DogeBook.__dogeBook()
        return DogeBook.__instance


class WatchDoge:
    # Watchdoge keep very watch over such internetz.
    # Many barks if he sees you too often.
    def __init__(self):
        # If he remembers seeing you more times than he's prepared to tollerate
        # he'll bark. But he also forgets you came after a given period of time.
        self.tollerance = utils.cfg.tollerance_attempts
        self.window = utils.cfg.tollerance_window
        self.dogebook = DogeBook()

    def such_h4x0r(self, src_ip):
        t = time()
        # Is there already an entry for this IP in dogebook?
        if src_ip in self.dogebook:
            # If the list is not empty, perhaps it's because we're not
            # meant to re-report this IP yet... if it's empty, it will
            # throw an IndexError on the first test in the try block below.
            # In this case, we know it's okay to start monitoring this IP and
            # re-report it if it exceeds our tollerance again.
            try:
                # If we're currently monitoring an IP, it will have a timestamp
                # at index 0, thus it will evalute True here and we can proceed
                # to append the current time and check if we want to report or
                # not:
                if self.dogebook[src_ip][0]:
                    self.dogebook[src_ip].append(t)
                    
                    self.dogebook.clean_stale(src_ip, t)

                    if len(self.dogebook[src_ip]) >= self.tollerance:
                        self.woof_woof_wow(src_ip)
    
                # Index 0 is set to None if we've already reported an IP, so
                # the last test will have failed. Here we check if enough time
                # has passed in order for us to start monitoring it again for
                # re-reporting.
                elif self.dogebook.can_rereport(src_ip, t):
                    self.dogebook[src_ip].append(t)

                else:
                    return

            except IndexError:
                self.dogebook[src_ip].append(t)

        # If no entry, let's make one and log this IP's first timestamp in it.
        else:
            self.dogebook[src_ip] = deque([t], maxlen=utils.cfg.tollerance_attempts)

    def woof_woof_wow(self, src_ip):
        utils.Log.message('reporting {} to the internet police...'.format(src_ip))
        self.dogebook[src_ip] = (None, self.dogebook[src_ip][0])


class Reporter:
    def __init__(self):
        pass
