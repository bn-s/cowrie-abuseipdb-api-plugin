from collections import deque
from time import time

from cowrie.output.abuseipdb import utils


# TODO: watchdoge... singleton?? borg???...
# TODO: Schedule cleanup task... hourly?
#           - while ip[0] < time() - window; popleft()
#           - delete empty list entries in dict


class WatchDoge(object):
    # Watchdoge keep very watch over such internetz.
    # Many barks if he sees you too often.
    _dogebook = {}

    def __init__(self):
        # If he remembers seeing you more times than he's prepared to tollerate
        # he'll bark. But he also forgets you came after a given period of time.
        self.tollerance = utils.cfg.tollerance_attempts
        self.window = utils.cfg.tollerance_window

    def such_h4x0r(self, src_ip):
        t = time()
        if src_ip in self._dogebook:
            self._dogebook[src_ip].append(t)
            # TODO: cleanup expired entries before len
            if len(self._dogebook[src_ip]) >= self.tollerance:
                self.woof_woof_wow(ip=src_ip)
        else:
            self._dogebook[src_ip] = deque([t])

    def woof_woof_wow(self, *args, **kwargs):
        utils.Log.message('reporting {} to the internet police...'.format(kwargs['ip']))
