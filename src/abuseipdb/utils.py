import re
import configparser
import datetime
import functools
from os.path import dirname, join

from twisted.python import log

from cowrie.core.config import CowrieConfig

DEFAULT_CONFIG_FILE = 'default.cfg'
DOGE_DUMP = 'doge.dump'


class __mergedConfigs:
    """ Private class. Should not be instantiated or accessed outside of this
    module other than via the instance created by the global 'cfg' variable.

    Reads and merges config files (etc/cowrie.cfg*, .../abuseipdb/default.cfg),
    overriding variables in the supplied default.cfg if their respective values
    are found in the Cowrie configs.

    Updates class __dict__ with read configs allowing us to access them by
    keyword as class attributes when we need access to them.
    """
    def __init__(self):
        self.plugin_path = join('src', *dirname(__file__).split('src').pop().split('/'))
        self.__dict__.update(self.__build_dict())
        self.__conversions_types_units()
        # cleanup values no longer needed
        del self.enabled
        del self.quota_utc_offset

    def __build_dict(self):
        configs = {
            **self.__get_defaults(), **CowrieConfig()['output_abuseipdb'],
            'doge_dump': join(self.plugin_path, DOGE_DUMP)
        }
        return configs

    def __get_defaults(self):
        parser = configparser.ConfigParser()
        f = join(self.plugin_path, DEFAULT_CONFIG_FILE)
        parser.read(f)
        return parser['abuseipdb_defaults']

    def __conversions_types_units(self):
        # Configs are all strings. Sometimes we might let users enter
        # something as one unit when we really want to work with another
        # unit. Sometimes we want different types and/or data structures to
        # work with. Let's do the hokey-pokey and turn about...
        def _tru_dat(b):
            # Returns bool. CaSe InSeNsItIvE. No spellcheck ;)
            if b.lower() == 'true' or b.lower() == 'yes':
                return True
            else:
                return False

        def _no_limits(v):
            # Returns None type if none or 0 is set in configs. Otherwise,
            # convert to int.
            if v.lower() == 'none' or int(v) == 0:
                return None
            else:
                return int(v)

        def _hammer_time(string):
            # Returns a tuple in UTC for the time we can start hammering the
            # API again.
            try:
                t = string.split(':')
                t = tuple(int(i) for i in t)
                if t[0] > 23:
                    raise ValueError("24 hours a day is all the time we have: check configured 'quota_reset_hour'")
                for i in t:
                    if i > 59:
                        raise ValueError("AbuseIPDB plugin can't bend time: check configured 'quota_reset_hour'")
            except AttributeError:
                t = (int(string),)
                if t[0] > 23:
                    raise ValueError("24 hours a day is all the time we have: check configured 'quota_reset_hour'")

            # Add UTC offset to hour; result mod 24; then unpack minutes
            # [and seconds] into new tuple.
            t = ((t[0] + int(self.quota_utc_offset)) % 24, *t[1:])

            return t

        def _retry_codes(string):
            status_codes = []
            for i in re.findall('(5[0-9]{2})', string):
                status_codes.append(int(i))
            return status_codes

        self.verbose_logging = _tru_dat(self.verbose_logging)
        self.singleip_daily_quota = _no_limits(self.singleip_daily_quota)
        self.bulk_daily_quota = _no_limits(self.bulk_daily_quota)
        self.quota_reset_hour = _hammer_time(self.quota_reset_hour)
        self.retry_status_codes = _retry_codes(self.retry_status_codes)
        self.rereport_after = int(self.rereport_after) * 3600
        self.tollerance_window = int(self.tollerance_window) * 60
        self.tollerance_attempts = int(self.tollerance_attempts)
        self.retry_no_attempts = int(self.retry_no_attempts)
        self.http_request_timeout = int(self.http_request_timeout)
        self.retry_backoff_factor = int(self.retry_backoff_factor)


cfg = __mergedConfigs()
""" utils.cfg: to be used when access to __mergedConfigs' dictionary is desired
Available attributes:
.plugin_path           STR          The path to this plugin
.verbose_logging       BOOL         Enables verbose logging when set to True
.tollerance_window     INT          The window of time in which to observe login attempts
.tollerance_attempts   INT          The number of login attempts allowed before an attacker is reported
.rereport_after        INT          Time to wait before re-reporting an IP address
.api_key               STR          The API gatekeepers will grant you access to their kingdom if you have a valid key
.report_url: https     STR          Standard reporting endpoint
.bulk_report_url       STR          Bulk reporting endpoint
.http_client_ua        STR          User Agent to include in HTTP headers
.quota_reset_hour      TUP(INT,)    Time at which our daily usage quota resets
.singleip_daily_quota  INT          Sets daily quota for standard 'single IP' reporting
.bulk_daily_quota      INT          Limits number of daily bulk reports we make
.retry_status_codes    LST[INT,]    List of HTTP status codes to retry failed requests on
.retry_no_attempts     INT          Number of retry attempts to make on requests failing on provided retry_status_code
.retry_backoff_factor  INT          Base number of seconds on which to calculate the time between retry attempts
.http_request_timeout  INT          Number of seconds to wait before HTTP requests timeout.
.doge_dump             STR          File from/to which we load/dump our watchdoge's dict on startup/shutdown
"""


def verbose_logging(func):
    """ Decorator function for silencing log entries we don't normally want
    to see.
    """
    @functools.wraps(func)
    def verbose(*args, **kwargs):
        func(*args, **kwargs)

    def ta_gueule(*args, **kwargs):
        pass

    if cfg.verbose_logging:
        return verbose
    else:
        return ta_gueule


class Log:
    """ Let's log some stuff.
    """
    @staticmethod
    @verbose_logging
    def message(message):
        # Use for any general message we might want to to log
        log.msg(
            eventid='cowrie.abuseipdb.message',
            format='AbuseIPDB General Message: {}'.format(message)
        )

    @staticmethod
    @verbose_logging
    def starting():
        log.msg(
            eventid='cowrie.abuseipdb.starting',
            format='AbuseIPDB Plugin starting with verbose logging enabled.'
        )
        # Log the loaded configuration
        for k, v in cfg.__dict__.items():
            log.msg(
                eventid='cowrie.abuseipdb.starting',
                format='AbuseIPDB Plugin CONFIG:: {}: {}'.format(k, v)
            )

    @staticmethod
    @verbose_logging
    def stopping():
        log.msg(
            eventid='cowrie.abuseipdb.stopping',
            format='AbuseIPDB Plugin has nothing left to say. Goodbye.'
        )


class TimeTools:
    """ Scheduling tasks and things
    """
    def __init__(self):
        pass

    @staticmethod
    def rl_reset_o_clock():
        """ Returns the number of seconds into the future that we should
        schedule a reset of our daily API usage quota
        """
        utc_now = datetime.datetime.utcnow()

        # Make a datetime object for our reset time
        try:
            reset_time = datetime.datetime(
                utc_now.year, utc_now.month, utc_now.day,
                *cfg.quota_reset_hour,
            )
        except ValueError:
            Log.message('rl_reset_oclock() ValueError: Quota reset time will default to 19:00:00 (UTC)')

            reset_time = datetime.datetime(
                utc_now.year, utc_now.month, utc_now.day, 19)

        # If the reset time has already passed today, set it for tomorrow
        if utc_now >= reset_time:
            reset_time += datetime.timedelta(days=1)

        delta = reset_time - utc_now

        Log.message('resetting quota in {} secconds'.format(delta.total_seconds()))

        # Return in seconds as twisted scheduler likes to know how many seconds
        # into the future it should run a task... and we add 60 seconds, just
        # in case our clocks aren't quite in sync.
        return delta.total_seconds() + 60

    @staticmethod
    # Converts seconds since epoch into an ISO 8601 compliant timestamp in UTC.
    def epoch_to_iso_string(time):
        from_time_to_time = datetime.datetime.utcfromtimestamp(time)
        return from_time_to_time.strftime('%Y-%m-%dT%H:%M:%SZ')
