from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from cowrie.output.abuseipdb import utils


# NOTES:
# 1 - urllib... retries exhausted...:
#         raise MaxRetryError(_pool, url, error or ResponseError(cause))
#
# 2 - HTTPAdapter: github.com/psf/requests/blob/master/requests/adapters.py


class Adapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        kwargs['max_retries'] = Retry(
            total=utils.cfg.retry_no_attempts,
            status_forcelist=utils.cfg.retry_status_codes,
            method_whitelist=['POST'],  # TODO: CONFIGS--Maybe...but what's the point if we only ever post?
            backoff_factor=utils.cfg.retry_backoff_factor,
        )
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        kwargs['timeout'] = utils.cfg.http_request_timeout
        return super().send(request, **kwargs)


class AbuseClient:
    def __init__(self):
        self.session = Session()
        self.headers = {
            'Accept': 'application/json',
            'Key': utils.cfg.api_key,
            'User-Agent': utils.cfg.http_client_ua,
            }
        self.adapter = Adapter()
        self.session.mount('https://', self.adapter)
        self.session.headers.update(self.headers)
