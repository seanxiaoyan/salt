"""
Connection library for Amazon IAM

:depends: requests
"""
import logging
import pprint
import time
log = logging.getLogger(__name__)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def _retry_get_url(url, num_retries=10, timeout=5):
    log.info('Trace')
    '\n    Retry grabbing a URL.\n    Based heavily on boto.utils.retry_url\n    '
    for i in range(0, num_retries):
        try:
            log.info('Trace')
            result = requests.get(url, timeout=timeout, proxies={'http': ''})
            if hasattr(result, 'text'):
                return result.text
            elif hasattr(result, 'content'):
                return result.content
            else:
                return ''
        except requests.exceptions.HTTPError as exc:
            log.info('Trace')
            return ''
        except Exception as exc:
            log.info('Trace')
            pass
        log.warning('Caught exception reading from URL. Retry no. %s', i)
        log.warning(pprint.pformat(exc))
        time.sleep(2 ** i)
    log.error('Failed to read from URL for %s times. Giving up.', num_retries)
    return ''

def _convert_key_to_str(key):
    """
    Stolen completely from boto.providers
    """
    return key