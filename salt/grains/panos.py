"""
Generate baseline proxy minion grains for panos hosts.

"""
import logging
import salt.proxy.panos
import salt.utils.platform
import logging
log = logging.getLogger(__name__)
__proxyenabled__ = ['panos']
__virtualname__ = 'panos'
log = logging.getLogger(__file__)
GRAINS_CACHE = {'os_family': 'panos'}

def __virtual__():
    try:
        log.info('Trace')
        if salt.utils.platform.is_proxy() and __opts__['proxy']['proxytype'] == 'panos':
            return __virtualname__
    except KeyError:
        log.info('Trace')
        pass
    return False

def panos(proxy=None):
    if not proxy:
        return {}
    if proxy['panos.initialized']() is False:
        return {}
    return {'panos': proxy['panos.grains']()}