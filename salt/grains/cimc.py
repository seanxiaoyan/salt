"""
Generate baseline proxy minion grains for cimc hosts.

"""
import logging
import salt.proxy.cimc
import salt.utils.platform
import logging
log = logging.getLogger(__name__)
__proxyenabled__ = ['cimc']
__virtualname__ = 'cimc'
log = logging.getLogger(__file__)
GRAINS_CACHE = {'os_family': 'Cisco UCS'}

def __virtual__():
    try:
        log.info('Trace')
        if salt.utils.platform.is_proxy() and __opts__['proxy']['proxytype'] == 'cimc':
            return __virtualname__
    except KeyError:
        log.info('Trace')
        pass
    return False

def cimc(proxy=None):
    if not proxy:
        return {}
    if proxy['cimc.initialized']() is False:
        return {}
    return {'cimc': proxy['cimc.grains']()}