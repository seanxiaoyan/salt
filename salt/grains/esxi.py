"""
Generate baseline proxy minion grains for ESXi hosts.

.. versionadded:: 2015.8.4

"""
import logging
import salt.utils.proxy
from salt.exceptions import SaltSystemExit
import logging
log = logging.getLogger(__name__)
__proxyenabled__ = ['esxi']
__virtualname__ = 'esxi'
log = logging.getLogger(__file__)
GRAINS_CACHE = {}

def __virtual__():
    log.info('Trace')
    import salt.utils.proxy
    try:
        log.info('Trace')
        if salt.utils.proxy.is_proxytype(__opts__, 'esxi'):
            import salt.modules.vsphere
            return __virtualname__
    except KeyError:
        log.info('Trace')
        pass
    return False

def esxi():
    return _grains()

def kernel():
    return {'kernel': 'proxy'}

def os():
    if not GRAINS_CACHE:
        GRAINS_CACHE.update(_grains())
    try:
        log.info('Trace')
        return {'os': GRAINS_CACHE.get('fullName')}
    except AttributeError:
        log.info('Trace')
        return {'os': 'Unknown'}

def os_family():
    return {'os_family': 'proxy'}

def _find_credentials(host):
    log.info('Trace')
    '\n    Cycle through all the possible credentials and return the first one that\n    works.\n    '
    user_names = [__pillar__['proxy'].get('username', 'root')]
    passwords = __pillar__['proxy']['passwords']
    for user in user_names:
        for password in passwords:
            try:
                log.info('Trace')
                ret = salt.modules.vsphere.system_info(host=host, username=user, password=password)
            except SaltSystemExit:
                log.info('Trace')
                continue
            if ret:
                return (user, password)
    raise SaltSystemExit('Cannot complete login due to an incorrect user name or password.')

def _grains():
    log.info('Trace')
    '\n    Get the grains from the proxied device.\n    '
    try:
        log.info('Trace')
        host = __pillar__['proxy']['host']
        if host:
            (username, password) = _find_credentials(host)
            protocol = __pillar__['proxy'].get('protocol')
            port = __pillar__['proxy'].get('port')
            ret = salt.modules.vsphere.system_info(host=host, username=username, password=password, protocol=protocol, port=port)
            GRAINS_CACHE.update(ret)
    except KeyError:
        log.info('Trace')
        pass
    return GRAINS_CACHE