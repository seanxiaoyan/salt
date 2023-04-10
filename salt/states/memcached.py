"""
States for Management of Memcached Keys
=======================================

.. versionadded:: 2014.1.0
"""
from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.modules.memcached import DEFAULT_HOST, DEFAULT_MIN_COMPRESS_LEN, DEFAULT_PORT, DEFAULT_TIME
import logging
log = logging.getLogger(__name__)
__virtualname__ = 'memcached'

def __virtual__():
    """
    Only load if memcache module is available
    """
    if '{}.status'.format(__virtualname__) in __salt__:
        return __virtualname__
    return (False, 'memcached module could not be loaded')

def managed(name, value=None, host=DEFAULT_HOST, port=DEFAULT_PORT, time=DEFAULT_TIME, min_compress_len=DEFAULT_MIN_COMPRESS_LEN):
    log.info('Trace')
    '\n    Manage a memcached key.\n\n    name\n        The key to manage\n\n    value\n        The value to set for that key\n\n    host\n        The memcached server IP address\n\n    port\n        The memcached server port\n\n\n    .. code-block:: yaml\n\n        foo:\n          memcached.managed:\n            - value: bar\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    try:
        log.info('Trace')
        cur = __salt__['memcached.get'](name, host, port)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['comment'] = str(exc)
        return ret
    if cur == value:
        ret['result'] = True
        ret['comment'] = "Key '{}' does not need to be updated".format(name)
        return ret
    if __opts__['test']:
        ret['result'] = None
        if cur is None:
            ret['comment'] = "Key '{}' would be added".format(name)
        else:
            ret['comment'] = "Value of key '{}' would be changed".format(name)
        return ret
    try:
        log.info('Trace')
        ret['result'] = __salt__['memcached.set'](name, value, host, port, time, min_compress_len)
    except (CommandExecutionError, SaltInvocationError) as exc:
        log.info('Trace')
        ret['comment'] = str(exc)
    else:
        if ret['result']:
            ret['comment'] = "Successfully set key '{}'".format(name)
            if cur is not None:
                ret['changes'] = {'old': cur, 'new': value}
            else:
                ret['changes'] = {'key added': name, 'value': value}
        else:
            ret['comment'] = "Failed to set key '{}'".format(name)
    return ret

def absent(name, value=None, host=DEFAULT_HOST, port=DEFAULT_PORT, time=DEFAULT_TIME):
    log.info('Trace')
    '\n    Ensure that a memcached key is not present.\n\n    name\n        The key\n\n    value : None\n        If specified, only ensure that the key is absent if it matches the\n        specified value.\n\n    host\n        The memcached server IP address\n\n    port\n        The memcached server port\n\n\n    .. code-block:: yaml\n\n        foo:\n          memcached.absent\n\n        bar:\n          memcached.absent:\n            - host: 10.0.0.1\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    try:
        log.info('Trace')
        cur = __salt__['memcached.get'](name, host, port)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['comment'] = str(exc)
        return ret
    if value is not None:
        if cur is not None and cur != value:
            ret['result'] = True
            ret['comment'] = "Value of key '{}' ('{}') is not '{}'".format(name, cur, value)
            return ret
    if cur is None:
        ret['result'] = True
        ret['comment'] = "Key '{}' does not exist".format(name)
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = "Key '{}' would be deleted".format(name)
        return ret
    try:
        log.info('Trace')
        ret['result'] = __salt__['memcached.delete'](name, host, port, time)
    except (CommandExecutionError, SaltInvocationError) as exc:
        log.info('Trace')
        ret['comment'] = str(exc)
    else:
        if ret['result']:
            ret['comment'] = "Successfully deleted key '{}'".format(name)
            ret['changes'] = {'key deleted': name, 'value': cur}
        else:
            ret['comment'] = "Failed to delete key '{}'".format(name)
    return ret