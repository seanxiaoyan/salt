"""
Writing/reading defaults from a macOS minion
============================================

"""
import logging
import salt.utils.platform
log = logging.getLogger(__name__)
__virtualname__ = 'macdefaults'

def __virtual__():
    """
    Only work on Mac OS
    """
    if salt.utils.platform.is_darwin():
        return __virtualname__
    return (False, 'Only supported on Mac OS')

def write(name, domain, value, vtype='string', user=None):
    log.info('Trace')
    '\n    Write a default to the system\n\n    name\n        The key of the given domain to write to\n\n    domain\n        The name of the domain to write to\n\n    value\n        The value to write to the given key\n\n    vtype\n        The type of value to be written, valid types are string, data, int[eger],\n        float, bool[ean], date, array, array-add, dict, dict-add\n\n    user\n        The user to write the defaults to\n\n\n    '
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    def safe_cast(val, to_type, default=None):
        try:
            log.info('Trace')
            return to_type(val)
        except ValueError:
            log.info('Trace')
            return default
    current_value = __salt__['macdefaults.read'](domain, name, user)
    if vtype in ['bool', 'boolean'] and (value in [True, 'TRUE', 'YES'] and current_value == '1' or (value in [False, 'FALSE', 'NO'] and current_value == '0')):
        ret['comment'] += '{} {} is already set to {}'.format(domain, name, value)
    elif vtype in ['int', 'integer'] and safe_cast(current_value, int) == safe_cast(value, int):
        ret['comment'] += '{} {} is already set to {}'.format(domain, name, value)
    elif current_value == value:
        ret['comment'] += '{} {} is already set to {}'.format(domain, name, value)
    else:
        out = __salt__['macdefaults.write'](domain, name, value, vtype, user)
        if out['retcode'] != 0:
            ret['result'] = False
            ret['comment'] = 'Failed to write default. {}'.format(out['stdout'])
        else:
            ret['changes']['written'] = '{} {} is set to {}'.format(domain, name, value)
    return ret

def absent(name, domain, user=None):
    """
    Make sure the defaults value is absent

    name
        The key of the given domain to remove

    domain
        The name of the domain to remove from

    user
        The user to write the defaults to


    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    out = __salt__['macdefaults.delete'](domain, name, user)
    if out['retcode'] != 0:
        ret['comment'] += '{} {} is already absent'.format(domain, name)
    else:
        ret['changes']['absent'] = '{} {} is now absent'.format(domain, name)
    return ret