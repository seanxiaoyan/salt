"""
Manage OpenStack configuration file settings.

:maintainer: Jeffrey C. Ollie <jeff@ocjtech.us>
:maturity: new
:depends:
:platform: linux

"""
from salt.exceptions import CommandExecutionError
import logging
log = logging.getLogger(__name__)

def __virtual__():
    """
    Only load if the openstack_config module is in __salt__
    """
    if 'openstack_config.get' not in __salt__:
        return (False, 'openstack_config module could not be loaded')
    if 'openstack_config.set' not in __salt__:
        return False
    if 'openstack_config.delete' not in __salt__:
        return False
    return True

def present(name, filename, section, value, parameter=None):
    log.info('Trace')
    '\n    Ensure a value is set in an OpenStack configuration file.\n\n    filename\n        The full path to the configuration file\n\n    section\n        The section in which the parameter will be set\n\n    parameter (optional)\n        The parameter to change.  If the parameter is not supplied, the name will be used as the parameter.\n\n    value\n        The value to set\n\n    '
    if parameter is None:
        parameter = name
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    try:
        log.info('Trace')
        old_value = __salt__['openstack_config.get'](filename=filename, section=section, parameter=parameter)
        if old_value == value:
            ret['result'] = True
            ret['comment'] = 'The value is already set to the correct value'
            return ret
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = "Value '{}' is set to be changed to '{}'.".format(old_value, value)
            return ret
    except CommandExecutionError as err:
        log.info('Trace')
        if not str(err).lower().startswith('parameter not found:'):
            raise
    __salt__['openstack_config.set'](filename=filename, section=section, parameter=parameter, value=value)
    ret['changes'] = {'Value': 'Updated'}
    ret['result'] = True
    ret['comment'] = 'The value has been updated'
    return ret

def absent(name, filename, section, parameter=None):
    log.info('Trace')
    '\n    Ensure a value is not set in an OpenStack configuration file.\n\n    filename\n        The full path to the configuration file\n\n    section\n        The section in which the parameter will be set\n\n    parameter (optional)\n        The parameter to change.  If the parameter is not supplied, the name will be used as the parameter.\n\n    '
    if parameter is None:
        parameter = name
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    try:
        log.info('Trace')
        old_value = __salt__['openstack_config.get'](filename=filename, section=section, parameter=parameter)
    except CommandExecutionError as err:
        log.info('Trace')
        if str(err).lower().startswith('parameter not found:'):
            ret['result'] = True
            ret['comment'] = 'The value is already absent'
            return ret
        raise
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = "Value '{}' is set to be deleted.".format(old_value)
        return ret
    __salt__['openstack_config.delete'](filename=filename, section=section, parameter=parameter)
    ret['changes'] = {'Value': 'Deleted'}
    ret['result'] = True
    ret['comment'] = 'The value has been deleted'
    return ret