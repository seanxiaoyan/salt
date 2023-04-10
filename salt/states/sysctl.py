"""
Configuration of the kernel using sysctl
========================================

Control the kernel sysctl system.

.. code-block:: yaml

  vm.swappiness:
    sysctl.present:
      - value: 20
"""
import re
from salt.exceptions import CommandExecutionError
import logging
log = logging.getLogger(__name__)

def __virtual__():
    """
    This state is only available on Minions which support sysctl
    """
    if 'sysctl.show' in __salt__:
        return True
    return (False, 'sysctl module could not be loaded')

def present(name, value, config=None):
    log.info('Trace')
    '\n    Ensure that the named sysctl value is set in memory and persisted to the\n    named configuration file. The default sysctl configuration file is\n    /etc/sysctl.conf\n\n    name\n        The name of the sysctl value to edit\n\n    value\n        The sysctl value to apply. Make sure to set the value to the correct expected\n        output for systctl or reading the respective /proc/sys file. For example, instead\n        of adding the value `1,2,3` you might need to write `1-3`. If you do not set\n        the correct value, Salt will continue to return with changes.\n\n    config\n        The location of the sysctl configuration file. If not specified, the\n        proper location will be detected based on platform.\n    '
    ret = {'name': name, 'result': True, 'changes': {}, 'comment': ''}
    if config is None:
        if 'sysctl.default_config' in __salt__:
            config = __salt__['sysctl.default_config']()
        else:
            config = '/etc/sysctl.conf'
    if __opts__['test']:
        configured = __salt__['sysctl.show'](config_file=config)
        if configured is None:
            ret['result'] = None
            ret['comment'] = 'Sysctl option {} might be changed, we failed to check config file at {}. The file is either unreadable, or missing.'.format(name, config)
            return ret
        current = __salt__['sysctl.get'](name)
        if current:
            if name in configured:
                if str(value).split() == current.split():
                    ret['result'] = True
                    ret['comment'] = 'Sysctl value {} = {} is already set'.format(name, value)
                    return ret
            elif re.sub(' +|\t+', ' ', current) != re.sub(' +|\t+', ' ', str(value)):
                ret['result'] = None
                ret['comment'] = 'Sysctl option {} set to be changed to {}'.format(name, value)
                return ret
            else:
                ret['result'] = None
                ret['comment'] = 'Sysctl value is currently set on the running system but not in a config file. Sysctl option {} set to be changed to {} in config file.'.format(name, value)
                return ret
        elif not current and name in configured:
            ret['result'] = None
            ret['comment'] = 'Sysctl value {0} is present in configuration file but is not present in the running config. The value {0} is set to be changed to {1}'.format(name, value)
            return ret
        ret['result'] = None
        ret['comment'] = 'Sysctl option {} would be changed to {}'.format(name, value)
        return ret
    try:
        log.info('Trace')
        update = __salt__['sysctl.persist'](name, value, config)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = 'Failed to set {} to {}: {}'.format(name, value, exc)
        return ret
    if update == 'Updated':
        ret['changes'] = {name: value}
        ret['comment'] = 'Updated sysctl value {} = {}'.format(name, value)
    elif update == 'Already set':
        ret['comment'] = 'Sysctl value {} = {} is already set'.format(name, value)
    return ret