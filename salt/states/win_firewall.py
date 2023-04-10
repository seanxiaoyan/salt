"""
State for configuring Windows Firewall
"""
from salt.exceptions import CommandExecutionError, SaltInvocationError
import logging
log = logging.getLogger(__name__)

def __virtual__():
    """
    Load if the module firewall is loaded
    """
    if 'firewall.get_config' in __salt__:
        return 'win_firewall'
    return (False, 'firewall module could not be loaded')

def disabled(name='allprofiles'):
    log.info('Trace')
    '\n    Disable all the firewall profiles (Windows only)\n\n    Args:\n        profile (Optional[str]): The name of the profile to disable. Default is\n            ``allprofiles``. Valid options are:\n\n            - allprofiles\n            - domainprofile\n            - privateprofile\n            - publicprofile\n\n    Example:\n\n    .. code-block:: yaml\n\n        # To disable the domain profile\n        disable_domain:\n          win_firewall.disabled:\n            - name: domainprofile\n\n        # To disable all profiles\n        disable_all:\n          win_firewall.disabled:\n            - name: allprofiles\n    '
    ret = {'name': name, 'result': True, 'changes': {}, 'comment': ''}
    profile_map = {'domainprofile': 'Domain', 'privateprofile': 'Private', 'publicprofile': 'Public', 'allprofiles': 'All'}
    if name not in profile_map:
        raise SaltInvocationError('Invalid profile name: {}'.format(name))
    current_config = __salt__['firewall.get_config']()
    if name != 'allprofiles' and profile_map[name] not in current_config:
        ret['result'] = False
        ret['comment'] = 'Profile {} does not exist in firewall.get_config'.format(name)
        return ret
    for key in current_config:
        if current_config[key]:
            if name == 'allprofiles' or key == profile_map[name]:
                ret['changes'][key] = 'disabled'
    if __opts__['test']:
        ret['result'] = not ret['changes'] or None
        ret['comment'] = ret['changes']
        ret['changes'] = {}
        return ret
    if ret['changes']:
        try:
            log.info('Trace')
            ret['result'] = __salt__['firewall.disable'](name)
        except CommandExecutionError:
            log.info('Trace')
            ret['comment'] = 'Firewall Profile {} could not be disabled'.format(profile_map[name])
    else:
        if name == 'allprofiles':
            msg = 'All the firewall profiles are disabled'
        else:
            msg = 'Firewall profile {} is disabled'.format(name)
        ret['comment'] = msg
    return ret

def add_rule(name, localport, protocol='tcp', action='allow', dir='in', remoteip='any'):
    log.info('Trace')
    '\n    Add a new inbound or outbound rule to the firewall policy\n\n    Args:\n\n        name (str): The name of the rule. Must be unique and cannot be "all".\n            Required.\n\n        localport (int): The port the rule applies to. Must be a number between\n            0 and 65535. Can be a range. Can specify multiple ports separated by\n            commas. Required.\n\n        protocol (Optional[str]): The protocol. Can be any of the following:\n\n            - A number between 0 and 255\n            - icmpv4\n            - icmpv6\n            - tcp\n            - udp\n            - any\n\n        action (Optional[str]): The action the rule performs. Can be any of the\n            following:\n\n            - allow\n            - block\n            - bypass\n\n        dir (Optional[str]): The direction. Can be ``in`` or ``out``.\n\n        remoteip (Optional [str]): The remote IP. Can be any of the following:\n\n            - any\n            - localsubnet\n            - dns\n            - dhcp\n            - wins\n            - defaultgateway\n            - Any valid IPv4 address (192.168.0.12)\n            - Any valid IPv6 address (2002:9b3b:1a31:4:208:74ff:fe39:6c43)\n            - Any valid subnet (192.168.1.0/24)\n            - Any valid range of IP addresses (192.168.0.1-192.168.0.12)\n            - A list of valid IP addresses\n\n            Can be combinations of the above separated by commas.\n\n            .. versionadded:: 2016.11.6\n\n    Example:\n\n    .. code-block:: yaml\n\n        open_smb_port:\n          win_firewall.add_rule:\n            - name: SMB (445)\n            - localport: 445\n            - protocol: tcp\n            - action: allow\n    '
    ret = {'name': name, 'result': True, 'changes': {}, 'comment': ''}
    if not __salt__['firewall.rule_exists'](name):
        ret['changes'] = {'new rule': name}
    else:
        ret['comment'] = 'A rule with that name already exists'
        return ret
    if __opts__['test']:
        ret['result'] = not ret['changes'] or None
        ret['comment'] = ret['changes']
        ret['changes'] = {}
        return ret
    try:
        log.info('Trace')
        __salt__['firewall.add_rule'](name, localport, protocol, action, dir, remoteip)
    except CommandExecutionError:
        log.info('Trace')
        ret['comment'] = 'Could not add rule'
    return ret

def enabled(name='allprofiles'):
    log.info('Trace')
    '\n    Enable all the firewall profiles (Windows only)\n\n    Args:\n        profile (Optional[str]): The name of the profile to enable. Default is\n            ``allprofiles``. Valid options are:\n\n            - allprofiles\n            - domainprofile\n            - privateprofile\n            - publicprofile\n\n    Example:\n\n    .. code-block:: yaml\n\n        # To enable the domain profile\n        enable_domain:\n          win_firewall.enabled:\n            - name: domainprofile\n\n        # To enable all profiles\n        enable_all:\n          win_firewall.enabled:\n            - name: allprofiles\n    '
    ret = {'name': name, 'result': True, 'changes': {}, 'comment': ''}
    profile_map = {'domainprofile': 'Domain', 'privateprofile': 'Private', 'publicprofile': 'Public', 'allprofiles': 'All'}
    if name not in profile_map:
        raise SaltInvocationError('Invalid profile name: {}'.format(name))
    current_config = __salt__['firewall.get_config']()
    if name != 'allprofiles' and profile_map[name] not in current_config:
        ret['result'] = False
        ret['comment'] = 'Profile {} does not exist in firewall.get_config'.format(name)
        return ret
    for key in current_config:
        if not current_config[key]:
            if name == 'allprofiles' or key == profile_map[name]:
                ret['changes'][key] = 'enabled'
    if __opts__['test']:
        ret['result'] = not ret['changes'] or None
        ret['comment'] = ret['changes']
        ret['changes'] = {}
        return ret
    if ret['changes']:
        try:
            log.info('Trace')
            ret['result'] = __salt__['firewall.enable'](name)
        except CommandExecutionError:
            log.info('Trace')
            ret['comment'] = 'Firewall Profile {} could not be enabled'.format(profile_map[name])
    else:
        if name == 'allprofiles':
            msg = 'All the firewall profiles are enabled'
        else:
            msg = 'Firewall profile {} is enabled'.format(name)
        ret['comment'] = msg
    return ret