"""
Starting or restarting of services and daemons
==============================================

Services are defined as system daemons and are typically launched using system
init or rc scripts. This service state uses whichever service module is loaded
on the minion with the virtualname of ``service``. Services can be defined as
either running or dead.

If you need to know if your init system is supported, see the list of supported
:mod:`service modules <salt.modules.service.py>` for your desired init system
(systemd, sysvinit, launchctl, etc.).

Note that Salt's service execution module, and therefore this service state,
uses OS grains to ascertain which service module should be loaded and used to
execute service functions. As existing distributions change init systems or
new distributions are created, OS detection can sometimes be incomplete.
If your service states are running into trouble with init system detection,
please see the :ref:`Overriding Virtual Module Providers <module-provider-override>`
section of Salt's module documentation to work around possible errors.

.. note::
    The current status of a service is determined by the return code of the init/rc
    script status command. A status return code of 0 it is considered running.  Any
    other return code is considered dead.

.. code-block:: yaml

    httpd:
      service.running: []

The service can also be set to start at runtime via the enable option:

.. code-block:: yaml

    openvpn:
      service.running:
        - enable: True

By default if a service is triggered to refresh due to a watch statement the
service is restarted. If the desired behavior is to reload the service, then
set the reload value to True:

.. code-block:: yaml

    redis:
      service.running:
        - enable: True
        - reload: True
        - watch:
          - pkg: redis

.. note::

    More details regarding ``watch`` can be found in the
    :ref:`Requisites <requisites>` documentation.

"""
import logging
import time
import salt.utils.data
import salt.utils.platform
from salt.exceptions import CommandExecutionError
from salt.utils.args import get_function_argspec as _argspec
from salt.utils.systemd import booted
log = logging.getLogger(__name__)
SYSTEMD_ONLY = ('no_block', 'unmask', 'unmask_runtime')
__virtualname__ = 'service'

def __virtual__():
    """
    Only make these states available if a service provider has been detected or
    assigned for this minion
    """
    if 'service.start' in __salt__:
        return __virtualname__
    else:
        return (False, 'No service execution module loaded: check support for service management on {} '.format(__grains__.get('osfinger', __grains__['os'])))

def _get_systemd_only(func, kwargs):
    if not hasattr(_get_systemd_only, 'HAS_SYSTEMD'):
        setattr(_get_systemd_only, 'HAS_SYSTEMD', booted())
    ret = {}
    warnings = []
    valid_args = _argspec(func).args
    for systemd_arg in SYSTEMD_ONLY:
        if systemd_arg in kwargs and systemd_arg in valid_args:
            if _get_systemd_only.HAS_SYSTEMD:
                ret[systemd_arg] = kwargs[systemd_arg]
            else:
                warnings.append("The '{}' argument is not supported by this platform".format(systemd_arg))
    return (ret, warnings)

def _add_warnings(ret, warnings):
    current_warnings = ret.setdefault('warnings', [])
    current_warnings.extend([x for x in warnings if x not in current_warnings])

def _enabled_used_error(ret):
    """
    Warn of potential typo.
    """
    ret['result'] = False
    ret['comment'] = 'Service {} uses non-existent option "enabled".  Perhaps "enable" option was intended?'.format(ret['name'])
    return ret

def _enable(name, started, result=True, **kwargs):
    log.info('Trace')
    '\n    Enable the service\n    '
    ret = {}
    try:
        log.info('Trace')
        if not _available(name, ret):
            return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    ret['result'] = result
    if 'service.enable' not in __salt__ or 'service.enabled' not in __salt__:
        if started is True:
            ret['comment'] = 'Enable is not available on this minion, service {} started'.format(name)
        elif started is None:
            ret['comment'] = 'Enable is not available on this minion, service {} is in the desired state'.format(name)
        else:
            ret['comment'] = 'Enable is not available on this minion, service {} is dead'.format(name)
        return ret
    before_toggle_enable_status = __salt__['service.enabled'](name, **kwargs)
    if before_toggle_enable_status:
        if started is True:
            ret['comment'] = 'Service {} is already enabled, and is running'.format(name)
        elif started is None:
            ret['changes'] = {}
            ret['comment'] = 'Service {} is already enabled, and is in the desired state'.format(name)
        else:
            ret['comment'] = 'Service {} is already enabled, and is dead'.format(name)
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Service {} set to be enabled'.format(name)
        return ret
    try:
        log.info('Trace')
        if __salt__['service.enable'](name, **kwargs):
            ret['changes'] = {}
            after_toggle_enable_status = __salt__['service.enabled'](name, **kwargs)
            if before_toggle_enable_status != after_toggle_enable_status:
                ret['changes'][name] = True
            if started is True:
                ret['comment'] = 'Service {} has been enabled, and is running'.format(name)
            elif started is None:
                ret['comment'] = 'Service {} has been enabled, and is in the desired state'.format(name)
            else:
                ret['comment'] = 'Service {} has been enabled, and is dead'.format(name)
            return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        enable_error = exc.strerror
    else:
        enable_error = False
    ret['result'] = False
    if started is True:
        ret['comment'] = 'Failed when setting service {} to start at boot, but the service is running'.format(name)
    elif started is None:
        ret['comment'] = 'Failed when setting service {} to start at boot, but the service was already running'.format(name)
    else:
        ret['comment'] = 'Failed when setting service {} to start at boot, and the service is dead'.format(name)
    if enable_error:
        ret['comment'] += '. Additional information follows:\n\n{}'.format(enable_error)
    return ret

def _disable(name, started, result=True, **kwargs):
    log.info('Trace')
    '\n    Disable the service\n    '
    ret = {}
    try:
        log.info('Trace')
        if not _available(name, ret):
            ret['result'] = True
            return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    ret['result'] = result
    if 'service.disable' not in __salt__ or 'service.disabled' not in __salt__:
        if started is True:
            ret['comment'] = 'Disable is not available on this minion, service {} started'.format(name)
        elif started is None:
            ret['comment'] = 'Disable is not available on this minion, service {} is in the desired state'.format(name)
        else:
            ret['comment'] = 'Disable is not available on this minion, service {} is dead'.format(name)
        return ret
    if salt.utils.platform.is_windows():
        before_toggle_disable_status = __salt__['service.info'](name)['StartType'] in ['Disabled']
    else:
        before_toggle_disable_status = __salt__['service.disabled'](name)
    if before_toggle_disable_status:
        if started is True:
            ret['comment'] = 'Service {} is already disabled, and is running'.format(name)
        elif started is None:
            ret['changes'] = {}
            ret['comment'] = 'Service {} is already disabled, and is in the desired state'.format(name)
        else:
            ret['comment'] = 'Service {} is already disabled, and is dead'.format(name)
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Service {} set to be disabled'.format(name)
        return ret
    if __salt__['service.disable'](name, **kwargs):
        ret['changes'] = {}
        after_toggle_disable_status = __salt__['service.disabled'](name)
        if before_toggle_disable_status != after_toggle_disable_status:
            ret['changes'][name] = True
        if started is True:
            ret['comment'] = 'Service {} has been disabled, and is running'.format(name)
        elif started is None:
            ret['comment'] = 'Service {} has been disabled, and is in the desired state'.format(name)
        else:
            ret['comment'] = 'Service {} has been disabled, and is dead'.format(name)
        return ret
    ret['result'] = False
    if started is True:
        ret['comment'] = 'Failed when setting service {} to not start at boot, and is running'.format(name)
    elif started is None:
        ret['comment'] = 'Failed when setting service {} to not start at boot, but the service was already running'.format(name)
    else:
        ret['comment'] = 'Failed when setting service {} to not start at boot, and the service is dead'.format(name)
    return ret

def _offline():
    return 'service.offline' in __salt__ and __salt__['service.offline']()

def _available(name, ret):
    """
    Check if the service is available
    """
    avail = False
    if 'service.available' in __salt__:
        avail = __salt__['service.available'](name)
    elif 'service.get_all' in __salt__:
        avail = name in __salt__['service.get_all']()
    if not avail:
        ret['result'] = False
        ret['comment'] = 'The named service {} is not available'.format(name)
    return avail

def running(name, enable=None, sig=None, init_delay=None, **kwargs):
    log.info('Trace')
    "\n    Ensure that the service is running\n\n    name\n        The name of the init or rc script used to manage the service\n\n    enable\n        Set the service to be enabled at boot time, ``True`` sets the service\n        to be enabled, ``False`` sets the named service to be disabled. The\n        default is ``None``, which does not enable or disable anything.\n\n    sig\n        The string to search for when looking for the service process with ps\n\n    init_delay\n        Some services may not be truly available for a short period after their\n        startup script indicates to the system that they are. Provide an\n        'init_delay' to specify that this state should wait an additional given\n        number of seconds after a service has started before returning. Useful\n        for requisite states wherein a dependent state might assume a service\n        has started but is not yet fully initialized.\n\n    no_block : False\n        **For systemd minions only.** Starts the service using ``--no-block``.\n\n        .. versionadded:: 2017.7.0\n\n    timeout\n        **For Windows minions only.**\n\n        The time in seconds to wait for the service to start before returning.\n        Default is the default for :py:func:`win_service.start\n        <salt.modules.win_service.start>`.\n\n        .. versionadded:: 2017.7.9,2018.3.4\n\n    unmask : False\n        **For systemd minions only.** Set to ``True`` to remove an indefinite\n        mask before attempting to start the service.\n\n        .. versionadded:: 2017.7.0\n            In previous releases, Salt would simply unmask a service before\n            making any changes. This behavior is no longer the default.\n\n    unmask_runtime : False\n        **For systemd minions only.** Set to ``True`` to remove a runtime mask\n        before attempting to start the service.\n\n        .. versionadded:: 2017.7.0\n            In previous releases, Salt would simply unmask a service before\n            making any changes. This behavior is no longer the default.\n\n    wait : 3\n        **For systemd minions only.** Passed through when using\n        :py:func:`service.status <salt.modules.systemd_service.status>` to\n        determine whether the service is running or not.\n\n        .. versionadded:: 2019.2.3\n\n    .. note::\n        ``watch`` can be used with service.running to restart a service when\n         another state changes ( example: a file.managed state that creates the\n         service's config file ). More details regarding ``watch`` can be found\n         in the :ref:`Requisites <requisites>` documentation.\n    "
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    __context__['service.state'] = 'running'
    if 'enabled' in kwargs:
        return _enabled_used_error(ret)
    if isinstance(enable, str):
        enable = salt.utils.data.is_true(enable)
    if _offline():
        ret['result'] = True
        ret['comment'] = 'Running in OFFLINE mode. Nothing to do'
        return ret
    try:
        log.info('Trace')
        if not _available(name, ret):
            if __opts__.get('test'):
                ret['result'] = None
                ret['comment'] = 'Service {} not present; if created in this state run, it would have been started'.format(name)
            return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    (status_kwargs, warnings) = _get_systemd_only(__salt__['service.status'], kwargs)
    if warnings:
        _add_warnings(ret, warnings)
    before_toggle_status = __salt__['service.status'](name, sig, **status_kwargs)
    if 'service.enabled' in __salt__:
        before_toggle_enable_status = __salt__['service.enabled'](name)
    else:
        before_toggle_enable_status = True
    unmask_ret = {'comment': ''}
    if kwargs.get('unmask', False):
        unmask_ret = unmasked(name, kwargs.get('unmask_runtime', False))
    if before_toggle_status:
        ret['comment'] = '\n'.join([_f for _f in ['The service {} is already running'.format(name), unmask_ret['comment']] if _f])
        if enable is True and (not before_toggle_enable_status):
            ret.update(_enable(name, None, **kwargs))
        elif enable is False and before_toggle_enable_status:
            ret.update(_disable(name, None, **kwargs))
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = '\n'.join([_f for _f in ['Service {} is set to start'.format(name), unmask_ret['comment']] if _f])
        return ret
    (start_kwargs, warnings) = _get_systemd_only(__salt__['service.start'], kwargs)
    if warnings:
        _add_warnings(ret, warnings)
    if salt.utils.platform.is_windows() and kwargs.get('timeout', False):
        start_kwargs.update({'timeout': kwargs.get('timeout')})
    macos = salt.utils.platform.is_darwin()
    windows = salt.utils.platform.is_windows()
    if (macos or windows) and (not before_toggle_enable_status):
        if not enable:
            ret['comment'] = 'The service {} is disabled but enable is not True. Set enable to True to successfully start the service.'.format(name)
            ret['result'] = False
            return ret
        ret.update(_enable(name, None, **kwargs))
        enable = None
    try:
        log.info('Trace')
        func_ret = __salt__['service.start'](name, **start_kwargs)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    if not func_ret:
        ret['result'] = False
        ret['comment'] = 'Service {} failed to start'.format(name)
        if enable is True:
            ret.update(_enable(name, False, result=False, **kwargs))
        elif enable is False:
            ret.update(_disable(name, False, result=False, **kwargs))
        return ret
    if init_delay:
        time.sleep(init_delay)
    after_toggle_status = __salt__['service.status'](name, sig, **status_kwargs)
    if 'service.enabled' in __salt__:
        after_toggle_enable_status = __salt__['service.enabled'](name)
    else:
        after_toggle_enable_status = True
    if (before_toggle_enable_status != after_toggle_enable_status or before_toggle_status != after_toggle_status) and (not ret.get('changes', {})):
        ret['changes'][name] = after_toggle_status
    if after_toggle_status:
        ret['comment'] = 'Started service {}'.format(name)
    else:
        ret['comment'] = 'Service {} failed to start'.format(name)
        ret['result'] = False
    if enable is True:
        ret.update(_enable(name, after_toggle_status, result=after_toggle_status, **kwargs))
    elif enable is False:
        ret.update(_disable(name, after_toggle_status, result=after_toggle_status, **kwargs))
    if init_delay:
        ret['comment'] = '{}\nDelayed return for {} seconds'.format(ret['comment'], init_delay)
    if kwargs.get('unmask', False):
        ret['comment'] = '\n'.join([ret['comment'], unmask_ret['comment']])
    return ret

def dead(name, enable=None, sig=None, init_delay=None, **kwargs):
    log.info('Trace')
    '\n    Ensure that the named service is dead by stopping the service if it is running\n\n    name\n        The name of the init or rc script used to manage the service\n\n    enable\n        Set the service to be enabled at boot time, ``True`` sets the service\n        to be enabled, ``False`` sets the named service to be disabled. The\n        default is ``None``, which does not enable or disable anything.\n\n    sig\n        The string to search for when looking for the service process with ps\n\n    init_delay\n        Add a sleep command (in seconds) before the check to make sure service\n        is killed.\n\n        .. versionadded:: 2017.7.0\n\n    no_block : False\n        **For systemd minions only.** Stops the service using ``--no-block``.\n\n        .. versionadded:: 2017.7.0\n\n    timeout\n        **For Windows minions only.**\n\n        The time in seconds to wait for the service to stop before returning.\n        Default is the default for :py:func:`win_service.stop\n        <salt.modules.win_service.stop>`.\n\n        .. versionadded:: 2017.7.9,2018.3.4\n\n    '
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    __context__['service.state'] = 'dead'
    if 'enabled' in kwargs:
        return _enabled_used_error(ret)
    if isinstance(enable, str):
        enable = salt.utils.data.is_true(enable)
    if _offline():
        ret['result'] = True
        ret['comment'] = 'Running in OFFLINE mode. Nothing to do'
        return ret
    try:
        log.info('Trace')
        if not _available(name, ret):
            if __opts__.get('test'):
                ret['result'] = None
                ret['comment'] = 'Service {} not present; if created in this state run, it would have been stopped'.format(name)
            else:
                ret['result'] = True
            return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    (status_kwargs, warnings) = _get_systemd_only(__salt__['service.status'], kwargs)
    if warnings:
        _add_warnings(ret, warnings)
    before_toggle_status = __salt__['service.status'](name, sig, **status_kwargs)
    if 'service.enabled' in __salt__:
        if salt.utils.platform.is_windows():
            before_toggle_enable_status = __salt__['service.info'](name)['StartType'] in ['Auto', 'Manual']
        else:
            before_toggle_enable_status = __salt__['service.enabled'](name)
    else:
        before_toggle_enable_status = True
    if not before_toggle_status:
        ret['comment'] = 'The service {} is already dead'.format(name)
        if enable is True and (not before_toggle_enable_status):
            ret.update(_enable(name, None, **kwargs))
        elif enable is False and before_toggle_enable_status:
            ret.update(_disable(name, None, **kwargs))
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Service {} is set to be killed'.format(name)
        return ret
    (stop_kwargs, warnings) = _get_systemd_only(__salt__['service.stop'], kwargs)
    if warnings:
        _add_warnings(ret, warnings)
    if salt.utils.platform.is_windows() and kwargs.get('timeout', False):
        stop_kwargs.update({'timeout': kwargs.get('timeout')})
    func_ret = __salt__['service.stop'](name, **stop_kwargs)
    if not func_ret:
        ret['result'] = False
        ret['comment'] = 'Service {} failed to die'.format(name)
        if enable is True:
            ret.update(_enable(name, True, result=False, **kwargs))
        elif enable is False:
            ret.update(_disable(name, True, result=False, **kwargs))
        return ret
    if init_delay:
        time.sleep(init_delay)
    after_toggle_status = __salt__['service.status'](name, **status_kwargs)
    if 'service.enabled' in __salt__:
        after_toggle_enable_status = __salt__['service.enabled'](name)
    else:
        after_toggle_enable_status = True
    if (before_toggle_enable_status != after_toggle_enable_status or before_toggle_status != after_toggle_status) and (not ret.get('changes', {})):
        ret['changes'][name] = after_toggle_status
    if after_toggle_status:
        ret['result'] = False
        ret['comment'] = 'Service {} failed to die'.format(name)
    else:
        ret['comment'] = 'Service {} was killed'.format(name)
    if enable is True:
        ret.update(_enable(name, after_toggle_status, result=not after_toggle_status, **kwargs))
    elif enable is False:
        ret.update(_disable(name, after_toggle_status, result=not after_toggle_status, **kwargs))
    return ret

def enabled(name, **kwargs):
    """
    Ensure that the service is enabled on boot, only use this state if you
    don't want to manage the running process, remember that if you want to
    enable a running service to use the enable: True option for the running
    or dead function.

    name
        The name of the init or rc script used to manage the service
    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    __context__['service.state'] = 'enabled'
    ret.update(_enable(name, None, **kwargs))
    if __opts__.get('test') and ret.get('comment') == 'The named service {} is not available'.format(name):
        ret['result'] = None
        ret['comment'] = 'Service {} not present; if created in this state run, it would have been enabled'.format(name)
    return ret

def disabled(name, **kwargs):
    """
    Ensure that the service is disabled on boot, only use this state if you
    don't want to manage the running process, remember that if you want to
    disable a service to use the enable: False option for the running or dead
    function.

    name
        The name of the init or rc script used to manage the service
    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    __context__['service.state'] = 'disabled'
    ret.update(_disable(name, None, **kwargs))
    return ret

def masked(name, runtime=False):
    """
    .. versionadded:: 2017.7.0

    .. note::
        This state is only available on minions which use systemd_.

    Ensures that the named service is masked (i.e. prevented from being
    started).

    name
        Name of the service to mask

    runtime : False
        By default, this state will manage an indefinite mask for the named
        service. Set this argument to ``True`` to runtime mask the service.

    .. note::
        It is possible for a service to have both indefinite and runtime masks
        set for it. Therefore, this state will manage a runtime or indefinite
        mask independently of each other. This means that if the service is
        already indefinitely masked, running this state with ``runtime`` set to
        ``True`` will _not_ remove the indefinite mask before setting a runtime
        mask. In these cases, if it is desirable to ensure that the service is
        runtime masked and not indefinitely masked, pair this state with a
        :py:func:`service.unmasked <salt.states.service.unmasked>` state, like
        so:

        .. code-block:: yaml

            mask_runtime_foo:
              service.masked:
                - name: foo
                - runtime: True

            unmask_indefinite_foo:
              service.unmasked:
                - name: foo
                - runtime: False

    .. _systemd: https://freedesktop.org/wiki/Software/systemd/

    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if 'service.masked' not in __salt__:
        ret['comment'] = 'Service masking not available on this minion'
        ret['result'] = False
        return ret
    mask_type = 'runtime masked' if runtime else 'masked'
    expected_changes = {mask_type: {'old': False, 'new': True}}
    try:
        log.info('Trace')
        if __salt__['service.masked'](name, runtime):
            ret['comment'] = 'Service {} is already {}'.format(name, mask_type)
            return ret
        if __opts__['test']:
            ret['result'] = None
            ret['changes'] = expected_changes
            ret['comment'] = 'Service {} would be {}'.format(name, mask_type)
            return ret
        __salt__['service.mask'](name, runtime)
        if __salt__['service.masked'](name, runtime):
            ret['changes'] = expected_changes
            ret['comment'] = 'Service {} was {}'.format(name, mask_type)
        else:
            ret['comment'] = 'Failed to mask service {}'.format(name)
        return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret

def unmasked(name, runtime=False):
    """
    .. versionadded:: 2017.7.0

    .. note::
        This state is only available on minions which use systemd_.

    Ensures that the named service is unmasked

    name
        Name of the service to unmask

    runtime : False
        By default, this state will manage an indefinite mask for the named
        service. Set this argument to ``True`` to ensure that the service is
        runtime masked.

    .. note::
        It is possible for a service to have both indefinite and runtime masks
        set for it. Therefore, this state will manage a runtime or indefinite
        mask independently of each other. This means that if the service is
        indefinitely masked, running this state with ``runtime`` set to
        ``True`` will _not_ remove the indefinite mask.

    .. _systemd: https://freedesktop.org/wiki/Software/systemd/

    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if 'service.masked' not in __salt__:
        ret['comment'] = 'Service masking not available on this minion'
        ret['result'] = False
        return ret
    mask_type = 'runtime masked' if runtime else 'masked'
    action = 'runtime unmasked' if runtime else 'unmasked'
    expected_changes = {mask_type: {'old': True, 'new': False}}
    try:
        log.info('Trace')
        if not __salt__['service.masked'](name, runtime):
            ret['comment'] = 'Service {} was already {}'.format(name, action)
            return ret
        if __opts__['test']:
            ret['result'] = None
            ret['changes'] = expected_changes
            ret['comment'] = 'Service {} would be {}'.format(name, action)
            return ret
        __salt__['service.unmask'](name, runtime)
        if not __salt__['service.masked'](name, runtime):
            ret['changes'] = expected_changes
            ret['comment'] = 'Service {} was {}'.format(name, action)
        else:
            ret['comment'] = 'Failed to unmask service {}'.format(name)
        return ret
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret

def mod_watch(name, sfun=None, sig=None, reload=False, full_restart=False, init_delay=None, force=False, **kwargs):
    log.info('Trace')
    '\n    The service watcher, called to invoke the watch command.\n    When called, it will restart or reload the named service.\n\n    .. note::\n        This state exists to support special handling of the ``watch``\n        :ref:`requisite <requisites>`. It should not be called directly.\n\n        Parameters for this function should be set by the watching service\n        (e.g. ``service.running``).\n\n    name\n        The name of the service to control.\n\n    sfun\n        The original function which triggered the mod_watch call\n        (`service.running`, for example).\n\n    sig\n        The string to search for when looking for the service process with ps.\n\n    reload\n        When set, reload the service instead of restarting it\n        (e.g. ``service nginx reload``).\n\n    full_restart\n        Perform a full stop/start of a service by passing ``--full-restart``.\n        This option is ignored if ``reload`` is set and is supported by only a few\n        :py:func:`service modules <salt.modules.service>`.\n\n    force\n        Use service.force_reload instead of reload (needs reload to be set to True).\n\n    init_delay\n        Add a sleep command (in seconds) before the service is restarted/reloaded.\n    '
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    past_participle = None
    (status_kwargs, warnings) = _get_systemd_only(__salt__['service.status'], kwargs)
    if warnings:
        _add_warnings(ret, warnings)
    if sfun == 'dead':
        verb = 'stop'
        past_participle = verb + 'ped'
        if __salt__['service.status'](name, sig, **status_kwargs):
            func = __salt__['service.stop']
        else:
            ret['result'] = True
            ret['comment'] = 'Service is already {}'.format(past_participle)
            return ret
    elif sfun == 'running':
        if __salt__['service.status'](name, sig, **status_kwargs):
            if 'service.reload' in __salt__ and reload:
                if 'service.force_reload' in __salt__ and force:
                    func = __salt__['service.force_reload']
                    verb = 'forcefully reload'
                else:
                    func = __salt__['service.reload']
                    verb = 'reload'
            elif 'service.full_restart' in __salt__ and full_restart:
                func = __salt__['service.full_restart']
                verb = 'fully restart'
            else:
                func = __salt__['service.restart']
                verb = 'restart'
        else:
            func = __salt__['service.start']
            verb = 'start'
        if not past_participle:
            past_participle = verb + 'ed'
    else:
        ret['comment'] = 'Unable to trigger watch for service.{}'.format(sfun)
        ret['result'] = False
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Service is set to be {}'.format(past_participle)
        return ret
    if verb == 'start' and 'service.stop' in __salt__:
        __salt__['service.stop'](name)
    (func_kwargs, warnings) = _get_systemd_only(func, kwargs)
    if warnings:
        _add_warnings(ret, warnings)
    try:
        log.info('Trace')
        result = func(name, **func_kwargs)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    if init_delay:
        time.sleep(init_delay)
    ret['changes'] = {name: result}
    ret['result'] = result
    ret['comment'] = 'Service {}'.format(past_participle) if result else 'Failed to {} the service'.format(verb)
    return ret

def mod_beacon(name, **kwargs):
    """
    Create a beacon to monitor a service based on a beacon state argument.

    .. note::
        This state exists to support special handling of the ``beacon``
        state argument for supported state functions. It should not be called directly.
    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    sfun = kwargs.pop('sfun', None)
    supported_funcs = ['running', 'dead']
    if sfun in supported_funcs:
        if kwargs.get('beacon'):
            beacon_module = 'service'
            data = {}
            _beacon_data = kwargs.get('beacon_data', {})
            data['onchangeonly'] = _beacon_data.get('onchangeonly', True)
            data['delay'] = _beacon_data.get('delay', 0)
            data['emitatstartup'] = _beacon_data.get('emitatstartup', False)
            data['uncleanshutdown'] = _beacon_data.get('emitatstartup', None)
            beacon_name = 'beacon_{}_{}'.format(beacon_module, name)
            beacon_kwargs = {'name': beacon_name, 'services': {name: data}, 'interval': _beacon_data.get('interval', 60), 'beacon_module': beacon_module}
            ret = __states__['beacon.present'](**beacon_kwargs)
            return ret
        else:
            return {'name': name, 'changes': {}, 'comment': 'Not adding beacon.', 'result': True}
    else:
        return {'name': name, 'changes': {}, 'comment': 'service.{} does not work with the beacon state function'.format(sfun), 'result': False}