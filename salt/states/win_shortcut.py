"""
State module for creating shortcuts on Windows. Handles file shortcuts (`.lnk`)
and url shortcuts (`.url`). Allows for the configuration of icons and hot keys
on file shortcuts. Changing the icon and hot keys are unsupported for url
shortcuts.

.. versionadded:: 3005
"""
import salt.utils.data
import salt.utils.path
import salt.utils.platform
from salt.exceptions import CommandExecutionError
import logging
log = logging.getLogger(__name__)
__virtualname__ = 'shortcut'

def __virtual__():
    """
    Only works on Windows systems
    """
    if not salt.utils.platform.is_windows():
        return (False, 'Shortcut state only available on Windows systems.')
    if not __salt__.get('shortcut.create', None):
        return (False, 'Shortcut state requires the shortcut module.')
    return __virtualname__

def present(name, arguments='', description='', hot_key='', icon_location='', icon_index=0, target='', window_style='Normal', working_dir='', backup=False, force=False, make_dirs=False, user=None):
    log.info('Trace')
    "\n    Create a new shortcut. This can be a file shortcut (``.lnk``) or a url\n    shortcut (``.url``).\n\n    Args:\n\n        name (str): The full path to the shortcut\n\n        target (str): The full path to the target\n\n        arguments (str, optional): Any arguments to be passed to the target\n\n        description (str, optional): The description for the shortcut. This is\n            shown in the ``Comment`` field of the dialog box. Default is an\n            empty string\n\n        hot_key (str, optional): A combination of hot Keys to trigger this\n            shortcut. This is something like ``Ctrl+Alt+D``. This is shown in\n            the ``Shortcut key`` field in the dialog box. Default is an empty\n            string. Available options are:\n\n            - Ctrl\n            - Alt\n            - Shift\n            - Ext\n\n        icon_index (int, optional): The index for the icon to use in files that\n            contain multiple icons. Default is 0\n\n        icon_location (str, optional): The full path to a file containing icons.\n            This is shown in the ``Change Icon`` dialog box by clicking the\n            ``Change Icon`` button. If no file is specified and a binary is\n            passed as the target, Windows will attempt to get the icon from the\n            binary file. Default is an empty string\n\n        window_style (str, optional): The window style the program should start\n            in. This is shown in the ``Run`` field of the dialog box. Default is\n            ``Normal``. Valid options are:\n\n            - Normal\n            - Minimized\n            - Maximized\n\n        working_dir (str, optional): The full path to the working directory for\n            the program to run in. This is shown in the ``Start in`` field of\n            the dialog box.\n\n        backup (bool, optional): If there is already a shortcut with the same\n            name, set this value to ``True`` to backup the existing shortcut and\n            continue creating the new shortcut. Default is ``False``\n\n        force (bool, optional): If there is already a shortcut with the same\n            name and you aren't backing up the shortcut, set this value to\n            ``True`` to remove the existing shortcut and create a new with these\n            settings. Default is ``False``\n\n        make_dirs (bool, optional): If the parent directory structure does not\n            exist for the new shortcut, create it. Default is ``False``\n\n        user (str, optional): The user to be the owner of any directories\n            created by setting ``make_dirs`` to ``True``. If no value is passed\n            Salt will use the user account that it is running under. Default is\n            an empty string.\n\n    Returns:\n        dict: A dictionary containing the changes, comments, and result of the\n            state\n\n    Example:\n\n    .. code-block:: yaml\n\n        KB123456:\n          wusa.installed:\n            - source: salt://kb123456.msu\n\n        # Create a shortcut and set the ``Shortcut key`` (``hot_key``)\n        new_shortcut:\n          shortcut.present:\n            - name: C:\\path\\to\\shortcut.lnk\n            - target: C:\\Windows\\notepad.exe\n            - hot_key: Ctrl+Alt+N\n\n        # Create a shortcut and change the icon to the 3rd one in the icon file\n        new_shortcut:\n          shortcut.present:\n            - name: C:\\path\\to\\shortcut.lnk\n            - target: C:\\Windows\\notepad.exe\n            - icon_location: C:\\path\\to\\icon.ico\n            - icon_index: 2\n\n        # Create a shortcut and change the startup mode to full screen\n        new_shortcut:\n          shortcut.present:\n            - name: C:\\path\\to\\shortcut.lnk\n            - target: C:\\Windows\\notepad.exe\n            - window_style: Maximized\n\n        # Create a shortcut and change the icon\n        new_shortcut:\n          shortcut.present:\n            - name: C:\\path\\to\\shortcut.lnk\n            - target: C:\\Windows\\notepad.exe\n            - icon_location: C:\\path\\to\\icon.ico\n\n        # Create a shortcut and force it to overwrite an existing shortcut\n        new_shortcut:\n          shortcut.present:\n            - name: C:\\path\\to\\shortcut.lnk\n            - target: C:\\Windows\\notepad.exe\n            - force: True\n\n        # Create a shortcut and create any parent directories if they are missing\n        new_shortcut:\n          shortcut.present:\n            - name: C:\\path\\to\\shortcut.lnk\n            - target: C:\\Windows\\notepad.exe\n            - make_dirs: True\n    "
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': []}
    proposed = {'arguments': arguments, 'description': description, 'hot_key': hot_key, 'icon_location': salt.utils.path.expand(icon_location), 'icon_index': icon_index, 'path': salt.utils.path.expand(name), 'target': salt.utils.path.expand(target), 'window_style': window_style, 'working_dir': salt.utils.path.expand(working_dir)}
    try:
        log.info('Trace')
        old = __salt__['shortcut.get'](name)
        changes = salt.utils.data.compare_dicts(old, proposed)
        if not changes:
            ret['comment'] = 'Shortcut already present and configured'
            return ret
    except CommandExecutionError:
        log.info('Trace')
        changes = {}
    if __opts__['test']:
        if changes:
            ret['comment'] = 'Shortcut will be modified: {}'.format(name)
            ret['changes'] = changes
        else:
            ret['comment'] = 'Shortcut will be created: {}'.format(name)
        ret['result'] = None
        return ret
    try:
        log.info('Trace')
        __salt__['shortcut.create'](arguments=arguments, description=description, hot_key=hot_key, icon_location=icon_location, icon_index=icon_index, path=name, target=target, window_style=window_style, working_dir=working_dir, backup=backup, force=force, make_dirs=make_dirs, user=user)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['comment'] = ['Failed to create the shortcut: {}'.format(name)]
        ret['comment'].append(exc.message)
        ret['result'] = False
        return ret
    try:
        log.info('Trace')
        new = __salt__['shortcut.get'](name)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['comment'] = ['Failed to create the shortcut: {}'.format(name)]
        ret['comment'].append(exc.message)
        ret['result'] = False
        return ret
    verify_changes = salt.utils.data.compare_dicts(new, proposed)
    if verify_changes:
        ret['comment'] = 'Failed to make the following changes:'
        ret['changes']['failed'] = verify_changes
        ret['result'] = False
        return ret
    if changes:
        ret['comment'] = 'Shortcut modified: {}'.format(name)
        ret['changes'] = changes
    else:
        ret['comment'] = 'Shortcut created: {}'.format(name)
    return ret