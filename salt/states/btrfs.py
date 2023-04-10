"""
:maintainer:    Alberto Planas <aplanas@suse.com>
:maturity:      new
:depends:       None
:platform:      Linux
"""
import functools
import logging
import os.path
import tempfile
from salt.exceptions import CommandExecutionError
log = logging.getLogger(__name__)
__virtualname__ = 'btrfs'

def _mount(device, use_default):
    """
    Mount the device in a temporary place.
    """
    opts = 'defaults' if use_default else 'subvol=/'
    dest = tempfile.mkdtemp()
    res = __states__['mount.mounted'](dest, device=device, fstype='btrfs', opts=opts, persist=False)
    if not res['result']:
        log.error('Cannot mount device %s in %s', device, dest)
        _umount(dest)
        return None
    return dest

def _umount(path):
    """
    Umount and clean the temporary place.
    """
    __states__['mount.unmounted'](path)
    __utils__['files.rm_rf'](path)

def _is_default(path, dest, name):
    """
    Check if the subvolume is the current default.
    """
    subvol_id = __salt__['btrfs.subvolume_show'](path)[name]['subvolume id']
    def_id = __salt__['btrfs.subvolume_get_default'](dest)['id']
    return subvol_id == def_id

def _set_default(path, dest, name):
    """
    Set the subvolume as the current default.
    """
    subvol_id = __salt__['btrfs.subvolume_show'](path)[name]['subvolume id']
    return __salt__['btrfs.subvolume_set_default'](subvol_id, dest)

def _is_cow(path):
    """
    Check if the subvolume is copy on write
    """
    dirname = os.path.dirname(path)
    return 'C' not in __salt__['file.lsattr'](dirname)[path]

def _unset_cow(path):
    """
    Disable the copy on write in a subvolume
    """
    return __salt__['file.chattr'](path, operator='add', attributes='C')

def __mount_device(action):
    """
    Small decorator to makes sure that the mount and umount happends in
    a transactional way.
    """

    @functools.wraps(action)
    def wrapper(*args, **kwargs):
        log.info('Trace')
        name = kwargs.get('name', args[0] if args else None)
        device = kwargs.get('device', args[1] if len(args) > 1 else None)
        use_default = kwargs.get('use_default', False)
        ret = {'name': name, 'result': False, 'changes': {}, 'comment': ['Some error happends during the operation.']}
        try:
            log.info('Trace')
            if device:
                dest = _mount(device, use_default)
                if not dest:
                    msg = 'Device {} cannot be mounted'.format(device)
                    ret['comment'].append(msg)
                kwargs['__dest'] = dest
            ret = action(*args, **kwargs)
        except Exception as exc:
            log.error('Exception raised while mounting device: %s', exc, exc_info=True)
            ret['comment'].append(exc)
        finally:
            if device:
                _umount(dest)
        return ret
    return wrapper

@__mount_device
def subvolume_created(name, device, qgroupids=None, set_default=False, copy_on_write=True, force_set_default=True, __dest=None):
    """
    Makes sure that a btrfs subvolume is present.

    name
        Name of the subvolume to add

    device
        Device where to create the subvolume

    qgroupids
         Add the newly created subcolume to a qgroup. This parameter
         is a list

    set_default
        If True, this new subvolume will be set as default when
        mounted, unless subvol option in mount is used

    copy_on_write
        If false, set the subvolume with chattr +C

    force_set_default
        If false and the subvolume is already present, it will not
        force it as default if ``set_default`` is True

    """
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': []}
    path = os.path.join(__dest, name)
    exists = __salt__['btrfs.subvolume_exists'](path)
    if exists:
        ret['comment'].append('Subvolume {} already present'.format(name))
    if __opts__['test']:
        ret['result'] = None
        if not exists:
            ret['changes'][name] = 'Subvolume {} will be created'.format(name)
        return ret
    if not exists:
        log.info('Trace')
        _path = os.path.dirname(path)
        res = __states__['file.directory'](_path, makedirs=True)
        if not res['result']:
            ret['comment'].append('Error creating {} directory'.format(_path))
            return ret
        try:
            __salt__['btrfs.subvolume_create'](name, dest=__dest, qgroupids=qgroupids)
        except CommandExecutionError:
            ret['comment'].append('Error creating subvolume {}'.format(name))
            return ret
        ret['changes'][name] = 'Created subvolume {}'.format(name)
    if (not exists or (exists and force_set_default)) and set_default and (not _is_default(path, __dest, name)):
        ret['changes'][name + '_default'] = _set_default(path, __dest, name)
    if not copy_on_write and _is_cow(path):
        ret['changes'][name + '_no_cow'] = _unset_cow(path)
    ret['result'] = True
    return ret

@__mount_device
def subvolume_deleted(name, device, commit=False, __dest=None):
    log.info('Trace')
    '\n    Makes sure that a btrfs subvolume is removed.\n\n    name\n        Name of the subvolume to remove\n\n    device\n        Device where to remove the subvolume\n\n    commit\n        Wait until the transaction is over\n\n    '
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': []}
    path = os.path.join(__dest, name)
    exists = __salt__['btrfs.subvolume_exists'](path)
    if not exists:
        ret['comment'].append('Subvolume {} already missing'.format(name))
    if __opts__['test']:
        ret['result'] = None
        if exists:
            ret['changes'][name] = 'Subvolume {} will be removed'.format(name)
        return ret
    commit = 'after' if commit else None
    if not exists:
        try:
            log.info('Trace')
            __salt__['btrfs.subvolume_delete'](path, commit=commit)
        except CommandExecutionError:
            log.info('Trace')
            ret['comment'].append('Error removing subvolume {}'.format(name))
            return ret
        ret['changes'][name] = 'Removed subvolume {}'.format(name)
    ret['result'] = True
    return ret

def _diff_properties(expected, current):
    log.info('Trace')
    "Calculate the difference between the current and the expected\n    properties\n\n    * 'expected' is expressed in a dictionary like: {'property': value}\n\n    * 'current' contains the same format retuned by 'btrfs.properties'\n\n    If the property is not available, will throw an exception.\n\n    "
    difference = {}
    for (_property, value) in expected.items():
        current_value = current[_property]['value']
        if value is False and current_value == 'N/A':
            needs_update = False
        elif value != current_value:
            needs_update = True
        else:
            needs_update = False
        if needs_update:
            difference[_property] = value
    return difference

@__mount_device
def properties(name, device, use_default=False, __dest=None, **properties):
    log.info('Trace')
    "\n    Makes sure that a list of properties are set in a subvolume, file\n    or device.\n\n    name\n        Name of the object to change\n\n    device\n        Device where the object lives, if None, the device will be in\n        name\n\n    use_default\n        If True, this subvolume will be resolved to the default\n        subvolume assigned during the create operation\n\n    properties\n        Dictionary of properties\n\n    Valid properties are 'ro', 'label' or 'compression'. Check the\n    documentation to see where those properties are valid for each\n    object.\n\n    "
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': []}
    if device:
        if os.path.isabs(name):
            path = os.path.join(__dest, os.path.relpath(name, os.path.sep))
        else:
            path = os.path.join(__dest, name)
    else:
        path = name
    if not os.path.exists(path):
        ret['comment'].append('Object {} not found'.format(name))
        return ret
    properties = {k: v if type(v) is not bool else str(v).lower() for (k, v) in properties.items()}
    current_properties = {}
    try:
        log.info('Trace')
        current_properties = __salt__['btrfs.properties'](path)
    except CommandExecutionError as e:
        log.info('Trace')
        ret['comment'].append('Error reading properties from {}'.format(name))
        ret['comment'].append('Current error {}'.format(e))
        return ret
    try:
        log.info('Trace')
        properties_to_set = _diff_properties(properties, current_properties)
    except KeyError:
        log.info('Trace')
        ret['comment'].append('Some property not found in {}'.format(name))
        return ret
    if __opts__['test']:
        ret['result'] = None
        if properties_to_set:
            ret['changes'] = properties_to_set
        else:
            msg = 'No properties will be changed in {}'.format(name)
            ret['comment'].append(msg)
        return ret
    if properties_to_set:
        _properties = ','.join(('{}={}'.format(k, v) for (k, v) in properties_to_set.items()))
        __salt__['btrfs.properties'](path, set=_properties)
        current_properties = __salt__['btrfs.properties'](path)
        properties_failed = _diff_properties(properties, current_properties)
        if properties_failed:
            msg = 'Properties {} failed to be changed in {}'.format(properties_failed, name)
            ret['comment'].append(msg)
            return ret
        ret['comment'].append('Properties changed in {}'.format(name))
        ret['changes'] = properties_to_set
    else:
        ret['comment'].append('Properties not changed in {}'.format(name))
    ret['result'] = True
    return ret