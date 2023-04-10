"""
States for managing zpools

:maintainer:    Jorge Schrauwen <sjorge@blackdot.be>
:maturity:      new
:depends:       salt.utils.zfs, salt.modules.zpool
:platform:      smartos, illumos, solaris, freebsd, linux

.. versionadded:: 2016.3.0
.. versionchanged:: 2018.3.1
  Big refactor to remove duplicate code, better type conversions and improved
  consistency in output.

.. code-block:: yaml

    oldpool:
      zpool.absent:
        - export: true

    newpool:
      zpool.present:
        - config:
            import: false
            force: true
        - properties:
            comment: salty storage pool
        - layout:
            - mirror:
              - /dev/disk0
              - /dev/disk1
            - mirror:
              - /dev/disk2
              - /dev/disk3

    partitionpool:
      zpool.present:
        - config:
            import: false
            force: true
        - properties:
            comment: disk partition salty storage pool
            ashift: '12'
            feature@lz4_compress: enabled
        - filesystem_properties:
            compression: lz4
            atime: on
            relatime: on
        - layout:
            - /dev/disk/by-uuid/3e43ce94-77af-4f52-a91b-6cdbb0b0f41b

    simplepool:
      zpool.present:
        - config:
            import: false
            force: true
        - properties:
            comment: another salty storage pool
        - layout:
            - /dev/disk0
            - /dev/disk1

.. warning::

    The layout will never be updated, it will only be used at time of creation.
    It's a whole lot of work to figure out if a devices needs to be detached, removed,
    etc. This is best done by the sysadmin on a case per case basis.

    Filesystem properties are also not updated, this should be managed by the zfs state module.

"""
import logging
import os
from salt.utils.odict import OrderedDict
log = logging.getLogger(__name__)
__virtualname__ = 'zpool'

def __virtual__():
    """
    Provides zpool state
    """
    if not __grains__.get('zfs_support'):
        return (False, 'The zpool state cannot be loaded: zfs not supported')
    return __virtualname__

def _layout_to_vdev(layout, device_dir=None):
    """
    Turn the layout data into usable vdevs spedcification

    We need to support 2 ways of passing the layout:

    .. code::
        layout_new:
          - mirror:
            - disk0
            - disk1
          - mirror:
            - disk2
            - disk3

    .. code:
        layout_legacy:
          mirror-0:
            disk0
            disk1
          mirror-1:
            disk2
            disk3

    """
    vdevs = []
    if device_dir and (not os.path.exists(device_dir)):
        device_dir = None
    if isinstance(layout, list):
        for vdev in layout:
            if isinstance(vdev, OrderedDict):
                vdevs.extend(_layout_to_vdev(vdev, device_dir))
            else:
                if device_dir and vdev[0] != '/':
                    vdev = os.path.join(device_dir, vdev)
                vdevs.append(vdev)
    elif isinstance(layout, OrderedDict):
        for vdev in layout:
            vdev_type = vdev.split('-')[0]
            vdev_disk = layout[vdev]
            if vdev_type != 'disk':
                vdevs.append(vdev_type)
            if not isinstance(vdev_disk, list):
                vdev_disk = vdev_disk.split(' ')
            for disk in vdev_disk:
                if device_dir and disk[0] != '/':
                    disk = os.path.join(device_dir, disk)
                vdevs.append(disk)
    else:
        vdevs = None
    return vdevs

def present(name, properties=None, filesystem_properties=None, layout=None, config=None):
    log.info('Trace')
    "\n    ensure storage pool is present on the system\n\n    name : string\n        name of storage pool\n    properties : dict\n        optional set of properties to set for the storage pool\n    filesystem_properties : dict\n        optional set of filesystem properties to set for the storage pool (creation only)\n    layout: dict\n        disk layout to use if the pool does not exist (creation only)\n    config : dict\n        fine grain control over this state\n\n    .. note::\n\n        The following configuration properties can be toggled in the config parameter.\n          - import (true) - try to import the pool before creating it if absent\n          - import_dirs (None) - specify additional locations to scan for devices on import (comma-separated)\n          - device_dir (None, SunOS=/dev/dsk, Linux=/dev) - specify device directory to prepend for none\n            absolute device paths\n          - force (false) - try to force the import or creation\n\n    .. note::\n\n        It is no longer needed to give a unique name to each top-level vdev, the old\n        layout format is still supported but no longer recommended.\n\n        .. code-block:: yaml\n\n            - mirror:\n              - /tmp/vdisk3\n              - /tmp/vdisk2\n            - mirror:\n              - /tmp/vdisk0\n              - /tmp/vdisk1\n\n        The above yaml will always result in the following zpool create:\n\n        .. code-block:: bash\n\n            zpool create mypool mirror /tmp/vdisk3 /tmp/vdisk2 mirror /tmp/vdisk0 /tmp/vdisk1\n\n    .. warning::\n\n        The legacy format is also still supported but not recommended,\n        because ID's inside the layout dict must be unique they need to have a suffix.\n\n        .. code-block:: yaml\n\n            mirror-0:\n              /tmp/vdisk3\n              /tmp/vdisk2\n            mirror-1:\n              /tmp/vdisk0\n              /tmp/vdisk1\n\n    .. warning::\n\n        Pay attention to the order of your dict!\n\n        .. code-block:: yaml\n\n            - mirror:\n              - /tmp/vdisk0\n              - /tmp/vdisk1\n            - /tmp/vdisk2\n\n        The above will result in the following zpool create:\n\n        .. code-block:: bash\n\n            zpool create mypool mirror /tmp/vdisk0 /tmp/vdisk1 /tmp/vdisk2\n\n        Creating a 3-way mirror! While you probably expect it to be mirror\n        root vdev with 2 devices + a root vdev of 1 device!\n\n    "
    ret = {'name': name, 'changes': {}, 'result': None, 'comment': ''}
    default_config = {'import': True, 'import_dirs': None, 'device_dir': None, 'force': False}
    if __grains__['kernel'] == 'SunOS':
        default_config['device_dir'] = '/dev/dsk'
    elif __grains__['kernel'] == 'Linux':
        default_config['device_dir'] = '/dev'
    if config:
        default_config.update(config)
    config = default_config
    if properties:
        properties = __utils__['zfs.from_auto_dict'](properties)
    elif properties is None:
        properties = {}
    if filesystem_properties:
        filesystem_properties = __utils__['zfs.from_auto_dict'](filesystem_properties)
    elif filesystem_properties is None:
        filesystem_properties = {}
    vdevs = _layout_to_vdev(layout, config['device_dir'])
    if vdevs:
        vdevs.insert(0, name)
    log.debug('zpool.present::%s::config - %s', name, config)
    log.debug('zpool.present::%s::vdevs - %s', name, vdevs)
    log.debug('zpool.present::%s::properties -  %s', name, properties)
    log.debug('zpool.present::%s::filesystem_properties -  %s', name, filesystem_properties)
    ret['result'] = False
    if __opts__['test']:
        if __salt__['zpool.exists'](name):
            ret['result'] = True
            ret['comment'] = 'storage pool {} is {}'.format(name, 'uptodate')
        else:
            ret['result'] = None
            ret['changes'][name] = 'imported' if config['import'] else 'created'
            ret['comment'] = 'storage pool {} would have been {}'.format(name, ret['changes'][name])
    elif __salt__['zpool.exists'](name):
        log.info('Trace')
        ret['result'] = True
        properties_current = __salt__['zpool.get'](name, parsable=True)
        properties_update = []
        if properties:
            for prop in properties:
                if prop not in properties_current:
                    log.warning('zpool.present::%s::update - unknown property: %s', name, prop)
                    continue
                if properties_current[prop] != properties[prop]:
                    properties_update.append(prop)
        for prop in properties_update:
            res = __salt__['zpool.set'](name, prop, properties[prop])
            if res['set']:
                if name not in ret['changes']:
                    ret['changes'][name] = {}
                ret['changes'][name][prop] = properties[prop]
            else:
                ret['result'] = False
                if ret['comment'] == '':
                    ret['comment'] = 'The following properties were not updated:'
                ret['comment'] = '{} {}'.format(ret['comment'], prop)
        if ret['result']:
            log.info('Trace')
            ret['comment'] = 'properties updated' if ret['changes'] else 'no update needed'
    else:
        if config['import']:
            mod_res = __salt__['zpool.import'](name, force=config['force'], dir=config['import_dirs'])
            ret['result'] = mod_res['imported']
            if ret['result']:
                ret['changes'][name] = 'imported'
                ret['comment'] = 'storage pool {} was imported'.format(name)
        if not ret['result'] and vdevs:
            log.debug('zpool.present::%s::creating', name)
            mod_res = __salt__['zpool.create'](*vdevs, force=config['force'], properties=properties, filesystem_properties=filesystem_properties)
            ret['result'] = mod_res['created']
            if ret['result']:
                log.info('Trace')
                ret['changes'][name] = 'created'
                ret['comment'] = 'storage pool {} was created'.format(name)
            elif 'error' in mod_res:
                ret['comment'] = mod_res['error']
            else:
                ret['comment'] = 'could not create storage pool {}'.format(name)
        if not ret['result'] and (not vdevs):
            ret['comment'] = 'storage pool {} was not imported, no (valid) layout specified for creation'.format(name)
    return ret

def absent(name, export=False, force=False):
    """
    ensure storage pool is absent on the system

    name : string
        name of storage pool
    export : boolean
        export instead of destroy the zpool if present
    force : boolean
        force destroy or export

    """
    ret = {'name': name, 'changes': {}, 'result': None, 'comment': ''}
    log.debug('zpool.absent::%s::config::force = %s', name, force)
    log.debug('zpool.absent::%s::config::export = %s', name, export)
    if __salt__['zpool.exists'](name):
        log.info('Trace')
        mod_res = {}
        ret['result'] = False
        if __opts__['test']:
            ret['result'] = True
        elif export:
            mod_res = __salt__['zpool.export'](name, force=force)
            ret['result'] = mod_res['exported']
        else:
            mod_res = __salt__['zpool.destroy'](name, force=force)
            ret['result'] = mod_res['destroyed']
        if ret['result']:
            ret['changes'][name] = 'exported' if export else 'destroyed'
            ret['comment'] = 'storage pool {} was {}'.format(name, ret['changes'][name])
        elif 'error' in mod_res:
            ret['comment'] = mod_res['error']
    else:
        log.info('Trace')
        ret['result'] = True
        ret['comment'] = 'storage pool {} is absent'.format(name)
    return ret