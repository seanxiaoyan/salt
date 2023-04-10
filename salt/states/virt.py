"""
Manage virt
===========

For the key certificate this state uses the external pillar in the master to call
for the generation and signing of certificates for systems running libvirt:

.. code-block:: yaml

    libvirt_keys:
      virt.keys
"""
import fnmatch
import logging
import os
import salt.utils.args
import salt.utils.files
import salt.utils.stringutils
import salt.utils.versions
from salt.exceptions import CommandExecutionError, SaltInvocationError
log = logging.getLogger(__name__)
try:
    import libvirt
    HAS_LIBVIRT = True
except ImportError:
    HAS_LIBVIRT = False
__virtualname__ = 'virt'

def __virtual__():
    """
    Only if virt module is available.

    :return:
    """
    if 'virt.node_info' in __salt__:
        return __virtualname__
    return (False, 'virt module could not be loaded')

def keys(name, basepath='/etc/pki', **kwargs):
    """
    Manage libvirt keys.

    name
        The name variable used to track the execution

    basepath
        Defaults to ``/etc/pki``, this is the root location used for libvirt
        keys on the hypervisor

    The following parameters are optional:

        country
            The country that the certificate should use.  Defaults to US.

        .. versionadded:: 2018.3.0

        state
            The state that the certificate should use.  Defaults to Utah.

        .. versionadded:: 2018.3.0

        locality
            The locality that the certificate should use.
            Defaults to Salt Lake City.

        .. versionadded:: 2018.3.0

        organization
            The organization that the certificate should use.
            Defaults to Salted.

        .. versionadded:: 2018.3.0

        expiration_days
            The number of days that the certificate should be valid for.
            Defaults to 365 days (1 year)

        .. versionadded:: 2018.3.0

    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    pillar_kwargs = {}
    for (key, value) in kwargs.items():
        pillar_kwargs['ext_pillar_virt.{}'.format(key)] = value
    pillar = __salt__['pillar.ext']({'libvirt': '_'}, pillar_kwargs)
    paths = {'serverkey': os.path.join(basepath, 'libvirt', 'private', 'serverkey.pem'), 'servercert': os.path.join(basepath, 'libvirt', 'servercert.pem'), 'clientkey': os.path.join(basepath, 'libvirt', 'private', 'clientkey.pem'), 'clientcert': os.path.join(basepath, 'libvirt', 'clientcert.pem'), 'cacert': os.path.join(basepath, 'CA', 'cacert.pem')}
    for key in paths:
        p_key = 'libvirt.{}.pem'.format(key)
        if p_key not in pillar:
            continue
        if not os.path.exists(os.path.dirname(paths[key])):
            os.makedirs(os.path.dirname(paths[key]))
        if os.path.isfile(paths[key]):
            with salt.utils.files.fopen(paths[key], 'r') as fp_:
                if salt.utils.stringutils.to_unicode(fp_.read()) != pillar[p_key]:
                    ret['changes'][key] = 'update'
        else:
            ret['changes'][key] = 'new'
    if not ret['changes']:
        ret['comment'] = 'All keys are correct'
    elif __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Libvirt keys are set to be updated'
        ret['changes'] = {}
    else:
        for key in ret['changes']:
            with salt.utils.files.fopen(paths[key], 'w+') as fp_:
                fp_.write(salt.utils.stringutils.to_str(pillar['libvirt.{}.pem'.format(key)]))
        ret['comment'] = 'Updated libvirt certs and keys'
    return ret

def _virt_call(domain, function, section, comment, state=None, connection=None, username=None, password=None, **kwargs):
    log.info('Trace')
    "\n    Helper to call the virt functions. Wildcards supported.\n\n    :param domain: the domain to apply the function on. Can contain wildcards.\n    :param function: virt function to call\n    :param section: key for the changed domains in the return changes dictionary\n    :param comment: comment to return\n    :param state: the expected final state of the VM. If None the VM state won't be checked.\n    :return: the salt state return\n    "
    result = True if not __opts__['test'] else None
    ret = {'name': domain, 'changes': {}, 'result': result, 'comment': ''}
    targeted_domains = fnmatch.filter(__salt__['virt.list_domains'](), domain)
    changed_domains = list()
    ignored_domains = list()
    noaction_domains = list()
    for targeted_domain in targeted_domains:
        try:
            log.info('Trace')
            action_needed = True
            if state is not None:
                domain_state = __salt__['virt.vm_state'](targeted_domain)
                action_needed = domain_state.get(targeted_domain) != state
            if action_needed:
                response = True
                if not __opts__['test']:
                    response = __salt__['virt.{}'.format(function)](targeted_domain, connection=connection, username=username, password=password, **kwargs)
                    if isinstance(response, dict):
                        response = response['name']
                changed_domains.append({'domain': targeted_domain, function: response})
            else:
                noaction_domains.append(targeted_domain)
        except libvirt.libvirtError as err:
            log.info('Trace')
            ignored_domains.append({'domain': targeted_domain, 'issue': str(err)})
    if not changed_domains:
        ret['result'] = not ignored_domains and bool(targeted_domains)
        ret['comment'] = 'No changes had happened'
        if ignored_domains:
            ret['changes'] = {'ignored': ignored_domains}
    else:
        ret['changes'] = {section: changed_domains}
        ret['comment'] = comment
    return ret

def stopped(name, connection=None, username=None, password=None):
    """
    Stops a VM by shutting it down nicely.

    .. versionadded:: 2016.3.0

    :param connection: libvirt connection URI, overriding defaults

        .. versionadded:: 2019.2.0
    :param username: username to connect with, overriding defaults

        .. versionadded:: 2019.2.0
    :param password: password to connect with, overriding defaults

        .. versionadded:: 2019.2.0

    .. code-block:: yaml

        domain_name:
          virt.stopped
    """
    return _virt_call(name, 'shutdown', 'stopped', 'Machine has been shut down', state='shutdown', connection=connection, username=username, password=password)

def powered_off(name, connection=None, username=None, password=None):
    """
    Stops a VM by power off.

    .. versionadded:: 2016.3.0

    :param connection: libvirt connection URI, overriding defaults

        .. versionadded:: 2019.2.0
    :param username: username to connect with, overriding defaults

        .. versionadded:: 2019.2.0
    :param password: password to connect with, overriding defaults

        .. versionadded:: 2019.2.0

    .. code-block:: yaml

        domain_name:
          virt.stopped
    """
    return _virt_call(name, 'stop', 'unpowered', 'Machine has been powered off', state='shutdown', connection=connection, username=username, password=password)

def defined(name, cpu=None, mem=None, vm_type=None, disk_profile=None, disks=None, nic_profile=None, interfaces=None, graphics=None, seed=True, install=True, pub_key=None, priv_key=None, connection=None, username=None, password=None, os_type=None, arch=None, boot=None, numatune=None, boot_dev=None, hypervisor_features=None, clock=None, serials=None, consoles=None, stop_on_reboot=False, live=True, host_devices=None):
    log.info('Trace')
    '\n    Starts an existing guest, or defines and starts a new VM with specified arguments.\n\n    .. versionadded:: 3001\n\n    :param name: name of the virtual machine to run\n    :param cpu:\n        Number of virtual CPUs to assign to the virtual machine or a dictionary with detailed information to configure\n        cpu model and topology, numa node tuning, cpu tuning and iothreads allocation. The structure of the dictionary is\n        documented in :ref:`init-cpu-def`.\n\n        .. code-block:: yaml\n\n             cpu:\n               placement: static\n               cpuset: 0-11\n               current: 5\n               maximum: 12\n               vcpus:\n                 0:\n                   enabled: \'yes\'\n                   hotpluggable: \'no\'\n                   order: 1\n                 1:\n                   enabled: \'no\'\n                   hotpluggable: \'yes\'\n               match: minimum\n               mode: custom\n               check: full\n               vendor: Intel\n               model:\n                 name: core2duo\n                 fallback: allow\n                 vendor_id: GenuineIntel\n               topology:\n                 sockets: 1\n                 cores: 12\n                 threads: 1\n               cache:\n                 level: 3\n                 mode: emulate\n               feature:\n                 policy: optional\n                 name: lahf_lm\n               numa:\n                 0:\n                    cpus: 0-3\n                    memory: 1g\n                    discard: \'yes\'\n                    distances:\n                      0: 10     # sibling id : value\n                      1: 21\n                      2: 31\n                      3: 41\n                 1:\n                    cpus: 4-6\n                    memory: 1g\n                    memAccess: shared\n                    distances:\n                      0: 21\n                      1: 10\n                      2: 21\n                      3: 31\n               tuning:\n                    vcpupin:\n                      0: 1-4,^2  # vcpuid : cpuset\n                      1: 0,1\n                      2: 2,3\n                      3: 0,4\n                    emulatorpin: 1-3\n                    iothreadpin:\n                      1: 5,6    # iothread id: cpuset\n                      2: 7,8\n                    shares: 2048\n                    period: 1000000\n                    quota: -1\n                    global_period: 1000000\n                    global_quota: -1\n                    emulator_period: 1000000\n                    emulator_quota: -1\n                    iothread_period: 1000000\n                    iothread_quota: -1\n                    vcpusched:\n                      - scheduler: fifo\n                        priority: 1\n                      - scheduler: fifo\n                        priority: 2\n                        vcpus: 1-3\n                      - scheduler: rr\n                        priority: 3\n                        vcpus: 4\n                    iothreadsched:\n                      - scheduler: batch\n                        iothreads: 2\n                    emulatorsched:\n                      scheduler: idle\n                    cachetune:\n                      0-3:      # vcpus set\n                        0:      # cache id\n                          level: 3\n                          type: both\n                          size: 4\n                        1:\n                          level: 3\n                          type: both\n                          size: 6\n                        monitor:\n                          1: 3\n                          0-3: 3\n                      4-5:\n                        monitor:\n                          4: 3  # vcpus: level\n                          5: 3\n                    memorytune:\n                      0-3:      # vcpus set\n                        0: 60   # node id: bandwidth\n                      4-5:\n                        0: 60\n               iothreads: 4\n\n        .. versionadded:: 3003\n\n    :param mem: Amount of memory to allocate to the virtual machine in MiB. Since 3002, a dictionary can be used to\n        contain detailed configuration which support memory allocation or tuning. Supported parameters are ``boot``,\n        ``current``, ``max``, ``slots``, ``hard_limit``, ``soft_limit``, ``swap_hard_limit``, ``min_guarantee``,\n        ``hugepages`` ,  ``nosharepages``, ``locked``, ``source``, ``access``, ``allocation`` and ``discard``. The structure\n        of the dictionary is documented in  :ref:`init-mem-def`. Both decimal and binary base are supported. Detail unit\n        specification is documented  in :ref:`virt-units`. Please note that the value for ``slots`` must be an integer.\n\n        .. code-block:: yaml\n\n            boot: 1g\n            current: 1g\n            max: 1g\n            slots: 10\n            hard_limit: 1024\n            soft_limit: 512m\n            swap_hard_limit: 1g\n            min_guarantee: 512mib\n            hugepages:\n              - size: 2m\n              - nodeset: 0-2\n                size: 1g\n              - nodeset: 3\n                size: 2g\n            nosharepages: True\n            locked: True\n            source: file\n            access: shared\n            allocation: immediate\n            discard: True\n\n        .. versionchanged:: 3002\n\n    :param vm_type: force virtual machine type for the new VM. The default value is taken from\n        the host capabilities. This could be useful for example to use ``\'qemu\'`` type instead\n        of the ``\'kvm\'`` one.\n    :param disk_profile:\n        Name of the disk profile to use for the new virtual machine\n    :param disks:\n        List of disk to create for the new virtual machine.\n        See :ref:`init-disk-def` for more details on the items on this list.\n    :param nic_profile:\n        Name of the network interfaces profile to use for the new virtual machine\n    :param interfaces:\n        List of network interfaces to create for the new virtual machine.\n        See :ref:`init-nic-def` for more details on the items on this list.\n    :param graphics:\n        Graphics device to create for the new virtual machine.\n        See :ref:`init-graphics-def` for more details on this dictionary\n    :param saltenv:\n        Fileserver environment (Default: ``\'base\'``).\n        See :mod:`cp module for more details <salt.modules.cp>`\n    :param seed: ``True`` to seed the disk image. Only used when the ``image`` parameter is provided.\n                 (Default: ``True``)\n    :param install: install salt minion if absent (Default: ``True``)\n    :param pub_key: public key to seed with (Default: ``None``)\n    :param priv_key: public key to seed with (Default: ``None``)\n    :param seed_cmd: Salt command to execute to seed the image. (Default: ``\'seed.apply\'``)\n    :param connection: libvirt connection URI, overriding defaults\n    :param username: username to connect with, overriding defaults\n    :param password: password to connect with, overriding defaults\n    :param os_type:\n        type of virtualization as found in the ``//os/type`` element of the libvirt definition.\n        The default value is taken from the host capabilities, with a preference for ``hvm``.\n        Only used when creating a new virtual machine.\n    :param arch:\n        architecture of the virtual machine. The default value is taken from the host capabilities,\n        but ``x86_64`` is prefed over ``i686``. Only used when creating a new virtual machine.\n\n    :param boot:\n        Specifies kernel, initial ramdisk and kernel command line parameters for the virtual machine.\n        This is an optional parameter, all of the keys are optional within the dictionary.\n\n        Refer to :ref:`init-boot-def` for the complete boot parameters description.\n\n        To update any boot parameters, specify the new path for each. To remove any boot parameters,\n        pass a None object, for instance: \'kernel\': ``None``.\n\n        .. versionadded:: 3000\n\n    :param boot_dev:\n        Space separated list of devices to boot from sorted by decreasing priority.\n        Values can be ``hd``, ``fd``, ``cdrom`` or ``network``.\n\n        By default, the value will ``"hd"``.\n\n        .. versionadded:: 3002\n\n    :param numatune:\n        The optional numatune element provides details of how to tune the performance of a NUMA host via controlling NUMA\n        policy for domain process. The optional ``memory`` element specifies how to allocate memory for the domain process\n        on a NUMA host. ``memnode`` elements can specify memory allocation policies per each guest NUMA node. The definition\n        used in the dictionary can be found at :ref:`init-cpu-def`.\n\n        .. versionadded:: 3003\n\n        .. code-block:: python\n\n            {\n                \'memory\': {\'mode\': \'strict\', \'nodeset\': \'0-11\'},\n                \'memnodes\': {0: {\'mode\': \'strict\', \'nodeset\': 1}, 1: {\'mode\': \'preferred\', \'nodeset\': 2}}\n            }\n\n    :param hypervisor_features:\n        Enable or disable hypervisor-specific features on the virtual machine.\n\n        .. versionadded:: 3003\n\n        .. code-block:: yaml\n\n            hypervisor_features:\n              kvm-hint-dedicated: True\n\n    :param clock:\n        Configure the guest clock.\n        The value is a dictionary with the following keys:\n\n        adjustment\n            time adjustment in seconds or ``reset``\n\n        utc\n            set to ``False`` to use the host local time as the guest clock. Defaults to ``True``.\n\n        timezone\n            synchronize the guest to the correspding timezone\n\n        timers\n            a dictionary associating the timer name with its configuration.\n            This configuration is a dictionary with the properties ``track``, ``tickpolicy``,\n            ``catchup``, ``frequency``, ``mode``, ``present``, ``slew``, ``threshold`` and ``limit``.\n            See `libvirt time keeping documentation <https://libvirt.org/formatdomain.html#time-keeping>`_ for the possible values.\n\n        .. versionadded:: 3003\n\n        Set the clock to local time using an offset in seconds\n        .. code-block:: yaml\n\n            clock:\n              adjustment: 3600\n              utc: False\n\n        Set the clock to a specific time zone:\n\n        .. code-block:: yaml\n\n            clock:\n              timezone: CEST\n\n    :param serials:\n        Dictionary providing details on the serials connection to create. (Default: ``None``)\n        See :ref:`init-chardevs-def` for more details on the possible values.\n\n        .. versionadded:: 3003\n    :param consoles:\n        Dictionary providing details on the consoles device to create. (Default: ``None``)\n        See :ref:`init-chardevs-def` for more details on the possible values.\n\n        .. versionadded:: 3003\n\n    :param stop_on_reboot:\n        If set to ``True`` the guest will stop instead of rebooting.\n        This is specially useful when creating a virtual machine with an installation cdrom or\n        an autoinstallation needing a special first boot configuration.\n        Defaults to ``False``\n\n        .. versionadded:: 3003\n\n    :param live:\n        If set to ``False`` the changes will not be applied live to the running instance, but will\n        only apply at the next start. Note that reboot will not take those changes.\n\n        .. versionadded:: 3003\n\n    :param host_devices:\n        List of host devices to passthrough to the guest.\n        The value is a list of device names as provided by the :py:func:`~salt.modules.virt.node_devices` function.\n        (Default: ``None``)\n\n        .. versionadded:: 3003\n\n    .. rubric:: Example States\n\n    Make sure a virtual machine called ``domain_name`` is defined:\n\n    .. code-block:: yaml\n\n        domain_name:\n          virt.defined:\n            - cpu: 2\n            - mem: 2048\n            - boot_dev: network hd\n            - disk_profile: prod\n            - disks:\n              - name: system\n                size: 8192\n                overlay_image: True\n                pool: default\n                image: /path/to/image.qcow2\n              - name: data\n                size: 16834\n            - nic_profile: prod\n            - interfaces:\n              - name: eth0\n                mac: 01:23:45:67:89:AB\n              - name: eth1\n                type: network\n                source: admin\n            - graphics:\n                type: spice\n                listen:\n                    type: address\n                    address: 192.168.0.125\n\n    '
    ret = {'name': name, 'changes': {}, 'result': True if not __opts__['test'] else None, 'comment': ''}
    try:
        log.info('Trace')
        if name in __salt__['virt.list_domains'](connection=connection, username=username, password=password):
            status = __salt__['virt.update'](name, cpu=cpu, mem=mem, disk_profile=disk_profile, disks=disks, nic_profile=nic_profile, interfaces=interfaces, graphics=graphics, live=live, connection=connection, username=username, password=password, boot=boot, numatune=numatune, serials=serials, consoles=consoles, test=__opts__['test'], boot_dev=boot_dev, hypervisor_features=hypervisor_features, clock=clock, stop_on_reboot=stop_on_reboot, host_devices=host_devices)
            ret['changes'][name] = status
            if not status.get('definition'):
                ret['changes'] = {}
                ret['comment'] = 'Domain {} unchanged'.format(name)
                ret['result'] = True
            elif status.get('errors'):
                ret['comment'] = 'Domain {} updated with live update(s) failures'.format(name)
            else:
                ret['comment'] = 'Domain {} updated'.format(name)
        else:
            if not __opts__['test']:
                __salt__['virt.init'](name, cpu=cpu, mem=mem, os_type=os_type, arch=arch, hypervisor=vm_type, disk=disk_profile, disks=disks, nic=nic_profile, interfaces=interfaces, graphics=graphics, seed=seed, install=install, pub_key=pub_key, priv_key=priv_key, connection=connection, username=username, password=password, boot=boot, numatune=numatune, serials=serials, consoles=consoles, start=False, boot_dev=boot_dev, hypervisor_features=hypervisor_features, clock=clock, stop_on_reboot=stop_on_reboot, host_devices=host_devices)
            ret['changes'][name] = {'definition': True}
            ret['comment'] = 'Domain {} defined'.format(name)
    except libvirt.libvirtError as err:
        log.info('Trace')
        ret['comment'] = str(err)
        ret['result'] = False
    return ret

def running(name, cpu=None, mem=None, vm_type=None, disk_profile=None, disks=None, nic_profile=None, interfaces=None, graphics=None, seed=True, install=True, pub_key=None, priv_key=None, connection=None, username=None, password=None, os_type=None, arch=None, boot=None, boot_dev=None, numatune=None, hypervisor_features=None, clock=None, serials=None, consoles=None, stop_on_reboot=False, host_devices=None):
    log.info('Trace')
    '\n    Starts an existing guest, or defines and starts a new VM with specified arguments.\n\n    .. versionadded:: 2016.3.0\n\n    :param name: name of the virtual machine to run\n    :param cpu:\n        Number of virtual CPUs to assign to the virtual machine or a dictionary with detailed information to configure\n        cpu model and topology, numa node tuning, cpu tuning and iothreads allocation. The structure of the dictionary is\n        documented in :ref:`init-cpu-def`.\n\n        To update any cpu parameters specify the new values to the corresponding tag. To remove any element or attribute,\n        specify ``None`` object. Please note that ``None`` object is mapped to ``null`` in yaml, use ``null`` in sls file\n        instead.\n    :param mem: Amount of memory to allocate to the virtual machine in MiB. Since 3002, a dictionary can be used to\n        contain detailed configuration which support memory allocation or tuning. Supported parameters are ``boot``,\n        ``current``, ``max``, ``slots``, ``hard_limit``, ``soft_limit``, ``swap_hard_limit``, ``min_guarantee``,\n        ``hugepages`` ,  ``nosharepages``, ``locked``, ``source``, ``access``, ``allocation`` and ``discard``. The structure\n        of the dictionary is documented in  :ref:`init-mem-def`. Both decimal and binary base are supported. Detail unit\n        specification is documented  in :ref:`virt-units`. Please note that the value for ``slots`` must be an integer.\n\n        To remove any parameters, pass a None object, for instance: \'soft_limit\': ``None``. Please note  that ``None``\n        is mapped to ``null`` in sls file, pass ``null`` in sls file instead.\n\n        .. code-block:: yaml\n\n            - mem:\n                hard_limit: null\n                soft_limit: null\n\n        .. versionchanged:: 3002\n    :param vm_type: force virtual machine type for the new VM. The default value is taken from\n        the host capabilities. This could be useful for example to use ``\'qemu\'`` type instead\n        of the ``\'kvm\'`` one.\n\n        .. versionadded:: 2019.2.0\n    :param disk_profile:\n        Name of the disk profile to use for the new virtual machine\n\n        .. versionadded:: 2019.2.0\n    :param disks:\n        List of disk to create for the new virtual machine.\n        See :ref:`init-disk-def` for more details on the items on this list.\n\n        .. versionadded:: 2019.2.0\n    :param nic_profile:\n        Name of the network interfaces profile to use for the new virtual machine\n\n        .. versionadded:: 2019.2.0\n    :param interfaces:\n        List of network interfaces to create for the new virtual machine.\n        See :ref:`init-nic-def` for more details on the items on this list.\n\n        .. versionadded:: 2019.2.0\n    :param graphics:\n        Graphics device to create for the new virtual machine.\n        See :ref:`init-graphics-def` for more details on this dictionary\n\n        .. versionadded:: 2019.2.0\n    :param saltenv:\n        Fileserver environment (Default: ``\'base\'``).\n        See :mod:`cp module for more details <salt.modules.cp>`\n\n        .. versionadded:: 2019.2.0\n    :param seed: ``True`` to seed the disk image. Only used when the ``image`` parameter is provided.\n                 (Default: ``True``)\n\n        .. versionadded:: 2019.2.0\n    :param install: install salt minion if absent (Default: ``True``)\n\n        .. versionadded:: 2019.2.0\n    :param pub_key: public key to seed with (Default: ``None``)\n\n        .. versionadded:: 2019.2.0\n    :param priv_key: public key to seed with (Default: ``None``)\n\n        .. versionadded:: 2019.2.0\n    :param seed_cmd: Salt command to execute to seed the image. (Default: ``\'seed.apply\'``)\n\n        .. versionadded:: 2019.2.0\n    :param connection: libvirt connection URI, overriding defaults\n\n        .. versionadded:: 2019.2.0\n    :param username: username to connect with, overriding defaults\n\n        .. versionadded:: 2019.2.0\n    :param password: password to connect with, overriding defaults\n\n        .. versionadded:: 2019.2.0\n    :param os_type:\n        type of virtualization as found in the ``//os/type`` element of the libvirt definition.\n        The default value is taken from the host capabilities, with a preference for ``hvm``.\n        Only used when creating a new virtual machine.\n\n        .. versionadded:: 3000\n    :param arch:\n        architecture of the virtual machine. The default value is taken from the host capabilities,\n        but ``x86_64`` is prefed over ``i686``. Only used when creating a new virtual machine.\n\n        .. versionadded:: 3000\n\n    :param boot:\n        Specifies kernel, initial ramdisk and kernel command line parameters for the virtual machine.\n        This is an optional parameter, all of the keys are optional within the dictionary.\n\n        Refer to :ref:`init-boot-def` for the complete boot parameters description.\n\n        To update any boot parameters, specify the new path for each. To remove any boot parameters,\n        pass a None object, for instance: \'kernel\': ``None``.\n\n        .. versionadded:: 3000\n    :param serials:\n        Dictionary providing details on the serials connection to create. (Default: ``None``)\n        See :ref:`init-chardevs-def` for more details on the possible values.\n\n        .. versionadded:: 3003\n    :param consoles:\n        Dictionary providing details on the consoles device to create. (Default: ``None``)\n        See :ref:`init-chardevs-def` for more details on the possible values.\n\n        .. versionadded:: 3003\n\n    :param boot_dev:\n        Space separated list of devices to boot from sorted by decreasing priority.\n        Values can be ``hd``, ``fd``, ``cdrom`` or ``network``.\n\n        By default, the value will ``"hd"``.\n\n        .. versionadded:: 3002\n\n    :param numatune:\n        The optional numatune element provides details of how to tune the performance of a NUMA host via controlling NUMA\n        policy for domain process. The optional ``memory`` element specifies how to allocate memory for the domain process\n        on a NUMA host. ``memnode`` elements can specify memory allocation policies per each guest NUMA node. The definition\n        used in the dictionary can be found at :ref:`init-cpu-def`.\n\n        To update any numatune parameters, specify the new value. To remove any ``numatune`` parameters, pass a None object,\n        for instance: \'numatune\': ``None``. Please note that ``None`` is mapped to ``null`` in sls file, pass ``null`` in\n        sls file instead.\n\n        .. versionadded:: 3003\n\n    :param stop_on_reboot:\n        If set to ``True`` the guest will stop instead of rebooting.\n        This is specially useful when creating a virtual machine with an installation cdrom or\n        an autoinstallation needing a special first boot configuration.\n        Defaults to ``False``\n\n        .. versionadded:: 3003\n\n    :param hypervisor_features:\n        Enable or disable hypervisor-specific features on the virtual machine.\n\n        .. versionadded:: 3003\n\n        .. code-block:: yaml\n\n            hypervisor_features:\n              kvm-hint-dedicated: True\n\n    :param clock:\n        Configure the guest clock.\n        The value is a dictionary with the following keys:\n\n        adjustment\n            time adjustment in seconds or ``reset``\n\n        utc\n            set to ``False`` to use the host local time as the guest clock. Defaults to ``True``.\n\n        timezone\n            synchronize the guest to the correspding timezone\n\n        timers\n            a dictionary associating the timer name with its configuration.\n            This configuration is a dictionary with the properties ``track``, ``tickpolicy``,\n            ``catchup``, ``frequency``, ``mode``, ``present``, ``slew``, ``threshold`` and ``limit``.\n            See `libvirt time keeping documentation <https://libvirt.org/formatdomain.html#time-keeping>`_ for the possible values.\n\n        .. versionadded:: 3003\n\n        Set the clock to local time using an offset in seconds\n        .. code-block:: yaml\n\n            clock:\n              adjustment: 3600\n              utc: False\n\n        Set the clock to a specific time zone:\n\n        .. code-block:: yaml\n\n            clock:\n              timezone: CEST\n\n    :param host_devices:\n        List of host devices to passthrough to the guest.\n        The value is a list of device names as provided by the :py:func:`~salt.modules.virt.node_devices` function.\n        (Default: ``None``)\n\n        .. versionadded:: 3003\n\n    .. rubric:: Example States\n\n    Make sure an already-defined virtual machine called ``domain_name`` is running:\n\n    .. code-block:: yaml\n\n        domain_name:\n          virt.running\n\n    Do the same, but define the virtual machine if needed:\n\n    .. code-block:: yaml\n\n        domain_name:\n          virt.running:\n            - cpu: 2\n            - mem: 2048\n            - disk_profile: prod\n            - boot_dev: network hd\n            - disks:\n              - name: system\n                size: 8192\n                overlay_image: True\n                pool: default\n                image: /path/to/image.qcow2\n              - name: data\n                size: 16834\n            - nic_profile: prod\n            - interfaces:\n              - name: eth0\n                mac: 01:23:45:67:89:AB\n              - name: eth1\n                type: network\n                source: admin\n            - graphics:\n                type: spice\n                listen:\n                    type: address\n                    address: 192.168.0.125\n\n    '
    merged_disks = disks
    ret = defined(name, cpu=cpu, mem=mem, vm_type=vm_type, disk_profile=disk_profile, disks=merged_disks, nic_profile=nic_profile, interfaces=interfaces, graphics=graphics, seed=seed, install=install, pub_key=pub_key, priv_key=priv_key, os_type=os_type, arch=arch, boot=boot, boot_dev=boot_dev, numatune=numatune, hypervisor_features=hypervisor_features, clock=clock, stop_on_reboot=stop_on_reboot, connection=connection, username=username, password=password, serials=serials, consoles=consoles, host_devices=host_devices)
    result = True if not __opts__['test'] else None
    if ret['result'] is None or ret['result']:
        changed = ret['changes'].get(name, {}).get('definition', False)
        try:
            log.info('Trace')
            domain_state = __salt__['virt.vm_state'](name)
            if domain_state.get(name) != 'running':
                if not __opts__['test']:
                    __salt__['virt.start'](name, connection=connection, username=username, password=password)
                comment = 'Domain {} started'.format(name)
                if not ret['comment'].endswith('unchanged'):
                    comment = '{} and started'.format(ret['comment'])
                ret['comment'] = comment
                if name not in ret['changes']:
                    ret['changes'][name] = {}
                ret['changes'][name]['started'] = True
            elif not changed:
                ret['comment'] = 'Domain {} exists and is running'.format(name)
        except libvirt.libvirtError as err:
            log.info('Trace')
            ret['comment'] = str(err)
            ret['result'] = False
    return ret

def snapshot(name, suffix=None, connection=None, username=None, password=None):
    """
    Takes a snapshot of a particular VM or by a UNIX-style wildcard.

    .. versionadded:: 2016.3.0

    :param connection: libvirt connection URI, overriding defaults

        .. versionadded:: 2019.2.0
    :param username: username to connect with, overriding defaults

        .. versionadded:: 2019.2.0
    :param password: password to connect with, overriding defaults

        .. versionadded:: 2019.2.0

    .. code-block:: yaml

        domain_name:
          virt.snapshot:
            - suffix: periodic

        domain*:
          virt.snapshot:
            - suffix: periodic
    """
    return _virt_call(name, 'snapshot', 'saved', 'Snapshot has been taken', suffix=suffix, connection=connection, username=username, password=password)

def rebooted(name, connection=None, username=None, password=None):
    """
    Reboots VMs

    .. versionadded:: 2016.3.0

    :param name:

    :param connection: libvirt connection URI, overriding defaults

        .. versionadded:: 2019.2.0
    :param username: username to connect with, overriding defaults

        .. versionadded:: 2019.2.0
    :param password: password to connect with, overriding defaults

        .. versionadded:: 2019.2.0
    """
    return _virt_call(name, 'reboot', 'rebooted', 'Machine has been rebooted', connection=connection, username=username, password=password)

def unpowered(name):
    """
    .. deprecated:: 2016.3.0
       Use :py:func:`~salt.modules.virt.powered_off` instead.

    Stops a VM by power off.

    .. versionadded:: 2016.3.0

    .. code-block:: yaml

        domain_name:
          virt.stopped
    """
    return _virt_call(name, 'stop', 'unpowered', 'Machine has been powered off')

def saved(name, suffix=None):
    """
    .. deprecated:: 2016.3.0
       Use :py:func:`~salt.modules.virt.snapshot` instead.

    Takes a snapshot of a particular VM or by a UNIX-style wildcard.

    .. versionadded:: 2016.3.0

    .. code-block:: yaml

        domain_name:
          virt.saved:
            - suffix: periodic

        domain*:
          virt.saved:
            - suffix: periodic
    """
    return _virt_call(name, 'snapshot', 'saved', 'Snapshots has been taken', suffix=suffix)

def reverted(name, snapshot=None, cleanup=False):
    log.info('Trace')
    '\n    .. deprecated:: 2016.3.0\n\n    Reverts to the particular snapshot.\n\n    .. versionadded:: 2016.3.0\n\n    .. code-block:: yaml\n\n        domain_name:\n          virt.reverted:\n            - cleanup: True\n\n        domain_name_1:\n          virt.reverted:\n            - snapshot: snapshot_name\n            - cleanup: False\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    try:
        log.info('Trace')
        domains = fnmatch.filter(__salt__['virt.list_domains'](), name)
        if not domains:
            ret['comment'] = 'No domains found for criteria "{}"'.format(name)
        else:
            ignored_domains = list()
            if len(domains) > 1:
                ret['changes'] = {'reverted': list()}
            for domain in domains:
                result = {}
                try:
                    log.info('Trace')
                    result = __salt__['virt.revert_snapshot'](domain, snapshot=snapshot, cleanup=cleanup)
                    result = {'domain': domain, 'current': result['reverted'], 'deleted': result['deleted']}
                except CommandExecutionError as err:
                    log.info('Trace')
                    if len(domains) > 1:
                        ignored_domains.append({'domain': domain, 'issue': str(err)})
                if len(domains) > 1:
                    if result:
                        ret['changes']['reverted'].append(result)
                else:
                    ret['changes'] = result
                    break
            ret['result'] = len(domains) != len(ignored_domains)
            if ret['result']:
                ret['comment'] = 'Domain{} has been reverted'.format(len(domains) > 1 and 's' or '')
            if ignored_domains:
                ret['changes']['ignored'] = ignored_domains
            if not ret['changes']['reverted']:
                ret['changes'].pop('reverted')
    except libvirt.libvirtError as err:
        log.info('Trace')
        ret['comment'] = str(err)
    except CommandExecutionError as err:
        log.info('Trace')
        ret['comment'] = str(err)
    return ret

def network_defined(name, bridge, forward, vport=None, tag=None, ipv4_config=None, ipv6_config=None, autostart=True, connection=None, username=None, password=None, mtu=None, domain=None, nat=None, interfaces=None, addresses=None, physical_function=None, dns=None):
    log.info('Trace')
    '\n    Defines a new network with specified arguments.\n\n    :param name: Network name\n    :param bridge: Bridge name\n    :param forward: Forward mode(bridge, router, nat)\n\n        .. versionchanged:: 3003\n           a ``None`` value creates an isolated network with no forwarding at all\n\n    :param vport: Virtualport type (Default: ``\'None\'``)\n        The value can also be a dictionary with ``type`` and ``parameters`` keys.\n        The ``parameters`` value is a dictionary of virtual port parameters.\n\n        .. code-block:: yaml\n\n          - vport:\n              type: openvswitch\n              parameters:\n                interfaceid: 09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f\n\n        .. versionchanged:: 3003\n           possible dictionary value\n\n    :param tag: Vlan tag (Default: ``\'None\'``)\n        The value can also be a dictionary with the ``tags`` and optional ``trunk`` keys.\n        ``trunk`` is a boolean value indicating whether to use VLAN trunking.\n        ``tags`` is a list of dictionaries with keys ``id`` and ``nativeMode``.\n        The ``nativeMode`` value can be one of ``tagged`` or ``untagged``.\n\n        .. code-block:: yaml\n\n          - tag:\n              trunk: True\n              tags:\n                - id: 42\n                  nativeMode: untagged\n                - id: 47\n\n        .. versionchanged:: 3003\n           possible dictionary value\n\n    :param ipv4_config:\n        IPv4 network configuration. See the\n        :py:func:`virt.network_define <salt.modules.virt.network_define>`\n        function corresponding parameter documentation\n        for more details on this dictionary.\n        (Default: None).\n    :param ipv6_config:\n        IPv6 network configuration. See the :py:func:`virt.network_define\n        <salt.modules.virt.network_define>` function corresponding parameter documentation\n        for more details on this dictionary.\n        (Default: None).\n    :param autostart: Network autostart (default ``\'True\'``)\n    :param connection: libvirt connection URI, overriding defaults\n    :param username: username to connect with, overriding defaults\n    :param password: password to connect with, overriding defaults\n    :param mtu: size of the Maximum Transmission Unit (MTU) of the network.\n        (default ``None``)\n\n        .. versionadded:: 3003\n\n    :param domain: DNS domain name of the DHCP server.\n        The value is a dictionary with a mandatory ``name`` property and an optional ``localOnly`` boolean one.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - domain:\n              name: lab.acme.org\n              localOnly: True\n\n        .. versionadded:: 3003\n\n    :param nat: addresses and ports to route in NAT forward mode.\n        The value is a dictionary with optional keys ``address`` and ``port``.\n        Both values are a dictionary with ``start`` and ``end`` values.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: nat\n          - nat:\n              address:\n                start: 1.2.3.4\n                end: 1.2.3.10\n              port:\n                start: 500\n                end: 1000\n\n        .. versionadded:: 3003\n\n    :param interfaces: whitespace separated list of network interfaces devices that can be used for this network.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: passthrough\n          - interfaces: "eth10 eth11 eth12"\n\n        .. versionadded:: 3003\n\n    :param addresses: whitespace separated list of addresses of PCI devices that can be used for this network in `hostdev` forward mode.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: hostdev\n          - interfaces: "0000:04:00.1 0000:e3:01.2"\n\n        .. versionadded:: 3003\n\n    :param physical_function: device name of the physical interface to use in ``hostdev`` forward mode.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: hostdev\n          - physical_function: "eth0"\n\n        .. versionadded:: 3003\n\n    :param dns: virtual network DNS configuration\n        The value is a dictionary described in :ref:`net-define-dns`.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - dns:\n              forwarders:\n                - domain: example.com\n                  addr: 192.168.1.1\n                - addr: 8.8.8.8\n                - domain: www.example.com\n              txt:\n                example.com: "v=spf1 a -all"\n                _http.tcp.example.com: "name=value,paper=A4"\n              hosts:\n                192.168.1.2:\n                  - mirror.acme.lab\n                  - test.acme.lab\n              srvs:\n                - name: ldap\n                  protocol: tcp\n                  domain: ldapserver.example.com\n                  target: .\n                  port: 389\n                  priority: 1\n                  weight: 10\n\n        .. versionadded:: 3003\n\n    .. versionadded:: 3001\n\n    .. code-block:: yaml\n\n        network_name:\n          virt.network_defined\n\n    .. code-block:: yaml\n\n        network_name:\n          virt.network_defined:\n            - bridge: main\n            - forward: bridge\n            - vport: openvswitch\n            - tag: 180\n            - autostart: True\n\n    .. code-block:: yaml\n\n        network_name:\n          virt.network_defined:\n            - bridge: natted\n            - forward: nat\n            - ipv4_config:\n                cidr: 192.168.42.0/24\n                dhcp_ranges:\n                  - start: 192.168.42.10\n                    end: 192.168.42.25\n                  - start: 192.168.42.100\n                    end: 192.168.42.150\n            - autostart: True\n\n    '
    ret = {'name': name, 'changes': {}, 'result': True if not __opts__['test'] else None, 'comment': ''}
    try:
        log.info('Trace')
        info = __salt__['virt.network_info'](name, connection=connection, username=username, password=password)
        if info and info[name]:
            needs_autostart = info[name]['autostart'] and (not autostart) or (not info[name]['autostart'] and autostart)
            needs_update = __salt__['virt.network_update'](name, bridge, forward, vport=vport, tag=tag, ipv4_config=ipv4_config, ipv6_config=ipv6_config, mtu=mtu, domain=domain, nat=nat, interfaces=interfaces, addresses=addresses, physical_function=physical_function, dns=dns, test=True, connection=connection, username=username, password=password)
            if needs_update:
                if not __opts__['test']:
                    __salt__['virt.network_update'](name, bridge, forward, vport=vport, tag=tag, ipv4_config=ipv4_config, ipv6_config=ipv6_config, mtu=mtu, domain=domain, nat=nat, interfaces=interfaces, addresses=addresses, physical_function=physical_function, dns=dns, test=False, connection=connection, username=username, password=password)
                action = ', autostart flag changed' if needs_autostart else ''
                ret['changes'][name] = 'Network updated{}'.format(action)
                ret['comment'] = 'Network {} updated{}'.format(name, action)
            else:
                ret['comment'] = 'Network {} unchanged'.format(name)
                ret['result'] = True
        else:
            needs_autostart = autostart
            if not __opts__['test']:
                __salt__['virt.network_define'](name, bridge, forward, vport=vport, tag=tag, ipv4_config=ipv4_config, ipv6_config=ipv6_config, mtu=mtu, domain=domain, nat=nat, interfaces=interfaces, addresses=addresses, physical_function=physical_function, dns=dns, autostart=False, start=False, connection=connection, username=username, password=password)
            if needs_autostart:
                ret['changes'][name] = 'Network defined, marked for autostart'
                ret['comment'] = 'Network {} defined, marked for autostart'.format(name)
            else:
                ret['changes'][name] = 'Network defined'
                ret['comment'] = 'Network {} defined'.format(name)
        if needs_autostart:
            if not __opts__['test']:
                __salt__['virt.network_set_autostart'](name, state='on' if autostart else 'off', connection=connection, username=username, password=password)
    except libvirt.libvirtError as err:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = err.get_error_message()
    return ret

def network_running(name, bridge, forward, vport=None, tag=None, ipv4_config=None, ipv6_config=None, autostart=True, connection=None, username=None, password=None, mtu=None, domain=None, nat=None, interfaces=None, addresses=None, physical_function=None, dns=None):
    log.info('Trace')
    '\n    Defines and starts a new network with specified arguments.\n\n    :param name: Network name\n    :param bridge: Bridge name\n    :param forward: Forward mode(bridge, router, nat)\n\n        .. versionchanged:: 3003\n           a ``None`` value creates an isolated network with no forwarding at all\n\n    :param vport: Virtualport type (Default: ``\'None\'``)\n        The value can also be a dictionary with ``type`` and ``parameters`` keys.\n        The ``parameters`` value is a dictionary of virtual port parameters.\n\n        .. code-block:: yaml\n\n          - vport:\n              type: openvswitch\n              parameters:\n                interfaceid: 09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f\n\n        .. versionchanged:: 3003\n           possible dictionary value\n\n    :param tag: Vlan tag (Default: ``\'None\'``)\n        The value can also be a dictionary with the ``tags`` and optional ``trunk`` keys.\n        ``trunk`` is a boolean value indicating whether to use VLAN trunking.\n        ``tags`` is a list of dictionaries with keys ``id`` and ``nativeMode``.\n        The ``nativeMode`` value can be one of ``tagged`` or ``untagged``.\n\n        .. code-block:: yaml\n\n          - tag:\n              trunk: True\n              tags:\n                - id: 42\n                  nativeMode: untagged\n                - id: 47\n\n        .. versionchanged:: 3003\n           possible dictionary value\n\n    :param ipv4_config:\n        IPv4 network configuration. See the :py:func`virt.network_define\n        <salt.modules.virt.network_define>` function corresponding parameter documentation\n        for more details on this dictionary.\n        (Default: None).\n\n        .. versionadded:: 3000\n    :param ipv6_config:\n        IPv6 network configuration. See the :py:func`virt.network_define\n        <salt.modules.virt.network_define>` function corresponding parameter documentation\n        for more details on this dictionary.\n        (Default: None).\n\n        .. versionadded:: 3000\n    :param autostart: Network autostart (default ``\'True\'``)\n    :param connection: libvirt connection URI, overriding defaults\n\n        .. versionadded:: 2019.2.0\n    :param username: username to connect with, overriding defaults\n\n        .. versionadded:: 2019.2.0\n    :param password: password to connect with, overriding defaults\n\n        .. versionadded:: 2019.2.0\n    :param mtu: size of the Maximum Transmission Unit (MTU) of the network.\n        (default ``None``)\n\n        .. versionadded:: 3003\n\n    :param domain: DNS domain name of the DHCP server.\n        The value is a dictionary with a mandatory ``name`` property and an optional ``localOnly`` boolean one.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - domain:\n              name: lab.acme.org\n              localOnly: True\n\n        .. versionadded:: 3003\n\n    :param nat: addresses and ports to route in NAT forward mode.\n        The value is a dictionary with optional keys ``address`` and ``port``.\n        Both values are a dictionary with ``start`` and ``end`` values.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: nat\n          - nat:\n              address:\n                start: 1.2.3.4\n                end: 1.2.3.10\n              port:\n                start: 500\n                end: 1000\n\n        .. versionadded:: 3003\n\n    :param interfaces: whitespace separated list of network interfaces devices that can be used for this network.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: passthrough\n          - interfaces: "eth10 eth11 eth12"\n\n        .. versionadded:: 3003\n\n    :param addresses: whitespace separated list of addresses of PCI devices that can be used for this network in `hostdev` forward mode.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: hostdev\n          - interfaces: "0000:04:00.1 0000:e3:01.2"\n\n        .. versionadded:: 3003\n\n    :param physical_function: device name of the physical interface to use in ``hostdev`` forward mode.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - forward: hostdev\n          - physical_function: "eth0"\n\n        .. versionadded:: 3003\n\n    :param dns: virtual network DNS configuration\n        The value is a dictionary described in :ref:`net-define-dns`.\n        (default ``None``)\n\n        .. code-block:: yaml\n\n          - dns:\n              forwarders:\n                - domain: example.com\n                  addr: 192.168.1.1\n                - addr: 8.8.8.8\n                - domain: www.example.com\n              txt:\n                host.widgets.com.: "printer=lpr5"\n                example.com.: "This domain name is reserved for use in documentation"\n              hosts:\n                192.168.1.2:\n                  - mirror.acme.lab\n                  - test.acme.lab\n              srvs:\n                - name: ldap\n                  protocol: tcp\n                  domain: ldapserver.example.com\n                  target: .\n                  port: 389\n                  priority: 1\n                  weight: 10\n\n        .. versionadded:: 3003\n\n    .. code-block:: yaml\n\n        network_name:\n          virt.network_running\n\n    .. code-block:: yaml\n\n        network_name:\n          virt.network_running:\n            - bridge: main\n            - forward: bridge\n            - vport: openvswitch\n            - tag: 180\n            - autostart: True\n\n    .. code-block:: yaml\n\n        network_name:\n          virt.network_running:\n            - bridge: natted\n            - forward: nat\n            - ipv4_config:\n                cidr: 192.168.42.0/24\n                dhcp_ranges:\n                  - start: 192.168.42.10\n                    end: 192.168.42.25\n                  - start: 192.168.42.100\n                    end: 192.168.42.150\n            - autostart: True\n\n    '
    ret = network_defined(name, bridge, forward, vport=vport, tag=tag, ipv4_config=ipv4_config, ipv6_config=ipv6_config, mtu=mtu, domain=domain, nat=nat, interfaces=interfaces, addresses=addresses, physical_function=physical_function, dns=dns, autostart=autostart, connection=connection, username=username, password=password)
    defined = name in ret['changes'] and ret['changes'][name].startswith('Network defined')
    result = True if not __opts__['test'] else None
    if ret['result'] is None or ret['result']:
        try:
            log.info('Trace')
            info = __salt__['virt.network_info'](name, connection=connection, username=username, password=password)
            if info.get(name, {}).get('active', False):
                ret['comment'] = '{} and is running'.format(ret['comment'])
            else:
                if not __opts__['test']:
                    __salt__['virt.network_start'](name, connection=connection, username=username, password=password)
                change = 'Network started'
                if name in ret['changes']:
                    change = '{} and started'.format(ret['changes'][name])
                ret['changes'][name] = change
                ret['comment'] = '{} and started'.format(ret['comment'])
            ret['result'] = result
        except libvirt.libvirtError as err:
            log.info('Trace')
            ret['result'] = False
            ret['comment'] = err.get_error_message()
    return ret
BUILDABLE_POOL_TYPES = {'disk', 'fs', 'netfs', 'dir', 'logical', 'vstorage', 'zfs'}

def pool_defined(name, ptype=None, target=None, permissions=None, source=None, transient=False, autostart=True, connection=None, username=None, password=None):
    log.info('Trace')
    '\n    Defines a new pool with specified arguments.\n\n    .. versionadded:: 3001\n\n    :param ptype: libvirt pool type\n    :param target: full path to the target device or folder. (Default: ``None``)\n    :param permissions:\n        target permissions. See :ref:`pool-define-permissions` for more details on this structure.\n    :param source:\n        dictionary containing keys matching the ``source_*`` parameters in function\n        :func:`salt.modules.virt.pool_define`.\n    :param transient:\n        when set to ``True``, the pool will be automatically undefined after being stopped. (Default: ``False``)\n    :param autostart:\n        Whether to start the pool when booting the host. (Default: ``True``)\n    :param start:\n        When ``True``, define and start the pool, otherwise the pool will be left stopped.\n    :param connection: libvirt connection URI, overriding defaults\n    :param username: username to connect with, overriding defaults\n    :param password: password to connect with, overriding defaults\n\n    .. code-block:: yaml\n\n        pool_name:\n          virt.pool_defined:\n            - ptype: netfs\n            - target: /mnt/cifs\n            - permissions:\n                - mode: 0770\n                - owner: 1000\n                - group: 100\n            - source:\n                dir: samba_share\n                hosts:\n                  - one.example.com\n                  - two.example.com\n                format: cifs\n            - autostart: True\n\n    '
    ret = {'name': name, 'changes': {}, 'result': True if not __opts__['test'] else None, 'comment': ''}
    try:
        log.info('Trace')
        info = __salt__['virt.pool_info'](name, connection=connection, username=username, password=password)
        needs_autostart = False
        if info:
            needs_autostart = info[name]['autostart'] and (not autostart) or (not info[name]['autostart'] and autostart)
            needs_update = __salt__['virt.pool_update'](name, ptype=ptype, target=target, permissions=permissions, source_devices=(source or {}).get('devices'), source_dir=(source or {}).get('dir'), source_initiator=(source or {}).get('initiator'), source_adapter=(source or {}).get('adapter'), source_hosts=(source or {}).get('hosts'), source_auth=(source or {}).get('auth'), source_name=(source or {}).get('name'), source_format=(source or {}).get('format'), test=True, connection=connection, username=username, password=password)
            if needs_update:
                if not __opts__['test']:
                    __salt__['virt.pool_update'](name, ptype=ptype, target=target, permissions=permissions, source_devices=(source or {}).get('devices'), source_dir=(source or {}).get('dir'), source_initiator=(source or {}).get('initiator'), source_adapter=(source or {}).get('adapter'), source_hosts=(source or {}).get('hosts'), source_auth=(source or {}).get('auth'), source_name=(source or {}).get('name'), source_format=(source or {}).get('format'), connection=connection, username=username, password=password)
                action = ''
                if info[name]['state'] != 'running':
                    if ptype in BUILDABLE_POOL_TYPES:
                        if not __opts__['test']:
                            try:
                                __salt__['virt.pool_build'](name, connection=connection, username=username, password=password)
                            except libvirt.libvirtError as err:
                                log.warning('Failed to build libvirt storage pool: %s', err.get_error_message())
                        action = ', built'
                action = '{}, autostart flag changed'.format(action) if needs_autostart else action
                ret['changes'][name] = 'Pool updated{}'.format(action)
                ret['comment'] = 'Pool {} updated{}'.format(name, action)
            else:
                ret['comment'] = 'Pool {} unchanged'.format(name)
                ret['result'] = True
        else:
            needs_autostart = autostart
            if not __opts__['test']:
                __salt__['virt.pool_define'](name, ptype=ptype, target=target, permissions=permissions, source_devices=(source or {}).get('devices'), source_dir=(source or {}).get('dir'), source_initiator=(source or {}).get('initiator'), source_adapter=(source or {}).get('adapter'), source_hosts=(source or {}).get('hosts'), source_auth=(source or {}).get('auth'), source_name=(source or {}).get('name'), source_format=(source or {}).get('format'), transient=transient, start=False, connection=connection, username=username, password=password)
                if ptype in BUILDABLE_POOL_TYPES:
                    try:
                        __salt__['virt.pool_build'](name, connection=connection, username=username, password=password)
                    except libvirt.libvirtError as err:
                        log.warning('Failed to build libvirt storage pool: %s', err.get_error_message())
            if needs_autostart:
                ret['changes'][name] = 'Pool defined, marked for autostart'
                ret['comment'] = 'Pool {} defined, marked for autostart'.format(name)
            else:
                ret['changes'][name] = 'Pool defined'
                ret['comment'] = 'Pool {} defined'.format(name)
        if needs_autostart:
            if not __opts__['test']:
                __salt__['virt.pool_set_autostart'](name, state='on' if autostart else 'off', connection=connection, username=username, password=password)
    except libvirt.libvirtError as err:
        log.info('Trace')
        ret['comment'] = err.get_error_message()
        ret['result'] = False
    return ret

def pool_running(name, ptype=None, target=None, permissions=None, source=None, transient=False, autostart=True, connection=None, username=None, password=None):
    log.info('Trace')
    '\n    Defines and starts a new pool with specified arguments.\n\n    .. versionadded:: 2019.2.0\n\n    :param ptype: libvirt pool type\n    :param target: full path to the target device or folder. (Default: ``None``)\n    :param permissions:\n        target permissions. See :ref:`pool-define-permissions` for more details on this structure.\n    :param source:\n        dictionary containing keys matching the ``source_*`` parameters in function\n        :func:`salt.modules.virt.pool_define`.\n    :param transient:\n        when set to ``True``, the pool will be automatically undefined after being stopped. (Default: ``False``)\n    :param autostart:\n        Whether to start the pool when booting the host. (Default: ``True``)\n    :param connection: libvirt connection URI, overriding defaults\n    :param username: username to connect with, overriding defaults\n    :param password: password to connect with, overriding defaults\n\n    .. code-block:: yaml\n\n        pool_name:\n          virt.pool_running\n\n    .. code-block:: yaml\n\n        pool_name:\n          virt.pool_running:\n            - ptype: netfs\n            - target: /mnt/cifs\n            - permissions:\n                - mode: 0770\n                - owner: 1000\n                - group: 100\n            - source:\n                dir: samba_share\n                hosts:\n                  - one.example.com\n                  - two.example.com\n                format: cifs\n            - autostart: True\n\n    '
    ret = pool_defined(name, ptype=ptype, target=target, permissions=permissions, source=source, transient=transient, autostart=autostart, connection=connection, username=username, password=password)
    defined = name in ret['changes'] and ret['changes'][name].startswith('Pool defined')
    updated = name in ret['changes'] and ret['changes'][name].startswith('Pool updated')
    result = True if not __opts__['test'] else None
    if ret['result'] is None or ret['result']:
        try:
            log.info('Trace')
            info = __salt__['virt.pool_info'](name, connection=connection, username=username, password=password)
            action = 'started'
            is_running = info.get(name, {}).get('state', 'stopped') == 'running'
            if is_running:
                if updated:
                    action = 'restarted'
                    if not __opts__['test']:
                        __salt__['virt.pool_stop'](name, connection=connection, username=username, password=password)
                    if ptype in BUILDABLE_POOL_TYPES - {'disk', 'logical'}:
                        if not __opts__['test']:
                            __salt__['virt.pool_build'](name, connection=connection, username=username, password=password)
                        action = 'built, {}'.format(action)
                else:
                    action = 'already running'
                    result = True
            if not is_running or updated or defined:
                if not __opts__['test']:
                    __salt__['virt.pool_start'](name, connection=connection, username=username, password=password)
            comment = 'Pool {}'.format(name)
            change = 'Pool'
            if name in ret['changes']:
                comment = '{},'.format(ret['comment'])
                change = '{},'.format(ret['changes'][name])
            if action != 'already running':
                ret['changes'][name] = '{} {}'.format(change, action)
            ret['comment'] = '{} {}'.format(comment, action)
            ret['result'] = result
        except libvirt.libvirtError as err:
            log.info('Trace')
            ret['comment'] = err.get_error_message()
            ret['result'] = False
    return ret

def pool_deleted(name, purge=False, connection=None, username=None, password=None):
    log.info('Trace')
    "\n    Deletes a virtual storage pool.\n\n    :param name: the name of the pool to delete.\n    :param purge:\n        if ``True``, the volumes contained in the pool will be deleted as well as the pool itself.\n        Note that these will be lost for ever. If ``False`` the pool will simply be undefined.\n        (Default: ``False``)\n    :param connection: libvirt connection URI, overriding defaults\n    :param username: username to connect with, overriding defaults\n    :param password: password to connect with, overriding defaults\n\n    In order to be purged a storage pool needs to be running to get the list of volumes to delete.\n\n    Some libvirt storage drivers may not implement deleting, those actions are implemented on a\n    best effort idea. In any case check the result's comment property to see if any of the action\n    was unsupported.\n\n    .. code-block:: yaml\n\n        pool_name:\n          uyuni_virt.pool_deleted:\n            - purge: True\n\n    .. versionadded:: 3000\n    "
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    try:
        log.info('Trace')
        info = __salt__['virt.pool_info'](name, connection=connection, username=username, password=password)
        if info:
            ret['changes']['stopped'] = False
            ret['changes']['deleted'] = False
            ret['changes']['undefined'] = False
            ret['changes']['deleted_volumes'] = []
            unsupported = []
            if info[name]['state'] == 'running':
                if purge:
                    unsupported_volume_delete = ['iscsi', 'iscsi-direct', 'mpath', 'scsi']
                    if info[name]['type'] not in unsupported_volume_delete:
                        __salt__['virt.pool_refresh'](name, connection=connection, username=username, password=password)
                        volumes = __salt__['virt.pool_list_volumes'](name, connection=connection, username=username, password=password)
                        for volume in volumes:
                            deleted = __opts__['test']
                            if not __opts__['test']:
                                deleted = __salt__['virt.volume_delete'](name, volume, connection=connection, username=username, password=password)
                            if deleted:
                                ret['changes']['deleted_volumes'].append(volume)
                    else:
                        unsupported.append('deleting volume')
                if not __opts__['test']:
                    ret['changes']['stopped'] = __salt__['virt.pool_stop'](name, connection=connection, username=username, password=password)
                else:
                    ret['changes']['stopped'] = True
                if purge:
                    supported_pool_delete = ['dir', 'fs', 'netfs', 'logical', 'vstorage', 'zfs']
                    if info[name]['type'] in supported_pool_delete:
                        if not __opts__['test']:
                            ret['changes']['deleted'] = __salt__['virt.pool_delete'](name, connection=connection, username=username, password=password)
                        else:
                            ret['changes']['deleted'] = True
                    else:
                        unsupported.append('deleting pool')
            if not __opts__['test']:
                ret['changes']['undefined'] = __salt__['virt.pool_undefine'](name, connection=connection, username=username, password=password)
            else:
                ret['changes']['undefined'] = True
                ret['result'] = None
            if unsupported:
                ret['comment'] = 'Unsupported actions for pool of type "{}": {}'.format(info[name]['type'], ', '.join(unsupported))
        else:
            ret['comment'] = 'Storage pool could not be found: {}'.format(name)
    except libvirt.libvirtError as err:
        log.info('Trace')
        ret['comment'] = 'Failed deleting pool: {}'.format(err.get_error_message())
        ret['result'] = False
    return ret

def volume_defined(pool, name, size, allocation=0, format=None, type=None, permissions=None, backing_store=None, nocow=False, connection=None, username=None, password=None):
    log.info('Trace')
    '\n    Ensure a disk volume is existing.\n\n    :param pool: name of the pool containing the volume\n    :param name: name of the volume\n    :param size: capacity of the volume to define in MiB\n    :param allocation: allocated size of the volume in MiB. Defaults to 0.\n    :param format:\n        volume format. The allowed values are depending on the pool type.\n        Check the virt.pool_capabilities output for the possible values and the default.\n    :param type:\n        type of the volume. One of file, block, dir, network, netdiri, ploop or None.\n        By default, the type is guessed by libvirt from the pool type.\n    :param permissions:\n        Permissions to set on the target folder. This is mostly used for filesystem-based\n        pool types. See :ref:`pool-define-permissions` for more details on this structure.\n    :param backing_store:\n        dictionary describing a backing file for the volume. It must contain a ``path``\n        property pointing to the base volume and a ``format`` property defining the format\n        of the base volume.\n\n        The base volume format will not be guessed for security reasons and is thus mandatory.\n    :param nocow: disable COW for the volume.\n    :param connection: libvirt connection URI, overriding defaults\n    :param username: username to connect with, overriding defaults\n    :param password: password to connect with, overriding defaults\n\n    .. rubric:: CLI Example:\n\n    Volume on ESX:\n\n    .. code-block:: yaml\n\n        esx_volume:\n          virt.volume_defined:\n            - pool: "[local-storage]"\n            - name: myvm/myvm.vmdk\n            - size: 8192\n\n    QCow2 volume with backing file:\n\n    .. code-block:: bash\n\n        myvolume:\n          virt.volume_defined:\n            - pool: default\n            - name: myvm.qcow2\n            - format: qcow2\n            - size: 8192\n            - permissions:\n                mode: \'0775\'\n                owner: \'123\'\n                group: \'345\'\n            - backing_store:\n                path: /path/to/base.img\n                format: raw\n            - nocow: True\n\n    .. versionadded:: 3001\n    '
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    pools = __salt__['virt.list_pools'](connection=connection, username=username, password=password)
    if pool not in pools:
        raise SaltInvocationError('Storage pool {} not existing'.format(pool))
    vol_infos = __salt__['virt.volume_infos'](pool, name, connection=connection, username=username, password=password).get(pool, {}).get(name)
    if vol_infos:
        ret['comment'] = 'volume is existing'
        backing_store_info = vol_infos.get('backing_store') or {}
        same_backing_store = backing_store_info.get('path') == (backing_store or {}).get('path') and backing_store_info.get('format') == (backing_store or {}).get('format')
        if not same_backing_store or (vol_infos.get('format') != format and format is not None):
            ret['result'] = False
            ret['comment'] = 'A volume with the same name but different backing store or format is existing'
            return ret
        if int(vol_infos.get('capacity')) != int(size) * 1024 * 1024:
            ret['comment'] = 'The capacity of the volume is different, but no resize performed'
        return ret
    ret['result'] = None if __opts__['test'] else True
    test_comment = 'would be '
    try:
        log.info('Trace')
        if not __opts__['test']:
            __salt__['virt.volume_define'](pool, name, size, allocation=allocation, format=format, type=type, permissions=permissions, backing_store=backing_store, nocow=nocow, connection=connection, username=username, password=password)
            test_comment = ''
        ret['comment'] = 'Volume {} {}defined in pool {}'.format(name, test_comment, pool)
        ret['changes'] = {'{}/{}'.format(pool, name): {'old': '', 'new': 'defined'}}
    except libvirt.libvirtError as err:
        log.info('Trace')
        ret['comment'] = err.get_error_message()
        ret['result'] = False
    return ret