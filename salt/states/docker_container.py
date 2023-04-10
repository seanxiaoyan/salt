"""
Management of Docker containers

.. versionadded:: 2017.7.0

:depends: docker_ Python module

.. note::
    Older releases of the Python bindings for Docker were called docker-py_ in
    PyPI. All releases of docker_, and releases of docker-py_ >= 1.6.0 are
    supported. These python bindings can easily be installed using
    :py:func:`pip.install <salt.modules.pip.install>`:

    .. code-block:: bash

        salt myminion pip.install docker

    To upgrade from docker-py_ to docker_, you must first uninstall docker-py_,
    and then install docker_:

    .. code-block:: bash

        salt myminion pip.uninstall docker-py
        salt myminion pip.install docker

.. _docker: https://pypi.python.org/pypi/docker
.. _docker-py: https://pypi.python.org/pypi/docker-py

These states were moved from the :mod:`docker <salt.states.docker>` state
module (formerly called **dockerng**) in the 2017.7.0 release. When running the
:py:func:`docker_container.running <salt.states.docker_container.running>`
state for the first time after upgrading to 2017.7.0, your container(s) may be
replaced. The changes may show diffs for certain parameters which say that the
old value was an empty string, and the new value is ``None``. This is due to
the fact that in prior releases Salt was passing empty strings for these values
when creating the container if they were undefined in the SLS file, where now
Salt simply does not pass any arguments not explicitly defined in the SLS file.
Subsequent runs of the state should not replace the container if the
configuration remains unchanged.


.. note::
    To pull from a Docker registry, authentication must be configured. See
    :ref:`here <docker-authentication>` for more information on how to
    configure access to docker registries in :ref:`Pillar <pillar>` data.
"""
import copy
import logging
import salt.utils.args
import salt.utils.data
import salt.utils.dockermod
from salt.exceptions import CommandExecutionError
log = logging.getLogger(__name__)
__virtualname__ = 'docker_container'
__virtual_aliases__ = ('moby_container',)

def __virtual__():
    """
    Only load if the docker execution module is available
    """
    if 'docker.version' in __salt__:
        return __virtualname__
    return (False, __salt__.missing_fun_string('docker.version'))

def _format_comments(ret, comments):
    log.info('Trace')
    '\n    DRY code for joining comments together and conditionally adding a period at\n    the end, and adding this comment string to the state return dict.\n    '
    if isinstance(comments, str):
        ret['comment'] = comments
    else:
        ret['comment'] = '. '.join(comments)
        if len(comments) > 1:
            ret['comment'] += '.'
    return ret

def _check_diff(changes):
    log.info('Trace')
    '\n    Check the diff for signs of incorrect argument handling in previous\n    releases, as discovered here:\n\n    https://github.com/saltstack/salt/pull/39996#issuecomment-288025200\n    '
    for conf_dict in changes:
        if conf_dict == 'Networks':
            continue
        for item in changes[conf_dict]:
            if changes[conf_dict][item]['new'] is None:
                old = changes[conf_dict][item]['old']
                if old == '':
                    return True
                else:
                    try:
                        log.info('Trace')
                        if all((x == '' for x in old)):
                            return True
                    except TypeError:
                        log.info('Trace')
                        pass
    return False

def _parse_networks(networks):
    log.info('Trace')
    '\n    Common logic for parsing the networks\n    '
    networks = salt.utils.args.split_input(networks or [])
    if not networks:
        networks = {}
    else:
        networks = salt.utils.data.repack_dictlist(networks)
        if not networks:
            raise CommandExecutionError('Invalid network configuration (see documentation)')
        for (net_name, net_conf) in networks.items():
            if net_conf is None:
                networks[net_name] = {}
            else:
                networks[net_name] = salt.utils.data.repack_dictlist(net_conf)
                if not networks[net_name]:
                    raise CommandExecutionError("Invalid configuration for network '{}' (see documentation)".format(net_name))
                for key in ('links', 'aliases'):
                    try:
                        log.info('Trace')
                        networks[net_name][key] = salt.utils.args.split_input(networks[net_name][key])
                    except KeyError:
                        log.info('Trace')
                        continue
        errors = []
        for (net_name, net_conf) in networks.items():
            if net_conf is not None:
                for (key, val) in net_conf.items():
                    if val is None:
                        errors.append("Config option '{}' for network '{}' is missing a value".format(key, net_name))
        if errors:
            raise CommandExecutionError('Invalid network configuration', info=errors)
    if networks:
        try:
            log.info('Trace')
            all_networks = [x['Name'] for x in __salt__['docker.networks']() if 'Name' in x]
        except CommandExecutionError as exc:
            log.info('Trace')
            raise CommandExecutionError('Failed to get list of existing networks: {}.'.format(exc))
        else:
            missing_networks = [x for x in sorted(networks) if x not in all_networks]
            if missing_networks:
                raise CommandExecutionError('The following networks are not present: {}'.format(', '.join(missing_networks)))
    return networks

def _resolve_image(ret, image, client_timeout):
    log.info('Trace')
    '\n    Resolve the image ID and pull the image if necessary\n    '
    image_id = __salt__['docker.resolve_image_id'](image)
    if image_id is False:
        if not __opts__['test']:
            try:
                log.info('Trace')
                pull_result = __salt__['docker.pull'](image, client_timeout=client_timeout)
            except Exception as exc:
                log.info('Trace')
                raise CommandExecutionError('Failed to pull {}: {}'.format(image, exc))
            else:
                ret['changes']['image'] = pull_result
                image_id = __salt__['docker.resolve_image_id'](image)
                if image_id is False:
                    raise CommandExecutionError("Image '{}' not present despite a docker pull raising no errors".format(image))
    return image_id

def running(name, image=None, skip_translate=None, ignore_collisions=False, validate_ip_addrs=True, force=False, watch_action='force', start=True, shutdown_timeout=None, client_timeout=salt.utils.dockermod.CLIENT_TIMEOUT, networks=None, **kwargs):
    log.info('Trace')
    '\n    Ensure that a container with a specific configuration is present and\n    running\n\n    name\n        Name of the container\n\n    image\n        Image to use for the container\n\n        .. note::\n            This state will pull the image if it is not present. However, if\n            the image needs to be built from a Dockerfile or loaded from a\n            saved image, or if you would like to use requisites to trigger a\n            replacement of the container when the image is updated, then the\n            :py:func:`docker_image.present\n            <salt.states.dockermod.image_present>` state should be used to\n            manage the image.\n\n        .. versionchanged:: 2018.3.0\n            If no tag is specified in the image name, and nothing matching the\n            specified image is pulled on the minion, the ``docker pull`` that\n            retrieves the image will pull *all tags* for the image. A tag of\n            ``latest`` is no longer implicit for the pull. For this reason, it\n            is recommended to specify the image in ``repo:tag`` notation.\n\n    .. _docker-container-running-skip-translate:\n\n    skip_translate\n        This function translates Salt CLI or SLS input into the format which\n        docker-py_ expects. However, in the event that Salt\'s translation logic\n        fails (due to potential changes in the Docker Remote API, or to bugs in\n        the translation code), this argument can be used to exert granular\n        control over which arguments are translated and which are not.\n\n        Pass this argument as a comma-separated list (or Python list) of\n        arguments, and translation for each passed argument name will be\n        skipped. Alternatively, pass ``True`` and *all* translation will be\n        skipped.\n\n        Skipping tranlsation allows for arguments to be formatted directly in\n        the format which docker-py_ expects. This allows for API changes and\n        other issues to be more easily worked around. An example of using this\n        option to skip translation would be:\n\n        For example, imagine that there is an issue with processing the\n        ``port_bindings`` argument, and the following configuration no longer\n        works as expected:\n\n        .. code-block:: yaml\n\n            mycontainer:\n              docker_container.running:\n                - image: 7.3.1611\n                - port_bindings:\n                  - 10.2.9.10:8080:80\n\n        By using ``skip_translate``, you can forego the input translation and\n        configure the port binding in the format docker-py_ needs:\n\n        .. code-block:: yaml\n\n            mycontainer:\n              docker_container.running:\n                - image: 7.3.1611\n                - skip_translate: port_bindings\n                - port_bindings: {8080: [(\'10.2.9.10\', 80)], \'4193/udp\': 9314}\n\n        See the following links for more information:\n\n        - `docker-py Low-level API`_\n        - `Docker Engine API`_\n\n    .. _docker-py: https://pypi.python.org/pypi/docker-py\n    .. _`docker-py Low-level API`: http://docker-py.readthedocs.io/en/stable/api.html#docker.api.container.ContainerApiMixin.create_container\n    .. _`Docker Engine API`: https://docs.docker.com/engine/api/v1.33/#operation/ContainerCreate\n\n    ignore_collisions : False\n        Since many of docker-py_\'s arguments differ in name from their CLI\n        counterparts (with which most Docker users are more familiar), Salt\n        detects usage of these and aliases them to the docker-py_ version of\n        that argument so that both CLI and API versions of a given argument are\n        supported. However, if both the alias and the docker-py_ version of the\n        same argument (e.g. ``env`` and ``environment``) are used, an error\n        will be raised. Set this argument to ``True`` to suppress these errors\n        and keep the docker-py_ version of the argument.\n\n    validate_ip_addrs : True\n        For parameters which accept IP addresses as input, IP address\n        validation will be performed. To disable, set this to ``False``\n\n    force : False\n        Set this parameter to ``True`` to force Salt to re-create the container\n        irrespective of whether or not it is configured as desired.\n\n    watch_action : force\n        Control what type of action is taken when this state :ref:`watches\n        <requisites-watch>` another state that has changes. The default action\n        is ``force``, which runs the state with ``force`` set to ``True``,\n        triggering a rebuild of the container.\n\n        If any other value is passed, it will be assumed to be a kill signal.\n        If the container matches the specified configuration, and is running,\n        then the action will be to send that signal to the container. Kill\n        signals can be either strings or numbers, and are defined in the\n        **Standard Signals** section of the ``signal(7)`` manpage. Run ``man 7\n        signal`` on a Linux host to browse this manpage. For example:\n\n        .. code-block:: yaml\n\n            mycontainer:\n              docker_container.running:\n                - image: busybox\n                - watch_action: SIGHUP\n                - watch:\n                  - file: some_file\n\n        .. note::\n\n            If the container differs from the specified configuration, or is\n            not running, then instead of sending a signal to the container, the\n            container will be re-created/started and no signal will be sent.\n\n    start : True\n        Set to ``False`` to suppress starting of the container if it exists,\n        matches the desired configuration, but is not running. This is useful\n        for data-only containers, or for non-daemonized container processes,\n        such as the Django ``migrate`` and ``collectstatic`` commands. In\n        instances such as this, the container only needs to be started the\n        first time.\n\n    shutdown_timeout\n        If the container needs to be replaced, the container will be stopped\n        using :py:func:`docker.stop <salt.modules.dockermod.stop>`. If a\n        ``shutdown_timout`` is not set, and the container was created using\n        ``stop_timeout``, that timeout will be used. If neither of these values\n        were set, then a timeout of 10 seconds will be used.\n\n        .. versionchanged:: 2017.7.0\n            This option was renamed from ``stop_timeout`` to\n            ``shutdown_timeout`` to accommodate the ``stop_timeout`` container\n            configuration setting.\n\n    client_timeout : 60\n        Timeout in seconds for the Docker client. This is not a timeout for\n        this function, but for receiving a response from the API.\n\n        .. note::\n            This is only used if Salt needs to pull the requested image.\n\n    .. _salt-states-docker-container-network-management:\n\n    **NETWORK MANAGEMENT**\n\n    .. versionadded:: 2018.3.0\n    .. versionchanged:: 2019.2.0\n        If the ``networks`` option is used, any networks (including the default\n        ``bridge`` network) which are not specified will be disconnected.\n\n    The ``networks`` argument can be used to ensure that a container is\n    attached to one or more networks. Optionally, arguments can be passed to\n    the networks. In the example below, ``net1`` is being configured with\n    arguments, while ``net2`` and ``bridge`` are being configured *without*\n    arguments:\n\n    .. code-block:: yaml\n\n        foo:\n          docker_container.running:\n            - image: myuser/myimage:foo\n            - networks:\n              - net1:\n                - aliases:\n                  - bar\n                  - baz\n                - ipv4_address: 10.0.20.50\n              - net2\n              - bridge\n            - require:\n              - docker_network: net1\n              - docker_network: net2\n\n    The supported arguments are the ones from the docker-py\'s\n    `connect_container_to_network`_ function (other than ``container`` and\n    ``net_id``).\n\n    .. important::\n        Unlike with the arguments described in the **CONTAINER CONFIGURATION\n        PARAMETERS** section below, these network configuration parameters are\n        not translated at all.  Consult the `connect_container_to_network`_\n        documentation for the correct type/format of data to pass.\n\n    .. _`connect_container_to_network`: https://docker-py.readthedocs.io/en/stable/api.html#docker.api.network.NetworkApiMixin.connect_container_to_network\n\n    To start a container with no network connectivity (only possible in\n    2019.2.0 and later) pass this option as an empty list. For example:\n\n    .. code-block:: yaml\n\n        foo:\n          docker_container.running:\n            - image: myuser/myimage:foo\n            - networks: []\n\n\n    **CONTAINER CONFIGURATION PARAMETERS**\n\n    auto_remove (or *rm*) : False\n        Enable auto-removal of the container on daemon side when the\n        container’s process exits (analogous to running a docker container with\n        ``--rm`` on the CLI).\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - auto_remove: True\n\n    binds\n        Files/directories to bind mount. Each bind mount should be passed in\n        one of the following formats:\n\n        - ``<host_path>:<container_path>`` - ``host_path`` is mounted within\n          the container as ``container_path`` with read-write access.\n        - ``<host_path>:<container_path>:<selinux_context>`` - ``host_path`` is\n          mounted within the container as ``container_path`` with read-write\n          access. Additionally, the specified selinux context will be set\n          within the container.\n        - ``<host_path>:<container_path>:<read_only>`` - ``host_path`` is\n          mounted within the container as ``container_path``, with the\n          read-only or read-write setting explicitly defined.\n        - ``<host_path>:<container_path>:<read_only>,<selinux_context>`` -\n          ``host_path`` is mounted within the container as ``container_path``,\n          with the read-only or read-write setting explicitly defined.\n          Additionally, the specified selinux context will be set within the\n          container.\n\n        ``<read_only>`` can be either ``rw`` for read-write access, or ``ro``\n        for read-only access. When omitted, it is assumed to be read-write.\n\n        ``<selinux_context>`` can be ``z`` if the volume is shared between\n        multiple containers, or ``Z`` if the volume should be private.\n\n        .. note::\n            When both ``<read_only>`` and ``<selinux_context>`` are specified,\n            there must be a comma before ``<selinux_context>``.\n\n        Binds can be expressed as a comma-separated list or a YAML list. The\n        below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - binds: /srv/www:/var/www:ro,/etc/foo.conf:/usr/local/etc/foo.conf:rw\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - binds:\n                  - /srv/www:/var/www:ro\n                  - /home/myuser/conf/foo.conf:/etc/foo.conf:rw\n\n        However, in cases where both ro/rw and an selinux context are combined,\n        the only option is to use a YAML list, like so:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - binds:\n                  - /srv/www:/var/www:ro,Z\n                  - /home/myuser/conf/foo.conf:/etc/foo.conf:rw,Z\n\n        Since the second bind in the previous example is mounted read-write,\n        the ``rw`` and comma can be dropped. For example:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - binds:\n                  - /srv/www:/var/www:ro,Z\n                  - /home/myuser/conf/foo.conf:/etc/foo.conf:Z\n\n    blkio_weight\n        Block IO weight (relative weight), accepts a weight value between 10\n        and 1000.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - blkio_weight: 100\n\n    blkio_weight_device\n        Block IO weight (relative device weight), specified as a list of\n        expressions in the format ``PATH:RATE``\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - blkio_weight_device: /dev/sda:100\n\n    cap_add\n        List of capabilities to add within the container. Can be expressed as a\n        comma-separated list or a Python list. The below two examples are\n        equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cap_add: SYS_ADMIN,MKNOD\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cap_add:\n                  - SYS_ADMIN\n                  - MKNOD\n\n        .. note::\n\n            This option requires Docker 1.2.0 or newer.\n\n    cap_drop\n        List of capabilities to drop within the container. Can be expressed as\n        a comma-separated list or a Python list. The below two examples are\n        equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cap_drop: SYS_ADMIN,MKNOD\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cap_drop:\n                  - SYS_ADMIN\n                  - MKNOD\n\n        .. note::\n            This option requires Docker 1.2.0 or newer.\n\n    command (or *cmd*)\n        Command to run in the container\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - command: bash\n\n    cpuset_cpus (or *cpuset*)\n        CPUs on which which to allow execution, specified as a string\n        containing a range (e.g. ``0-3``) or a comma-separated list of CPUs\n        (e.g. ``0,1``).\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cpuset_cpus: "0,1"\n\n    cpuset_mems\n        Memory nodes on which which to allow execution, specified as a string\n        containing a range (e.g. ``0-3``) or a comma-separated list of MEMs\n        (e.g. ``0,1``). Only effective on NUMA systems.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cpuset_mems: "0,1"\n\n    cpu_group\n        The length of a CPU period in microseconds\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cpu_group: 100000\n\n    cpu_period\n        Microseconds of CPU time that the container can get in a CPU period\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cpu_period: 50000\n\n    cpu_shares\n        CPU shares (relative weight), specified as an integer between 2 and 1024.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - cpu_shares: 512\n\n    detach : False\n        If ``True``, run the container\'s command in the background (daemon\n        mode)\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - detach: True\n\n    devices\n        List of host devices to expose within the container. Can be expressed\n        as a comma-separated list or a YAML list. The below two examples are\n        equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices: /dev/net/tun,/dev/xvda1:/dev/xvda1,/dev/xvdb1:/dev/xvdb1:r\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices:\n                  - /dev/net/tun\n                  - /dev/xvda1:/dev/xvda1\n                  - /dev/xvdb1:/dev/xvdb1:r\n\n    device_read_bps\n        Limit read rate (bytes per second) from a device, specified as a list\n        of expressions in the format ``PATH:RATE``, where ``RATE`` is either an\n        integer number of bytes, or a string ending in ``kb``, ``mb``, or\n        ``gb``. Can be expressed as a comma-separated list or a YAML list. The\n        below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_read_bps: /dev/sda:1mb,/dev/sdb:5mb\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_read_bps:\n                  - /dev/sda:1mb\n                  - /dev/sdb:5mb\n\n    device_read_iops\n        Limit read rate (I/O per second) from a device, specified as a list\n        of expressions in the format ``PATH:RATE``, where ``RATE`` is a number\n        of I/O operations. Can be expressed as a comma-separated list or a YAML\n        list. The below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_read_iops: /dev/sda:1000,/dev/sdb:500\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_read_iops:\n                  - /dev/sda:1000\n                  - /dev/sdb:500\n\n    device_write_bps\n        Limit write rate (bytes per second) from a device, specified as a list\n        of expressions in the format ``PATH:RATE``, where ``RATE`` is either an\n        integer number of bytes, or a string ending in ``kb``, ``mb``, or\n        ``gb``. Can be expressed as a comma-separated list or a YAML list. The\n        below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_write_bps: /dev/sda:1mb,/dev/sdb:5mb\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_write_bps:\n                  - /dev/sda:1mb\n                  - /dev/sdb:5mb\n\n\n    device_write_iops\n        Limit write rate (I/O per second) from a device, specified as a list\n        of expressions in the format ``PATH:RATE``, where ``RATE`` is a number\n        of I/O operations. Can be expressed as a comma-separated list or a\n        YAML list. The below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_write_iops: /dev/sda:1000,/dev/sdb:500\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - devices_write_iops:\n                  - /dev/sda:1000\n                  - /dev/sdb:500\n\n    dns\n        List of DNS nameservers. Can be expressed as a comma-separated list or\n        a YAML list. The below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dns: 8.8.8.8,8.8.4.4\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dns:\n                  - 8.8.8.8\n                  - 8.8.4.4\n\n        .. note::\n\n            To skip IP address validation, use ``validate_ip_addrs=False``\n\n    dns_opt\n        Additional options to be added to the container’s ``resolv.conf`` file.\n        Can be expressed as a comma-separated list or a YAML list. The below\n        two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dns_opt: ndots:9\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dns_opt:\n                  - ndots:9\n\n    dns_search\n        List of DNS search domains. Can be expressed as a comma-separated list\n        or a YAML list. The below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dns_search: foo1.domain.tld,foo2.domain.tld\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dns_search:\n                  - foo1.domain.tld\n                  - foo2.domain.tld\n\n    domainname\n        The domain name to use for the container\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - dommainname: domain.tld\n\n    entrypoint\n        Entrypoint for the container\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - entrypoint: "mycmd --arg1 --arg2"\n\n        This argument can also be specified as a list:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - entrypoint:\n                  - mycmd\n                  - --arg1\n                  - --arg2\n\n    environment\n        Either a list of variable/value mappings, or a list of strings in the\n        format ``VARNAME=value``. The below three examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - environment:\n                  - VAR1: value\n                  - VAR2: value\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - environment: \'VAR1=value,VAR2=value\'\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - environment:\n                  - VAR1=value\n                  - VAR2=value\n\n    extra_hosts\n        Additional hosts to add to the container\'s /etc/hosts file. Can be\n        expressed as a comma-separated list or a Python list. The below two\n        examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - extra_hosts: web1:10.9.8.7,web2:10.9.8.8\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - extra_hosts:\n                  - web1:10.9.8.7\n                  - web2:10.9.8.8\n\n        .. note::\n\n            To skip IP address validation, use ``validate_ip_addrs=False``\n\n        .. note::\n\n            This option requires Docker 1.3.0 or newer.\n\n    group_add\n        List of additional group names and/or IDs that the container process\n        will run as. Can be expressed as a comma-separated list or a YAML list.\n        The below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - group_add: web,network\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - group_add:\n                  - web\n                  - network\n\n    hostname\n        Hostname of the container. If not provided, the value passed as the\n        container\'s``name`` will be used for the hostname.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - hostname: web1\n\n        .. warning::\n\n            ``hostname`` cannot be set if ``network_mode`` is set to ``host``.\n            The below example will result in an error:\n\n            .. code-block:: yaml\n\n                foo:\n                  docker_container.running:\n                    - image: bar/baz:latest\n                    - hostname: web1\n                    - network_mode: host\n\n    interactive (or *stdin_open*) : False\n        Leave stdin open, even if not attached\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - interactive: True\n\n    ipc_mode (or *ipc*)\n        Set the IPC mode for the container. The default behavior is to create a\n        private IPC namespace for the container, but this option can be\n        used to change that behavior:\n\n        - ``container:<container_name_or_id>`` reuses another container shared\n          memory, semaphores and message queues\n        - ``host``: use the host\'s shared memory, semaphores and message queues\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ipc_mode: container:foo\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ipc_mode: host\n\n        .. warning::\n            Using ``host`` gives the container full access to local shared\n            memory and is therefore considered insecure.\n\n    isolation\n        Specifies the type of isolation technology used by containers\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - isolation: hyperv\n\n        .. note::\n            The default value on Windows server is ``process``, while the\n            default value on Windows client is ``hyperv``. On Linux, only\n            ``default`` is supported.\n\n    labels\n        Add metadata to the container. Labels can be set both with and without\n        values, and labels with values can be passed either as ``key=value`` or\n        ``key: value`` pairs. For example, while the below would be very\n        confusing to read, it is technically valid, and demonstrates the\n        different ways in which labels can be passed:\n\n        .. code-block:: yaml\n\n            mynet:\n              docker_network.present:\n                - labels:\n                  - foo\n                  - bar=baz\n                  - hello: world\n\n        The labels can also simply be passed as a YAML dictionary, though this\n        can be error-prone due to some :ref:`idiosyncrasies\n        <yaml-idiosyncrasies>` with how PyYAML loads nested data structures:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_network.present:\n                - labels:\n                    foo: \'\'\n                    bar: baz\n                    hello: world\n\n        .. versionchanged:: 2018.3.0\n            Methods for specifying labels can now be mixed. Earlier releases\n            required either labels with or without values.\n\n    links\n        Link this container to another. Links can be specified as a list of\n        mappings or a comma-separated or Python list of expressions in the\n        format ``<container_name_or_id>:<link_alias>``. The below three\n        examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - links:\n                  - web1: link1\n                  - web2: link2\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - links: web1:link1,web2:link2\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - links:\n                  - web1:link1\n                  - web2:link2\n\n    log_driver and log_opt\n        Set container\'s logging driver and options to configure that driver.\n        Requires Docker 1.6 or newer.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - log_driver: syslog\n                - log_opt:\n                  - syslog-address: tcp://192.168.0.42\n                  - syslog-facility: daemon\n\n        The ``log_opt`` can also be expressed as a comma-separated or YAML list\n        of ``key=value`` pairs. The below two examples are equivalent to the\n        above one:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - log_driver: syslog\n                - log_opt: "syslog-address=tcp://192.168.0.42,syslog-facility=daemon"\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - log_driver: syslog\n                - log_opt:\n                  - syslog-address=tcp://192.168.0.42\n                  - syslog-facility=daemon\n\n        .. note::\n            The logging driver feature was improved in Docker 1.13 introducing\n            option name changes. Please see Docker\'s\n            `Configure logging drivers`_ documentation for more information.\n\n        .. _`Configure logging drivers`: https://docs.docker.com/engine/admin/logging/overview/\n\n    lxc_conf\n        Additional LXC configuration parameters to set before starting the\n        container. Either a list of variable/value mappings, or a list of\n        strings in the format ``VARNAME=value``. The below three examples are\n        equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - lxc_conf:\n                  - lxc.utsname: docker\n                  - lxc.arch: x86_64\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - lxc_conf: lxc.utsname=docker,lxc.arch=x86_64\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - lxc_conf:\n                  - lxc.utsname=docker\n                  - lxc.arch=x86_64\n\n        .. note::\n            These LXC configuration parameters will only have the desired\n            effect if the container is using the LXC execution driver, which\n            has been deprecated for some time.\n\n    mac_address\n        MAC address to use for the container. If not specified, a random MAC\n        address will be used.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - mac_address: 01:23:45:67:89:0a\n\n    mem_limit (or *memory*) : 0\n        Memory limit. Can be specified in bytes or using single-letter units\n        (i.e. ``512M``, ``2G``, etc.). A value of ``0`` (the default) means no\n        memory limit.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - mem_limit: 512M\n\n    mem_swappiness\n        Tune a container\'s memory swappiness behavior. Accepts an integer\n        between 0 and 100.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - mem_swappiness: 60\n\n    memswap_limit (or *memory_swap*) : -1\n        Total memory limit (memory plus swap). Set to ``-1`` to disable swap. A\n        value of ``0`` means no swap limit.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - memswap_limit: 1G\n\n    network_disabled : False\n        If ``True``, networking will be disabled within the container\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - network_disabled: True\n\n    network_mode : bridge\n        One of the following:\n\n        - ``bridge`` - Creates a new network stack for the container on the\n          docker bridge\n        - ``none`` - No networking (equivalent of the Docker CLI argument\n          ``--net=none``). Not to be confused with Python\'s ``None``.\n        - ``container:<name_or_id>`` - Reuses another container\'s network stack\n        - ``host`` - Use the host\'s network stack inside the container\n\n          .. warning::\n\n                Using ``host`` mode gives the container full access to the\n                hosts system\'s services (such as D-bus), and is therefore\n                considered insecure.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - network_mode: "none"\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - network_mode: container:web1\n\n    oom_kill_disable\n        Whether to disable OOM killer\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - oom_kill_disable: False\n\n    oom_score_adj\n        An integer value containing the score given to the container in order\n        to tune OOM killer preferences\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - oom_score_adj: 500\n\n    pid_mode\n        Set to ``host`` to use the host container\'s PID namespace within the\n        container. Requires Docker 1.5.0 or newer.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - pid_mode: host\n\n        .. note::\n            This option requires Docker 1.5.0 or newer.\n\n    pids_limit\n        Set the container\'s PID limit. Set to ``-1`` for unlimited.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - pids_limit: 2000\n\n    port_bindings (or *publish*)\n        Bind exposed ports. Port bindings should be passed in the same way as\n        the ``--publish`` argument to the ``docker run`` CLI command:\n\n        - ``ip:hostPort:containerPort`` - Bind a specific IP and port on the\n          host to a specific port within the container.\n        - ``ip::containerPort`` - Bind a specific IP and an ephemeral port to a\n          specific port within the container.\n        - ``hostPort:containerPort`` - Bind a specific port on all of the\n          host\'s interfaces to a specific port within the container.\n        - ``containerPort`` - Bind an ephemeral port on all of the host\'s\n          interfaces to a specific port within the container.\n\n        Multiple bindings can be separated by commas, or expressed as a YAML\n        list, and port ranges can be defined using dashes. The below two\n        examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - port_bindings: "4505-4506:14505-14506,2123:2123/udp,8080"\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - port_bindings:\n                  - 4505-4506:14505-14506\n                  - 2123:2123/udp\n                  - 8080\n\n        .. note::\n            When specifying a protocol, it must be passed in the\n            ``containerPort`` value, as seen in the examples above.\n\n    ports\n        A list of ports to expose on the container. Can either be a\n        comma-separated list or a YAML list. If the protocol is omitted, the\n        port will be assumed to be a TCP port. The below two examples are\n        equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ports: 1111,2222/udp\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ports:\n                  - 1111\n                  - 2222/udp\n\n    privileged : False\n        If ``True``, runs the exec process with extended privileges\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - privileged: True\n\n    publish_all_ports (or *publish_all*) : False\n        Publish all ports to the host\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ports: 8080\n                - publish_all_ports: True\n\n    read_only : False\n        If ``True``, mount the container’s root filesystem as read only\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - read_only: True\n\n    restart_policy (or *restart*)\n        Set a restart policy for the container. Must be passed as a string in\n        the format ``policy[:retry_count]`` where ``policy`` is one of\n        ``always``, ``unless-stopped``, or ``on-failure``, and ``retry_count``\n        is an optional limit to the number of retries. The retry count is ignored\n        when using the ``always`` or ``unless-stopped`` restart policy.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - restart_policy: on-failure:5\n\n            bar:\n              docker_container.running:\n                - image: bar/baz:latest\n                - restart_policy: always\n\n    security_opt (or *security_opts*):\n        Security configuration for MLS systems such as SELinux and AppArmor.\n        Can be expressed as a comma-separated list or a YAML list. The below\n        two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - security_opt: apparmor:unconfined\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - security_opt:\n                  - apparmor:unconfined\n\n        .. important::\n            Some security options can contain commas. In these cases, this\n            argument *must* be passed as a Python list, as splitting by comma\n            will result in an invalid configuration.\n\n        .. note::\n            See the documentation for security_opt at\n            https://docs.docker.com/engine/reference/run/#security-configuration\n\n    shm_size\n        Size of /dev/shm\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - shm_size: 128M\n\n    stop_signal\n        Specify the signal docker will send to the container when stopping.\n        Useful when running systemd as PID 1 inside the container.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - stop_signal: SIGRTMIN+3\n\n        .. note::\n\n            This option requires Docker 1.9.0 or newer and docker-py 1.7.0 or\n            newer.\n\n        .. versionadded:: 2016.11.0\n\n    stop_timeout\n        Timeout to stop the container, in seconds\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - stop_timeout: 5\n\n        .. note::\n            In releases prior to 2017.7.0, this option was not set in the\n            container configuration, but rather this timeout was enforced only\n            when shutting down an existing container to replace it. To remove\n            the ambiguity, and to allow for the container to have a stop\n            timeout set for it, the old ``stop_timeout`` argument has been\n            renamed to ``shutdown_timeout``, while ``stop_timeout`` now refer\'s\n            to the container\'s configured stop timeout.\n\n    storage_opt\n        Storage driver options for the container. Can be either a list of\n        strings in the format ``option=value``, or a list of mappings between\n        option and value. The below three examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - storage_opt:\n                  - dm.basesize: 40G\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - storage_opt: dm.basesize=40G\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - storage_opt:\n                  - dm.basesize=40G\n\n    sysctls (or *sysctl*)\n        Set sysctl options for the container. Can be either a list of strings\n        in the format ``option=value``, or a list of mappings between option\n        and value. The below three examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - sysctls:\n                  - fs.nr_open: 1048576\n                  - kernel.pid_max: 32768\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - sysctls: fs.nr_open=1048576,kernel.pid_max=32768\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - sysctls:\n                  - fs.nr_open=1048576\n                  - kernel.pid_max=32768\n\n    tmpfs\n        A map of container directories which should be replaced by tmpfs mounts\n        and their corresponding mount options.\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - tmpfs:\n                  - /run: rw,noexec,nosuid,size=65536k\n\n    tty : False\n        Attach TTYs\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - tty: True\n\n    ulimits\n        List of ulimits. These limits should be passed in the format\n        ``<ulimit_name>:<soft_limit>:<hard_limit>``, with the hard limit being\n        optional. Can be expressed as a comma-separated list or a YAML list.\n        The below two examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ulimits: nofile=1024:1024,nproc=60\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - ulimits:\n                  - nofile=1024:1024\n                  - nproc=60\n\n    user\n        User under which to run exec process\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - user: foo\n\n    userns_mode (or *user_ns_mode*)\n        Sets the user namsepace mode, when the user namespace remapping option\n        is enabled\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - userns_mode: host\n\n    volumes (or *volume*)\n        List of directories to expose as volumes. Can be expressed as a\n        comma-separated list or a YAML list. The below two examples are\n        equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - volumes: /mnt/vol1,/mnt/vol2\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - volumes:\n                  - /mnt/vol1\n                  - /mnt/vol2\n\n    volumes_from\n        Container names or IDs from which the container will get volumes. Can\n        be expressed as a comma-separated list or a YAML list. The below two\n        examples are equivalent:\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - volumes_from: foo\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - volumes_from:\n                  - foo\n\n    volume_driver\n        sets the container\'s volume driver\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - volume_driver: foobar\n\n    working_dir (or *workdir*)\n        Working directory inside the container\n\n        .. code-block:: yaml\n\n            foo:\n              docker_container.running:\n                - image: bar/baz:latest\n                - working_dir: /var/log/nginx\n    '
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if image is None:
        ret['result'] = False
        ret['comment'] = "The 'image' argument is required"
        return ret
    elif not isinstance(image, str):
        image = str(image)
    try:
        log.info('Trace')
        configured_networks = networks
        networks = _parse_networks(networks)
        if networks:
            kwargs['networks'] = networks
        image_id = _resolve_image(ret, image, client_timeout)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        if exc.info is not None:
            return _format_comments(ret, exc.info)
        else:
            ret['comment'] = exc.__str__()
            return ret
    comments = []
    send_signal = kwargs.pop('send_signal', False)
    try:
        log.info('Trace')
        current_image_id = __salt__['docker.inspect_container'](name)['Image']
    except CommandExecutionError:
        log.info('Trace')
        current_image_id = None
    except KeyError:
        log.info('Trace')
        ret['result'] = False
        comments.append("Unable to detect current image for container '{}'. This might be due to a change in the Docker API.".format(name))
        return _format_comments(ret, comments)
    exists = current_image_id is not None
    pre_state = __salt__['docker.state'](name) if exists else None
    skip_comparison = force or not exists or current_image_id != image_id
    if skip_comparison and __opts__['test']:
        ret['result'] = None
        if force:
            ret['changes']['forced_update'] = True
        elif current_image_id != image_id:
            ret['changes']['image'] = {'old': current_image_id, 'new': image_id}
        comments.append("Container '{}' would be {}".format(name, 'created' if not exists else 'replaced'))
        return _format_comments(ret, comments)
    try:
        log.info('Trace')
        temp_container = __salt__['docker.create'](image, name=name if not exists else None, skip_translate=skip_translate, ignore_collisions=ignore_collisions, validate_ip_addrs=validate_ip_addrs, client_timeout=client_timeout, **kwargs)
        temp_container_name = temp_container['Name']
    except KeyError as exc:
        log.info('Trace')
        ret['result'] = False
        comments.append("Key '{}' missing from API response, this may be due to a change in the Docker Remote API. Please report this on the SaltStack issue tracker if it has not already been reported.".format(exc))
        return _format_comments(ret, comments)
    except Exception as exc:
        log.info('Trace')
        ret['result'] = False
        msg = exc.__str__()
        if isinstance(exc, CommandExecutionError) and isinstance(exc.info, dict) and ('invalid' in exc.info):
            msg += '\n\nIf you feel this information is incorrect, the skip_translate argument can be used to skip input translation for the argument(s) identified as invalid. See the documentation for details.'
        comments.append(msg)
        return _format_comments(ret, comments)

    def _replace(orig, new):
        log.info('Trace')
        rm_kwargs = {'stop': True}
        if shutdown_timeout is not None:
            rm_kwargs['timeout'] = shutdown_timeout
        ret['changes'].setdefault('container_id', {})['removed'] = __salt__['docker.rm'](name, **rm_kwargs)
        try:
            log.info('Trace')
            result = __salt__['docker.rename'](new, orig)
        except CommandExecutionError as exc:
            log.info('Trace')
            result = False
            comments.append('Failed to rename temp container: {}'.format(exc))
        if result:
            comments.append("Replaced container '{}'".format(orig))
        else:
            comments.append("Failed to replace container '{0}'")
        return result

    def _delete_temp_container():
        log.debug("Removing temp container '%s'", temp_container_name)
        __salt__['docker.rm'](temp_container_name)
    cleanup_temp = not skip_comparison
    try:
        log.info('Trace')
        pre_net_connect = __salt__['docker.inspect_container'](name if exists else temp_container_name)
        for (net_name, net_conf) in networks.items():
            try:
                __salt__['docker.connect_container_to_network'](temp_container_name, net_name, **net_conf)
            except CommandExecutionError as exc:
                ret['result'] = False
                comments.append(exc.__str__())
                return _format_comments(ret, comments)
        post_net_connect = __salt__['docker.inspect_container'](temp_container_name)
        if configured_networks is not None:
            extra_nets = set(post_net_connect.get('NetworkSettings', {}).get('Networks', {})) - set(networks)
            if extra_nets:
                for extra_net in extra_nets:
                    __salt__['docker.disconnect_container_from_network'](temp_container_name, extra_net)
                post_net_connect = __salt__['docker.inspect_container'](temp_container_name)
        net_changes = __salt__['docker.compare_container_networks'](pre_net_connect, post_net_connect)
        if not skip_comparison:
            container_changes = __salt__['docker.compare_containers'](name, temp_container_name, ignore='Hostname')
            if container_changes:
                if _check_diff(container_changes):
                    ret.setdefault('warnings', []).append('The detected changes may be due to incorrect handling of arguments in earlier Salt releases. If this warning persists after running the state again{}, and no changes were made to the SLS file, then please report this.'.format(' without test=True' if __opts__['test'] else ''))
                changes_ptr = ret['changes'].setdefault('container', {})
                changes_ptr.update(container_changes)
                if __opts__['test']:
                    ret['result'] = None
                    comments.append("Container '{}' would be {}".format(name, 'created' if not exists else 'replaced'))
                else:
                    cleanup_temp = False
                    if not _replace(name, temp_container_name):
                        ret['result'] = False
                        return _format_comments(ret, comments)
                    ret['changes'].setdefault('container_id', {})['added'] = temp_container['Id']
            elif send_signal:
                if __opts__['test']:
                    comments.append('Signal {} would be sent to container'.format(watch_action))
                else:
                    try:
                        __salt__['docker.signal'](name, signal=watch_action)
                    except CommandExecutionError as exc:
                        ret['result'] = False
                        comments.append('Failed to signal container: {}'.format(exc))
                        return _format_comments(ret, comments)
                    else:
                        ret['changes']['signal'] = watch_action
                        comments.append('Sent signal {} to container'.format(watch_action))
            elif container_changes:
                if not comments:
                    log.warning("docker_container.running: detected changes without a specific comment for container '%s'", name)
                    comments.append("Container '{}'{} updated.".format(name, ' would be' if __opts__['test'] else ''))
            else:
                comments.append("Container '{}' is already configured as specified".format(name))
        if net_changes:
            ret['changes'].setdefault('container', {})['Networks'] = net_changes
            if __opts__['test']:
                ret['result'] = None
                comments.append('Network configuration would be updated')
            elif cleanup_temp:
                log.info('Trace')
                network_failure = False
                for net_name in sorted(net_changes):
                    errors = []
                    disconnected = connected = False
                    try:
                        if name in __salt__['docker.connected'](net_name):
                            __salt__['docker.disconnect_container_from_network'](name, net_name)
                            disconnected = True
                    except CommandExecutionError as exc:
                        errors.append(exc.__str__())
                    if net_name in networks:
                        try:
                            __salt__['docker.connect_container_to_network'](name, net_name, **networks[net_name])
                            connected = True
                        except CommandExecutionError as exc:
                            errors.append(exc.__str__())
                            if disconnected:
                                for item in list(net_changes[net_name]):
                                    if net_changes[net_name][item]['old'] is None:
                                        del net_changes[net_name][item]
                                    else:
                                        net_changes[net_name][item]['new'] = None
                    if errors:
                        comments.extend(errors)
                        network_failure = True
                    ret['changes'].setdefault('container', {}).setdefault('Networks', {})[net_name] = net_changes[net_name]
                    if disconnected and connected:
                        comments.append("Reconnected to network '{}' with updated configuration".format(net_name))
                    elif disconnected:
                        comments.append("Disconnected from network '{}'".format(net_name))
                    elif connected:
                        comments.append("Connected to network '{}'".format(net_name))
                if network_failure:
                    ret['result'] = False
                    return _format_comments(ret, comments)
    finally:
        if cleanup_temp:
            _delete_temp_container()
    if skip_comparison:
        if not exists:
            comments.append("Created container '{}'".format(name))
        elif not _replace(name, temp_container):
            ret['result'] = False
            return _format_comments(ret, comments)
        ret['changes'].setdefault('container_id', {})['added'] = temp_container['Id']
    if not cleanup_temp and (not exists or (exists and start)) or (start and cleanup_temp and (pre_state != 'running')):
        if __opts__['test']:
            ret['result'] = None
            comments.append('Container would be started')
            return _format_comments(ret, comments)
        else:
            try:
                log.info('Trace')
                post_state = __salt__['docker.start'](name)['state']['new']
            except Exception as exc:
                log.info('Trace')
                ret['result'] = False
                comments.append("Failed to start container '{}': '{}'".format(name, exc))
                return _format_comments(ret, comments)
    else:
        post_state = __salt__['docker.state'](name)
    if not __opts__['test'] and post_state == 'running':
        log.info('Trace')
        contextkey = '.'.join((name, 'docker_container.running'))

        def _get_nets():
            if contextkey not in __context__:
                new_container_info = __salt__['docker.inspect_container'](name)
                __context__[contextkey] = new_container_info.get('NetworkSettings', {}).get('Networks', {})
            return __context__[contextkey]
        autoip_keys = __salt__['config.option']('docker.compare_container_networks').get('automatic', [])
        for (net_name, net_changes) in ret['changes'].get('container', {}).get('Networks', {}).items():
            if 'IPConfiguration' in net_changes and net_changes['IPConfiguration']['new'] == 'automatic':
                for key in autoip_keys:
                    val = _get_nets().get(net_name, {}).get(key)
                    if val:
                        net_changes[key] = {'old': None, 'new': val}
                        try:
                            net_changes.pop('IPConfiguration')
                        except KeyError:
                            pass
        __context__.pop(contextkey, None)
    if pre_state != post_state:
        ret['changes']['state'] = {'old': pre_state, 'new': post_state}
        if pre_state is not None:
            comments.append("State changed from '{}' to '{}'".format(pre_state, post_state))
    if exists and current_image_id != image_id:
        comments.append('Container has a new image')
        ret['changes']['image'] = {'old': current_image_id, 'new': image_id}
    if post_state != 'running' and start:
        ret['result'] = False
        comments.append('Container is not running')
    return _format_comments(ret, comments)

def run(name, image=None, bg=False, failhard=True, replace=False, force=False, skip_translate=None, ignore_collisions=False, validate_ip_addrs=True, client_timeout=salt.utils.dockermod.CLIENT_TIMEOUT, **kwargs):
    log.info('Trace')
    "\n    .. versionadded:: 2018.3.0\n\n    .. note::\n        If no tag is specified in the image name, and nothing matching the\n        specified image is pulled on the minion, the ``docker pull`` that\n        retrieves the image will pull *all tags* for the image. A tag of\n        ``latest`` is not implicit for the pull. For this reason, it is\n        recommended to specify the image in ``repo:tag`` notation.\n\n    Like the :py:func:`cmd.run <salt.states.cmd.run>` state, only for Docker.\n    Does the equivalent of a ``docker run`` and returns information about the\n    container that was created, as well as its output.\n\n    This state accepts the same arguments as :py:func:`docker_container.running\n    <salt.states.docker_container.running>`, with the exception of\n    ``watch_action``, ``start``, and ``shutdown_timeout`` (though the ``force``\n    argument has a different meaning in this state).\n\n    In addition, this state accepts the arguments from :py:func:`docker.logs\n    <salt.modules.dockermod.logs>`, with the exception of ``follow``, to\n    control how logs are returned.\n\n    Additionally, the following arguments are supported:\n\n    creates\n        A path or list of paths. Only run if one or more of the specified paths\n        do not exist on the minion.\n\n    bg : False\n        If ``True``, run container in background and do not await or deliver\n        its results.\n\n        .. note::\n            This may not be useful in cases where other states depend on the\n            results of this state. Also, the logs will be inaccessible once the\n            container exits if ``auto_remove`` is set to ``True``, so keep this\n            in mind.\n\n    failhard : True\n        If ``True``, the state will return a ``False`` result if the exit code\n        of the container is non-zero. When this argument is set to ``False``,\n        the state will return a ``True`` result regardless of the container's\n        exit code.\n\n        .. note::\n            This has no effect if ``bg`` is set to ``True``.\n\n    replace : False\n        If ``True``, and if the named container already exists, this will\n        remove the existing container. The default behavior is to return a\n        ``False`` result when the container already exists.\n\n    force : False\n        If ``True``, and the named container already exists, *and* ``replace``\n        is also set to ``True``, then the container will be forcibly removed.\n        Otherwise, the state will not proceed and will return a ``False``\n        result.\n\n    CLI Examples:\n\n    .. code-block:: bash\n\n        salt myminion docker.run_container myuser/myimage command=/usr/local/bin/myscript.sh\n\n    **USAGE EXAMPLE**\n\n    .. code-block:: jinja\n\n        {% set pkg_version = salt.pillar.get('pkg_version', '1.0-1') %}\n        build_package:\n          docker_container.run:\n            - image: myuser/builder:latest\n            - binds: /home/myuser/builds:/build_dir\n            - command: /scripts/build.sh {{ pkg_version }}\n            - creates: /home/myuser/builds/myapp-{{ pkg_version }}.noarch.rpm\n            - replace: True\n            - networks:\n              - mynet\n            - require:\n              - docker_network: mynet\n    "
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    kwargs = salt.utils.args.clean_kwargs(**kwargs)
    for unsupported in ('watch_action', 'start', 'shutdown_timeout', 'follow'):
        if unsupported in kwargs:
            ret['result'] = False
            ret['comment'] = "The '{}' argument is not supported".format(unsupported)
            return ret
    if image is None:
        ret['result'] = False
        ret['comment'] = "The 'image' argument is required"
        return ret
    elif not isinstance(image, str):
        image = str(image)
    try:
        log.info('Trace')
        if 'networks' in kwargs and kwargs['networks'] is not None:
            kwargs['networks'] = _parse_networks(kwargs['networks'])
        _resolve_image(ret, image, client_timeout)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        if exc.info is not None:
            return _format_comments(ret, exc.info)
        else:
            ret['comment'] = exc.__str__()
            return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Container would be run{}'.format(' in the background' if bg else '')
        return ret
    if bg:
        remove = False
    else:
        remove = None
        for item in ('auto_remove', 'rm'):
            try:
                log.info('Trace')
                val = kwargs.pop(item)
            except KeyError:
                log.info('Trace')
                continue
            if remove is not None:
                if not ignore_collisions:
                    ret['result'] = False
                    ret['comment'] = "'rm' is an alias for 'auto_remove', they cannot both be used"
                    return ret
            else:
                remove = bool(val)
        if remove is not None:
            kwargs['auto_remove'] = False
        else:
            remove = False
    try:
        log.info('Trace')
        ret['changes'] = __salt__['docker.run_container'](image, name=name, skip_translate=skip_translate, ignore_collisions=ignore_collisions, validate_ip_addrs=validate_ip_addrs, client_timeout=client_timeout, bg=bg, replace=replace, force=force, **kwargs)
    except Exception as exc:
        log.exception('Encountered error running container')
        ret['result'] = False
        ret['comment'] = 'Encountered error running container: {}'.format(exc)
    else:
        if bg:
            ret['comment'] = 'Container was run in the background'
        else:
            try:
                retcode = ret['changes']['ExitCode']
            except KeyError:
                pass
            else:
                ret['result'] = False if failhard and retcode != 0 else True
                ret['comment'] = 'Container ran and exited with a return code of {}'.format(retcode)
    if remove:
        id_ = ret.get('changes', {}).get('Id')
        if id_:
            try:
                log.info('Trace')
                __salt__['docker.rm'](ret['changes']['Id'])
            except CommandExecutionError as exc:
                log.info('Trace')
                ret.setdefault('warnings', []).append('Failed to auto_remove container: {}'.format(exc))
    return ret

def stopped(name=None, containers=None, shutdown_timeout=None, unpause=False, error_on_absent=True, **kwargs):
    log.info('Trace')
    "\n    Ensure that a container (or containers) is stopped\n\n    name\n        Name or ID of the container\n\n    containers\n        Run this state on more than one container at a time. The following two\n        examples accomplish the same thing:\n\n        .. code-block:: yaml\n\n            stopped_containers:\n              docker_container.stopped:\n                - names:\n                  - foo\n                  - bar\n                  - baz\n\n        .. code-block:: yaml\n\n            stopped_containers:\n              docker_container.stopped:\n                - containers:\n                  - foo\n                  - bar\n                  - baz\n\n        However, the second example will be a bit quicker since Salt will stop\n        all specified containers in a single run, rather than executing the\n        state separately on each image (as it would in the first example).\n\n    shutdown_timeout\n        Timeout for graceful shutdown of the container. If this timeout is\n        exceeded, the container will be killed. If this value is not passed,\n        then the container's configured ``stop_timeout`` will be observed. If\n        ``stop_timeout`` was also unset on the container, then a timeout of 10\n        seconds will be used.\n\n    unpause : False\n        Set to ``True`` to unpause any paused containers before stopping. If\n        unset, then an error will be raised for any container that was paused.\n\n    error_on_absent : True\n        By default, this state will return an error if any of the specified\n        containers are absent. Set this to ``False`` to suppress that error.\n    "
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not name and (not containers):
        ret['comment'] = "One of 'name' and 'containers' must be provided"
        return ret
    if containers is not None:
        if not isinstance(containers, list):
            ret['comment'] = 'containers must be a list'
            return ret
        targets = []
        for target in containers:
            if not isinstance(target, str):
                target = str(target)
            targets.append(target)
    elif name:
        if not isinstance(name, str):
            targets = [str(name)]
        else:
            targets = [name]
    containers = {}
    for target in targets:
        try:
            log.info('Trace')
            c_state = __salt__['docker.state'](target)
        except CommandExecutionError:
            log.info('Trace')
            containers.setdefault('absent', []).append(target)
        else:
            containers.setdefault(c_state, []).append(target)
    errors = []
    if error_on_absent and 'absent' in containers:
        errors.append('The following container(s) are absent: {}'.format(', '.join(containers['absent'])))
    if not unpause and 'paused' in containers:
        ret['result'] = False
        errors.append('The following container(s) are paused: {}'.format(', '.join(containers['paused'])))
    if errors:
        ret['result'] = False
        ret['comment'] = '. '.join(errors)
        return ret
    to_stop = containers.get('running', []) + containers.get('paused', [])
    if not to_stop:
        ret['result'] = True
        if len(targets) == 1:
            ret['comment'] = "Container '{}' is ".format(targets[0])
        else:
            ret['comment'] = 'All specified containers are '
        if 'absent' in containers:
            ret['comment'] += 'absent or '
        ret['comment'] += 'not running'
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'The following container(s) will be stopped: {}'.format(', '.join(to_stop))
        return ret
    stop_errors = []
    for target in to_stop:
        stop_kwargs = {'unpause': unpause}
        if shutdown_timeout:
            stop_kwargs['timeout'] = shutdown_timeout
        changes = __salt__['docker.stop'](target, **stop_kwargs)
        if changes['result'] is True:
            ret['changes'][target] = changes
        elif 'comment' in changes:
            stop_errors.append(changes['comment'])
        else:
            stop_errors.append("Failed to stop container '{}'".format(target))
    if stop_errors:
        ret['comment'] = '; '.join(stop_errors)
        return ret
    ret['result'] = True
    ret['comment'] = 'The following container(s) were stopped: {}'.format(', '.join(to_stop))
    return ret

def absent(name, force=False):
    log.info('Trace')
    '\n    Ensure that a container is absent\n\n    name\n        Name of the container\n\n    force : False\n        Set to ``True`` to remove the container even if it is running\n\n    Usage Examples:\n\n    .. code-block:: yaml\n\n        mycontainer:\n          docker_container.absent\n\n        multiple_containers:\n          docker_container.absent:\n            - names:\n              - foo\n              - bar\n              - baz\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if name not in __salt__['docker.list_containers'](all=True):
        ret['result'] = True
        ret['comment'] = "Container '{}' does not exist".format(name)
        return ret
    pre_state = __salt__['docker.state'](name)
    if pre_state != 'stopped' and (not force):
        ret['comment'] = 'Container is running, set force to True to forcibly remove it'
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = "Container '{}' will be removed".format(name)
        return ret
    try:
        log.info('Trace')
        ret['changes']['removed'] = __salt__['docker.rm'](name, force=force)
    except Exception as exc:
        log.info('Trace')
        ret['comment'] = "Failed to remove container '{}': {}".format(name, exc)
        return ret
    if name in __salt__['docker.list_containers'](all=True):
        ret['comment'] = "Failed to remove container '{}'".format(name)
    else:
        if force and pre_state != 'stopped':
            method = 'Forcibly'
        else:
            method = 'Successfully'
        ret['comment'] = "{} removed container '{}'".format(method, name)
        ret['result'] = True
    return ret

def mod_watch(name, sfun=None, **kwargs):
    """
    The docker_container watcher, called to invoke the watch command.

    .. note::
        This state exists to support special handling of the ``watch``
        :ref:`requisite <requisites>`. It should not be called directly.

        Parameters for this function should be set by the state being triggered.
    """
    if sfun == 'running':
        watch_kwargs = copy.deepcopy(kwargs)
        if watch_kwargs.get('watch_action', 'force') == 'force':
            watch_kwargs['force'] = True
        else:
            watch_kwargs['send_signal'] = True
            watch_kwargs['force'] = False
        return running(name, **watch_kwargs)
    if sfun == 'stopped':
        return stopped(name, **salt.utils.args.clean_kwargs(**kwargs))
    if sfun == 'run':
        return run(name, **salt.utils.args.clean_kwargs(**kwargs))
    return {'name': name, 'changes': {}, 'result': False, 'comment': 'watch requisite is not implemented for {}'.format(sfun)}