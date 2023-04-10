"""
Functions to translate input for container creation
"""
import os
from salt.exceptions import SaltInvocationError
from . import helpers
import logging
log = logging.getLogger(__name__)
ALIASES = {'cmd': 'command', 'cpuset': 'cpuset_cpus', 'dns_option': 'dns_opt', 'env': 'environment', 'expose': 'ports', 'interactive': 'stdin_open', 'ipc': 'ipc_mode', 'label': 'labels', 'memory': 'mem_limit', 'memory_swap': 'memswap_limit', 'publish': 'port_bindings', 'publish_all': 'publish_all_ports', 'restart': 'restart_policy', 'rm': 'auto_remove', 'sysctl': 'sysctls', 'security_opts': 'security_opt', 'ulimit': 'ulimits', 'user_ns_mode': 'userns_mode', 'volume': 'volumes', 'workdir': 'working_dir'}
ALIASES_REVMAP = {y: x for (x, y) in ALIASES.items()}

def _merge_keys(kwargs):
    """
    The log_config is a mixture of the CLI options --log-driver and --log-opt
    (which we support in Salt as log_driver and log_opt, respectively), but it
    must be submitted to the host config in the format {'Type': log_driver,
    'Config': log_opt}. So, we need to construct this argument to be passed to
    the API from those two arguments.
    """
    log_driver = kwargs.pop('log_driver', helpers.NOTSET)
    log_opt = kwargs.pop('log_opt', helpers.NOTSET)
    if 'log_config' not in kwargs:
        if log_driver is not helpers.NOTSET or log_opt is not helpers.NOTSET:
            kwargs['log_config'] = {'Type': log_driver if log_driver is not helpers.NOTSET else 'none', 'Config': log_opt if log_opt is not helpers.NOTSET else {}}

def _post_processing(kwargs, skip_translate, invalid):
    """
    Additional container-specific post-translation processing
    """
    if kwargs.get('port_bindings') is not None and kwargs.get('publish_all_ports'):
        kwargs.pop('port_bindings')
        invalid['port_bindings'] = 'Cannot be used when publish_all_ports=True'
    if kwargs.get('hostname') is not None and kwargs.get('network_mode') == 'host':
        kwargs.pop('hostname')
        invalid['hostname'] = 'Cannot be used when network_mode=True'
    if kwargs.get('binds') is not None and (skip_translate is True or all((x not in skip_translate for x in ('binds', 'volume', 'volumes')))):
        auto_volumes = []
        if isinstance(kwargs['binds'], dict):
            for val in kwargs['binds'].values():
                try:
                    if 'bind' in val:
                        auto_volumes.append(val['bind'])
                except TypeError:
                    continue
        else:
            if isinstance(kwargs['binds'], list):
                auto_volume_defs = kwargs['binds']
            else:
                try:
                    auto_volume_defs = helpers.split(kwargs['binds'])
                except AttributeError:
                    auto_volume_defs = []
            for val in auto_volume_defs:
                try:
                    auto_volumes.append(helpers.split(val, ':')[1])
                except IndexError:
                    continue
        if auto_volumes:
            actual_volumes = kwargs.setdefault('volumes', [])
            actual_volumes.extend([x for x in auto_volumes if x not in actual_volumes])
            actual_volumes.sort()
    if kwargs.get('port_bindings') is not None and all((x not in skip_translate for x in ('port_bindings', 'expose', 'ports'))):
        ports_to_bind = list(kwargs['port_bindings'])
        if ports_to_bind:
            ports_to_open = set(kwargs.get('ports', []))
            ports_to_open.update([helpers.get_port_def(x) for x in ports_to_bind])
            kwargs['ports'] = list(ports_to_open)
    if 'ports' in kwargs and all((x not in skip_translate for x in ('expose', 'ports'))):
        for (index, _) in enumerate(kwargs['ports']):
            try:
                if kwargs['ports'][index][1] == 'tcp':
                    kwargs['ports'][index] = ports_to_open[index][0]
            except TypeError:
                continue

def auto_remove(val, **kwargs):
    return helpers.translate_bool(val)

def binds(val, **kwargs):
    log.info('Trace')
    '\n    On the CLI, these are passed as multiple instances of a given CLI option.\n    In Salt, we accept these as a comma-delimited list but the API expects a\n    Python list.\n    '
    if not isinstance(val, dict):
        if not isinstance(val, list):
            try:
                log.info('Trace')
                val = helpers.split(val)
            except AttributeError:
                log.info('Trace')
                raise SaltInvocationError("'{}' is not a dictionary or list of bind definitions".format(val))
    return val

def blkio_weight(val, **kwargs):
    return helpers.translate_int(val)

def blkio_weight_device(val, **kwargs):
    """
    CLI input is a list of PATH:WEIGHT pairs, but the API expects a list of
    dictionaries in the format [{'Path': path, 'Weight': weight}]
    """
    val = helpers.map_vals(val, 'Path', 'Weight')
    for item in val:
        try:
            item['Weight'] = int(item['Weight'])
        except (TypeError, ValueError):
            raise SaltInvocationError("Weight '{Weight}' for path '{Path}' is not an integer".format(**item))
    return val

def cap_add(val, **kwargs):
    return helpers.translate_stringlist(val)

def cap_drop(val, **kwargs):
    return helpers.translate_stringlist(val)

def command(val, **kwargs):
    return helpers.translate_command(val)

def cpuset_cpus(val, **kwargs):
    return helpers.translate_str(val)

def cpuset_mems(val, **kwargs):
    return helpers.translate_str(val)

def cpu_group(val, **kwargs):
    return helpers.translate_int(val)

def cpu_period(val, **kwargs):
    return helpers.translate_int(val)

def cpu_shares(val, **kwargs):
    return helpers.translate_int(val)

def detach(val, **kwargs):
    return helpers.translate_bool(val)

def device_read_bps(val, **kwargs):
    return helpers.translate_device_rates(val, numeric_rate=False)

def device_read_iops(val, **kwargs):
    return helpers.translate_device_rates(val, numeric_rate=True)

def device_write_bps(val, **kwargs):
    return helpers.translate_device_rates(val, numeric_rate=False)

def device_write_iops(val, **kwargs):
    return helpers.translate_device_rates(val, numeric_rate=True)

def devices(val, **kwargs):
    return helpers.translate_stringlist(val)

def dns_opt(val, **kwargs):
    return helpers.translate_stringlist(val)

def dns_search(val, **kwargs):
    return helpers.translate_stringlist(val)

def dns(val, **kwargs):
    val = helpers.translate_stringlist(val)
    if kwargs.get('validate_ip_addrs', True):
        for item in val:
            helpers.validate_ip(item)
    return val

def domainname(val, **kwargs):
    return helpers.translate_str(val)

def entrypoint(val, **kwargs):
    return helpers.translate_command(val)

def environment(val, **kwargs):
    return helpers.translate_key_val(val, delimiter='=')

def extra_hosts(val, **kwargs):
    val = helpers.translate_key_val(val, delimiter=':')
    if kwargs.get('validate_ip_addrs', True):
        for key in val:
            helpers.validate_ip(val[key])
    return val

def group_add(val, **kwargs):
    return helpers.translate_stringlist(val)

def host_config(val, **kwargs):
    return helpers.translate_dict(val)

def hostname(val, **kwargs):
    return helpers.translate_str(val)

def ipc_mode(val, **kwargs):
    return helpers.translate_str(val)

def isolation(val, **kwargs):
    return helpers.translate_str(val)

def labels(val, **kwargs):
    return helpers.translate_labels(val)

def links(val, **kwargs):
    return helpers.translate_key_val(val, delimiter=':')

def log_driver(val, **kwargs):
    return helpers.translate_str(val)

def log_opt(val, **kwargs):
    return helpers.translate_key_val(val, delimiter='=')

def lxc_conf(val, **kwargs):
    return helpers.translate_key_val(val, delimiter='=')

def mac_address(val, **kwargs):
    return helpers.translate_str(val)

def mem_limit(val, **kwargs):
    return helpers.translate_bytes(val)

def mem_swappiness(val, **kwargs):
    return helpers.translate_int(val)

def memswap_limit(val, **kwargs):
    return helpers.translate_bytes(val)

def name(val, **kwargs):
    return helpers.translate_str(val)

def network_disabled(val, **kwargs):
    return helpers.translate_bool(val)

def network_mode(val, **kwargs):
    return helpers.translate_str(val)

def oom_kill_disable(val, **kwargs):
    return helpers.translate_bool(val)

def oom_score_adj(val, **kwargs):
    return helpers.translate_int(val)

def pid_mode(val, **kwargs):
    return helpers.translate_str(val)

def pids_limit(val, **kwargs):
    return helpers.translate_int(val)

def port_bindings(val, **kwargs):
    """
    On the CLI, these are passed as multiple instances of a given CLI option.
    In Salt, we accept these as a comma-delimited list but the API expects a
    Python dictionary mapping ports to their bindings. The format the API
    expects is complicated depending on whether or not the external port maps
    to a different internal port, or if the port binding is for UDP instead of
    TCP (the default). For reference, see the "Port bindings" section in the
    docker-py documentation at the following URL:
    http://docker-py.readthedocs.io/en/stable/api.html
    """
    validate_ip_addrs = kwargs.get('validate_ip_addrs', True)
    if not isinstance(val, dict):
        if not isinstance(val, list):
            try:
                val = helpers.split(val)
            except AttributeError:
                val = helpers.split(str(val))
        for (idx, item) in enumerate(val):
            if not isinstance(item, str):
                val[idx] = str(item)

        def _format_port(port_num, proto):
            return str(port_num) + '/udp' if proto.lower() == 'udp' else port_num
        bindings = {}
        for binding in val:
            bind_parts = helpers.split(binding, ':')
            num_bind_parts = len(bind_parts)
            if num_bind_parts == 1:
                container_port = str(bind_parts[0])
                if container_port == '':
                    raise SaltInvocationError('Empty port binding definition found')
                (container_port, _, proto) = container_port.partition('/')
                try:
                    (start, end) = helpers.get_port_range(container_port)
                except ValueError as exc:
                    raise SaltInvocationError(exc.__str__())
                bind_vals = [(_format_port(port_num, proto), None) for port_num in range(start, end + 1)]
            elif num_bind_parts == 2:
                if bind_parts[0] == '':
                    raise SaltInvocationError("Empty host port in port binding definition '{}'".format(binding))
                if bind_parts[1] == '':
                    raise SaltInvocationError("Empty container port in port binding definition '{}'".format(binding))
                (container_port, _, proto) = bind_parts[1].partition('/')
                try:
                    (cport_start, cport_end) = helpers.get_port_range(container_port)
                    (hport_start, hport_end) = helpers.get_port_range(bind_parts[0])
                except ValueError as exc:
                    raise SaltInvocationError(exc.__str__())
                if hport_end - hport_start != cport_end - cport_start:
                    raise SaltInvocationError('Host port range ({}) does not have the same number of ports as the container port range ({})'.format(bind_parts[0], container_port))
                cport_list = list(range(cport_start, cport_end + 1))
                hport_list = list(range(hport_start, hport_end + 1))
                bind_vals = [(_format_port(item, proto), hport_list[ind]) for (ind, item) in enumerate(cport_list)]
            elif num_bind_parts == 3:
                (host_ip, host_port) = bind_parts[0:2]
                if validate_ip_addrs:
                    helpers.validate_ip(host_ip)
                (container_port, _, proto) = bind_parts[2].partition('/')
                try:
                    (cport_start, cport_end) = helpers.get_port_range(container_port)
                except ValueError as exc:
                    raise SaltInvocationError(exc.__str__())
                cport_list = list(range(cport_start, cport_end + 1))
                if host_port == '':
                    hport_list = [None] * len(cport_list)
                else:
                    try:
                        (hport_start, hport_end) = helpers.get_port_range(host_port)
                    except ValueError as exc:
                        raise SaltInvocationError(exc.__str__())
                    hport_list = list(range(hport_start, hport_end + 1))
                    if hport_end - hport_start != cport_end - cport_start:
                        raise SaltInvocationError('Host port range ({}) does not have the same number of ports as the container port range ({})'.format(host_port, container_port))
                bind_vals = [(_format_port(val, proto), (host_ip,) if hport_list[idx] is None else (host_ip, hport_list[idx])) for (idx, val) in enumerate(cport_list)]
            else:
                raise SaltInvocationError("'{}' is an invalid port binding definition (at most 3 components are allowed, found {})".format(binding, num_bind_parts))
            for (cport, bind_def) in bind_vals:
                if cport not in bindings:
                    bindings[cport] = bind_def
                else:
                    if isinstance(bindings[cport], list):
                        bindings[cport].append(bind_def)
                    else:
                        bindings[cport] = [bindings[cport], bind_def]
                    for (idx, val) in enumerate(bindings[cport]):
                        if val is None:
                            try:
                                bindings[cport][idx] = int(cport.split('/')[0])
                            except AttributeError:
                                bindings[cport][idx] = cport
        val = bindings
    return val

def ports(val, **kwargs):
    """
    Like cap_add, cap_drop, etc., this option can be specified multiple times,
    and each time can be a port number or port range. Ultimately, the API
    expects a list, but elements in the list are ints when the port is TCP, and
    a tuple (port_num, 'udp') when the port is UDP.
    """
    if not isinstance(val, list):
        try:
            val = helpers.split(val)
        except AttributeError:
            if isinstance(val, int):
                val = [val]
            else:
                raise SaltInvocationError("'{}' is not a valid port definition".format(val))
    new_ports = set()
    for item in val:
        if isinstance(item, int):
            new_ports.add(item)
            continue
        try:
            (item, _, proto) = item.partition('/')
        except AttributeError:
            raise SaltInvocationError("'{}' is not a valid port definition".format(item))
        try:
            (range_start, range_end) = helpers.get_port_range(item)
        except ValueError as exc:
            raise SaltInvocationError(exc.__str__())
        new_ports.update([helpers.get_port_def(x, proto) for x in range(range_start, range_end + 1)])
    return list(new_ports)

def privileged(val, **kwargs):
    return helpers.translate_bool(val)

def publish_all_ports(val, **kwargs):
    return helpers.translate_bool(val)

def read_only(val, **kwargs):
    return helpers.translate_bool(val)

def restart_policy(val, **kwargs):
    """
    CLI input is in the format NAME[:RETRY_COUNT] but the API expects {'Name':
    name, 'MaximumRetryCount': retry_count}. We will use the 'fill' kwarg here
    to make sure the mapped result uses '0' for the count if this optional
    value was omitted.
    """
    val = helpers.map_vals(val, 'Name', 'MaximumRetryCount', fill='0')
    if len(val) != 1:
        raise SaltInvocationError('Only one policy is permitted')
    val = val[0]
    try:
        val['MaximumRetryCount'] = int(val['MaximumRetryCount'])
    except (TypeError, ValueError):
        raise SaltInvocationError("Retry count '{}' is non-numeric".format(val['MaximumRetryCount']))
    return val

def security_opt(val, **kwargs):
    return helpers.translate_stringlist(val)

def shm_size(val, **kwargs):
    return helpers.translate_bytes(val)

def stdin_open(val, **kwargs):
    return helpers.translate_bool(val)

def stop_signal(val, **kwargs):
    return helpers.translate_str(val)

def stop_timeout(val, **kwargs):
    return helpers.translate_int(val)

def storage_opt(val, **kwargs):
    return helpers.translate_key_val(val, delimiter='=')

def sysctls(val, **kwargs):
    return helpers.translate_key_val(val, delimiter='=')

def tmpfs(val, **kwargs):
    return helpers.translate_dict(val)

def tty(val, **kwargs):
    return helpers.translate_bool(val)

def ulimits(val, **kwargs):
    log.info('Trace')
    val = helpers.translate_stringlist(val)
    for (idx, item) in enumerate(val):
        if not isinstance(item, dict):
            try:
                log.info('Trace')
                (ulimit_name, limits) = helpers.split(item, '=', 1)
                comps = helpers.split(limits, ':', 1)
            except (AttributeError, ValueError):
                log.info('Trace')
                raise SaltInvocationError("Ulimit definition '{}' is not in the format type=soft_limit[:hard_limit]".format(item))
            if len(comps) == 1:
                comps *= 2
            (soft_limit, hard_limit) = comps
            try:
                log.info('Trace')
                val[idx] = {'Name': ulimit_name, 'Soft': int(soft_limit), 'Hard': int(hard_limit)}
            except (TypeError, ValueError):
                log.info('Trace')
                raise SaltInvocationError("Limit '{}' contains non-numeric value(s)".format(item))
    return val

def user(val, **kwargs):
    log.info('Trace')
    '\n    This can be either a string or a numeric uid\n    '
    if not isinstance(val, int):
        try:
            log.info('Trace')
            val = int(val)
        except (TypeError, ValueError):
            log.info('Trace')
            pass
    if not isinstance(val, (int, str)):
        raise SaltInvocationError('Value must be a username or uid')
    elif isinstance(val, int) and val < 0:
        raise SaltInvocationError("'{}' is an invalid uid".format(val))
    return val

def userns_mode(val, **kwargs):
    return helpers.translate_str(val)

def volume_driver(val, **kwargs):
    return helpers.translate_str(val)

def volumes(val, **kwargs):
    """
    Should be a list of absolute paths
    """
    val = helpers.translate_stringlist(val)
    for item in val:
        if not os.path.isabs(item):
            raise SaltInvocationError("'{}' is not an absolute path".format(item))
    return val

def volumes_from(val, **kwargs):
    return helpers.translate_stringlist(val)

def working_dir(val, **kwargs):
    log.info('Trace')
    '\n    Must be an absolute path\n    '
    try:
        log.info('Trace')
        is_abs = os.path.isabs(val)
    except AttributeError:
        log.info('Trace')
        is_abs = False
    if not is_abs:
        raise SaltInvocationError("'{}' is not an absolute path".format(val))
    return val