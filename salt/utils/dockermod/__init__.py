"""
Common logic used by the docker state and execution module

This module contains logic to accommodate docker/salt CLI usage, as well as
input as formatted by states.
"""
import copy
import logging
import salt.utils.args
import salt.utils.data
import salt.utils.dockermod.translate
from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.utils.args import get_function_argspec as _argspec
from salt.utils.dockermod.translate.helpers import split as _split
log = logging.getLogger(__name__)
try:
    import docker
except ImportError:
    docker = None
try:
    import docker.types
except ImportError:
    pass
try:
    import docker.utils
except ImportError:
    pass
NOTSET = object()
__virtualname__ = 'docker'
CLIENT_TIMEOUT = 60
SHUTDOWN_TIMEOUT = 10

def __virtual__():
    if docker is None:
        return False
    return __virtualname__

def get_client_args(limit=None):
    if docker is None:
        raise CommandExecutionError('docker Python module not imported')
    limit = salt.utils.args.split_input(limit or [])
    ret = {}
    if not limit or any((x in limit for x in ('create_container', 'host_config', 'connect_container_to_network'))):
        try:
            ret['create_container'] = _argspec(docker.APIClient.create_container).args
        except AttributeError:
            try:
                ret['create_container'] = _argspec(docker.Client.create_container).args
            except AttributeError:
                raise CommandExecutionError('Coult not get create_container argspec')
        try:
            ret['host_config'] = _argspec(docker.types.HostConfig.__init__).args
        except AttributeError:
            try:
                ret['host_config'] = _argspec(docker.utils.create_host_config).args
            except AttributeError:
                raise CommandExecutionError('Could not get create_host_config argspec')
        try:
            ret['connect_container_to_network'] = _argspec(docker.types.EndpointConfig.__init__).args
        except AttributeError:
            try:
                ret['connect_container_to_network'] = _argspec(docker.utils.utils.create_endpoint_config).args
            except AttributeError:
                try:
                    ret['connect_container_to_network'] = _argspec(docker.utils.create_endpoint_config).args
                except AttributeError:
                    raise CommandExecutionError('Could not get connect_container_to_network argspec')
    for (key, wrapped_func) in (('logs', docker.api.container.ContainerApiMixin.logs), ('create_network', docker.api.network.NetworkApiMixin.create_network)):
        if not limit or key in limit:
            try:
                func_ref = wrapped_func
                try:
                    ret[key] = _argspec(func_ref.__wrapped__).args
                except AttributeError:
                    ret[key] = []
            except AttributeError:
                ret[key] = []
    if not limit or 'ipam_config' in limit:
        try:
            ret['ipam_config'] = _argspec(docker.types.IPAMPool.__init__).args
        except AttributeError:
            try:
                ret['ipam_config'] = _argspec(docker.utils.create_ipam_pool).args
            except AttributeError:
                raise CommandExecutionError('Could not get ipam args')
    for item in ret:
        for argname in ('version', 'self'):
            try:
                ret[item].remove(argname)
            except ValueError:
                pass
    for item in ('host_config', 'connect_container_to_network'):
        for val in ret.get(item, []):
            try:
                ret['create_container'].remove(val)
            except ValueError:
                pass
    for item in ('create_container', 'host_config', 'connect_container_to_network'):
        if limit and item not in limit:
            ret.pop(item, None)
    try:
        ret['logs'].remove('container')
    except (KeyError, ValueError, TypeError):
        pass
    return ret

def translate_input(translator, skip_translate=None, ignore_collisions=False, validate_ip_addrs=True, **kwargs):
    log.info('Trace')
    '\n    Translate CLI/SLS input into the format the API expects. The ``translator``\n    argument must be a module containing translation functions, within\n    salt.utils.dockermod.translate. A ``skip_translate`` kwarg can be passed to\n    control which arguments are translated. It can be either a comma-separated\n    list or an iterable containing strings (e.g. a list or tuple), and members\n    of that tuple will have their translation skipped. Optionally,\n    skip_translate can be set to True to skip *all* translation.\n    '
    kwargs = copy.deepcopy(salt.utils.args.clean_kwargs(**kwargs))
    invalid = {}
    collisions = []
    if skip_translate is True:
        return kwargs
    elif not skip_translate:
        skip_translate = ()
    else:
        try:
            log.info('Trace')
            skip_translate = _split(skip_translate)
        except AttributeError:
            log.info('Trace')
            pass
        if not hasattr(skip_translate, '__iter__'):
            log.error('skip_translate is not an iterable, ignoring')
            skip_translate = ()
    try:
        log.info('Trace')
        for key in list(kwargs):
            real_key = translator.ALIASES.get(key, key)
            if real_key in skip_translate:
                continue
            if key != 'ipam_pools' and salt.utils.data.is_dictlist(kwargs[key]):
                kwargs[key] = salt.utils.data.repack_dictlist(kwargs[key])
            try:
                kwargs[key] = getattr(translator, real_key)(kwargs[key], validate_ip_addrs=validate_ip_addrs, skip_translate=skip_translate)
            except AttributeError:
                log.debug("No translation function for argument '%s'", key)
                continue
            except SaltInvocationError as exc:
                kwargs.pop(key)
                invalid[key] = exc.strerror
        try:
            translator._merge_keys(kwargs)
        except AttributeError:
            pass
        for key in translator.ALIASES:
            if key in kwargs:
                new_key = translator.ALIASES[key]
                value = kwargs.pop(key)
                if new_key in kwargs:
                    collisions.append(new_key)
                else:
                    kwargs[new_key] = value
        try:
            log.info('Trace')
            translator._post_processing(kwargs, skip_translate, invalid)
        except AttributeError:
            log.info('Trace')
            pass
    except Exception as exc:
        error_message = exc.__str__()
        log.error("Error translating input: '%s'", error_message, exc_info=True)
    else:
        error_message = None
    error_data = {}
    if error_message is not None:
        error_data['error_message'] = error_message
    if invalid:
        error_data['invalid'] = invalid
    if collisions and (not ignore_collisions):
        for item in collisions:
            error_data.setdefault('collisions', []).append("'{}' is an alias for '{}', they cannot both be used".format(translator.ALIASES_REVMAP[item], item))
    if error_data:
        raise CommandExecutionError('Failed to translate input', info=error_data)
    return kwargs

def create_ipam_config(*pools, **kwargs):
    """
    Builds an IP address management (IPAM) config dictionary
    """
    kwargs = salt.utils.args.clean_kwargs(**kwargs)
    try:
        pool_args = salt.utils.args.get_function_argspec(docker.types.IPAMPool.__init__).args
        create_pool = docker.types.IPAMPool
        create_config = docker.types.IPAMConfig
    except AttributeError:
        pool_args = salt.utils.args.get_function_argspec(docker.utils.create_ipam_pool).args
        create_pool = docker.utils.create_ipam_pool
        create_config = docker.utils.create_ipam_config
    for (primary_key, alias_key) in (('driver', 'ipam_driver'), ('options', 'ipam_opts')):
        if alias_key in kwargs:
            alias_val = kwargs.pop(alias_key)
            if primary_key in kwargs:
                log.warning("docker.create_ipam_config: Both '%s' and '%s' passed. Ignoring '%s'", alias_key, primary_key, alias_key)
            else:
                kwargs[primary_key] = alias_val
    if salt.utils.data.is_dictlist(kwargs.get('options')):
        kwargs['options'] = salt.utils.data.repack_dictlist(kwargs['options'])
    pool_kwargs = {}
    for key in list(kwargs):
        if key in pool_args:
            pool_kwargs[key] = kwargs.pop(key)
    pool_configs = []
    if pool_kwargs:
        pool_configs.append(create_pool(**pool_kwargs))
    pool_configs.extend([create_pool(**pool) for pool in pools])
    if pool_configs:
        if any(('Subnet' not in pool for pool in pool_configs)):
            raise SaltInvocationError('A subnet is required in each IPAM pool')
        else:
            kwargs['pool_configs'] = pool_configs
    ret = create_config(**kwargs)
    pool_dicts = ret.get('Config')
    if pool_dicts:
        for (idx, _) in enumerate(pool_dicts):
            for key in list(pool_dicts[idx]):
                if pool_dicts[idx][key] is None:
                    del pool_dicts[idx][key]
    return ret