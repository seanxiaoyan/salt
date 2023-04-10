"""
The Salt loader is the core to Salt's plugin system, the loader scans
directories for python loadable code and organizes the code into the
plugin interfaces used by Salt.
"""
import contextlib
import inspect
import logging
import os
import re
import time
import types
import salt.config
import salt.defaults.events
import salt.defaults.exitcodes
import salt.loader.context
import salt.syspaths
import salt.utils.context
import salt.utils.data
import salt.utils.dictupdate
import salt.utils.event
import salt.utils.files
import salt.utils.lazy
import salt.utils.odict
import salt.utils.platform
import salt.utils.stringutils
import salt.utils.versions
from salt.exceptions import LoaderError
from salt.template import check_render_pipe_str
from salt.utils import entrypoints
from .lazy import SALT_BASE_PATH, FilterDictWrapper, LazyLoader
log = logging.getLogger(__name__)
LIBCLOUD_FUNCS_NOT_SUPPORTED = ('parallels.avail_sizes', 'parallels.avail_locations', 'proxmox.avail_sizes')
SALT_INTERNAL_LOADERS_PATHS = (str(SALT_BASE_PATH / 'auth'), str(SALT_BASE_PATH / 'beacons'), str(SALT_BASE_PATH / 'cache'), str(SALT_BASE_PATH / 'client' / 'ssh' / 'wrapper'), str(SALT_BASE_PATH / 'cloud' / 'clouds'), str(SALT_BASE_PATH / 'engines'), str(SALT_BASE_PATH / 'executors'), str(SALT_BASE_PATH / 'fileserver'), str(SALT_BASE_PATH / 'grains'), str(SALT_BASE_PATH / 'log_handlers'), str(SALT_BASE_PATH / 'matchers'), str(SALT_BASE_PATH / 'metaproxy'), str(SALT_BASE_PATH / 'modules'), str(SALT_BASE_PATH / 'netapi'), str(SALT_BASE_PATH / 'output'), str(SALT_BASE_PATH / 'pillar'), str(SALT_BASE_PATH / 'proxy'), str(SALT_BASE_PATH / 'queues'), str(SALT_BASE_PATH / 'renderers'), str(SALT_BASE_PATH / 'returners'), str(SALT_BASE_PATH / 'roster'), str(SALT_BASE_PATH / 'runners'), str(SALT_BASE_PATH / 'sdb'), str(SALT_BASE_PATH / 'serializers'), str(SALT_BASE_PATH / 'spm' / 'pkgdb'), str(SALT_BASE_PATH / 'spm' / 'pkgfiles'), str(SALT_BASE_PATH / 'states'), str(SALT_BASE_PATH / 'thorium'), str(SALT_BASE_PATH / 'tokens'), str(SALT_BASE_PATH / 'tops'), str(SALT_BASE_PATH / 'utils'), str(SALT_BASE_PATH / 'wheel'))

def static_loader(opts, ext_type, tag, pack=None, int_type=None, ext_dirs=True, ext_type_dirs=None, base_path=None, filter_name=None, loaded_base_name=None):
    funcs = LazyLoader(_module_dirs(opts, ext_type, tag, int_type, ext_dirs, ext_type_dirs, base_path), opts, tag=tag, pack=pack, loaded_base_name=loaded_base_name)
    ret = {}
    funcs._load_all()
    if filter_name:
        funcs = FilterDictWrapper(funcs, filter_name)
    for key in funcs:
        ret[key] = funcs[key]
    return ret

def _module_dirs(opts, ext_type, tag=None, int_type=None, ext_dirs=True, ext_type_dirs=None, base_path=None, load_extensions=True):
    if tag is None:
        tag = ext_type
    sys_types = os.path.join(base_path or str(SALT_BASE_PATH), int_type or ext_type)
    return_types = [sys_types]
    if opts.get('extension_modules'):
        ext_types = os.path.join(opts['extension_modules'], ext_type)
        return_types.insert(0, ext_types)
    if not sys_types.startswith(SALT_INTERNAL_LOADERS_PATHS):
        raise RuntimeError('{!r} is not considered a salt internal loader path. If this is a new loader being added, please also add it to {}.SALT_INTERNAL_LOADERS_PATHS.'.format(sys_types, __name__))
    ext_type_types = []
    if ext_dirs:
        if ext_type_dirs is None:
            ext_type_dirs = '{}_dirs'.format(tag)
        if ext_type_dirs in opts:
            ext_type_types.extend(opts[ext_type_dirs])
        if ext_type_dirs and load_extensions is True:
            for entry_point in entrypoints.iter_entry_points('salt.loader'):
                with catch_entry_points_exception(entry_point) as ctx:
                    loaded_entry_point = entry_point.load()
                if ctx.exception_caught:
                    continue
                loaded_entry_point_paths = set()
                if isinstance(loaded_entry_point, types.FunctionType):
                    with catch_entry_points_exception(entry_point) as ctx:
                        loaded_entry_point_value = loaded_entry_point()
                    if ctx.exception_caught:
                        continue
                    if isinstance(loaded_entry_point_value, dict):
                        if ext_type not in loaded_entry_point_value:
                            continue
                        with catch_entry_points_exception(entry_point) as ctx:
                            if isinstance(loaded_entry_point_value[ext_type], str):
                                raise ValueError('The callable must return an iterable of strings. A single string is not supported.')
                            for path in loaded_entry_point_value[ext_type]:
                                loaded_entry_point_paths.add(path)
                    else:
                        if entry_point.name != ext_type_dirs:
                            continue
                        for path in loaded_entry_point_value:
                            loaded_entry_point_paths.add(path)
                elif isinstance(loaded_entry_point, types.ModuleType):
                    for loaded_entry_point_path in loaded_entry_point.__path__:
                        with catch_entry_points_exception(entry_point) as ctx:
                            entry_point_ext_type_package_path = os.path.join(loaded_entry_point_path, ext_type)
                            if not os.path.exists(entry_point_ext_type_package_path):
                                continue
                        if ctx.exception_caught:
                            continue
                        loaded_entry_point_paths.add(entry_point_ext_type_package_path)
                else:
                    with catch_entry_points_exception(entry_point):
                        raise ValueError("Don't know how to load a salt extension from {}".format(loaded_entry_point))
                for path in loaded_entry_point_paths:
                    if os.path.exists(path):
                        ext_type_types.append(path)
    cli_module_dirs = []
    for _dir in opts.get('module_dirs', []):
        maybe_dir = os.path.join(_dir, ext_type)
        if os.path.isdir(maybe_dir):
            cli_module_dirs.insert(0, maybe_dir)
            continue
        maybe_dir = os.path.join(_dir, '_{}'.format(ext_type))
        if os.path.isdir(maybe_dir):
            cli_module_dirs.insert(0, maybe_dir)
    return cli_module_dirs + ext_type_types + return_types

def minion_mods(opts, context=None, utils=None, whitelist=None, initial_load=False, loaded_base_name=None, notify=False, static_modules=None, proxy=None):
    log.info('Trace')
    "\n    Load execution modules\n\n    Returns a dictionary of execution modules appropriate for the current\n    system by evaluating the __virtual__() function in each module.\n\n    :param dict opts: The Salt options dictionary\n\n    :param dict context: A Salt context that should be made present inside\n                            generated modules in __context__\n\n    :param dict utils: Utility functions which should be made available to\n                            Salt modules in __utils__. See `utils_dirs` in\n                            salt.config for additional information about\n                            configuration.\n\n    :param list whitelist: A list of modules which should be whitelisted.\n    :param bool initial_load: Deprecated flag! Unused.\n    :param str loaded_base_name: The imported modules namespace when imported\n                                 by the salt loader.\n    :param bool notify: Flag indicating that an event should be fired upon\n                        completion of module loading.\n\n\n    Example:\n\n    .. code-block:: python\n\n        import salt.config\n        import salt.loader\n\n        __opts__ = salt.config.minion_config('/etc/salt/minion')\n        __grains__ = salt.loader.grains(__opts__)\n        __opts__['grains'] = __grains__\n        __utils__ = salt.loader.utils(__opts__)\n        __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__)\n        __salt__['test.ping']()\n    "
    if not whitelist:
        whitelist = opts.get('whitelist_modules', None)
    ret = LazyLoader(_module_dirs(opts, 'modules', 'module'), opts, tag='module', pack={'__context__': context, '__utils__': utils, '__proxy__': proxy, '__opts__': opts}, whitelist=whitelist, loaded_base_name=loaded_base_name, static_modules=static_modules, extra_module_dirs=utils.module_dirs if utils else None, pack_self='__salt__')
    providers = opts.get('providers', False)
    if providers and isinstance(providers, dict):
        for mod in providers:
            try:
                log.info('Trace')
                funcs = raw_mod(opts, providers[mod], ret)
            except TypeError:
                log.info('Trace')
                break
            else:
                if funcs:
                    for func in funcs:
                        f_key = '{}{}'.format(mod, func[func.rindex('.'):])
                        ret[f_key] = funcs[func]
    if notify:
        with salt.utils.event.get_event('minion', opts=opts, listen=False) as evt:
            evt.fire_event({'complete': True}, tag=salt.defaults.events.MINION_MOD_REFRESH_COMPLETE)
    return ret

def raw_mod(opts, name, functions, mod='modules', loaded_base_name=None):
    """
    Returns a single module loaded raw and bypassing the __virtual__ function

    :param dict opts: The Salt options dictionary
    :param str name: The name of the module to load
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param str mod: The extension type.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.

    Example:

    .. code-block:: python

        import salt.config
        import salt.loader

        __opts__ = salt.config.minion_config('/etc/salt/minion')
        testmod = salt.loader.raw_mod(__opts__, 'test', None)
        testmod['test.ping']()
    """
    loader = LazyLoader(_module_dirs(opts, mod, 'module'), opts, tag='rawmodule', virtual_enable=False, pack={'__salt__': functions}, loaded_base_name=loaded_base_name)
    if name not in loader.file_mapping:
        return {}
    loader._load_module(name)
    return dict({x: loader[x] for x in loader._dict})

def metaproxy(opts, loaded_base_name=None):
    """
    Return functions used in the meta proxy

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'metaproxy'), opts, tag='metaproxy', loaded_base_name=loaded_base_name)

def matchers(opts, loaded_base_name=None):
    """
    Return the matcher services plugins

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'matchers'), opts, tag='matchers', loaded_base_name=loaded_base_name)

def engines(opts, functions, runners, utils, proxy=None, loaded_base_name=None):
    """
    Return the engines plugins

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param LazyLoader runners: A LazyLoader instance returned from ``runner``.
    :param LazyLoader utils: A LazyLoader instance returned from ``utils``.
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    pack = {'__salt__': functions, '__runners__': runners, '__proxy__': proxy, '__utils__': utils}
    return LazyLoader(_module_dirs(opts, 'engines'), opts, tag='engines', pack=pack, extra_module_dirs=utils.module_dirs if utils else None, loaded_base_name=loaded_base_name)

def proxy(opts, functions=None, returners=None, whitelist=None, utils=None, context=None, pack_self='__proxy__', loaded_base_name=None):
    """
    Returns the proxy module for this salt-proxy-minion

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param LazyLoader returners: A LazyLoader instance returned from ``returners``.
    :param LazyLoader utils: A LazyLoader instance returned from ``utils``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'proxy'), opts, tag='proxy', pack={'__salt__': functions, '__ret__': returners, '__utils__': utils, '__context__': context}, extra_module_dirs=utils.module_dirs if utils else None, pack_self=pack_self, loaded_base_name=loaded_base_name)

def returners(opts, functions, whitelist=None, context=None, proxy=None, loaded_base_name=None):
    """
    Returns the returner modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param list whitelist: A list of modules which should be whitelisted.
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'returners', 'returner'), opts, tag='returner', whitelist=whitelist, pack={'__salt__': functions, '__context__': context, '__proxy__': proxy or {}}, loaded_base_name=loaded_base_name)

def utils(opts, whitelist=None, context=None, proxy=None, pack_self=None, loaded_base_name=None):
    """
    Returns the utility modules

    :param dict opts: The Salt options dictionary
    :param list whitelist: A list of modules which should be whitelisted.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'utils', ext_type_dirs='utils_dirs', load_extensions=False), opts, tag='utils', whitelist=whitelist, pack={'__context__': context, '__proxy__': proxy or {}}, pack_self=pack_self, loaded_base_name=loaded_base_name, _only_pack_properly_namespaced_functions=False)

def pillars(opts, functions, context=None, loaded_base_name=None):
    """
    Returns the pillars modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    _utils = utils(opts)
    ret = LazyLoader(_module_dirs(opts, 'pillar'), opts, tag='pillar', pack={'__salt__': functions, '__context__': context, '__utils__': _utils}, extra_module_dirs=_utils.module_dirs, pack_self='__ext_pillar__', loaded_base_name=loaded_base_name)
    return FilterDictWrapper(ret, '.ext_pillar')

def tops(opts, loaded_base_name=None):
    """
    Returns the tops modules

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    if 'master_tops' not in opts:
        return {}
    whitelist = list(opts['master_tops'].keys())
    ret = LazyLoader(_module_dirs(opts, 'tops', 'top'), opts, tag='top', whitelist=whitelist, loaded_base_name=loaded_base_name)
    return FilterDictWrapper(ret, '.top')

def wheels(opts, whitelist=None, context=None, loaded_base_name=None):
    """
    Returns the wheels modules

    :param dict opts: The Salt options dictionary
    :param list whitelist: A list of modules which should be whitelisted.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    if context is None:
        context = {}
    return LazyLoader(_module_dirs(opts, 'wheel'), opts, tag='wheel', whitelist=whitelist, pack={'__context__': context}, loaded_base_name=loaded_base_name)

def outputters(opts, loaded_base_name=None):
    """
    Returns the outputters modules

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    :returns: LazyLoader instance, with only outputters present in the keyspace
    """
    ret = LazyLoader(_module_dirs(opts, 'output', ext_type_dirs='outputter_dirs'), opts, tag='output', loaded_base_name=loaded_base_name)
    wrapped_ret = FilterDictWrapper(ret, '.output')
    ret.pack['__salt__'] = wrapped_ret
    return wrapped_ret

def serializers(opts, loaded_base_name=None):
    """
    Returns the serializers modules
    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    :returns: LazyLoader instance, with only serializers present in the keyspace
    """
    return LazyLoader(_module_dirs(opts, 'serializers'), opts, tag='serializers', loaded_base_name=loaded_base_name)

def eauth_tokens(opts, loaded_base_name=None):
    """
    Returns the tokens modules
    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    :returns: LazyLoader instance, with only token backends present in the keyspace
    """
    return LazyLoader(_module_dirs(opts, 'tokens'), opts, tag='tokens', loaded_base_name=loaded_base_name)

def auth(opts, whitelist=None, loaded_base_name=None):
    """
    Returns the auth modules

    :param dict opts: The Salt options dictionary

    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param list whitelist: A list of modules which should be whitelisted.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    :returns: LazyLoader
    """
    return LazyLoader(_module_dirs(opts, 'auth'), opts, tag='auth', whitelist=whitelist, pack={'__salt__': minion_mods(opts)}, loaded_base_name=loaded_base_name)

def fileserver(opts, backends, loaded_base_name=None):
    """
    Returns the file server modules

    :param dict opts: The Salt options dictionary
    :param list backends: List of backends to load.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    _utils = utils(opts)
    if backends is not None:
        if not isinstance(backends, list):
            backends = [backends]
        backend_set = set()
        vcs_re = re.compile('^(git|svn|hg)(?:fs)?$')
        for backend in backends:
            match = vcs_re.match(backend)
            if match:
                backend_set.add(match.group(1))
                backend_set.add(match.group(1) + 'fs')
            else:
                backend_set.add(backend)
        backends = list(backend_set)
    return LazyLoader(_module_dirs(opts, 'fileserver'), opts, tag='fileserver', whitelist=backends, pack={'__utils__': _utils}, extra_module_dirs=_utils.module_dirs, loaded_base_name=loaded_base_name)

def roster(opts, runner=None, utils=None, whitelist=None, loaded_base_name=None):
    """
    Returns the roster modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader runner: A LazyLoader instance returned from ``runner``.
    :param LazyLoader utils: A LazyLoader instance returned from ``utils``.
    :param list whitelist: A list of modules which should be whitelisted.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'roster'), opts, tag='roster', whitelist=whitelist, pack={'__runner__': runner, '__utils__': utils}, extra_module_dirs=utils.module_dirs if utils else None, loaded_base_name=loaded_base_name)

def thorium(opts, functions, runners, loaded_base_name=None):
    """
    Load the thorium runtime modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param LazyLoader runners: A LazyLoader instance returned from ``runner``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    pack = {'__salt__': functions, '__runner__': runners, '__context__': {}}
    ret = LazyLoader(_module_dirs(opts, 'thorium'), opts, tag='thorium', pack=pack, loaded_base_name=loaded_base_name)
    ret.pack['__thorium__'] = ret
    return ret

def states(opts, functions, utils, serializers, whitelist=None, proxy=None, context=None, loaded_base_name=None):
    """
    Returns the state modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param LazyLoader runners: A LazyLoader instance returned from ``runner``.
    :param LazyLoader utils: A LazyLoader instance returned from ``utils``.
    :param LazyLoader serializers: An optional LazyLoader instance returned from ``serializers``.
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param list whitelist: A list of modules which should be whitelisted.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.

    .. code-block:: python

        import salt.config
        import salt.loader

        __opts__ = salt.config.minion_config('/etc/salt/minion')
        statemods = salt.loader.states(__opts__, None, None)
    """
    if context is None:
        context = {}
    return LazyLoader(_module_dirs(opts, 'states'), opts, tag='states', pack={'__salt__': functions, '__proxy__': proxy or {}, '__utils__': utils, '__serializers__': serializers, '__context__': context}, whitelist=whitelist, extra_module_dirs=utils.module_dirs if utils else None, pack_self='__states__', loaded_base_name=loaded_base_name)

def beacons(opts, functions, context=None, proxy=None, loaded_base_name=None):
    """
    Load the beacon modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'beacons'), opts, tag='beacons', pack={'__context__': context, '__salt__': functions, '__proxy__': proxy or {}}, virtual_funcs=[], loaded_base_name=loaded_base_name)

def log_handlers(opts, loaded_base_name=None):
    """
    Returns the custom logging handler modules

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    ret = LazyLoader(_module_dirs(opts, 'log_handlers'), opts, tag='log_handlers', loaded_base_name=loaded_base_name)
    return FilterDictWrapper(ret, '.setup_handlers')

def ssh_wrapper(opts, functions=None, context=None, loaded_base_name=None):
    """
    Returns the custom logging handler modules

    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'wrapper', base_path=str(SALT_BASE_PATH / 'client' / 'ssh')), opts, tag='wrapper', pack={'__salt__': functions, '__context__': context}, loaded_base_name=loaded_base_name)

def render(opts, functions, states=None, proxy=None, context=None, loaded_base_name=None):
    """
    Returns the render modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param LazyLoader states: A LazyLoader instance returned from ``states``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    if context is None:
        context = {}
    pack = {'__salt__': functions, '__grains__': opts.get('grains', {}), '__context__': context}
    if states:
        pack['__states__'] = states
    if proxy is None:
        proxy = {}
    pack['__proxy__'] = proxy
    ret = LazyLoader(_module_dirs(opts, 'renderers', 'render', ext_type_dirs='render_dirs'), opts, tag='render', pack=pack, loaded_base_name=loaded_base_name)
    rend = FilterDictWrapper(ret, '.render')
    if not check_render_pipe_str(opts['renderer'], rend, opts['renderer_blacklist'], opts['renderer_whitelist']):
        err = 'The renderer {} is unavailable, this error is often because the needed software is unavailable'.format(opts['renderer'])
        log.critical(err)
        raise LoaderError(err)
    return rend

def grain_funcs(opts, proxy=None, context=None, loaded_base_name=None):
    """
    Returns the grain functions

    :param dict opts: The Salt options dictionary
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.

      .. code-block:: python

          import salt.config
          import salt.loader

          __opts__ = salt.config.minion_config('/etc/salt/minion')
          grainfuncs = salt.loader.grain_funcs(__opts__)
    """
    _utils = utils(opts, proxy=proxy)
    pack = {'__utils__': utils(opts, proxy=proxy), '__context__': context}
    ret = LazyLoader(_module_dirs(opts, 'grains', 'grain', ext_type_dirs='grains_dirs'), opts, tag='grains', extra_module_dirs=_utils.module_dirs, pack=pack, loaded_base_name=loaded_base_name)
    ret.pack['__utils__'] = _utils
    return ret

def _format_cached_grains(cached_grains):
    """
    Returns cached grains with fixed types, like tuples.
    """
    if cached_grains.get('osrelease_info'):
        osrelease_info = cached_grains['osrelease_info']
        if isinstance(osrelease_info, list):
            cached_grains['osrelease_info'] = tuple(osrelease_info)
    return cached_grains

def _load_cached_grains(opts, cfn):
    """
    Returns the grains cached in cfn, or None if the cache is too old or is
    corrupted.
    """
    if not os.path.isfile(cfn):
        log.debug('Grains cache file does not exist.')
        return None
    grains_cache_age = int(time.time() - os.path.getmtime(cfn))
    if grains_cache_age > opts.get('grains_cache_expiration', 300):
        log.debug('Grains cache last modified %s seconds ago and cache expiration is set to %s. Grains cache expired. Refreshing.', grains_cache_age, opts.get('grains_cache_expiration', 300))
        return None
    if opts.get('refresh_grains_cache', False):
        log.debug('refresh_grains_cache requested, Refreshing.')
        return None
    log.debug('Retrieving grains from cache')
    try:
        with salt.utils.files.fopen(cfn, 'rb') as fp_:
            cached_grains = salt.utils.data.decode(salt.payload.load(fp_), preserve_tuples=True)
        if not cached_grains:
            log.debug('Cached grains are empty, cache might be corrupted. Refreshing.')
            return None
        return _format_cached_grains(cached_grains)
    except OSError:
        return None

def grains(opts, force_refresh=False, proxy=None, context=None, loaded_base_name=None):
    """
    Return the functions for the dynamic grains and the values for the static
    grains.

    :param dict opts: The Salt options dictionary
    :param bool force_refresh: Force the refresh of grains
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.

    Since grains are computed early in the startup process, grains functions
    do not have __salt__ or __proxy__ available.  At proxy-minion startup,
    this function is called with the proxymodule LazyLoader object so grains
    functions can communicate with their controlled device.

    .. code-block:: python

        import salt.config
        import salt.loader

        __opts__ = salt.config.minion_config('/etc/salt/minion')
        __grains__ = salt.loader.grains(__opts__)
        print __grains__['id']
    """
    import salt.config
    cfn = os.path.join(opts['cachedir'], 'grains.cache.p')
    if not force_refresh and opts.get('grains_cache', False):
        cached_grains = _load_cached_grains(opts, cfn)
        if cached_grains:
            return cached_grains
    else:
        log.debug('Grains refresh requested. Refreshing grains.')
    if opts.get('skip_grains', False):
        return {}
    grains_deep_merge = opts.get('grains_deep_merge', False) is True
    if 'conf_file' in opts:
        pre_opts = {}
        pre_opts.update(salt.config.load_config(opts['conf_file'], 'SALT_MINION_CONFIG', salt.config.DEFAULT_MINION_OPTS['conf_file']))
        default_include = pre_opts.get('default_include', opts['default_include'])
        include = pre_opts.get('include', [])
        pre_opts.update(salt.config.include_config(default_include, opts['conf_file'], verbose=False))
        pre_opts.update(salt.config.include_config(include, opts['conf_file'], verbose=True))
        if 'grains' in pre_opts:
            opts['grains'] = pre_opts['grains']
        else:
            opts['grains'] = {}
    else:
        opts['grains'] = {}
    grains_data = {}
    blist = opts.get('grains_blacklist', [])
    funcs = grain_funcs(opts, proxy=proxy, context=context or {}, loaded_base_name=loaded_base_name)
    if force_refresh:
        funcs.clear()
    for key in funcs:
        if not key.startswith('core.'):
            continue
        log.trace('Loading %s grain', key)
        ret = funcs[key]()
        if not isinstance(ret, dict):
            continue
        if blist:
            for key in list(ret):
                for block in blist:
                    if salt.utils.stringutils.expr_match(key, block):
                        del ret[key]
                        log.trace('Filtering %s grain', key)
            if not ret:
                continue
        if grains_deep_merge:
            salt.utils.dictupdate.update(grains_data, ret)
        else:
            grains_data.update(ret)
    for key in funcs:
        if key.startswith('core.') or key == '_errors':
            continue
        try:
            log.trace('Loading %s grain', key)
            parameters = inspect.signature(funcs[key]).parameters
            kwargs = {}
            if 'proxy' in parameters:
                kwargs['proxy'] = proxy
            if 'grains' in parameters:
                kwargs['grains'] = grains_data
            ret = funcs[key](**kwargs)
        except Exception:
            if salt.utils.platform.is_proxy():
                log.info('The following CRITICAL message may not be an error; the proxy may not be completely established yet.')
            log.critical('Failed to load grains defined in grain file %s in function %s, error:\n', key, funcs[key], exc_info=True)
            continue
        if not isinstance(ret, dict):
            continue
        if blist:
            for key in list(ret):
                for block in blist:
                    if salt.utils.stringutils.expr_match(key, block):
                        del ret[key]
                        log.trace('Filtering %s grain', key)
            if not ret:
                continue
        if grains_deep_merge:
            salt.utils.dictupdate.update(grains_data, ret)
        else:
            grains_data.update(ret)
    if opts.get('proxy_merge_grains_in_module', True) and proxy:
        try:
            proxytype = proxy.opts['proxy']['proxytype']
            if proxytype + '.grains' in proxy:
                if proxytype + '.initialized' in proxy and proxy[proxytype + '.initialized']():
                    try:
                        proxytype = proxy.opts['proxy']['proxytype']
                        ret = proxy[proxytype + '.grains']()
                        if grains_deep_merge:
                            salt.utils.dictupdate.update(grains_data, ret)
                        else:
                            grains_data.update(ret)
                    except Exception:
                        log.critical("Failed to run proxy's grains function!", exc_info=True)
        except KeyError:
            pass
    grains_data.update(opts['grains'])
    if opts.get('grains_cache', False):
        with salt.utils.files.set_umask(63):
            try:
                if salt.utils.platform.is_windows():
                    import salt.modules.cmdmod
                    salt.modules.cmdmod._run_quiet('attrib -R "{}"'.format(cfn))
                with salt.utils.files.fopen(cfn, 'w+b') as fp_:
                    try:
                        salt.payload.dump(grains_data, fp_)
                    except TypeError as e:
                        log.error('Failed to serialize grains cache: %s', e)
                        raise
            except Exception as e:
                log.error('Unable to write to grains cache file %s: %s', cfn, e)
                if os.path.isfile(cfn):
                    os.unlink(cfn)
    if grains_deep_merge:
        salt.utils.dictupdate.update(grains_data, opts['grains'])
    else:
        grains_data.update(opts['grains'])
    return salt.utils.data.decode(grains_data, preserve_tuples=True)

def call(fun, **kwargs):
    """
    Directly call a function inside a loader directory
    """
    args = kwargs.get('args', [])
    dirs = kwargs.get('dirs', [])
    loaded_base_name = kwargs.pop('loaded_base_name', None)
    funcs = LazyLoader([str(SALT_BASE_PATH / 'modules')] + dirs, None, tag='modules', virtual_enable=False, loaded_base_name=loaded_base_name)
    return funcs[fun](*args)

def runner(opts, utils=None, context=None, whitelist=None, loaded_base_name=None):
    """
    Directly call a function inside a loader directory

    :param dict opts: The Salt options dictionary
    :param list whitelist: A list of modules which should be whitelisted.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader utils: A LazyLoader instance returned from ``utils``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    if utils is None:
        utils = {}
    if context is None:
        context = {}
    return LazyLoader(_module_dirs(opts, 'runners', 'runner', ext_type_dirs='runner_dirs'), opts, tag='runners', pack={'__utils__': utils, '__context__': context}, whitelist=whitelist, extra_module_dirs=utils.module_dirs if utils else None, pack_self='__salt__', loaded_base_name=loaded_base_name)

def queues(opts, loaded_base_name=None):
    """
    Directly call a function inside a loader directory

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'queues', 'queue', ext_type_dirs='queue_dirs'), opts, tag='queues', loaded_base_name=loaded_base_name)

def sdb(opts, functions=None, whitelist=None, utils=None, loaded_base_name=None):
    """
    Make a very small database call

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param list whitelist: A list of modules which should be whitelisted.
    :param LazyLoader utils: A LazyLoader instance returned from ``utils``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    if utils is None:
        utils = {}
    return LazyLoader(_module_dirs(opts, 'sdb'), opts, tag='sdb', pack={'__sdb__': functions, '__utils__': utils, '__salt__': minion_mods(opts, utils=utils)}, whitelist=whitelist, extra_module_dirs=utils.module_dirs if utils else None, loaded_base_name=loaded_base_name)

def pkgdb(opts, loaded_base_name=None):
    """
    Return modules for SPM's package database

    .. versionadded:: 2015.8.0

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'pkgdb', base_path=str(SALT_BASE_PATH / 'spm')), opts, tag='pkgdb', loaded_base_name=loaded_base_name)

def pkgfiles(opts, loaded_base_name=None):
    """
    Return modules for SPM's file handling

    .. versionadded:: 2015.8.0


    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'pkgfiles', base_path=str(SALT_BASE_PATH / 'spm')), opts, tag='pkgfiles', loaded_base_name=loaded_base_name)

def clouds(opts, loaded_base_name=None):
    """
    Return the cloud functions

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    _utils = utils(opts)
    functions = LazyLoader(_module_dirs(opts, 'clouds', 'cloud', base_path=str(SALT_BASE_PATH / 'cloud'), int_type='clouds'), opts, tag='clouds', pack={'__utils__': _utils, '__active_provider_name__': None}, extra_module_dirs=_utils.module_dirs, loaded_base_name=loaded_base_name)
    for funcname in LIBCLOUD_FUNCS_NOT_SUPPORTED:
        log.trace("'%s' has been marked as not supported. Removing from the list of supported cloud functions", funcname)
        functions.pop(funcname, None)
    return functions

def netapi(opts, loaded_base_name=None):
    """
    Return the network api functions

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'netapi'), opts, tag='netapi', loaded_base_name=loaded_base_name)

def executors(opts, functions=None, context=None, proxy=None, loaded_base_name=None):
    """
    Returns the executor modules

    :param dict opts: The Salt options dictionary
    :param LazyLoader functions: A LazyLoader instance returned from ``minion_mods``.
    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__
    :param LazyLoader proxy: An optional LazyLoader instance returned from ``proxy``.
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    if proxy is None:
        proxy = {}
    if context is None:
        context = {}
    return LazyLoader(_module_dirs(opts, 'executors', 'executor'), opts, tag='executor', pack={'__salt__': functions, '__context__': context, '__proxy__': proxy}, pack_self='__executors__', loaded_base_name=loaded_base_name)

def cache(opts, loaded_base_name=None):
    """
    Returns the returner modules

    :param dict opts: The Salt options dictionary
    :param str loaded_base_name: The imported modules namespace when imported
                                 by the salt loader.
    """
    return LazyLoader(_module_dirs(opts, 'cache', 'cache'), opts, tag='cache', loaded_base_name=loaded_base_name)

@contextlib.contextmanager
def catch_entry_points_exception(entry_point):
    context = types.SimpleNamespace(exception_caught=False)
    try:
        log.info('Trace')
        yield context
    except Exception as exc:
        context.exception_caught = True
        entry_point_details = entrypoints.name_and_version_from_entry_point(entry_point)
        log.error('Error processing Salt Extension %s(version: %s): %s', entry_point_details.name, entry_point_details.version, exc, exc_info_on_loglevel=logging.DEBUG)