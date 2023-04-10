import copy
import functools
import importlib
import importlib.machinery
import importlib.util
import inspect
import logging
import os
import pathlib
import re
import sys
import tempfile
import threading
import time
import traceback
import types
from collections.abc import MutableMapping
from zipimport import zipimporter
import salt.config
import salt.defaults.events
import salt.defaults.exitcodes
import salt.loader.context
import salt.syspaths
import salt.utils.args
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
from salt.utils.decorators import Depends
log = logging.getLogger(__name__)
try:
    import _contextvars as contextvars
except ImportError:
    import contextvars
MODULE_KIND_SOURCE = 1
MODULE_KIND_COMPILED = 2
MODULE_KIND_EXTENSION = 3
MODULE_KIND_PKG_DIRECTORY = 5
SUFFIXES = []
for suffix in importlib.machinery.EXTENSION_SUFFIXES:
    SUFFIXES.append((suffix, 'rb', MODULE_KIND_EXTENSION))
for suffix in importlib.machinery.SOURCE_SUFFIXES:
    SUFFIXES.append((suffix, 'rb', MODULE_KIND_SOURCE))
for suffix in importlib.machinery.BYTECODE_SUFFIXES:
    SUFFIXES.append((suffix, 'rb', MODULE_KIND_COMPILED))
MODULE_KIND_MAP = {MODULE_KIND_SOURCE: importlib.machinery.SourceFileLoader, MODULE_KIND_COMPILED: importlib.machinery.SourcelessFileLoader, MODULE_KIND_EXTENSION: importlib.machinery.ExtensionFileLoader}
SALT_BASE_PATH = pathlib.Path(salt.syspaths.INSTALL_DIR).resolve()
LOADED_BASE_NAME = 'salt.loaded'
PY3_PRE_EXT = re.compile('\\.cpython-{}{}(\\.opt-[1-9])?'.format(*sys.version_info[:2]))
pyximport = None

def _generate_module(name):
    if name in sys.modules:
        return
    code = "'''Salt loaded {} parent module'''".format(name.split('.')[-1])
    module = types.ModuleType(str(name))
    exec(code, module.__dict__)
    sys.modules[name] = module

def _mod_type(module_path):
    if module_path.startswith(str(SALT_BASE_PATH)):
        return 'int'
    return 'ext'

class FilterDictWrapper(MutableMapping):
    """
    Create a dict which wraps another dict with a specific key suffix on get

    This is to replace "filter_load"
    """

    def __init__(self, d, suffix):
        self._dict = d
        self.suffix = suffix

    def __setitem__(self, key, val):
        self._dict[key] = val

    def __delitem__(self, key):
        del self._dict[key]

    def __getitem__(self, key):
        return self._dict[key + self.suffix]

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        for key in self._dict:
            if key.endswith(self.suffix):
                yield key.replace(self.suffix, '')

class LoadedFunc:
    """
    The functions loaded by LazyLoader instances using subscript notation
    'a[k]' will be wrapped with LoadedFunc.

      - Makes sure functions are called with the correct loader's context.
      - Provides access to a wrapped func's __global__ attribute

    :param func str: The function name to wrap
    :param LazyLoader loader: The loader instance to use in the context when the wrapped callable is called.
    """

    def __init__(self, name, loader):
        self.name = name
        self.loader = loader
        functools.update_wrapper(self, self.func)

    @property
    def func(self):
        return self.loader._dict[self.name]

    def __getattr__(self, name):
        return getattr(self.func, name)

    def __call__(self, *args, **kwargs):
        run_func = self.func
        if self.loader.inject_globals:
            run_func = global_injector_decorator(self.loader.inject_globals)(run_func)
        return self.loader.run(run_func, *args, **kwargs)

    def __repr__(self):
        return '<{} name={!r}>'.format(self.__class__.__name__, self.name)

class LoadedMod:
    """
    This class is used as a proxy to a loaded module
    """
    __slots__ = ('mod', 'loader')

    def __init__(self, mod, loader):
        """
        Return the wrapped func's globals via this object's __globals__
        attribute.
        """
        self.mod = mod
        self.loader = loader

    def __getattr__(self, name):
        """
        Run the wrapped function in the loader's context.
        """
        try:
            return self.loader['{}.{}'.format(self.mod, name)]
        except KeyError:
            raise AttributeError('No attribute by the name of {} was found on {}'.format(name, self.mod))

    def __repr__(self):
        return "<{} module='{}.{}'>".format(self.__class__.__name__, self.loader.loaded_base_name, self.mod)

class LazyLoader(salt.utils.lazy.LazyDict):
    """
    A pseduo-dictionary which has a set of keys which are the
    name of the module and function, delimited by a dot. When
    the value of the key is accessed, the function is then loaded
    from disk and into memory.

    .. note::

        Iterating over keys will cause all modules to be loaded.

    :param list module_dirs: A list of directories on disk to search for modules
    :param dict opts: The salt options dictionary.
    :param str tag: The tag for the type of module to load
    :param func mod_type_check: A function which can be used to verify files
    :param dict pack: A dictionary of function to be packed into modules as they are loaded
    :param list whitelist: A list of modules to whitelist
    :param bool virtual_enable: Whether or not to respect the __virtual__ function when loading modules.
    :param str virtual_funcs: The name of additional functions in the module to call to verify its functionality.
                                If not true, the module will not load.
    :param list extra_module_dirs: A list of directories that will be able to import from
    :param str pack_self: Pack this module into a variable by this name into modules loaded
    :returns: A LazyLoader object which functions as a dictionary. Keys are 'module.function' and values
    are function references themselves which are loaded on-demand.
    # TODO:
        - move modules_max_memory into here
        - singletons (per tag)
    """
    mod_dict_class = dict

    def __init__(self, module_dirs, opts=None, tag='module', loaded_base_name=None, mod_type_check=None, pack=None, whitelist=None, virtual_enable=True, static_modules=None, proxy=None, virtual_funcs=None, extra_module_dirs=None, pack_self=None, _only_pack_properly_namespaced_functions=True):
        """
        In pack, if any of the values are None they will be replaced with an
        empty context-specific dict
        """
        self.parent_loader = None
        self.inject_globals = {}
        self.pack = {} if pack is None else pack
        for i in self.pack:
            if isinstance(self.pack[i], salt.loader.context.NamedLoaderContext):
                self.pack[i] = self.pack[i].value()
        if opts is None:
            opts = {}
        opts = copy.deepcopy(opts)
        for i in ['pillar', 'grains']:
            if i in opts and isinstance(opts[i], salt.loader.context.NamedLoaderContext):
                opts[i] = opts[i].value()
        threadsafety = not opts.get('multiprocessing')
        self.context_dict = salt.utils.context.ContextDict(threadsafe=threadsafety)
        self.opts = self.__prep_mod_opts(opts)
        self.pack_self = pack_self
        self.module_dirs = module_dirs
        self.tag = tag
        self._gc_finalizer = None
        self.loaded_base_name = loaded_base_name or LOADED_BASE_NAME
        self.mod_type_check = mod_type_check or _mod_type
        self._only_pack_properly_namespaced_functions = _only_pack_properly_namespaced_functions
        if '__context__' not in self.pack:
            self.pack['__context__'] = None
        for (k, v) in self.pack.items():
            if v is None:
                self.context_dict.setdefault(k, {})
                self.pack[k] = salt.utils.context.NamespacedDictWrapper(self.context_dict, k)
        self.whitelist = whitelist
        self.virtual_enable = virtual_enable
        self.initial_load = True
        self.missing_modules = {}
        self.loaded_modules = set()
        self.loaded_files = set()
        self.static_modules = static_modules if static_modules else []
        if virtual_funcs is None:
            virtual_funcs = []
        self.virtual_funcs = virtual_funcs
        self.extra_module_dirs = extra_module_dirs if extra_module_dirs else []
        self._clean_module_dirs = []
        self.disabled = set(self.opts.get('disable_{}{}'.format(self.tag, '' if self.tag[-1] == 's' else 's'), []))
        self.suffix_map = {}
        self.suffix_order = ['']
        for (suffix, mode, kind) in SUFFIXES:
            self.suffix_map[suffix] = (suffix, mode, kind)
            self.suffix_order.append(suffix)
        self._lock = threading.RLock()
        with self._lock:
            self._refresh_file_mapping()
        super().__init__()
        _generate_module('{}.int'.format(self.loaded_base_name))
        _generate_module('{}.int.{}'.format(self.loaded_base_name, tag))
        _generate_module('{}.ext'.format(self.loaded_base_name))
        _generate_module('{}.ext.{}'.format(self.loaded_base_name, tag))

    def clean_modules(self):
        """
        Clean modules
        """
        for name in list(sys.modules):
            if name.startswith(self.loaded_base_name):
                del sys.modules[name]

    def __getitem__(self, item):
        """
        Override the __getitem__ in order to decorate the returned function if we need
        to last-minute inject globals
        """
        super().__getitem__(item)
        return LoadedFunc(item, self)

    def __getattr__(self, mod_name):
        """
        Allow for "direct" attribute access-- this allows jinja templates to
        access things like `salt.test.ping()`
        """
        if mod_name in ('__getstate__', '__setstate__'):
            return object.__getattribute__(self, mod_name)
        try:
            return object.__getattr__(self, mod_name)
        except AttributeError:
            pass
        if mod_name not in self.loaded_modules and (not self.loaded):
            for name in self._iter_files(mod_name):
                if name in self.loaded_files:
                    continue
                if self._load_module(name) and mod_name in self.loaded_modules:
                    break
        if mod_name in self.loaded_modules:
            return LoadedMod(mod_name, self)
        else:
            raise AttributeError(mod_name)

    def __repr__(self):
        return "<{} module='{}.{}'>".format(self.__class__.__name__, self.loaded_base_name, self.tag)

    def missing_fun_string(self, function_name):
        """
        Return the error string for a missing function.

        This can range from "not available' to "__virtual__" returned False
        """
        mod_name = function_name.split('.')[0]
        if mod_name in self.loaded_modules:
            return "'{}' is not available.".format(function_name)
        else:
            try:
                reason = self.missing_modules[mod_name]
            except KeyError:
                return "'{}' is not available.".format(function_name)
            else:
                if reason is not None:
                    return "'{}' __virtual__ returned False: {}".format(mod_name, reason)
                else:
                    return "'{}' __virtual__ returned False".format(mod_name)

    def _refresh_file_mapping(self):
        log.info('Trace')
        '\n        refresh the mapping of the FS on disk\n        '
        if self.opts.get('cython_enable', True) is True and '.pyx' not in self.suffix_map:
            try:
                log.info('Trace')
                global pyximport
                pyximport = __import__('pyximport')
                pyximport.install()
                self.suffix_map['.pyx'] = tuple()
                if '.pyx' not in self.suffix_order:
                    self.suffix_order.append('.pyx')
            except ImportError:
                log.info('Cython is enabled in the options but not present in the system path. Skipping Cython modules.')
        if self.opts.get('enable_zip_modules', True) is True and '.zip' not in self.suffix_map:
            self.suffix_map['.zip'] = tuple()
            if '.zip' not in self.suffix_order:
                self.suffix_order.append('.zip')
        self.suffix_map[''] = ('', '', MODULE_KIND_PKG_DIRECTORY)
        self.file_mapping = salt.utils.odict.OrderedDict()
        opt_match = []

        def _replace_pre_ext(obj):
            """
            Hack so we can get the optimization level that we replaced (if
            any) out of the re.sub call below. We use a list here because
            it is a persistent data structure that we will be able to
            access after re.sub is called.
            """
            opt_match.append(obj)
            return ''
        for mod_dir in self.module_dirs:
            try:
                log.info('Trace')
                files = sorted((x for x in os.listdir(mod_dir) if x != '__pycache__'))
            except OSError:
                log.info('Trace')
                continue
            try:
                log.info('Trace')
                pycache_files = [os.path.join('__pycache__', x) for x in sorted(os.listdir(os.path.join(mod_dir, '__pycache__')))]
            except OSError:
                log.info('Trace')
                pass
            else:
                files.extend(pycache_files)
            for filename in files:
                try:
                    log.info('Trace')
                    (dirname, basename) = os.path.split(filename)
                    if basename.startswith('_'):
                        continue
                    (f_noext, ext) = os.path.splitext(basename)
                    f_noext = PY3_PRE_EXT.sub(_replace_pre_ext, f_noext)
                    try:
                        opt_level = int(opt_match.pop().group(1).rsplit('-', 1)[-1])
                    except (AttributeError, IndexError, ValueError):
                        opt_level = 0
                    try:
                        opt_index = self.opts['optimization_order'].index(opt_level)
                    except KeyError:
                        log.trace("Disallowed optimization level %d for module name '%s', skipping. Add %d to the 'optimization_order' config option if you do not want to ignore this optimization level.", opt_level, f_noext, opt_level)
                        continue
                    if ext not in self.suffix_map:
                        continue
                    if f_noext in self.disabled:
                        log.trace('Skipping %s, it is disabled by configuration', filename)
                        continue
                    fpath = os.path.join(mod_dir, filename)
                    if ext == '':
                        subfiles = os.listdir(fpath)
                        for suffix in self.suffix_order:
                            if '' == suffix:
                                continue
                            init_file = '__init__{}'.format(suffix)
                            if init_file in subfiles:
                                break
                        else:
                            continue
                    try:
                        curr_ext = self.file_mapping[f_noext][1]
                        curr_opt_index = self.file_mapping[f_noext][2]
                    except KeyError:
                        pass
                    else:
                        if '' in (curr_ext, ext) and curr_ext != ext:
                            log.error("Module/package collision: '%s' and '%s'", fpath, self.file_mapping[f_noext][0])
                        if ext == '.pyc' and curr_ext == '.pyc':
                            if opt_index >= curr_opt_index:
                                continue
                        elif not curr_ext or self.suffix_order.index(ext) >= self.suffix_order.index(curr_ext):
                            continue
                    if not dirname and ext == '.pyc':
                        continue
                    self.file_mapping[f_noext] = (fpath, ext, opt_index)
                except OSError:
                    log.info('Trace')
                    continue
        for smod in self.static_modules:
            f_noext = smod.split('.')[-1]
            self.file_mapping[f_noext] = (smod, '.o', 0)

    def clear(self):
        """
        Clear the dict
        """
        with self._lock:
            super().clear()
            self.loaded_files = set()
            self.missing_modules = {}
            self.loaded_modules = set()
            if hasattr(self, 'opts'):
                self._refresh_file_mapping()
            self.initial_load = False

    def __prep_mod_opts(self, opts):
        """
        Strip out of the opts any logger instance
        """
        if '__grains__' not in self.pack:
            grains = opts.get('grains', {})
            if isinstance(grains, salt.loader.context.NamedLoaderContext):
                grains = grains.value()
            self.context_dict['grains'] = grains
            self.pack['__grains__'] = salt.utils.context.NamespacedDictWrapper(self.context_dict, 'grains')
        if '__pillar__' not in self.pack:
            pillar = opts.get('pillar', {})
            if isinstance(pillar, salt.loader.context.NamedLoaderContext):
                pillar = pillar.value()
            self.context_dict['pillar'] = pillar
            self.pack['__pillar__'] = salt.utils.context.NamespacedDictWrapper(self.context_dict, 'pillar')
        mod_opts = {}
        for (key, val) in list(opts.items()):
            if key == 'logger':
                continue
            mod_opts[key] = val
        return mod_opts

    def _iter_files(self, mod_name):
        """
        Iterate over all file_mapping files in order of closeness to mod_name
        """
        if mod_name in self.file_mapping:
            yield mod_name
        for k in self.file_mapping:
            if mod_name in k:
                yield k
        for k in self.file_mapping:
            if mod_name not in k:
                yield k

    def _reload_submodules(self, mod):
        submodules = (getattr(mod, sname) for sname in dir(mod) if isinstance(getattr(mod, sname), mod.__class__))
        for submodule in submodules:
            if submodule.__name__.startswith(mod.__name__ + '.'):
                importlib.reload(submodule)
                self._reload_submodules(submodule)

    def __populate_sys_path(self):
        for directory in self.extra_module_dirs:
            if directory not in sys.path:
                sys.path.append(directory)
                self._clean_module_dirs.append(directory)

    def __clean_sys_path(self):
        invalidate_path_importer_cache = False
        for directory in self._clean_module_dirs:
            if directory in sys.path:
                sys.path.remove(directory)
                invalidate_path_importer_cache = True
        self._clean_module_dirs = []
        importlib.invalidate_caches()
        if invalidate_path_importer_cache:
            for directory in self.extra_module_dirs:
                if directory in sys.path_importer_cache and sys.path_importer_cache[directory] is None:
                    del sys.path_importer_cache[directory]

    def _load_module(self, name):
        mod = None
        (fpath, suffix) = self.file_mapping[name][:2]
        try:
            (implementation_tag, cache_tag_ver) = sys.implementation.cache_tag.split('-')
            if cache_tag_ver not in fpath and implementation_tag in fpath:
                log.trace('Trying to load %s on %s, returning False.', fpath, sys.implementation.cache_tag)
                return False
        except AttributeError:
            pass
        self.loaded_files.add(name)
        fpath_dirname = os.path.dirname(fpath)
        try:
            self.__populate_sys_path()
            sys.path.append(fpath_dirname)
            if suffix == '.pyx':
                mod = pyximport.load_module(name, fpath, tempfile.gettempdir())
            elif suffix == '.o':
                top_mod = __import__(fpath, globals(), locals(), [])
                comps = fpath.split('.')
                if len(comps) < 2:
                    mod = top_mod
                else:
                    mod = top_mod
                    for subname in comps[1:]:
                        mod = getattr(mod, subname)
            elif suffix == '.zip':
                mod = zipimporter(fpath).load_module(name)
            else:
                desc = self.suffix_map[suffix]
                try:
                    mod_namespace = '.'.join((self.loaded_base_name, self.mod_type_check(fpath), self.tag, name))
                except TypeError:
                    mod_namespace = '{}.{}.{}.{}'.format(self.loaded_base_name, self.mod_type_check(fpath), self.tag, name)
                if suffix == '':
                    loader_details = [(importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES), (importlib.machinery.SourcelessFileLoader, importlib.machinery.BYTECODE_SUFFIXES), (importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES)]
                    file_finder = importlib.machinery.FileFinder(fpath_dirname, *loader_details)
                    spec = file_finder.find_spec(mod_namespace)
                    if spec is None:
                        raise ImportError()
                    mod = spec.loader.load_module()
                    sys.modules[mod_namespace] = mod
                    if not self.initial_load:
                        self._reload_submodules(mod)
                else:
                    loader = MODULE_KIND_MAP[desc[2]](mod_namespace, fpath)
                    spec = importlib.util.spec_from_file_location(mod_namespace, fpath, loader=loader)
                    if spec is None:
                        raise ImportError()
                    mod = self.run(spec.loader.load_module)
                    sys.modules[mod_namespace] = mod
        except OSError:
            raise
        except ImportError as exc:
            if 'magic number' in str(exc):
                error_msg = 'Failed to import {} {}. Bad magic number. If migrating from Python2 to Python3, remove all .pyc files and try again.'.format(self.tag, name)
                log.warning(error_msg)
                self.missing_modules[name] = error_msg
            log.debug('Failed to import %s %s:\n', self.tag, name, exc_info=True)
            self.missing_modules[name] = exc
            return False
        except Exception as error:
            log.error('Failed to import %s %s, this is due most likely to a syntax error:\n', self.tag, name, exc_info=True)
            self.missing_modules[name] = error
            return False
        except SystemExit as error:
            try:
                (fn_, _, caller, _) = traceback.extract_tb(sys.exc_info()[2])[-1]
            except IndexError:
                pass
            else:
                tgt_fns = [os.path.join('salt', 'utils', 'process.py'), os.path.join('salt', 'cli', 'daemons.py'), os.path.join('salt', 'cli', 'api.py')]
                for tgt_fn in tgt_fns:
                    if fn_.endswith(tgt_fn) and '_handle_signals' in caller:
                        sys.exit(salt.defaults.exitcodes.EX_OK)
            log.error('Failed to import %s %s as the module called exit()\n', self.tag, name, exc_info=True)
            self.missing_modules[name] = error
            return False
        finally:
            sys.path.remove(fpath_dirname)
            self.__clean_sys_path()
        loader_context = salt.loader.context.LoaderContext()
        if hasattr(mod, '__salt_loader__'):
            if not isinstance(mod.__salt_loader__, salt.loader.context.LoaderContext):
                log.warning('Override  __salt_loader__: %s', mod)
                mod.__salt_loader__ = loader_context
        else:
            mod.__salt_loader__ = loader_context
        if hasattr(mod, '__opts__'):
            if not isinstance(mod.__opts__, salt.loader.context.NamedLoaderContext):
                if not hasattr(mod, '__orig_opts__'):
                    mod.__orig_opts__ = copy.deepcopy(mod.__opts__)
                mod.__opts__ = copy.deepcopy(mod.__orig_opts__)
                mod.__opts__.update(self.opts)
        else:
            if not hasattr(mod, '__orig_opts__'):
                mod.__orig_opts__ = {}
            mod.__opts__ = copy.deepcopy(mod.__orig_opts__)
            mod.__opts__.update(self.opts)
        for (p_name, p_value) in self.pack.items():
            if p_name == '__opts__':
                continue
            mod_named_context = getattr(mod, p_name, None)
            if hasattr(mod_named_context, 'default'):
                default = copy.deepcopy(mod_named_context.default)
            else:
                default = None
            named_context = loader_context.named_context(p_name, default)
            if mod_named_context is None:
                setattr(mod, p_name, named_context)
            elif named_context != mod_named_context:
                log.debug('Override  %s: %s', p_name, mod)
                setattr(mod, p_name, named_context)
            else:
                setattr(mod, p_name, named_context)
        if self.pack_self is not None:
            mod_named_context = getattr(mod, self.pack_self, None)
            if hasattr(mod_named_context, 'default'):
                default = copy.deepcopy(mod_named_context.default)
            else:
                default = None
            named_context = loader_context.named_context(self.pack_self, default)
            if mod_named_context is None:
                setattr(mod, self.pack_self, named_context)
            elif named_context != mod_named_context:
                log.debug('Override  %s: %s', self.pack_self, mod)
                setattr(mod, self.pack_self, named_context)
            else:
                setattr(mod, self.pack_self, named_context)
        module_name = mod.__name__.rsplit('.', 1)[-1]
        module_init = getattr(mod, '__init__', None)
        if inspect.isfunction(module_init):
            try:
                self.run(module_init, self.opts)
            except TypeError as e:
                log.error(e)
            except Exception:
                err_string = '__init__ failed'
                log.debug('Error loading %s.%s: %s', self.tag, module_name, err_string, exc_info=True)
                self.missing_modules[module_name] = err_string
                self.missing_modules[name] = err_string
                return False
        if self.virtual_enable:
            virtual_funcs_to_process = ['__virtual__'] + self.virtual_funcs
            for virtual_func in virtual_funcs_to_process:
                (virtual_ret, module_name, virtual_err, virtual_aliases) = self._process_virtual(mod, module_name, virtual_func)
                if virtual_err is not None:
                    log.trace('Error loading %s.%s: %s', self.tag, module_name, virtual_err)
                if virtual_ret is not True and module_name not in self.missing_modules:
                    self.missing_modules[module_name] = virtual_err
                    self.missing_modules[name] = virtual_err
                    return False
        else:
            virtual_aliases = ()
        if 'proxy' in self.opts:
            if self.tag in ['grains', 'proxy']:
                if not hasattr(mod, '__proxyenabled__') or (self.opts['proxy']['proxytype'] not in mod.__proxyenabled__ and '*' not in mod.__proxyenabled__):
                    err_string = 'not a proxy_minion enabled module'
                    self.missing_modules[module_name] = err_string
                    self.missing_modules[name] = err_string
                    return False
        try:
            funcs_to_load = mod.__load__
            log.debug("The functions from module '%s' are being loaded from the provided __load__ attribute", module_name)
        except AttributeError:
            try:
                funcs_to_load = mod.__all__
                log.debug("The functions from module '%s' are being loaded from the provided __all__ attribute", module_name)
            except AttributeError:
                funcs_to_load = dir(mod)
                log.debug("The functions from module '%s' are being loaded by dir() on the loaded module", module_name)
        mod_names = [module_name] + list(virtual_aliases)
        for attr in funcs_to_load:
            if attr.startswith('_'):
                continue
            func = getattr(mod, attr)
            if not inspect.isfunction(func) and (not isinstance(func, functools.partial)):
                continue
            if self._only_pack_properly_namespaced_functions and (not func.__module__.startswith(self.loaded_base_name)):
                continue
            funcname = getattr(mod, '__func_alias__', {}).get(attr, attr)
            for tgt_mod in mod_names:
                try:
                    full_funcname = '.'.join((tgt_mod, funcname))
                except TypeError:
                    full_funcname = '{}.{}'.format(tgt_mod, funcname)
                if full_funcname not in self._dict:
                    self._dict[full_funcname] = func
                    self._apply_outputter(func, mod)
                self.loaded_modules.add(tgt_mod)
        try:
            Depends.enforce_dependencies(self._dict, self.tag, name)
        except RuntimeError as exc:
            log.info('Depends.enforce_dependencies() failed for the following reason: %s', exc)
        return True

    def _load(self, key):
        """
        Load a single item if you have it
        """
        if not isinstance(key, str):
            raise KeyError('The key must be a string.')
        if '.' not in key:
            raise KeyError("The key '{}' should contain a '.'".format(key))
        (mod_name, _) = key.split('.', 1)
        with self._lock:
            if mod_name in self.missing_modules or key in self._dict:
                return True
            if self.whitelist and mod_name not in self.whitelist:
                log.error('Failed to load function %s because its module (%s) is not in the whitelist: %s', key, mod_name, self.whitelist)
                raise KeyError(key)

            def _inner_load(mod_name):
                for name in self._iter_files(mod_name):
                    if name in self.loaded_files:
                        continue
                    if self._load_module(name) and key in self._dict:
                        return True
                return False
            ret = None
            reloaded = False
            while True:
                try:
                    ret = _inner_load(mod_name)
                    if not reloaded and ret is not True:
                        self._refresh_file_mapping()
                        reloaded = True
                        continue
                    break
                except OSError:
                    if not reloaded:
                        self._refresh_file_mapping()
                        reloaded = True
                    continue
        return ret

    def _load_all(self):
        """
        Load all of them
        """
        with self._lock:
            for name in self.file_mapping:
                if name in self.loaded_files or name in self.missing_modules:
                    continue
                self._load_module(name)
            self.loaded = True

    def reload_modules(self):
        with self._lock:
            self.loaded_files = set()
            self._load_all()

    def _apply_outputter(self, func, mod):
        """
        Apply the __outputter__ variable to the functions
        """
        if hasattr(mod, '__outputter__'):
            outp = mod.__outputter__
            if func.__name__ in outp:
                func.__outputter__ = outp[func.__name__]

    def _process_virtual(self, mod, module_name, virtual_func='__virtual__'):
        """
        Given a loaded module and its default name determine its virtual name

        This function returns a tuple. The first value will be either True or
        False and will indicate if the module should be loaded or not (i.e. if
        it threw and exception while processing its __virtual__ function). The
        second value is the determined virtual name, which may be the same as
        the value provided.

        The default name can be calculated as follows::

            module_name = mod.__name__.rsplit('.', 1)[-1]
        """
        virtual_aliases = getattr(mod, '__virtual_aliases__', tuple())
        try:
            error_reason = None
            if hasattr(mod, '__virtual__') and inspect.isfunction(mod.__virtual__):
                try:
                    start = time.time()
                    virtual_attr = getattr(mod, virtual_func)
                    virtual = self.run(virtual_attr)
                    if isinstance(virtual, tuple):
                        error_reason = virtual[1]
                        virtual = virtual[0]
                    if self.opts.get('virtual_timer', False):
                        end = time.time() - start
                        msg = 'Virtual function took {} seconds for {}'.format(end, module_name)
                        log.warning(msg)
                except Exception as exc:
                    error_reason = 'Exception raised when processing __virtual__ function for {}. Module will not be loaded: {}'.format(mod.__name__, exc)
                    log.error(error_reason, exc_info_on_loglevel=logging.DEBUG)
                    virtual = None
                virtualname = getattr(mod, '__virtualname__', virtual)
                if not virtual:
                    if virtual is None:
                        log.warning("%s.__virtual__() is wrongly returning `None`. It should either return `True`, `False` or a new name. If you're the developer of the module '%s', please fix this.", mod.__name__, module_name)
                    return (False, module_name, error_reason, virtual_aliases)
                if virtual is not True and module_name != virtual:
                    log.trace('Loaded %s as virtual %s', module_name, virtual)
                    if virtualname != virtual:
                        log.error("The module '%s' is showing some bad usage. Its __virtualname__ attribute is set to '%s' yet the __virtual__() function is returning '%s'. These values should match!", mod.__name__, virtualname, virtual)
                    module_name = virtualname
                elif virtual is True and virtualname != module_name:
                    if virtualname is not True:
                        module_name = virtualname
        except KeyError:
            log.debug('KeyError when loading %s', module_name, exc_info=True)
        except Exception:
            log.error('Failed to read the virtual function for %s: %s', self.tag, module_name, exc_info=True)
            return (False, module_name, error_reason, virtual_aliases)
        return (True, module_name, None, virtual_aliases)

    def run(self, _func_or_method, *args, **kwargs):
        """
        Run the `_func_or_method` in this loader's context
        """
        self._last_context = contextvars.copy_context()
        return self._last_context.run(self._run_as, _func_or_method, *args, **kwargs)

    def _run_as(self, _func_or_method, *args, **kwargs):
        """
        Handle setting up the context properly and call the method
        """
        self.parent_loader = None
        try:
            current_loader = salt.loader.context.loader_ctxvar.get()
        except LookupError:
            current_loader = None
        if current_loader is not self:
            self.parent_loader = current_loader
        token = salt.loader.context.loader_ctxvar.set(self)
        try:
            return _func_or_method(*args, **kwargs)
        finally:
            self.parent_loader = None
            salt.loader.context.loader_ctxvar.reset(token)

    def run_in_thread(self, _func_or_method, *args, **kwargs):
        """
        Run the function in a new thread with the context of this loader
        """
        argslist = [self, _func_or_method]
        argslist.extend(args)
        thread = threading.Thread(target=self.target, args=argslist, kwargs=kwargs)
        thread.start()
        return thread

    @staticmethod
    def target(loader, _func_or_method, *args, **kwargs):
        loader.run(_func_or_method, *args, **kwargs)

def global_injector_decorator(inject_globals):
    """
    Decorator used by the LazyLoader to inject globals into a function at
    execute time.

    globals
        Dictionary with global variables to inject
    """

    def inner_decorator(f):

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            with salt.utils.context.func_globals_inject(f, **inject_globals):
                return f(*args, **kwargs)
        return wrapper
    return inner_decorator