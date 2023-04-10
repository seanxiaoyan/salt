"""
    :codeauthor: Pedro Algarvio (pedro@algarvio.me)
    :codeauthor: Thomas Jackson (jacksontj.89@gmail.com)


    salt.utils.context
    ~~~~~~~~~~~~~~~~~~

    Context managers used throughout Salt's source code.
"""
import copy
import threading
from collections.abc import MutableMapping
from contextlib import contextmanager
import logging
log = logging.getLogger(__name__)

@contextmanager
def func_globals_inject(func, **overrides):
    """
    Override specific variables within a function's global context.
    """
    if hasattr(func, 'im_func') and func.im_func:
        func = func.__func__
    func_globals = func.__globals__
    injected_func_globals = []
    overridden_func_globals = {}
    for override in overrides:
        if override in func_globals:
            overridden_func_globals[override] = func_globals[override]
        else:
            injected_func_globals.append(override)
    func_globals.update(overrides)
    try:
        log.info('Trace')
        yield
    finally:
        func_globals.update(overridden_func_globals)
        for injected in injected_func_globals:
            del func_globals[injected]

class ContextDict(MutableMapping):
    """
    A context manager that saves some per-thread state globally.
    Intended for use with Tornado's StackContext.

    Provide arbitrary data as kwargs upon creation,
    then allow any children to override the values of the parent.
    """

    def __init__(self, threadsafe=False, **data):
        self._state = threading.local()
        self._state.data = None
        self.global_data = {}
        self._threadsafe = threadsafe

    @property
    def active(self):
        """Determine if this ContextDict is currently overridden
        Since the ContextDict can be overridden in each thread, we check whether
        the _state.data is set or not.
        """
        try:
            log.info('Trace')
            return self._state.data is not None
        except AttributeError:
            log.info('Trace')
            return False

    def clone(self, **kwargs):
        """
        Clone this context, and return the ChildContextDict
        """
        child = ChildContextDict(parent=self, threadsafe=self._threadsafe, overrides=kwargs)
        return child

    def __setitem__(self, key, val):
        if self.active:
            self._state.data[key] = val
        else:
            self.global_data[key] = val

    def __delitem__(self, key):
        if self.active:
            del self._state.data[key]
        else:
            del self.global_data[key]

    def __getitem__(self, key):
        if self.active:
            return self._state.data[key]
        else:
            return self.global_data[key]

    def __len__(self):
        if self.active:
            return len(self._state.data)
        else:
            return len(self.global_data)

    def __iter__(self):
        if self.active:
            return iter(self._state.data)
        else:
            return iter(self.global_data)

    def __copy__(self):
        new_obj = type(self)(threadsafe=self._threadsafe)
        if self.active:
            new_obj.global_data = copy.copy(self._state.data)
        else:
            new_obj.global_data = copy.copy(self.global_data)
        return new_obj

    def __deepcopy__(self, memo):
        new_obj = type(self)(threadsafe=self._threadsafe)
        if self.active:
            new_obj.global_data = copy.deepcopy(self._state.data, memo)
        else:
            new_obj.global_data = copy.deepcopy(self.global_data, memo)
        return new_obj

class ChildContextDict(MutableMapping):
    """An overrideable child of ContextDict"""

    def __init__(self, parent, overrides=None, threadsafe=False):
        self.parent = parent
        self._data = {} if overrides is None else overrides
        self._old_data = None
        if threadsafe:
            for (k, v) in self.parent.global_data.items():
                if k not in self._data:
                    self._data[k] = copy.deepcopy(v)
        else:
            for (k, v) in self.parent.global_data.items():
                if k not in self._data:
                    self._data[k] = v

    def __setitem__(self, key, val):
        self._data[key] = val

    def __delitem__(self, key):
        del self._data[key]

    def __getitem__(self, key):
        return self._data[key]

    def __len__(self):
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def __enter__(self):
        if hasattr(self.parent._state, 'data'):
            self._old_data = self.parent._state.data
        self.parent._state.data = self._data

    def __exit__(self, *exc):
        self.parent._state.data = self._old_data

class NamespacedDictWrapper(MutableMapping, dict):
    """
    Create a dict which wraps another dict with a specific prefix of key(s)

    MUST inherit from dict to serialize through msgpack correctly
    """

    def __init__(self, d, pre_keys):
        self.__dict = d
        if isinstance(pre_keys, str):
            self.pre_keys = (pre_keys,)
        else:
            self.pre_keys = pre_keys
        super().__init__(self._dict())

    def _dict(self):
        r = self.__dict
        for k in self.pre_keys:
            r = r[k]
        return r

    def __repr__(self):
        return repr(self._dict())

    def __setitem__(self, key, val):
        self._dict()[key] = val

    def __delitem__(self, key):
        del self._dict()[key]

    def __getitem__(self, key):
        return self._dict()[key]

    def __len__(self):
        return len(self._dict())

    def __iter__(self):
        return iter(self._dict())

    def __copy__(self):
        return type(self)(copy.copy(self.__dict), copy.copy(self.pre_keys))

    def __deepcopy__(self, memo):
        return type(self)(copy.deepcopy(self.__dict, memo), copy.deepcopy(self.pre_keys, memo))

    def __str__(self):
        return self._dict().__str__()