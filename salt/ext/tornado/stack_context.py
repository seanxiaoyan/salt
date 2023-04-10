"""`StackContext` allows applications to maintain threadlocal-like state
that follows execution as it moves to other execution contexts.

The motivating examples are to eliminate the need for explicit
``async_callback`` wrappers (as in `tornado.web.RequestHandler`), and to
allow some additional context to be kept for logging.

This is slightly magic, but it's an extension of the idea that an
exception handler is a kind of stack-local state and when that stack
is suspended and resumed in a new context that state needs to be
preserved.  `StackContext` shifts the burden of restoring that state
from each call site (e.g.  wrapping each `.AsyncHTTPClient` callback
in ``async_callback``) to the mechanisms that transfer control from
one context to another (e.g. `.AsyncHTTPClient` itself, `.IOLoop`,
thread pools, etc).

Example usage::

    @contextlib.contextmanager
    def die_on_error():
        try:
            yield
        except Exception:
            logging.error("exception in asynchronous operation",exc_info=True)
            sys.exit(1)

    with StackContext(die_on_error):
        # Any exception thrown here *or in callback and its descendants*
        # will cause the process to exit instead of spinning endlessly
        # in the ioloop.
        http_client.fetch(url, callback)
    ioloop.start()

Most applications shouldn't have to work with `StackContext` directly.
Here are a few rules of thumb for when it's necessary:

* If you're writing an asynchronous library that doesn't rely on a
  stack_context-aware library like `tornado.ioloop` or `tornado.iostream`
  (for example, if you're writing a thread pool), use
  `.stack_context.wrap()` before any asynchronous operations to capture the
  stack context from where the operation was started.

* If you're writing an asynchronous library that has some shared
  resources (such as a connection pool), create those shared resources
  within a ``with stack_context.NullContext():`` block.  This will prevent
  ``StackContexts`` from leaking from one request to another.

* If you want to write something like an exception handler that will
  persist across asynchronous calls, create a new `StackContext` (or
  `ExceptionStackContext`), and make your asynchronous calls in a ``with``
  block that references your `StackContext`.
"""
from __future__ import absolute_import, division, print_function
import sys
import threading
from salt.ext.tornado.util import raise_exc_info
import logging
log = logging.getLogger(__name__)

class StackContextInconsistentError(Exception):
    pass

class _State(threading.local):

    def __init__(self):
        self.contexts = (tuple(), None)
_state = _State()

class StackContext(object):
    """Establishes the given context as a StackContext that will be transferred.

    Note that the parameter is a callable that returns a context
    manager, not the context itself.  That is, where for a
    non-transferable context manager you would say::

      with my_context():

    StackContext takes the function itself rather than its result::

      with StackContext(my_context):

    The result of ``with StackContext() as cb:`` is a deactivation
    callback.  Run this callback when the StackContext is no longer
    needed to ensure that it is not propagated any further (note that
    deactivating a context does not affect any instances of that
    context that are currently pending).  This is an advanced feature
    and not necessary in most applications.
    """

    def __init__(self, context_factory):
        self.context_factory = context_factory
        self.contexts = []
        self.active = True

    def _deactivate(self):
        self.active = False

    def enter(self):
        context = self.context_factory()
        self.contexts.append(context)
        context.__enter__()

    def exit(self, type, value, traceback):
        log.info('Trace')
        context = self.contexts.pop()
        context.__exit__(type, value, traceback)

    def __enter__(self):
        self.old_contexts = _state.contexts
        self.new_contexts = (self.old_contexts[0] + (self,), self)
        _state.contexts = self.new_contexts
        try:
            self.enter()
        except:
            _state.contexts = self.old_contexts
            raise
        return self._deactivate

    def __exit__(self, type, value, traceback):
        try:
            log.info('Trace')
            self.exit(type, value, traceback)
        finally:
            final_contexts = _state.contexts
            _state.contexts = self.old_contexts
            if final_contexts is not self.new_contexts:
                raise StackContextInconsistentError('stack_context inconsistency (may be caused by yield within a "with StackContext" block)')
            self.new_contexts = None

class ExceptionStackContext(object):
    """Specialization of StackContext for exception handling.

    The supplied ``exception_handler`` function will be called in the
    event of an uncaught exception in this context.  The semantics are
    similar to a try/finally clause, and intended use cases are to log
    an error, close a socket, or similar cleanup actions.  The
    ``exc_info`` triple ``(type, value, traceback)`` will be passed to the
    exception_handler function.

    If the exception handler returns true, the exception will be
    consumed and will not be propagated to other exception handlers.
    """

    def __init__(self, exception_handler):
        self.exception_handler = exception_handler
        self.active = True

    def _deactivate(self):
        self.active = False

    def exit(self, type, value, traceback):
        if type is not None:
            return self.exception_handler(type, value, traceback)

    def __enter__(self):
        self.old_contexts = _state.contexts
        self.new_contexts = (self.old_contexts[0], self)
        _state.contexts = self.new_contexts
        return self._deactivate

    def __exit__(self, type, value, traceback):
        try:
            log.info('Trace')
            if type is not None:
                return self.exception_handler(type, value, traceback)
        finally:
            final_contexts = _state.contexts
            _state.contexts = self.old_contexts
            if final_contexts is not self.new_contexts:
                raise StackContextInconsistentError('stack_context inconsistency (may be caused by yield within a "with StackContext" block)')
            self.new_contexts = None

class NullContext(object):
    """Resets the `StackContext`.

    Useful when creating a shared resource on demand (e.g. an
    `.AsyncHTTPClient`) where the stack that caused the creating is
    not relevant to future operations.
    """

    def __enter__(self):
        self.old_contexts = _state.contexts
        _state.contexts = (tuple(), None)

    def __exit__(self, type, value, traceback):
        _state.contexts = self.old_contexts

def _remove_deactivated(contexts):
    """Remove deactivated handlers from the chain"""
    stack_contexts = tuple([h for h in contexts[0] if h.active])
    head = contexts[1]
    while head is not None and (not head.active):
        head = head.old_contexts[1]
    ctx = head
    while ctx is not None:
        parent = ctx.old_contexts[1]
        while parent is not None:
            if parent.active:
                break
            ctx.old_contexts = parent.old_contexts
            parent = parent.old_contexts[1]
        ctx = parent
    return (stack_contexts, head)

def wrap(fn):
    """Returns a callable object that will restore the current `StackContext`
    when executed.

    Use this whenever saving a callback to be executed later in a
    different execution context (either in a different thread or
    asynchronously in the same thread).
    """
    if fn is None or hasattr(fn, '_wrapped'):
        return fn
    cap_contexts = [_state.contexts]
    if not cap_contexts[0][0] and (not cap_contexts[0][1]):
        log.info('Trace')

        def null_wrapper(*args, **kwargs):
            try:
                current_state = _state.contexts
                _state.contexts = cap_contexts[0]
                return fn(*args, **kwargs)
            finally:
                _state.contexts = current_state
        null_wrapper._wrapped = True
        return null_wrapper

    def wrapped(*args, **kwargs):
        ret = None
        try:
            current_state = _state.contexts
            cap_contexts[0] = contexts = _remove_deactivated(cap_contexts[0])
            _state.contexts = contexts
            exc = (None, None, None)
            top = None
            last_ctx = 0
            stack = contexts[0]
            for n in stack:
                try:
                    n.enter()
                    last_ctx += 1
                except:
                    exc = sys.exc_info()
                    top = n.old_contexts[1]
            if top is None:
                try:
                    ret = fn(*args, **kwargs)
                except:
                    exc = sys.exc_info()
                    top = contexts[1]
            if top is not None:
                exc = _handle_exception(top, exc)
            else:
                while last_ctx > 0:
                    last_ctx -= 1
                    c = stack[last_ctx]
                    try:
                        c.exit(*exc)
                    except:
                        exc = sys.exc_info()
                        top = c.old_contexts[1]
                        break
                else:
                    top = None
                if top is not None:
                    exc = _handle_exception(top, exc)
            if exc != (None, None, None):
                raise_exc_info(exc)
        finally:
            _state.contexts = current_state
        return ret
    wrapped._wrapped = True
    return wrapped

def _handle_exception(tail, exc):
    while tail is not None:
        try:
            if tail.exit(*exc):
                exc = (None, None, None)
        except:
            exc = sys.exc_info()
        tail = tail.old_contexts[1]
    return exc

def run_with_stack_context(context, func):
    """Run a coroutine ``func`` in the given `StackContext`.

    It is not safe to have a ``yield`` statement within a ``with StackContext``
    block, so it is difficult to use stack context with `.gen.coroutine`.
    This helper function runs the function in the correct context while
    keeping the ``yield`` and ``with`` statements syntactically separate.

    Example::

        @gen.coroutine
        def incorrect():
            with StackContext(ctx):
                # ERROR: this will raise StackContextInconsistentError
                yield other_coroutine()

        @gen.coroutine
        def correct():
            yield run_with_stack_context(StackContext(ctx), other_coroutine)

    .. versionadded:: 3.1
    """
    with context:
        return func()