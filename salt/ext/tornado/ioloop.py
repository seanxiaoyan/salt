"""An I/O event loop for non-blocking sockets.

Typical applications will use a single `IOLoop` object, in the
`IOLoop.instance` singleton.  The `IOLoop.start` method should usually
be called at the end of the ``main()`` function.  Atypical applications may
use more than one `IOLoop`, such as one `IOLoop` per thread, or per `unittest`
case.

In addition to I/O events, the `IOLoop` can also schedule time-based events.
`IOLoop.add_timeout` is a non-blocking alternative to `time.sleep`.
"""
from __future__ import absolute_import, division, print_function
import collections
import datetime
import errno
import functools
import heapq
import itertools
import logging
import numbers
import os
import select
import sys
import threading
import time
import traceback
import math
from salt.ext.tornado.concurrent import TracebackFuture, is_future
from salt.ext.tornado.log import app_log, gen_log
from salt.ext.tornado.platform.auto import set_close_exec, Waker
from salt.ext.tornado import stack_context
from salt.ext.tornado.util import PY3, Configurable, errno_from_exception, timedelta_to_seconds
import logging
log = logging.getLogger(__name__)
try:
    import signal
except ImportError:
    signal = None
if PY3:
    import _thread as thread
else:
    import thread
_POLL_TIMEOUT = 3600.0

class TimeoutError(Exception):
    pass

class IOLoop(Configurable):
    """A level-triggered I/O loop.

    We use ``epoll`` (Linux) or ``kqueue`` (BSD and Mac OS X) if they
    are available, or else we fall back on select(). If you are
    implementing a system that needs to handle thousands of
    simultaneous connections, you should use a system that supports
    either ``epoll`` or ``kqueue``.

    Example usage for a simple TCP server:

    .. testcode::

        import errno
        import functools
        import tornado.ioloop
        import socket

        def connection_ready(sock, fd, events):
            while True:
                try:
                    connection, address = sock.accept()
                except socket.error as e:
                    if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
                        raise
                    return
                connection.setblocking(0)
                handle_connection(connection, address)

        if __name__ == '__main__':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(0)
            sock.bind(("", port))
            sock.listen(128)

            io_loop = tornado.ioloop.IOLoop.current()
            callback = functools.partial(connection_ready, sock)
            io_loop.add_handler(sock.fileno(), callback, io_loop.READ)
            io_loop.start()

    .. testoutput::
       :hide:

    By default, a newly-constructed `IOLoop` becomes the thread's current
    `IOLoop`, unless there already is a current `IOLoop`. This behavior
    can be controlled with the ``make_current`` argument to the `IOLoop`
    constructor: if ``make_current=True``, the new `IOLoop` will always
    try to become current and it raises an error if there is already a
    current instance. If ``make_current=False``, the new `IOLoop` will
    not try to become current.

    .. versionchanged:: 4.2
       Added the ``make_current`` keyword argument to the `IOLoop`
       constructor.
    """
    _EPOLLIN = 1
    _EPOLLPRI = 2
    _EPOLLOUT = 4
    _EPOLLERR = 8
    _EPOLLHUP = 16
    _EPOLLRDHUP = 8192
    _EPOLLONESHOT = 1 << 30
    _EPOLLET = 1 << 31
    NONE = 0
    READ = _EPOLLIN
    WRITE = _EPOLLOUT
    ERROR = _EPOLLERR | _EPOLLHUP
    _instance_lock = threading.Lock()
    _current = threading.local()

    @staticmethod
    def instance():
        """Returns a global `IOLoop` instance.

        Most applications have a single, global `IOLoop` running on the
        main thread.  Use this method to get this instance from
        another thread.  In most other cases, it is better to use `current()`
        to get the current thread's `IOLoop`.
        """
        if not hasattr(IOLoop, '_instance'):
            with IOLoop._instance_lock:
                if not hasattr(IOLoop, '_instance'):
                    IOLoop._instance = IOLoop()
        return IOLoop._instance

    @staticmethod
    def initialized():
        """Returns true if the singleton instance has been created."""
        return hasattr(IOLoop, '_instance')

    def install(self):
        """Installs this `IOLoop` object as the singleton instance.

        This is normally not necessary as `instance()` will create
        an `IOLoop` on demand, but you may want to call `install` to use
        a custom subclass of `IOLoop`.

        When using an `IOLoop` subclass, `install` must be called prior
        to creating any objects that implicitly create their own
        `IOLoop` (e.g., :class:`tornado.httpclient.AsyncHTTPClient`).
        """
        assert not IOLoop.initialized()
        IOLoop._instance = self

    @staticmethod
    def clear_instance():
        """Clear the global `IOLoop` instance.

        .. versionadded:: 4.0
        """
        if hasattr(IOLoop, '_instance'):
            del IOLoop._instance

    @staticmethod
    def current(instance=True):
        """Returns the current thread's `IOLoop`.

        If an `IOLoop` is currently running or has been marked as
        current by `make_current`, returns that instance.  If there is
        no current `IOLoop`, returns `IOLoop.instance()` (i.e. the
        main thread's `IOLoop`, creating one if necessary) if ``instance``
        is true.

        In general you should use `IOLoop.current` as the default when
        constructing an asynchronous object, and use `IOLoop.instance`
        when you mean to communicate to the main thread from a different
        one.

        .. versionchanged:: 4.1
           Added ``instance`` argument to control the fallback to
           `IOLoop.instance()`.
        """
        current = getattr(IOLoop._current, 'instance', None)
        if current is None and instance:
            return IOLoop.instance()
        return current

    def make_current(self):
        """Makes this the `IOLoop` for the current thread.

        An `IOLoop` automatically becomes current for its thread
        when it is started, but it is sometimes useful to call
        `make_current` explicitly before starting the `IOLoop`,
        so that code run at startup time can find the right
        instance.

        .. versionchanged:: 4.1
           An `IOLoop` created while there is no current `IOLoop`
           will automatically become current.
        """
        IOLoop._current.instance = self

    @staticmethod
    def clear_current():
        IOLoop._current.instance = None

    @classmethod
    def configurable_base(cls):
        return IOLoop

    @classmethod
    def configurable_default(cls):
        if hasattr(select, 'epoll'):
            from salt.ext.tornado.platform.epoll import EPollIOLoop
            return EPollIOLoop
        if hasattr(select, 'kqueue'):
            from salt.ext.tornado.platform.kqueue import KQueueIOLoop
            return KQueueIOLoop
        from salt.ext.tornado.platform.select import SelectIOLoop
        return SelectIOLoop

    def initialize(self, make_current=None):
        if make_current is None:
            if IOLoop.current(instance=False) is None:
                self.make_current()
        elif make_current:
            if IOLoop.current(instance=False) is not None:
                raise RuntimeError('current IOLoop already exists')
            self.make_current()

    def close(self, all_fds=False):
        """Closes the `IOLoop`, freeing any resources used.

        If ``all_fds`` is true, all file descriptors registered on the
        IOLoop will be closed (not just the ones created by the
        `IOLoop` itself).

        Many applications will only use a single `IOLoop` that runs for the
        entire lifetime of the process.  In that case closing the `IOLoop`
        is not necessary since everything will be cleaned up when the
        process exits.  `IOLoop.close` is provided mainly for scenarios
        such as unit tests, which create and destroy a large number of
        ``IOLoops``.

        An `IOLoop` must be completely stopped before it can be closed.  This
        means that `IOLoop.stop()` must be called *and* `IOLoop.start()` must
        be allowed to return before attempting to call `IOLoop.close()`.
        Therefore the call to `close` will usually appear just after
        the call to `start` rather than near the call to `stop`.

        .. versionchanged:: 3.1
           If the `IOLoop` implementation supports non-integer objects
           for "file descriptors", those objects will have their
           ``close`` method when ``all_fds`` is true.
        """
        raise NotImplementedError()

    def add_handler(self, fd, handler, events):
        """Registers the given handler to receive the given events for ``fd``.

        The ``fd`` argument may either be an integer file descriptor or
        a file-like object with a ``fileno()`` method (and optionally a
        ``close()`` method, which may be called when the `IOLoop` is shut
        down).

        The ``events`` argument is a bitwise or of the constants
        ``IOLoop.READ``, ``IOLoop.WRITE``, and ``IOLoop.ERROR``.

        When an event occurs, ``handler(fd, events)`` will be run.

        .. versionchanged:: 4.0
           Added the ability to pass file-like objects in addition to
           raw file descriptors.
        """
        raise NotImplementedError()

    def update_handler(self, fd, events):
        """Changes the events we listen for ``fd``.

        .. versionchanged:: 4.0
           Added the ability to pass file-like objects in addition to
           raw file descriptors.
        """
        raise NotImplementedError()

    def remove_handler(self, fd):
        """Stop listening for events on ``fd``.

        .. versionchanged:: 4.0
           Added the ability to pass file-like objects in addition to
           raw file descriptors.
        """
        raise NotImplementedError()

    def set_blocking_signal_threshold(self, seconds, action):
        """Sends a signal if the `IOLoop` is blocked for more than
        ``s`` seconds.

        Pass ``seconds=None`` to disable.  Requires Python 2.6 on a unixy
        platform.

        The action parameter is a Python signal handler.  Read the
        documentation for the `signal` module for more information.
        If ``action`` is None, the process will be killed if it is
        blocked for too long.
        """
        raise NotImplementedError()

    def set_blocking_log_threshold(self, seconds):
        """Logs a stack trace if the `IOLoop` is blocked for more than
        ``s`` seconds.

        Equivalent to ``set_blocking_signal_threshold(seconds,
        self.log_stack)``
        """
        self.set_blocking_signal_threshold(seconds, self.log_stack)

    def log_stack(self, signal, frame):
        """Signal handler to log the stack trace of the current thread.

        For use with `set_blocking_signal_threshold`.
        """
        gen_log.warning('IOLoop blocked for %f seconds in\n%s', self._blocking_signal_threshold, ''.join(traceback.format_stack(frame)))

    def start(self):
        """Starts the I/O loop.

        The loop will run until one of the callbacks calls `stop()`, which
        will make the loop stop after the current event iteration completes.
        """
        raise NotImplementedError()

    def _setup_logging(self):
        """The IOLoop catches and logs exceptions, so it's
        important that log output be visible.  However, python's
        default behavior for non-root loggers (prior to python
        3.2) is to print an unhelpful "no handlers could be
        found" message rather than the actual log entry, so we
        must explicitly configure logging if we've made it this
        far without anything.

        This method should be called from start() in subclasses.
        """
        if not any([logging.getLogger().handlers, logging.getLogger('tornado').handlers, logging.getLogger('tornado.application').handlers]):
            logging.basicConfig()

    def stop(self):
        """Stop the I/O loop.

        If the event loop is not currently running, the next call to `start()`
        will return immediately.

        To use asynchronous methods from otherwise-synchronous code (such as
        unit tests), you can start and stop the event loop like this::

          ioloop = IOLoop()
          async_method(ioloop=ioloop, callback=ioloop.stop)
          ioloop.start()

        ``ioloop.start()`` will return after ``async_method`` has run
        its callback, whether that callback was invoked before or
        after ``ioloop.start``.

        Note that even after `stop` has been called, the `IOLoop` is not
        completely stopped until `IOLoop.start` has also returned.
        Some work that was scheduled before the call to `stop` may still
        be run before the `IOLoop` shuts down.
        """
        raise NotImplementedError()

    def run_sync(self, func, timeout=None):
        """Starts the `IOLoop`, runs the given function, and stops the loop.

        The function must return either a yieldable object or
        ``None``. If the function returns a yieldable object, the
        `IOLoop` will run until the yieldable is resolved (and
        `run_sync()` will return the yieldable's result). If it raises
        an exception, the `IOLoop` will stop and the exception will be
        re-raised to the caller.

        The keyword-only argument ``timeout`` may be used to set
        a maximum duration for the function.  If the timeout expires,
        a `TimeoutError` is raised.

        This method is useful in conjunction with `tornado.gen.coroutine`
        to allow asynchronous calls in a ``main()`` function::

            @gen.coroutine
            def main():
                # do stuff...

            if __name__ == '__main__':
                IOLoop.current().run_sync(main)

        .. versionchanged:: 4.3
           Returning a non-``None``, non-yieldable value is now an error.
        """
        future_cell = [None]

        def run():
            try:
                result = func()
                if result is not None:
                    from salt.ext.tornado.gen import convert_yielded
                    result = convert_yielded(result)
            except Exception:
                future_cell[0] = TracebackFuture()
                future_cell[0].set_exc_info(sys.exc_info())
            else:
                if is_future(result):
                    future_cell[0] = result
                else:
                    future_cell[0] = TracebackFuture()
                    future_cell[0].set_result(result)
            self.add_future(future_cell[0], lambda future: self.stop())
        self.add_callback(run)
        if timeout is not None:
            timeout_handle = self.add_timeout(self.time() + timeout, self.stop)
        self.start()
        if timeout is not None:
            self.remove_timeout(timeout_handle)
        if not future_cell[0].done():
            raise TimeoutError('Operation timed out after %s seconds' % timeout)
        return future_cell[0].result()

    def time(self):
        """Returns the current time according to the `IOLoop`'s clock.

        The return value is a floating-point number relative to an
        unspecified time in the past.

        By default, the `IOLoop`'s time function is `time.time`.  However,
        it may be configured to use e.g. `time.monotonic` instead.
        Calls to `add_timeout` that pass a number instead of a
        `datetime.timedelta` should use this function to compute the
        appropriate time, so they can work no matter what time function
        is chosen.
        """
        return time.time()

    def add_timeout(self, deadline, callback, *args, **kwargs):
        """Runs the ``callback`` at the time ``deadline`` from the I/O loop.

        Returns an opaque handle that may be passed to
        `remove_timeout` to cancel.

        ``deadline`` may be a number denoting a time (on the same
        scale as `IOLoop.time`, normally `time.time`), or a
        `datetime.timedelta` object for a deadline relative to the
        current time.  Since Tornado 4.0, `call_later` is a more
        convenient alternative for the relative case since it does not
        require a timedelta object.

        Note that it is not safe to call `add_timeout` from other threads.
        Instead, you must use `add_callback` to transfer control to the
        `IOLoop`'s thread, and then call `add_timeout` from there.

        Subclasses of IOLoop must implement either `add_timeout` or
        `call_at`; the default implementations of each will call
        the other.  `call_at` is usually easier to implement, but
        subclasses that wish to maintain compatibility with Tornado
        versions prior to 4.0 must use `add_timeout` instead.

        .. versionchanged:: 4.0
           Now passes through ``*args`` and ``**kwargs`` to the callback.
        """
        if isinstance(deadline, numbers.Real):
            return self.call_at(deadline, callback, *args, **kwargs)
        elif isinstance(deadline, datetime.timedelta):
            return self.call_at(self.time() + timedelta_to_seconds(deadline), callback, *args, **kwargs)
        else:
            raise TypeError('Unsupported deadline %r' % deadline)

    def call_later(self, delay, callback, *args, **kwargs):
        """Runs the ``callback`` after ``delay`` seconds have passed.

        Returns an opaque handle that may be passed to `remove_timeout`
        to cancel.  Note that unlike the `asyncio` method of the same
        name, the returned object does not have a ``cancel()`` method.

        See `add_timeout` for comments on thread-safety and subclassing.

        .. versionadded:: 4.0
        """
        return self.call_at(self.time() + delay, callback, *args, **kwargs)

    def call_at(self, when, callback, *args, **kwargs):
        """Runs the ``callback`` at the absolute time designated by ``when``.

        ``when`` must be a number using the same reference point as
        `IOLoop.time`.

        Returns an opaque handle that may be passed to `remove_timeout`
        to cancel.  Note that unlike the `asyncio` method of the same
        name, the returned object does not have a ``cancel()`` method.

        See `add_timeout` for comments on thread-safety and subclassing.

        .. versionadded:: 4.0
        """
        return self.add_timeout(when, callback, *args, **kwargs)

    def remove_timeout(self, timeout):
        """Cancels a pending timeout.

        The argument is a handle as returned by `add_timeout`.  It is
        safe to call `remove_timeout` even if the callback has already
        been run.
        """
        raise NotImplementedError()

    def add_callback(self, callback, *args, **kwargs):
        """Calls the given callback on the next I/O loop iteration.

        It is safe to call this method from any thread at any time,
        except from a signal handler.  Note that this is the **only**
        method in `IOLoop` that makes this thread-safety guarantee; all
        other interaction with the `IOLoop` must be done from that
        `IOLoop`'s thread.  `add_callback()` may be used to transfer
        control from other threads to the `IOLoop`'s thread.

        To add a callback from a signal handler, see
        `add_callback_from_signal`.
        """
        raise NotImplementedError()

    def add_callback_from_signal(self, callback, *args, **kwargs):
        """Calls the given callback on the next I/O loop iteration.

        Safe for use from a Python signal handler; should not be used
        otherwise.

        Callbacks added with this method will be run without any
        `.stack_context`, to avoid picking up the context of the function
        that was interrupted by the signal.
        """
        raise NotImplementedError()

    def spawn_callback(self, callback, *args, **kwargs):
        """Calls the given callback on the next IOLoop iteration.

        Unlike all other callback-related methods on IOLoop,
        ``spawn_callback`` does not associate the callback with its caller's
        ``stack_context``, so it is suitable for fire-and-forget callbacks
        that should not interfere with the caller.

        .. versionadded:: 4.0
        """
        with stack_context.NullContext():
            self.add_callback(callback, *args, **kwargs)

    def add_future(self, future, callback):
        """Schedules a callback on the ``IOLoop`` when the given
        `.Future` is finished.

        The callback is invoked with one argument, the
        `.Future`.
        """
        assert is_future(future)
        callback = stack_context.wrap(callback)
        future.add_done_callback(lambda future: self.add_callback(callback, future))

    def _run_callback(self, callback):
        """Runs a callback with error handling.

        For use in subclasses.
        """
        try:
            ret = callback()
            if ret is not None:
                import salt.ext.tornado.gen
                try:
                    ret = salt.ext.tornado.gen.convert_yielded(ret)
                except salt.ext.tornado.gen.BadYieldError:
                    pass
                else:
                    self.add_future(ret, self._discard_future_result)
        except Exception:
            self.handle_callback_exception(callback)

    def _discard_future_result(self, future):
        """Avoid unhandled-exception warnings from spawned coroutines."""
        future.result()

    def handle_callback_exception(self, callback):
        """This method is called whenever a callback run by the `IOLoop`
        throws an exception.

        By default simply logs the exception as an error.  Subclasses
        may override this method to customize reporting of exceptions.

        The exception itself is not passed explicitly, but is available
        in `sys.exc_info`.
        """
        app_log.error('Exception in callback %r', callback, exc_info=True)

    def split_fd(self, fd):
        """Returns an (fd, obj) pair from an ``fd`` parameter.

        We accept both raw file descriptors and file-like objects as
        input to `add_handler` and related methods.  When a file-like
        object is passed, we must retain the object itself so we can
        close it correctly when the `IOLoop` shuts down, but the
        poller interfaces favor file descriptors (they will accept
        file-like objects and call ``fileno()`` for you, but they
        always return the descriptor itself).

        This method is provided for use by `IOLoop` subclasses and should
        not generally be used by application code.

        .. versionadded:: 4.0
        """
        try:
            log.info('Trace')
            return (fd.fileno(), fd)
        except AttributeError:
            log.info('Trace')
            return (fd, fd)

    def close_fd(self, fd):
        """Utility method to close an ``fd``.

        If ``fd`` is a file-like object, we close it directly; otherwise
        we use `os.close`.

        This method is provided for use by `IOLoop` subclasses (in
        implementations of ``IOLoop.close(all_fds=True)`` and should
        not generally be used by application code.

        .. versionadded:: 4.0
        """
        try:
            try:
                fd.close()
            except AttributeError:
                os.close(fd)
        except OSError:
            pass

class PollIOLoop(IOLoop):
    """Base class for IOLoops built around a select-like function.

    For concrete implementations, see `tornado.platform.epoll.EPollIOLoop`
    (Linux), `tornado.platform.kqueue.KQueueIOLoop` (BSD and Mac), or
    `tornado.platform.select.SelectIOLoop` (all platforms).
    """

    def initialize(self, impl, time_func=None, **kwargs):
        super(PollIOLoop, self).initialize(**kwargs)
        self._impl = impl
        if hasattr(self._impl, 'fileno'):
            set_close_exec(self._impl.fileno())
        self.time_func = time_func or time.time
        self._handlers = {}
        self._events = {}
        self._callbacks = collections.deque()
        self._timeouts = []
        self._cancellations = 0
        self._running = False
        self._stopped = False
        self._closing = False
        self._thread_ident = None
        self._blocking_signal_threshold = None
        self._timeout_counter = itertools.count()
        self._waker = Waker()
        self.add_handler(self._waker.fileno(), lambda fd, events: self._waker.consume(), self.READ)

    def close(self, all_fds=False):
        self._closing = True
        self.remove_handler(self._waker.fileno())
        if all_fds:
            for (fd, handler) in list(self._handlers.values()):
                self.close_fd(fd)
        self._waker.close()
        self._impl.close()
        self._callbacks = None
        self._timeouts = None

    def add_handler(self, fd, handler, events):
        (fd, obj) = self.split_fd(fd)
        self._handlers[fd] = (obj, stack_context.wrap(handler))
        self._impl.register(fd, events | self.ERROR)

    def update_handler(self, fd, events):
        (fd, obj) = self.split_fd(fd)
        self._impl.modify(fd, events | self.ERROR)

    def remove_handler(self, fd):
        (fd, obj) = self.split_fd(fd)
        self._handlers.pop(fd, None)
        self._events.pop(fd, None)
        try:
            log.info('Trace')
            self._impl.unregister(fd)
        except Exception:
            log.info('Trace')
            gen_log.debug('Error deleting fd from IOLoop', exc_info=True)

    def set_blocking_signal_threshold(self, seconds, action):
        if not hasattr(signal, 'setitimer'):
            gen_log.error('set_blocking_signal_threshold requires a signal module with the setitimer method')
            return
        self._blocking_signal_threshold = seconds
        if seconds is not None:
            signal.signal(signal.SIGALRM, action if action is not None else signal.SIG_DFL)

    def start(self):
        if self._running:
            raise RuntimeError('IOLoop is already running')
        self._setup_logging()
        if self._stopped:
            self._stopped = False
            return
        old_current = getattr(IOLoop._current, 'instance', None)
        IOLoop._current.instance = self
        self._thread_ident = thread.get_ident()
        self._running = True
        old_wakeup_fd = None
        if hasattr(signal, 'set_wakeup_fd') and os.name == 'posix':
            try:
                old_wakeup_fd = signal.set_wakeup_fd(self._waker.write_fileno())
                if old_wakeup_fd != -1:
                    signal.set_wakeup_fd(old_wakeup_fd)
                    old_wakeup_fd = None
            except ValueError:
                old_wakeup_fd = None
        try:
            while True:
                ncallbacks = len(self._callbacks)
                due_timeouts = []
                if self._timeouts:
                    now = self.time()
                    while self._timeouts:
                        if self._timeouts[0].callback is None:
                            heapq.heappop(self._timeouts)
                            self._cancellations -= 1
                        elif self._timeouts[0].deadline <= now:
                            due_timeouts.append(heapq.heappop(self._timeouts))
                        else:
                            break
                    if self._cancellations > 512 and self._cancellations > len(self._timeouts) >> 1:
                        self._cancellations = 0
                        self._timeouts = [x for x in self._timeouts if x.callback is not None]
                        heapq.heapify(self._timeouts)
                for i in range(ncallbacks):
                    self._run_callback(self._callbacks.popleft())
                for timeout in due_timeouts:
                    if timeout.callback is not None:
                        self._run_callback(timeout.callback)
                due_timeouts = timeout = None
                if self._callbacks:
                    poll_timeout = 0.0
                elif self._timeouts:
                    poll_timeout = self._timeouts[0].deadline - self.time()
                    poll_timeout = max(0, min(poll_timeout, _POLL_TIMEOUT))
                else:
                    poll_timeout = _POLL_TIMEOUT
                if not self._running:
                    break
                if self._blocking_signal_threshold is not None:
                    signal.setitimer(signal.ITIMER_REAL, 0, 0)
                try:
                    event_pairs = self._impl.poll(poll_timeout)
                except Exception as e:
                    if errno_from_exception(e) == errno.EINTR:
                        continue
                    else:
                        raise
                if self._blocking_signal_threshold is not None:
                    signal.setitimer(signal.ITIMER_REAL, self._blocking_signal_threshold, 0)
                self._events.update(event_pairs)
                while self._events:
                    (fd, events) = self._events.popitem()
                    try:
                        (fd_obj, handler_func) = self._handlers[fd]
                        handler_func(fd_obj, events)
                    except (OSError, IOError) as e:
                        if errno_from_exception(e) == errno.EPIPE:
                            pass
                        else:
                            self.handle_callback_exception(self._handlers.get(fd))
                    except Exception:
                        self.handle_callback_exception(self._handlers.get(fd))
                fd_obj = handler_func = None
        finally:
            self._stopped = False
            if self._blocking_signal_threshold is not None:
                signal.setitimer(signal.ITIMER_REAL, 0, 0)
            IOLoop._current.instance = old_current
            if old_wakeup_fd is not None:
                signal.set_wakeup_fd(old_wakeup_fd)

    def stop(self):
        self._running = False
        self._stopped = True
        self._waker.wake()

    def time(self):
        return self.time_func()

    def call_at(self, deadline, callback, *args, **kwargs):
        timeout = _Timeout(deadline, functools.partial(stack_context.wrap(callback), *args, **kwargs), self)
        heapq.heappush(self._timeouts, timeout)
        return timeout

    def remove_timeout(self, timeout):
        timeout.callback = None
        self._cancellations += 1

    def add_callback(self, callback, *args, **kwargs):
        if self._closing:
            return
        self._callbacks.append(functools.partial(stack_context.wrap(callback), *args, **kwargs))
        if thread.get_ident() != self._thread_ident:
            self._waker.wake()
        else:
            pass

    def add_callback_from_signal(self, callback, *args, **kwargs):
        with stack_context.NullContext():
            self.add_callback(callback, *args, **kwargs)

class _Timeout(object):
    """An IOLoop timeout, a UNIX timestamp and a callback"""
    __slots__ = ['deadline', 'callback', 'tdeadline']

    def __init__(self, deadline, callback, io_loop):
        if not isinstance(deadline, numbers.Real):
            raise TypeError('Unsupported deadline %r' % deadline)
        self.deadline = deadline
        self.callback = callback
        self.tdeadline = (deadline, next(io_loop._timeout_counter))

    def __lt__(self, other):
        return self.tdeadline < other.tdeadline

    def __le__(self, other):
        return self.tdeadline <= other.tdeadline

class PeriodicCallback(object):
    """Schedules the given callback to be called periodically.

    The callback is called every ``callback_time`` milliseconds.
    Note that the timeout is given in milliseconds, while most other
    time-related functions in Tornado use seconds.

    If the callback runs for longer than ``callback_time`` milliseconds,
    subsequent invocations will be skipped to get back on schedule.

    `start` must be called after the `PeriodicCallback` is created.

    .. versionchanged:: 4.1
       The ``io_loop`` argument is deprecated.
    """

    def __init__(self, callback, callback_time, io_loop=None):
        self.callback = callback
        if callback_time <= 0:
            raise ValueError('Periodic callback must have a positive callback_time')
        self.callback_time = callback_time
        self.io_loop = io_loop or IOLoop.current()
        self._running = False
        self._timeout = None

    def start(self):
        """Starts the timer."""
        self._running = True
        self._next_timeout = self.io_loop.time()
        self._schedule_next()

    def stop(self):
        """Stops the timer."""
        self._running = False
        if self._timeout is not None:
            self.io_loop.remove_timeout(self._timeout)
            self._timeout = None

    def is_running(self):
        """Return True if this `.PeriodicCallback` has been started.

        .. versionadded:: 4.1
        """
        return self._running

    def _run(self):
        if not self._running:
            return
        try:
            return self.callback()
        except Exception:
            self.io_loop.handle_callback_exception(self.callback)
        finally:
            self._schedule_next()

    def _schedule_next(self):
        if self._running:
            current_time = self.io_loop.time()
            if self._next_timeout <= current_time:
                callback_time_sec = self.callback_time / 1000.0
                self._next_timeout += (math.floor((current_time - self._next_timeout) / callback_time_sec) + 1) * callback_time_sec
            self._timeout = self.io_loop.add_timeout(self._next_timeout, self._run)