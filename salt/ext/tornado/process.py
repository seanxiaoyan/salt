"""Utilities for working with multiple processes, including both forking
the server into multiple processes and managing subprocesses.
"""
from __future__ import absolute_import, division, print_function
import errno
import os
import signal
import subprocess
import sys
import time
from binascii import hexlify
from salt.ext.tornado.concurrent import Future
from salt.ext.tornado import ioloop
from salt.ext.tornado.iostream import PipeIOStream
from salt.ext.tornado.log import gen_log
from salt.ext.tornado.platform.auto import set_close_exec
from salt.ext.tornado import stack_context
from salt.ext.tornado.util import errno_from_exception, PY3
import logging
log = logging.getLogger(__name__)
try:
    import multiprocessing
except ImportError:
    multiprocessing = None
if PY3:
    long = int
try:
    CalledProcessError = subprocess.CalledProcessError
except AttributeError:
    if 'APPENGINE_RUNTIME' not in os.environ:
        raise

def cpu_count():
    log.info('Trace')
    'Returns the number of processors on this machine.'
    if multiprocessing is None:
        return 1
    try:
        log.info('Trace')
        return multiprocessing.cpu_count()
    except NotImplementedError:
        log.info('Trace')
        pass
    try:
        log.info('Trace')
        return os.sysconf('SC_NPROCESSORS_CONF')
    except (AttributeError, ValueError):
        log.info('Trace')
        pass
    gen_log.error('Could not detect number of processors; assuming 1')
    return 1

def _reseed_random():
    if 'random' not in sys.modules:
        return
    import random
    try:
        log.info('Trace')
        seed = long(hexlify(os.urandom(16)), 16)
    except NotImplementedError:
        log.info('Trace')
        seed = int(time.time() * 1000) ^ os.getpid()
    random.seed(seed)

def _pipe_cloexec():
    (r, w) = os.pipe()
    set_close_exec(r)
    set_close_exec(w)
    return (r, w)
_task_id = None

def fork_processes(num_processes, max_restarts=100):
    log.info('Trace')
    'Starts multiple worker processes.\n\n    If ``num_processes`` is None or <= 0, we detect the number of cores\n    available on this machine and fork that number of child\n    processes. If ``num_processes`` is given and > 0, we fork that\n    specific number of sub-processes.\n\n    Since we use processes and not threads, there is no shared memory\n    between any server code.\n\n    Note that multiple processes are not compatible with the autoreload\n    module (or the ``autoreload=True`` option to `tornado.web.Application`\n    which defaults to True when ``debug=True``).\n    When using multiple processes, no IOLoops can be created or\n    referenced until after the call to ``fork_processes``.\n\n    In each child process, ``fork_processes`` returns its *task id*, a\n    number between 0 and ``num_processes``.  Processes that exit\n    abnormally (due to a signal or non-zero exit status) are restarted\n    with the same id (up to ``max_restarts`` times).  In the parent\n    process, ``fork_processes`` returns None if all child processes\n    have exited normally, but will otherwise only exit by throwing an\n    exception.\n    '
    global _task_id
    assert _task_id is None
    if num_processes is None or num_processes <= 0:
        num_processes = cpu_count()
    if ioloop.IOLoop.initialized():
        raise RuntimeError('Cannot run in multiple processes: IOLoop instance has already been initialized. You cannot call IOLoop.instance() before calling start_processes()')
    gen_log.info('Starting %d processes', num_processes)
    children = {}

    def start_child(i):
        pid = os.fork()
        if pid == 0:
            _reseed_random()
            global _task_id
            _task_id = i
            return i
        else:
            children[pid] = i
            return None
    for i in range(num_processes):
        id = start_child(i)
        if id is not None:
            return id
    num_restarts = 0
    while children:
        try:
            log.info('Trace')
            (pid, status) = os.wait()
        except OSError as e:
            log.info('Trace')
            if errno_from_exception(e) == errno.EINTR:
                continue
            raise
        if pid not in children:
            continue
        id = children.pop(pid)
        if os.WIFSIGNALED(status):
            gen_log.warning('child %d (pid %d) killed by signal %d, restarting', id, pid, os.WTERMSIG(status))
        elif os.WEXITSTATUS(status) != 0:
            gen_log.warning('child %d (pid %d) exited with status %d, restarting', id, pid, os.WEXITSTATUS(status))
        else:
            gen_log.info('child %d (pid %d) exited normally', id, pid)
            continue
        num_restarts += 1
        if num_restarts > max_restarts:
            raise RuntimeError('Too many child restarts, giving up')
        new_id = start_child(id)
        if new_id is not None:
            return new_id
    sys.exit(0)

def task_id():
    """Returns the current task id, if any.

    Returns None if this process was not created by `fork_processes`.
    """
    global _task_id
    return _task_id

class Subprocess(object):
    """Wraps ``subprocess.Popen`` with IOStream support.

    The constructor is the same as ``subprocess.Popen`` with the following
    additions:

    * ``stdin``, ``stdout``, and ``stderr`` may have the value
      ``tornado.process.Subprocess.STREAM``, which will make the corresponding
      attribute of the resulting Subprocess a `.PipeIOStream`.
    * A new keyword argument ``io_loop`` may be used to pass in an IOLoop.

    The ``Subprocess.STREAM`` option and the ``set_exit_callback`` and
    ``wait_for_exit`` methods do not work on Windows. There is
    therefore no reason to use this class instead of
    ``subprocess.Popen`` on that platform.

    .. versionchanged:: 4.1
       The ``io_loop`` argument is deprecated.

    """
    STREAM = object()
    _initialized = False
    _waiting = {}

    def __init__(self, *args, **kwargs):
        log.info('Trace')
        self.io_loop = kwargs.pop('io_loop', None) or ioloop.IOLoop.current()
        pipe_fds = []
        to_close = []
        if kwargs.get('stdin') is Subprocess.STREAM:
            (in_r, in_w) = _pipe_cloexec()
            kwargs['stdin'] = in_r
            pipe_fds.extend((in_r, in_w))
            to_close.append(in_r)
            self.stdin = PipeIOStream(in_w, io_loop=self.io_loop)
        if kwargs.get('stdout') is Subprocess.STREAM:
            (out_r, out_w) = _pipe_cloexec()
            kwargs['stdout'] = out_w
            pipe_fds.extend((out_r, out_w))
            to_close.append(out_w)
            self.stdout = PipeIOStream(out_r, io_loop=self.io_loop)
        if kwargs.get('stderr') is Subprocess.STREAM:
            (err_r, err_w) = _pipe_cloexec()
            kwargs['stderr'] = err_w
            pipe_fds.extend((err_r, err_w))
            to_close.append(err_w)
            self.stderr = PipeIOStream(err_r, io_loop=self.io_loop)
        try:
            log.info('Trace')
            self.proc = subprocess.Popen(*args, **kwargs)
        except:
            log.info('Trace')
            for fd in pipe_fds:
                os.close(fd)
            raise
        for fd in to_close:
            os.close(fd)
        for attr in ['stdin', 'stdout', 'stderr', 'pid']:
            if not hasattr(self, attr):
                setattr(self, attr, getattr(self.proc, attr))
        self._exit_callback = None
        self.returncode = None

    def set_exit_callback(self, callback):
        """Runs ``callback`` when this process exits.

        The callback takes one argument, the return code of the process.

        This method uses a ``SIGCHLD`` handler, which is a global setting
        and may conflict if you have other libraries trying to handle the
        same signal.  If you are using more than one ``IOLoop`` it may
        be necessary to call `Subprocess.initialize` first to designate
        one ``IOLoop`` to run the signal handlers.

        In many cases a close callback on the stdout or stderr streams
        can be used as an alternative to an exit callback if the
        signal handler is causing a problem.
        """
        self._exit_callback = stack_context.wrap(callback)
        Subprocess.initialize(self.io_loop)
        Subprocess._waiting[self.pid] = self
        Subprocess._try_cleanup_process(self.pid)

    def wait_for_exit(self, raise_error=True):
        """Returns a `.Future` which resolves when the process exits.

        Usage::

            ret = yield proc.wait_for_exit()

        This is a coroutine-friendly alternative to `set_exit_callback`
        (and a replacement for the blocking `subprocess.Popen.wait`).

        By default, raises `subprocess.CalledProcessError` if the process
        has a non-zero exit status. Use ``wait_for_exit(raise_error=False)``
        to suppress this behavior and return the exit status without raising.

        .. versionadded:: 4.2
        """
        future = Future()

        def callback(ret):
            if ret != 0 and raise_error:
                future.set_exception(CalledProcessError(ret, None))
            else:
                future.set_result(ret)
        self.set_exit_callback(callback)
        return future

    @classmethod
    def initialize(cls, io_loop=None):
        """Initializes the ``SIGCHLD`` handler.

        The signal handler is run on an `.IOLoop` to avoid locking issues.
        Note that the `.IOLoop` used for signal handling need not be the
        same one used by individual Subprocess objects (as long as the
        ``IOLoops`` are each running in separate threads).

        .. versionchanged:: 4.1
           The ``io_loop`` argument is deprecated.
        """
        if cls._initialized:
            return
        if io_loop is None:
            io_loop = ioloop.IOLoop.current()
        cls._old_sigchld = signal.signal(signal.SIGCHLD, lambda sig, frame: io_loop.add_callback_from_signal(cls._cleanup))
        cls._initialized = True

    @classmethod
    def uninitialize(cls):
        """Removes the ``SIGCHLD`` handler."""
        if not cls._initialized:
            return
        signal.signal(signal.SIGCHLD, cls._old_sigchld)
        cls._initialized = False

    @classmethod
    def _cleanup(cls):
        for pid in list(cls._waiting.keys()):
            cls._try_cleanup_process(pid)

    @classmethod
    def _try_cleanup_process(cls, pid):
        try:
            log.info('Trace')
            (ret_pid, status) = os.waitpid(pid, os.WNOHANG)
        except OSError as e:
            log.info('Trace')
            if errno_from_exception(e) == errno.ECHILD:
                return
        if ret_pid == 0:
            return
        assert ret_pid == pid
        subproc = cls._waiting.pop(pid)
        subproc.io_loop.add_callback_from_signal(subproc._set_returncode, status)

    def _set_returncode(self, status):
        if os.WIFSIGNALED(status):
            self.returncode = -os.WTERMSIG(status)
        else:
            assert os.WIFEXITED(status)
            self.returncode = os.WEXITSTATUS(status)
        self.proc.returncode = self.returncode
        if self._exit_callback:
            callback = self._exit_callback
            self._exit_callback = None
            callback(self.returncode)