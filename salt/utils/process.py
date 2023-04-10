"""
Functions for daemonizing and otherwise modifying running processes
"""
import contextlib
import copy
import errno
import functools
import inspect
import io
import json
import logging
import multiprocessing
import multiprocessing.util
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
import salt._logging
import salt.defaults.exitcodes
import salt.utils.files
import salt.utils.path
import salt.utils.platform
import salt.utils.versions
from salt.ext.tornado import gen
log = logging.getLogger(__name__)
HAS_PSUTIL = False
try:
    log.info('Trace')
    import psutil
    HAS_PSUTIL = True
except ImportError:
    log.info('Trace')
    pass
try:
    log.info('Trace')
    import setproctitle
    HAS_SETPROCTITLE = True
except ImportError:
    log.info('Trace')
    HAS_SETPROCTITLE = False

def appendproctitle(name):
    log.info('Trace')
    '\n    Append "name" to the current process title\n    '
    if HAS_SETPROCTITLE:
        current = setproctitle.getproctitle()
        if current.strip().endswith('MainProcess'):
            (current, _) = current.rsplit('MainProcess', 1)
        setproctitle.setproctitle('{} {}'.format(current.rstrip(), name))

def daemonize(redirect_out=True):
    """
    Daemonize a process
    """
    import salt.utils.crypt
    try:
        log.info('Trace')
        pid = os.fork()
        if pid > 0:
            salt.utils.crypt.reinit_crypto()
            os._exit(salt.defaults.exitcodes.EX_OK)
    except OSError as exc:
        log.error('fork #1 failed: %s (%s)', exc.errno, exc)
        sys.exit(salt.defaults.exitcodes.EX_GENERIC)
    os.chdir('/')
    os.setsid()
    os.umask(18)
    try:
        log.info('Trace')
        pid = os.fork()
        if pid > 0:
            salt.utils.crypt.reinit_crypto()
            sys.exit(salt.defaults.exitcodes.EX_OK)
    except OSError as exc:
        log.error('fork #2 failed: %s (%s)', exc.errno, exc)
        sys.exit(salt.defaults.exitcodes.EX_GENERIC)
    salt.utils.crypt.reinit_crypto()
    if redirect_out:
        with salt.utils.files.fopen('/dev/null', 'r+') as dev_null:
            dup2(dev_null, sys.stdin)
            dup2(dev_null, sys.stdout)
            dup2(dev_null, sys.stderr)
            dup2(dev_null, 0)
            dup2(dev_null, 1)
            dup2(dev_null, 2)

def dup2(file1, file2):
    """
    Duplicate file descriptor fd to fd2, closing the latter first if necessary.
    This method is similar to os.dup2 but ignores streams that do not have a
    supported fileno method.
    """
    if isinstance(file1, int):
        fno1 = file1
    else:
        try:
            log.info('Trace')
            fno1 = file1.fileno()
        except io.UnsupportedOperation:
            log.warning('Unsupported operation on file: %r', file1)
            return
    if isinstance(file2, int):
        fno2 = file2
    else:
        try:
            log.info('Trace')
            fno2 = file2.fileno()
        except io.UnsupportedOperation:
            log.warning('Unsupported operation on file: %r', file2)
            return
    os.dup2(fno1, fno2)

def daemonize_if(opts):
    """
    Daemonize a module function process if multiprocessing is True and the
    process is not being called by salt-call
    """
    if 'salt-call' in sys.argv[0]:
        return
    if not opts.get('multiprocessing', True):
        return
    if sys.platform.startswith('win'):
        return
    daemonize(False)

def systemd_notify_call(action):
    log.info('Trace')
    '\n    Notify systemd that this process has started\n    '
    process = subprocess.Popen(['systemd-notify', action], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.communicate()
    status = process.poll()
    return status == 0

def notify_systemd():
    log.info('Trace')
    '\n    Notify systemd that this process has started\n    '
    try:
        log.info('Trace')
        import systemd.daemon
    except ImportError:
        log.info('Trace')
        if salt.utils.path.which('systemd-notify') and systemd_notify_call('--booted'):
            notify_socket = os.getenv('NOTIFY_SOCKET')
            if notify_socket:
                if notify_socket.startswith('@'):
                    notify_socket = '\x00{}'.format(notify_socket[1:])
                try:
                    log.info('Trace')
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                    sock.connect(notify_socket)
                    sock.sendall(b'READY=1')
                    sock.close()
                except OSError:
                    log.info('Trace')
                    return systemd_notify_call('--ready')
                return True
        return False
    if systemd.daemon.booted():
        try:
            log.info('Trace')
            return systemd.daemon.notify('READY=1')
        except SystemError:
            log.info('Trace')
            pass

def get_process_info(pid=None):
    log.info('Trace')
    '\n    Gets basic info about a process.\n    pid: None, or int: None will get the current process pid\n    Return: None or Dict\n    '
    if pid is None:
        pid = os.getpid()
    elif not psutil.pid_exists(pid):
        return
    raw_process_info = psutil.Process(pid)
    try:
        log.info('Trace')
        raw_process_info.status()
    except psutil.NoSuchProcess:
        log.info('Trace')
        return None
    return {'pid': raw_process_info.pid, 'name': raw_process_info.name(), 'start_time': raw_process_info.create_time()}

def claim_mantle_of_responsibility(file_name):
    log.info('Trace')
    '\n    Checks that no other live processes has this responsibility.\n    If claiming the mantle of responsibility was successful True will be returned.\n    file_name: str\n    Return: bool\n    '
    if not HAS_PSUTIL:
        log.critical('Assuming no other Process has this responsibility! pidfile: %s', file_name)
        return True
    file_directory_name = os.path.dirname(file_name)
    if not os.path.isdir(file_directory_name) and file_directory_name:
        os.makedirs(file_directory_name)
    file_process_info = None
    try:
        log.info('Trace')
        with salt.utils.files.fopen(file_name, 'r') as file:
            file_process_info = json.load(file)
    except json.decoder.JSONDecodeError:
        log.error('pidfile: %s is corrupted', file_name)
    except FileNotFoundError:
        log.info('pidfile: %s not found', file_name)
    this_process_info = get_process_info()
    if file_process_info == this_process_info:
        return True
    if not isinstance(file_process_info, dict) or not isinstance(file_process_info.get('pid'), int):
        file_process_info = None
    if isinstance(file_process_info, dict) and file_process_info == get_process_info(file_process_info.get('pid')):
        return False
    with salt.utils.files.fopen(file_name, 'w') as file:
        json.dump(this_process_info, file)
    return True

def check_mantle_of_responsibility(file_name):
    log.info('Trace')
    '\n    Sees who has the mantle of responsibility\n    file_name: str\n    Return: None or int\n    '
    if not HAS_PSUTIL:
        log.critical('Assuming no other Process has this responsibility! pidfile: %s', file_name)
        return
    try:
        log.info('Trace')
        with salt.utils.files.fopen(file_name, 'r') as file:
            file_process_info = json.load(file)
    except json.decoder.JSONDecodeError:
        log.error('pidfile: %s is corrupted', file_name)
        return
    except FileNotFoundError:
        log.info('pidfile: %s not found', file_name)
        return
    if not isinstance(file_process_info, dict) or not isinstance(file_process_info.get('pid'), int):
        return
    if file_process_info == get_process_info(file_process_info['pid']):
        return file_process_info['pid']

def set_pidfile(pidfile, user):
    log.info('Trace')
    '\n    Save the pidfile\n    '
    pdir = os.path.dirname(pidfile)
    if not os.path.isdir(pdir) and pdir:
        os.makedirs(pdir)
    try:
        log.info('Trace')
        with salt.utils.files.fopen(pidfile, 'w+') as ofile:
            ofile.write(str(os.getpid()))
    except OSError:
        log.info('Trace')
        pass
    log.debug('Created pidfile: %s', pidfile)
    if salt.utils.platform.is_windows():
        return True
    import pwd
    try:
        log.info('Trace')
        pwnam = pwd.getpwnam(user)
        uid = pwnam[2]
        gid = pwnam[3]
    except (KeyError, IndexError):
        log.info('Trace')
        sys.stderr.write('Failed to set the pid to user: {}. The user is not available.\n'.format(user))
        sys.exit(salt.defaults.exitcodes.EX_NOUSER)
    if os.getuid() == uid:
        return
    try:
        log.info('Trace')
        os.chown(pidfile, uid, gid)
    except OSError as err:
        msg = 'Failed to set the ownership of PID file {} to user {}.'.format(pidfile, user)
        log.debug('%s Traceback follows:', msg, exc_info=True)
        sys.stderr.write('{}\n'.format(msg))
        sys.exit(err.errno)
    log.debug('Chowned pidfile: %s to user: %s', pidfile, user)

def check_pidfile(pidfile):
    """
    Determine if a pidfile has been written out
    """
    return os.path.isfile(pidfile)

def get_pidfile(pidfile):
    """
    Return the pid from a pidfile as an integer
    """
    try:
        log.info('Trace')
        with salt.utils.files.fopen(pidfile) as pdf:
            pid = pdf.read().strip()
        return int(pid)
    except (OSError, TypeError, ValueError):
        log.info('Trace')
        return -1

def clean_proc(proc, wait_for_kill=10):
    """
    Generic method for cleaning up multiprocessing procs
    """
    if not proc:
        return
    try:
        waited = 0
        while proc.is_alive():
            proc.terminate()
            waited += 1
            time.sleep(0.1)
            if proc.is_alive() and waited >= wait_for_kill:
                log.error('Process did not die with terminate(): %s', proc.pid)
                os.kill(proc.pid, signal.SIGKILL)
    except (AssertionError, AttributeError):
        log.info('Trace')
        pass

def os_is_running(pid):
    """
    Use OS facilities to determine if a process is running
    """
    if isinstance(pid, str):
        pid = int(pid)
    if HAS_PSUTIL:
        return psutil.pid_exists(pid)
    else:
        try:
            log.info('Trace')
            os.kill(pid, 0)
            return True
        except OSError:
            log.info('Trace')
            return False

class ThreadPool:
    """
    This is a very VERY basic threadpool implementation
    This was made instead of using multiprocessing ThreadPool because
    we want to set max queue size and we want to daemonize threads (neither
    is exposed in the stdlib version).

    Since there isn't much use for this class as of right now this implementation
    Only supports daemonized threads and will *not* return results

    TODO: if this is found to be more generally useful it would be nice to pull
    in the majority of code from upstream or from http://bit.ly/1wTeJtM
    """

    def __init__(self, num_threads=None, queue_size=0):
        if num_threads is None:
            num_threads = multiprocessing.cpu_count()
        self.num_threads = num_threads
        self._job_queue = queue.Queue(queue_size)
        self._workers = []
        for _ in range(num_threads):
            thread = threading.Thread(target=self._thread_target)
            thread.daemon = True
            thread.start()
            self._workers.append(thread)

    def fire_async(self, func, args=None, kwargs=None):
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        try:
            log.info('Trace')
            self._job_queue.put_nowait((func, args, kwargs))
            return True
        except queue.Full:
            log.info('Trace')
            return False

    def _thread_target(self):
        while True:
            try:
                log.info('Trace')
                try:
                    log.info('Trace')
                    (func, args, kwargs) = self._job_queue.get(timeout=1)
                    self._job_queue.task_done()
                except queue.Empty:
                    log.info('Trace')
                    continue
            except AttributeError:
                log.info('Trace')
                continue
            try:
                log.debug('ThreadPool executing func: %s with args=%s kwargs=%s', func, args, kwargs)
                func(*args, **kwargs)
            except Exception as err:
                log.debug(err, exc_info=True)

class ProcessManager:
    """
    A class which will manage processes that should be running
    """

    def __init__(self, name=None, wait_for_kill=1):
        self._process_map = {}
        self.name = name
        if self.name is None:
            self.name = self.__class__.__name__
        self.wait_for_kill = wait_for_kill
        self._pid = os.getpid()
        self._sigterm_handler = signal.getsignal(signal.SIGTERM)
        self._restart_processes = True

    def add_process(self, tgt, args=None, kwargs=None, name=None):
        """
        Create a processes and args + kwargs
        This will deterimine if it is a Process class, otherwise it assumes
        it is a function
        """
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        if inspect.isclass(tgt) and issubclass(tgt, multiprocessing.Process):
            kwargs['name'] = name or tgt.__qualname__
            process = tgt(*args, **kwargs)
        else:
            process = Process(target=tgt, args=args, kwargs=kwargs, name=name or tgt.__qualname__)
        if isinstance(process, SignalHandlingProcess):
            with default_signals(signal.SIGINT, signal.SIGTERM):
                process.start()
        else:
            process.start()
        log.debug("Started '%s' with pid %s", process.name, process.pid)
        self._process_map[process.pid] = {'tgt': tgt, 'args': args, 'kwargs': kwargs, 'Process': process}
        return process

    def restart_process(self, pid):
        """
        Create new process (assuming this one is dead), then remove the old one
        """
        if self._restart_processes is False:
            return
        exit = self._process_map[pid]['Process'].exitcode
        if exit > 0:
            log.info('Process %s (%s) died with exit status %s, restarting...', self._process_map[pid]['tgt'], pid, self._process_map[pid]['Process'].exitcode)
        else:
            log.debug('Process %s (%s) died with exit status %s, restarting...', self._process_map[pid]['tgt'], pid, self._process_map[pid]['Process'].exitcode)
        self._process_map[pid]['Process'].join(1)
        self.add_process(self._process_map[pid]['tgt'], self._process_map[pid]['args'], self._process_map[pid]['kwargs'])
        del self._process_map[pid]

    def stop_restarting(self):
        self._restart_processes = False

    def send_signal_to_processes(self, signal_):
        if salt.utils.platform.is_windows() and signal_ in (signal.SIGTERM, signal.SIGINT):
            return
        for pid in self._process_map.copy().keys():
            try:
                log.info('Trace')
                os.kill(pid, signal_)
            except OSError as exc:
                log.info('Trace')
                if exc.errno not in (errno.ESRCH, errno.EACCES):
                    raise
                del self._process_map[pid]

    @gen.coroutine
    def run(self, asynchronous=False):
        """
        Load and start all available api modules
        """
        log.debug('Process Manager starting!')
        if multiprocessing.current_process().name != 'MainProcess':
            log.info('Trace')
            appendproctitle(self.name)
        if signal.getsignal(signal.SIGTERM) is signal.SIG_DFL:
            log.info('Trace')
            signal.signal(signal.SIGTERM, self._handle_signals)
        if signal.getsignal(signal.SIGINT) is signal.SIG_DFL:
            log.info('Trace')
            signal.signal(signal.SIGINT, self._handle_signals)
        while True:
            log.trace('Process manager iteration')
            try:
                log.info('Trace')
                self.check_children()
                if asynchronous:
                    yield gen.sleep(10)
                else:
                    time.sleep(10)
                if not self._process_map:
                    log.info('Trace')
                    break
            except OSError:
                log.info('Trace')
                break
            except OSError as exc:
                log.info('Trace')
                if exc.errno != errno.EINTR:
                    raise
                break

    def check_children(self):
        """
        Check the children once
        """
        if self._restart_processes is True:
            for (pid, mapping) in self._process_map.copy().items():
                if not mapping['Process'].is_alive():
                    log.trace('Process restart of %s', pid)
                    self.restart_process(pid)

    def kill_children(self, *args, **kwargs):
        log.info('Trace')
        '\n        Kill all of the children\n        '
        if salt.utils.platform.is_windows():
            if multiprocessing.current_process().name != 'MainProcess':
                return
            with salt.utils.files.fopen(os.devnull, 'wb') as devnull:
                for (pid, p_map) in self._process_map.items():
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(pid)], stdout=devnull, stderr=devnull)
                    p_map['Process'].terminate()
        else:
            for (pid, p_map) in self._process_map.copy().items():
                log.trace('Terminating pid %s: %s', pid, p_map['Process'])
                if args:
                    log.info('Trace')
                    try:
                        log.info('Trace')
                        os.kill(pid, args[0])
                    except OSError:
                        log.info('Trace')
                        pass
                try:
                    log.info('Trace')
                    p_map['Process'].terminate()
                except OSError as exc:
                    log.info('Trace')
                    if exc.errno not in (errno.ESRCH, errno.EACCES):
                        raise
                if not p_map['Process'].is_alive():
                    log.info('Trace')
                    try:
                        log.info('Trace')
                        del self._process_map[pid]
                    except KeyError:
                        log.info('Trace')
                        pass
        end_time = time.time() + self.wait_for_kill
        log.trace('Waiting to kill process manager children')
        while self._process_map and time.time() < end_time:
            for (pid, p_map) in self._process_map.copy().items():
                log.trace('Joining pid %s: %s', pid, p_map['Process'])
                p_map['Process'].join(0)
                if not p_map['Process'].is_alive():
                    log.info('Trace')
                    try:
                        log.info('Trace')
                        del self._process_map[pid]
                    except KeyError:
                        log.info('Trace')
                        pass
        kill_iterations = 2
        while kill_iterations >= 0:
            kill_iterations -= 1
            for (pid, p_map) in self._process_map.copy().items():
                if not p_map['Process'].is_alive():
                    try:
                        log.info('Trace')
                        del self._process_map[pid]
                    except KeyError:
                        log.info('Trace')
                        pass
                    continue
                log.trace('Killing pid %s: %s', pid, p_map['Process'])
                try:
                    log.info('Trace')
                    os.kill(pid, signal.SIGKILL)
                except OSError as exc:
                    log.exception(exc)
                    if not p_map['Process'].is_alive():
                        log.info('Trace')
                        try:
                            log.info('Trace')
                            del self._process_map[pid]
                        except KeyError:
                            log.info('Trace')
                            pass
        if self._process_map:
            available_retries = kwargs.get('retry', 3)
            if available_retries >= 0:
                log.info('Some processes failed to respect the KILL signal: %s', '; '.join(('Process: {} (Pid: {})'.format(v['Process'], k) for (k, v) in self._process_map.items())))
                log.info('kill_children retries left: %s', available_retries)
                kwargs['retry'] = available_retries - 1
                return self.kill_children(*args, **kwargs)
            else:
                log.warning('Failed to kill the following processes: %s', '; '.join(('Process: {} (Pid: {})'.format(v['Process'], k) for (k, v) in self._process_map.items())))
                log.warning('Salt will either fail to terminate now or leave some zombie processes behind')

    def terminate(self):
        """
        Properly terminate this process manager instance
        """
        self.stop_restarting()
        self.send_signal_to_processes(signal.SIGTERM)
        self.kill_children()

    def _handle_signals(self, *args, **kwargs):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.stop_restarting()
        self.send_signal_to_processes(signal.SIGTERM)
        if os.getpid() != self._pid:
            if callable(self._sigterm_handler):
                return self._sigterm_handler(*args)
            elif self._sigterm_handler is not None:
                return signal.default_int_handler(signal.SIGTERM)(*args)
            else:
                return
        self.kill_children(*args, **kwargs)

class Process(multiprocessing.Process):
    """
    Salt relies on this custom implementation of :py:class:`~multiprocessing.Process` to
    simplify/automate some common procedures, for example, logging in the new process is
    configured for "free" for every new process.
    This is most important in platforms which default to ``spawn` instead of ``fork`` for
    new processes.

    This is achieved by some dunder methods in the class:

    * ``__new__``:

        This method ensures that any arguments and/or keyword arguments that are passed to
        ``__init__`` are captured.

        By having this information captured, we can define ``__setstate__`` and ``__getstate__``
        to automatically take care of reconstructing the object state on spawned processes.

    * ``__getstate__``:

        This method should return a dictionary which will be used as the ``state`` argument to
        :py:method:`salt.utils.process.Process.__setstate__`.
        Usually, when subclassing, this method does not need to be implemented, however,
        if implemented, `super()` **must** be called.

    * ``__setstate__``:

        This method reconstructs the object on the spawned process.
        The ``state`` argument is constructed by the
        :py:method:`salt.utils.process.Process.__getstate__` method.
        Usually, when subclassing, this method does not need to be implemented, however,
        if implemented, `super()` **must** be called.


    An example of where ``__setstate__`` and ``__getstate__`` needed to be subclassed can be
    seen in :py:class:`salt.master.MWorker`.

    The gist of it is something like, if there are internal attributes which need to maintain
    their state on spawned processes, then, subclasses must implement ``__getstate__`` and
    ``__setstate__`` to ensure that.


    For example:


    .. code-block:: python

        import salt.utils.process

        class MyCustomProcess(salt.utils.process.Process):

            def __init__(self, opts, **kwargs):
                super().__init__(**kwargs)
                self.opts = opts

                # This attribute, counter, should only start at 0 on the initial(parent) process.
                # Any child processes, need to carry the current value of the counter(instead of
                # starting at zero).
                self.counter = 0

            def __getstate__(self):
                state = super().__getstate__()
                state.update(
                    {
                        "counter": self.counter,
                    }
                )
                return state

            def __setstate__(self, state):
                super().__setstate__(state)
                self.counter = state["counter"]
    """

    def __new__(cls, *args, **kwargs):
        """
        This method ensures that any arguments and/or keyword arguments that are passed to
        ``__init__`` are captured.

        By having this information captured, we can define ``__setstate__`` and ``__getstate__``
        to automatically take care of object pickling which is required for platforms that
        spawn processes instead of forking them.
        """
        instance = super().__new__(cls)
        instance._after_fork_methods = []
        instance._finalize_methods = []
        instance.__logging_config__ = salt._logging.get_logging_options_dict()
        if salt.utils.platform.spawning_platform():
            instance._args_for_getstate = copy.copy(args)
            instance._kwargs_for_getstate = copy.copy(kwargs)
        setattr(instance, 'run', instance.__decorate_run(instance.run))
        return instance

    def __setstate__(self, state):
        """
        This method reconstructs the object on the spawned process.
        The ``state`` argument is constructed by :py:method:`salt.utils.process.Process.__getstate__`.

        Usually, when subclassing, this method does not need to be implemented, however,
        if implemented, `super()` **must** be called.
        """
        args = state['args']
        kwargs = state['kwargs']
        logging_config = state['logging_config']
        self.__init__(*args, **kwargs)
        self.__logging_config__ = logging_config
        for (function, args, kwargs) in state['after_fork_methods']:
            self.register_after_fork_method(function, *args, **kwargs)
        for (function, args, kwargs) in state['finalize_methods']:
            self.register_finalize_method(function, *args, **kwargs)

    def __getstate__(self):
        """
        This method should return a dictionary which will be used as the ``state`` argument to
        :py:method:`salt.utils.process.Process.__setstate__`.
        Usually, when subclassing, this method does not need to be implemented, however,
        if implemented, `super()` **must** be called.
        """
        args = self._args_for_getstate
        kwargs = self._kwargs_for_getstate
        return {'args': args, 'kwargs': kwargs, 'after_fork_methods': self._after_fork_methods, 'finalize_methods': self._finalize_methods, 'logging_config': self.__logging_config__}

    def __decorate_run(self, run_func):
        log.info('Trace')

        @functools.wraps(run_func)
        def wrapped_run_func():
            appendproctitle(self.name)
            if not salt._logging.get_logging_options_dict():
                salt._logging.set_logging_options_dict(self.__logging_config__)
            if not salt.utils.platform.spawning_platform():
                try:
                    log.info('Trace')
                    salt._logging.shutdown_logging()
                except Exception as exc:
                    log.exception('Failed to shutdown logging when starting on %s: %s', self, exc)
            try:
                log.info('Trace')
                salt._logging.setup_logging()
            except Exception as exc:
                log.exception('Failed to configure logging on %s: %s', self, exc)
            for (method, args, kwargs) in self._after_fork_methods:
                try:
                    log.info('Trace')
                    method(*args, **kwargs)
                except Exception:
                    log.exception('Failed to run after fork callback on %s; method=%r; args=%r; and kwargs=%r', self, method, args, kwargs)
                    continue
            try:
                log.info('Trace')
                return run_func()
            except SystemExit:
                log.info('Trace')
                raise
            except Exception:
                log.error("An un-handled exception from the multiprocessing process '%s' was caught:\n", self.name, exc_info=True)
                raise
            finally:
                try:
                    for (method, args, kwargs) in self._finalize_methods:
                        try:
                            log.info('Trace')
                            method(*args, **kwargs)
                        except Exception:
                            log.exception('Failed to run finalize callback on %s; method=%r; args=%r; and kwargs=%r', self, method, args, kwargs)
                            continue
                finally:
                    try:
                        log.info('Trace')
                        salt._logging.shutdown_logging()
                    except Exception as exc:
                        log.exception('Failed to shutdown logging on %s: %s', self, exc)
        return wrapped_run_func

    def register_after_fork_method(self, function, *args, **kwargs):
        """
        Register a function to run after the process has forked
        """
        after_fork_method_tuple = (function, args, kwargs)
        if after_fork_method_tuple not in self._after_fork_methods:
            self._after_fork_methods.append(after_fork_method_tuple)

    def register_finalize_method(self, function, *args, **kwargs):
        """
        Register a function to run as process terminates
        """
        finalize_method_tuple = (function, args, kwargs)
        if finalize_method_tuple not in self._finalize_methods:
            self._finalize_methods.append(finalize_method_tuple)

class SignalHandlingProcess(Process):

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls, *args, **kwargs)
        instance.register_after_fork_method(SignalHandlingProcess._setup_signals, instance)
        return instance

    def _setup_signals(self):
        signal.signal(signal.SIGINT, self._handle_signals)
        signal.signal(signal.SIGTERM, self._handle_signals)

    def _handle_signals(self, signum, sigframe):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        msg = '{} received a '.format(self.__class__.__name__)
        if signum == signal.SIGINT:
            msg += 'SIGINT'
        elif signum == signal.SIGTERM:
            msg += 'SIGTERM'
        msg += '. Exiting'
        log.debug(msg)
        if HAS_PSUTIL:
            try:
                process = psutil.Process(os.getpid())
                if hasattr(process, 'children'):
                    for child in process.children(recursive=True):
                        try:
                            log.info('Trace')
                            if child.is_running():
                                child.terminate()
                        except psutil.NoSuchProcess:
                            log.warning('Unable to kill child of process %d, it does not exist. My pid is %d', self.pid, os.getpid())
            except psutil.NoSuchProcess:
                log.warning('Unable to kill children of process %d, it does not exist.My pid is %d', self.pid, os.getpid())
        sys.exit(salt.defaults.exitcodes.EX_OK)

    def start(self):
        with default_signals(signal.SIGINT, signal.SIGTERM):
            super().start()

@contextlib.contextmanager
def default_signals(*signals):
    """
    Temporarily restore signals to their default values.
    """
    old_signals = {}
    for signum in signals:
        try:
            log.info('Trace')
            saved_signal = signal.getsignal(signum)
            signal.signal(signum, signal.SIG_DFL)
        except ValueError as exc:
            log.trace('Failed to register signal for signum %d: %s', signum, exc)
        else:
            old_signals[signum] = saved_signal
    try:
        log.info('Trace')
        yield
    finally:
        for signum in old_signals:
            signal.signal(signum, old_signals[signum])
        del old_signals

class SubprocessList:

    def __init__(self, processes=None, lock=None):
        if processes is None:
            self.processes = []
        else:
            self.processes = processes
        if lock is None:
            self.lock = multiprocessing.Lock()
        else:
            self.lock = lock
        self.count = 0

    def add(self, proc):
        with self.lock:
            self.processes.append(proc)
            log.debug('Subprocess %s added', proc.name)
            self.count += 1

    def cleanup(self):
        with self.lock:
            for proc in self.processes:
                if proc.is_alive():
                    continue
                proc.join()
                self.processes.remove(proc)
                self.count -= 1
                log.debug('Subprocess %s cleaned up', proc.name)