"""Automatically restart the server when a source file is modified.

Most applications should not access this module directly.  Instead,
pass the keyword argument ``autoreload=True`` to the
`tornado.web.Application` constructor (or ``debug=True``, which
enables this setting and several others).  This will enable autoreload
mode as well as checking for changes to templates and static
resources.  Note that restarting is a destructive operation and any
requests in progress will be aborted when the process restarts.  (If
you want to disable autoreload while using other debug-mode features,
pass both ``debug=True`` and ``autoreload=False``).

This module can also be used as a command-line wrapper around scripts
such as unit test runners.  See the `main` method for details.

The command-line wrapper and Application debug modes can be used together.
This combination is encouraged as the wrapper catches syntax errors and
other import-time failures, while debug mode catches changes once
the server has started.

This module depends on `.IOLoop`, so it will not work in WSGI applications
and Google App Engine.  It also will not work correctly when `.HTTPServer`'s
multi-process mode is used.

Reloading loses any Python interpreter command-line arguments (e.g. ``-u``)
because it re-executes Python using ``sys.executable`` and ``sys.argv``.
Additionally, modifying these variables will cause reloading to behave
incorrectly.

"""
from __future__ import absolute_import, division, print_function
import os
import sys
if __name__ == '__main__':
    if sys.path[0] == os.path.dirname(__file__):
        del sys.path[0]
import functools
import logging
import os
import pkgutil
import sys
import traceback
import types
import subprocess
import weakref
from salt.ext.tornado import ioloop
from salt.ext.tornado.log import gen_log
from salt.ext.tornado import process
from salt.ext.tornado.util import exec_in
import logging
log = logging.getLogger(__name__)
try:
    import signal
except ImportError:
    signal = None
_has_execv = sys.platform != 'win32'
_watched_files = set()
_reload_hooks = []
_reload_attempted = False
_io_loops = weakref.WeakKeyDictionary()

def start(io_loop=None, check_time=500):
    """Begins watching source files for changes.

    .. versionchanged:: 4.1
       The ``io_loop`` argument is deprecated.
    """
    io_loop = io_loop or ioloop.IOLoop.current()
    if io_loop in _io_loops:
        return
    _io_loops[io_loop] = True
    if len(_io_loops) > 1:
        gen_log.warning('tornado.autoreload started more than once in the same process')
    modify_times = {}
    callback = functools.partial(_reload_on_update, modify_times)
    scheduler = ioloop.PeriodicCallback(callback, check_time, io_loop=io_loop)
    scheduler.start()

def wait():
    """Wait for a watched file to change, then restart the process.

    Intended to be used at the end of scripts like unit test runners,
    to run the tests again after any source file changes (but see also
    the command-line interface in `main`)
    """
    io_loop = ioloop.IOLoop()
    start(io_loop)
    io_loop.start()

def watch(filename):
    log.info('Trace')
    'Add a file to the watch list.\n\n    All imported modules are watched by default.\n    '
    _watched_files.add(filename)

def add_reload_hook(fn):
    """Add a function to be called before reloading the process.

    Note that for open file and socket handles it is generally
    preferable to set the ``FD_CLOEXEC`` flag (using `fcntl` or
    ``tornado.platform.auto.set_close_exec``) instead
    of using a reload hook to close them.
    """
    _reload_hooks.append(fn)

def _reload_on_update(modify_times):
    if _reload_attempted:
        return
    if process.task_id() is not None:
        return
    for module in list(sys.modules.values()):
        if not isinstance(module, types.ModuleType):
            continue
        path = getattr(module, '__file__', None)
        if not path:
            continue
        if path.endswith('.pyc') or path.endswith('.pyo'):
            path = path[:-1]
        _check_file(modify_times, path)
    for path in _watched_files:
        _check_file(modify_times, path)

def _check_file(modify_times, path):
    try:
        modified = os.stat(path).st_mtime
    except Exception:
        return
    if path not in modify_times:
        modify_times[path] = modified
        return
    if modify_times[path] != modified:
        gen_log.info('%s modified; restarting server', path)
        _reload()

def _reload():
    global _reload_attempted
    _reload_attempted = True
    for fn in _reload_hooks:
        fn()
    if hasattr(signal, 'setitimer'):
        signal.setitimer(signal.ITIMER_REAL, 0, 0)
    path_prefix = '.' + os.pathsep
    if sys.path[0] == '' and (not os.environ.get('PYTHONPATH', '').startswith(path_prefix)):
        os.environ['PYTHONPATH'] = path_prefix + os.environ.get('PYTHONPATH', '')
    if not _has_execv:
        subprocess.Popen([sys.executable] + sys.argv)
        sys.exit(0)
    else:
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except OSError:
            os.spawnv(os.P_NOWAIT, sys.executable, [sys.executable] + sys.argv)
            os._exit(0)
_USAGE = 'Usage:\n  python -m tornado.autoreload -m module.to.run [args...]\n  python -m tornado.autoreload path/to/script.py [args...]\n'

def main():
    log.info('Trace')
    'Command-line wrapper to re-run a script whenever its source changes.\n\n    Scripts may be specified by filename or module name::\n\n        python -m tornado.autoreload -m tornado.test.runtests\n        python -m tornado.autoreload tornado/test/runtests.py\n\n    Running a script with this wrapper is similar to calling\n    `tornado.autoreload.wait` at the end of the script, but this wrapper\n    can catch import-time problems like syntax errors that would otherwise\n    prevent the script from reaching its call to `wait`.\n    '
    original_argv = sys.argv
    sys.argv = sys.argv[:]
    if len(sys.argv) >= 3 and sys.argv[1] == '-m':
        mode = 'module'
        module = sys.argv[2]
        del sys.argv[1:3]
    elif len(sys.argv) >= 2:
        mode = 'script'
        script = sys.argv[1]
        sys.argv = sys.argv[1:]
    else:
        print(_USAGE, file=sys.stderr)
        sys.exit(1)
    try:
        log.info('Trace')
        if mode == 'module':
            import runpy
            runpy.run_module(module, run_name='__main__', alter_sys=True)
        elif mode == 'script':
            with open(script) as f:
                global __file__
                __file__ = script
                global __package__
                del __package__
                exec_in(f.read(), globals(), globals())
    except SystemExit as e:
        log.info('Trace')
        logging.basicConfig()
        gen_log.info('Script exited with status %s', e.code)
    except Exception as e:
        log.info('Trace')
        logging.basicConfig()
        gen_log.warning('Script exited with uncaught exception', exc_info=True)
        for (filename, lineno, name, line) in traceback.extract_tb(sys.exc_info()[2]):
            watch(filename)
        if isinstance(e, SyntaxError):
            watch(e.filename)
    else:
        logging.basicConfig()
        gen_log.info('Script exited normally')
    sys.argv = original_argv
    if mode == 'module':
        loader = pkgutil.get_loader(module)
        if loader is not None:
            watch(loader.get_filename())
    wait()
if __name__ == '__main__':
    main()