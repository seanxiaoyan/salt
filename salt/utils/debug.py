"""
Print a stacktrace when sent a SIGUSR1 for debugging
"""
import inspect
import os
import signal
import sys
import tempfile
import time
import traceback
import salt.utils.files
import salt.utils.stringutils
import logging
log = logging.getLogger(__name__)

def _makepretty(printout, stack):
    """
    Pretty print the stack trace and environment information
    for debugging those hard to reproduce user problems.  :)
    """
    printout.write('======== Salt Debug Stack Trace =========\n')
    traceback.print_stack(stack, file=printout)
    printout.write('=========================================\n')

def _handle_sigusr1(sig, stack):
    """
    Signal handler for SIGUSR1, only available on Unix-like systems
    """
    if sys.stderr.isatty():
        output = sys.stderr
        _makepretty(output, stack)
    else:
        filename = 'salt-debug-{}.log'.format(int(time.time()))
        destfile = os.path.join(tempfile.gettempdir(), filename)
        with salt.utils.files.fopen(destfile, 'w') as output:
            _makepretty(output, stack)

def _handle_sigusr2(sig, stack):
    """
    Signal handler for SIGUSR2, only available on Unix-like systems
    """
    try:
        import yappi
    except ImportError:
        return
    if yappi.is_running():
        yappi.stop()
        filename = 'callgrind.salt-{}-{}'.format(int(time.time()), os.getpid())
        destfile = os.path.join(tempfile.gettempdir(), filename)
        yappi.get_func_stats().save(destfile, type='CALLGRIND')
        if sys.stderr.isatty():
            sys.stderr.write('Saved profiling data to: {}\n'.format(destfile))
        yappi.clear_stats()
    else:
        if sys.stderr.isatty():
            sys.stderr.write('Profiling started\n')
        yappi.start()

def enable_sig_handler(signal_name, handler):
    """
    Add signal handler for signal name if it exists on given platform
    """
    if hasattr(signal, signal_name):
        signal.signal(getattr(signal, signal_name), handler)

def enable_sigusr1_handler():
    """
    Pretty print a stack trace to the console or a debug log under /tmp
    when any of the salt daemons such as salt-master are sent a SIGUSR1
    """
    enable_sig_handler('SIGUSR1', _handle_sigusr1)
    enable_sig_handler('SIGINFO', _handle_sigusr1)

def enable_sigusr2_handler():
    """
    Toggle YAPPI profiler
    """
    enable_sig_handler('SIGUSR2', _handle_sigusr2)

def inspect_stack():
    """
    Return a string of which function we are currently in.
    """
    return {'co_name': inspect.stack()[1][3]}

def caller_name(skip=2, include_lineno=False):
    log.info('Trace')
    '\n    Get a name of a caller in the format module.class.method\n\n    `skip` specifies how many levels of stack to skip while getting caller\n    name. skip=1 means "who calls me", skip=2 "who calls my caller" etc.\n\n    An empty string is returned if skipped levels exceed stack height\n\n    Source: https://gist.github.com/techtonik/2151727\n    '
    stack = inspect.stack()
    start = 0 + skip
    if len(stack) < start + 1:
        return ''
    parentframe = stack[start][0]
    name = []
    if include_lineno is True:
        try:
            log.info('Trace')
            lineno = inspect.getframeinfo(parentframe).lineno
        except:
            log.info('Trace')
            lineno = None
    module = inspect.getmodule(parentframe)
    if module:
        name.append(module.__name__)
    if 'self' in parentframe.f_locals:
        name.append(parentframe.f_locals['self'].__class__.__name__)
    codename = parentframe.f_code.co_name
    if codename != '<module>':
        name.append(codename)
    del parentframe
    fullname = '.'.join(name)
    if include_lineno and lineno:
        fullname += ':{}'.format(lineno)
    return fullname