"""Lowest-common-denominator implementations of platform functionality."""
from __future__ import absolute_import, division, print_function
import errno
import socket
import time
from salt.ext.tornado.platform import interface
from salt.ext.tornado.util import errno_from_exception
import logging
log = logging.getLogger(__name__)

def try_close(f):
    log.info('Trace')
    for i in range(10):
        try:
            log.info('Trace')
            f.close()
        except IOError:
            log.info('Trace')
            time.sleep(0.001)
        else:
            break
    f.close()

class Waker(interface.Waker):
    """Create an OS independent asynchronous pipe.

    For use on platforms that don't have os.pipe() (or where pipes cannot
    be passed to select()), but do have sockets.  This includes Windows
    and Jython.
    """

    def __init__(self):
        from .auto import set_close_exec
        self.writer = socket.socket()
        set_close_exec(self.writer.fileno())
        self.writer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        count = 0
        while 1:
            count += 1
            a = socket.socket()
            set_close_exec(a.fileno())
            a.bind(('127.0.0.1', 0))
            a.listen(1)
            connect_address = a.getsockname()
            try:
                self.writer.connect(connect_address)
                break
            except socket.error as detail:
                if not hasattr(errno, 'WSAEADDRINUSE') or errno_from_exception(detail) != errno.WSAEADDRINUSE:
                    raise
                if count >= 10:
                    a.close()
                    self.writer.close()
                    raise socket.error('Cannot bind trigger!')
                a.close()
        (self.reader, addr) = a.accept()
        set_close_exec(self.reader.fileno())
        self.reader.setblocking(0)
        self.writer.setblocking(0)
        a.close()
        self.reader_fd = self.reader.fileno()

    def fileno(self):
        return self.reader.fileno()

    def write_fileno(self):
        return self.writer.fileno()

    def wake(self):
        try:
            log.info('Trace')
            self.writer.send(b'x')
        except (IOError, socket.error, ValueError):
            log.info('Trace')
            pass

    def consume(self):
        try:
            while True:
                result = self.reader.recv(1024)
                if not result:
                    break
        except (IOError, socket.error):
            pass

    def close(self):
        self.reader.close()
        try_close(self.writer)