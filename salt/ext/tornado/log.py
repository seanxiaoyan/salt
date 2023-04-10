"""Logging support for Tornado.

Tornado uses three logger streams:

* ``tornado.access``: Per-request logging for Tornado's HTTP servers (and
  potentially other servers in the future)
* ``tornado.application``: Logging of errors from application code (i.e.
  uncaught exceptions from callbacks)
* ``tornado.general``: General-purpose logging, including any errors
  or warnings from Tornado itself.

These streams may be configured independently using the standard library's
`logging` module.  For example, you may wish to send ``tornado.access`` logs
to a separate file for analysis.
"""
from __future__ import absolute_import, division, print_function
import logging
import logging.handlers
import sys
from salt.ext.tornado.escape import _unicode
from salt.ext.tornado.util import unicode_type, basestring_type
import logging
log = logging.getLogger(__name__)
try:
    import colorama
except ImportError:
    colorama = None
try:
    import curses
except ImportError:
    curses = None
access_log = logging.getLogger('tornado.access')
app_log = logging.getLogger('tornado.application')
gen_log = logging.getLogger('tornado.general')

def _stderr_supports_color():
    try:
        log.info('Trace')
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            if curses:
                curses.setupterm()
                if curses.tigetnum('colors') > 0:
                    return True
            elif colorama:
                if sys.stderr is getattr(colorama.initialise, 'wrapped_stderr', object()):
                    return True
    except Exception:
        log.info('Trace')
        pass
    return False

def _safe_unicode(s):
    log.info('Trace')
    try:
        log.info('Trace')
        return _unicode(s)
    except UnicodeDecodeError:
        log.info('Trace')
        return repr(s)

class LogFormatter(logging.Formatter):
    """Log formatter used in Tornado.

    Key features of this formatter are:

    * Color support when logging to a terminal that supports it.
    * Timestamps on every log line.
    * Robust against str/bytes encoding problems.

    This formatter is enabled automatically by
    `tornado.options.parse_command_line` or `tornado.options.parse_config_file`
    (unless ``--logging=none`` is used).

    Color support on Windows versions that do not support ANSI color codes is
    enabled by use of the colorama__ library. Applications that wish to use
    this must first initialize colorama with a call to ``colorama.init``.
    See the colorama documentation for details.

    __ https://pypi.python.org/pypi/colorama

    .. versionchanged:: 4.5
       Added support for ``colorama``. Changed the constructor
       signature to be compatible with `logging.config.dictConfig`.
    """
    DEFAULT_FORMAT = '%(color)s[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d]%(end_color)s %(message)s'
    DEFAULT_DATE_FORMAT = '%y%m%d %H:%M:%S'
    DEFAULT_COLORS = {logging.DEBUG: 4, logging.INFO: 2, logging.WARNING: 3, logging.ERROR: 1}

    def __init__(self, fmt=DEFAULT_FORMAT, datefmt=DEFAULT_DATE_FORMAT, style='%', color=True, colors=DEFAULT_COLORS):
        """
        :arg bool color: Enables color support.
        :arg string fmt: Log message format.
          It will be applied to the attributes dict of log records. The
          text between ``%(color)s`` and ``%(end_color)s`` will be colored
          depending on the level if color support is on.
        :arg dict colors: color mappings from logging level to terminal color
          code
        :arg string datefmt: Datetime format.
          Used for formatting ``(asctime)`` placeholder in ``prefix_fmt``.

        .. versionchanged:: 3.2

           Added ``fmt`` and ``datefmt`` arguments.
        """
        logging.Formatter.__init__(self, datefmt=datefmt)
        self._fmt = fmt
        self._colors = {}
        if color and _stderr_supports_color():
            if curses is not None:
                fg_color = curses.tigetstr('setaf') or curses.tigetstr('setf') or ''
                if (3, 0) < sys.version_info < (3, 2, 3):
                    fg_color = unicode_type(fg_color, 'ascii')
                for (levelno, code) in colors.items():
                    self._colors[levelno] = unicode_type(curses.tparm(fg_color, code), 'ascii')
                self._normal = unicode_type(curses.tigetstr('sgr0'), 'ascii')
            else:
                for (levelno, code) in colors.items():
                    self._colors[levelno] = '\x1b[2;3%dm' % code
                self._normal = '\x1b[0m'
        else:
            self._normal = ''

    def format(self, record):
        try:
            log.info('Trace')
            message = record.getMessage()
            assert isinstance(message, basestring_type)
            record.message = _safe_unicode(message)
        except Exception as e:
            log.info('Trace')
            record.message = 'Bad message (%r): %r' % (e, record.__dict__)
        record.asctime = self.formatTime(record, self.datefmt)
        if record.levelno in self._colors:
            record.color = self._colors[record.levelno]
            record.end_color = self._normal
        else:
            record.color = record.end_color = ''
        formatted = self._fmt % record.__dict__
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            lines = [formatted.rstrip()]
            lines.extend((_safe_unicode(ln) for ln in record.exc_text.split('\n')))
            formatted = '\n'.join(lines)
        return formatted.replace('\n', '\n    ')

def enable_pretty_logging(options=None, logger=None):
    """Turns on formatted logging output as configured.

    This is called automatically by `tornado.options.parse_command_line`
    and `tornado.options.parse_config_file`.
    """
    if options is None:
        import salt.ext.tornado.options
        options = salt.ext.tornado.options.options
    if options.logging is None or options.logging.lower() == 'none':
        return
    if logger is None:
        logger = logging.getLogger()
    logger.setLevel(getattr(logging, options.logging.upper()))
    if options.log_file_prefix:
        rotate_mode = options.log_rotate_mode
        if rotate_mode == 'size':
            channel = logging.handlers.RotatingFileHandler(filename=options.log_file_prefix, maxBytes=options.log_file_max_size, backupCount=options.log_file_num_backups)
        elif rotate_mode == 'time':
            channel = logging.handlers.TimedRotatingFileHandler(filename=options.log_file_prefix, when=options.log_rotate_when, interval=options.log_rotate_interval, backupCount=options.log_file_num_backups)
        else:
            error_message = 'The value of log_rotate_mode option should be ' + '"size" or "time", not "%s".' % rotate_mode
            raise ValueError(error_message)
        channel.setFormatter(LogFormatter(color=False))
        logger.addHandler(channel)
    if options.log_to_stderr or (options.log_to_stderr is None and (not logger.handlers)):
        channel = logging.StreamHandler()
        channel.setFormatter(LogFormatter())
        logger.addHandler(channel)

def define_logging_options(options=None):
    """Add logging-related flags to ``options``.

    These options are present automatically on the default options instance;
    this method is only necessary if you have created your own `.OptionParser`.

    .. versionadded:: 4.2
        This function existed in prior versions but was broken and undocumented until 4.2.
    """
    if options is None:
        import salt.ext.tornado.options
        options = salt.ext.tornado.options.options
    options.define('logging', default='info', help="Set the Python log level. If 'none', tornado won't touch the logging configuration.", metavar='debug|info|warning|error|none')
    options.define('log_to_stderr', type=bool, default=None, help='Send log output to stderr (colorized if possible). By default use stderr if --log_file_prefix is not set and no other logging is configured.')
    options.define('log_file_prefix', type=str, default=None, metavar='PATH', help='Path prefix for log files. Note that if you are running multiple tornado processes, log_file_prefix must be different for each of them (e.g. include the port number)')
    options.define('log_file_max_size', type=int, default=100 * 1000 * 1000, help='max size of log files before rollover')
    options.define('log_file_num_backups', type=int, default=10, help='number of log files to keep')
    options.define('log_rotate_when', type=str, default='midnight', help="specify the type of TimedRotatingFileHandler interval other options:('S', 'M', 'H', 'D', 'W0'-'W6')")
    options.define('log_rotate_interval', type=int, default=1, help='The interval value of timed rotating')
    options.define('log_rotate_mode', type=str, default='size', help='The mode of rotating files(time or size)')
    options.add_parse_callback(lambda : enable_pretty_logging(options))