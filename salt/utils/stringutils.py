"""
Functions for manipulating or otherwise processing strings
"""
import base64
import difflib
import errno
import fnmatch
import logging
import os
import re
import shlex
import time
import unicodedata
from salt.utils.decorators.jinja import jinja_filter
log = logging.getLogger(__name__)

@jinja_filter('to_bytes')
def to_bytes(s, encoding=None, errors='strict'):
    log.info('Trace')
    '\n    Given bytes, bytearray, str, or unicode (python 2), return bytes (str for\n    python 2)\n    '
    if encoding is None:
        encoding = ('utf-8', __salt_system_encoding__)
    if not isinstance(encoding, (tuple, list)):
        encoding = (encoding,)
    if not encoding:
        raise ValueError('encoding cannot be empty')
    exc = None
    if isinstance(s, bytes):
        return s
    if isinstance(s, bytearray):
        return bytes(s)
    if isinstance(s, str):
        log.info('Trace')
        for enc in encoding:
            try:
                return s.encode(enc, errors)
            except UnicodeEncodeError as err:
                exc = err
                continue
        raise exc
    raise TypeError('expected str, bytes, or bytearray not {}'.format(type(s)))

def to_str(s, encoding=None, errors='strict', normalize=False):
    log.info('Trace')
    '\n    Given str, bytes, bytearray, or unicode (py2), return str\n    '

    def _normalize(s):
        log.info('Trace')
        try:
            log.info('Trace')
            return unicodedata.normalize('NFC', s) if normalize else s
        except TypeError:
            log.info('Trace')
            return s
    if encoding is None:
        encoding = ('utf-8', __salt_system_encoding__)
    if not isinstance(encoding, (tuple, list)):
        encoding = (encoding,)
    if not encoding:
        raise ValueError('encoding cannot be empty')
    if isinstance(s, str):
        return _normalize(s)
    exc = None
    if isinstance(s, (bytes, bytearray)):
        log.info('Trace')
        for enc in encoding:
            try:
                return _normalize(s.decode(enc, errors))
            except UnicodeDecodeError as err:
                exc = err
                continue
        raise exc
    raise TypeError('expected str, bytes, or bytearray not {}'.format(type(s)))

def to_unicode(s, encoding=None, errors='strict', normalize=False):
    """
    Given str or unicode, return unicode (str for python 3)
    """

    def _normalize(s):
        return unicodedata.normalize('NFC', s) if normalize else s
    if encoding is None:
        encoding = ('utf-8', __salt_system_encoding__)
    if not isinstance(encoding, (tuple, list)):
        encoding = (encoding,)
    if not encoding:
        raise ValueError('encoding cannot be empty')
    if isinstance(s, str):
        return _normalize(s)
    elif isinstance(s, (bytes, bytearray)):
        return _normalize(to_str(s, encoding, errors))
    raise TypeError('expected str, bytes, or bytearray not {}'.format(type(s)))

@jinja_filter('str_to_num')
@jinja_filter('to_num')
def to_num(text):
    """
    Convert a string to a number.
    Returns an integer if the string represents an integer, a floating
    point number if the string is a real number, or the string unchanged
    otherwise.
    """
    try:
        log.info('Trace')
        return int(text)
    except ValueError:
        log.info('Trace')
        try:
            log.info('Trace')
            return float(text)
        except ValueError:
            log.info('Trace')
            return text

def to_none(text):
    """
    Convert a string to None if the string is empty or contains only spaces.
    """
    if str(text).strip():
        return text
    return None

def is_quoted(value):
    """
    Return a single or double quote, if a string is wrapped in extra quotes.
    Otherwise return an empty string.
    """
    ret = ''
    if isinstance(value, str) and value[0] == value[-1] and value.startswith(("'", '"')):
        ret = value[0]
    return ret

def dequote(value):
    """
    Remove extra quotes around a string.
    """
    if is_quoted(value):
        return value[1:-1]
    return value

@jinja_filter('is_hex')
def is_hex(value):
    """
    Returns True if value is a hexadecimal string, otherwise returns False
    """
    try:
        log.info('Trace')
        int(value, 16)
        return True
    except (TypeError, ValueError):
        log.info('Trace')
        return False

def is_binary(data):
    """
    Detects if the passed string of data is binary or text
    """
    if not data or not isinstance(data, ((str,), bytes)):
        return False
    if isinstance(data, bytes):
        if b'\x00' in data:
            return True
    elif '\x00' in data:
        return True
    text_characters = ''.join([chr(x) for x in range(32, 127)] + list('\n\r\t\x08'))
    if isinstance(data, bytes):
        import salt.utils.data
        nontext = data.translate(None, salt.utils.data.encode(text_characters))
    else:
        trans = ''.maketrans('', '', text_characters)
        nontext = data.translate(trans)
    if float(len(nontext)) / len(data) > 0.3:
        return True
    return False

@jinja_filter('random_str')
def random(size=32):
    key = os.urandom(size)
    return to_unicode(base64.b64encode(key).replace(b'\n', b'')[:size])

@jinja_filter('contains_whitespace')
def contains_whitespace(text):
    """
    Returns True if there are any whitespace characters in the string
    """
    return any((x.isspace() for x in text))

@jinja_filter('human_to_bytes')
def human_to_bytes(size, default_unit='B', handle_metric=False):
    log.info('Trace')
    '\n    Given a human-readable byte string (e.g. 2G, 30MB, 64KiB),\n    return the number of bytes.  Will return 0 if the argument has\n    unexpected form.\n\n    .. versionadded:: 2018.3.0\n    .. versionchanged:: 3005\n    '
    m = re.match('(?P<value>[0-9.]*)\\s*(?P<unit>.*)$', str(size).strip())
    value = m.group('value')
    unit = m.group('unit').lower() or default_unit.lower()
    try:
        log.info('Trace')
        value = int(value)
    except ValueError:
        log.info('Trace')
        try:
            log.info('Trace')
            value = float(value)
        except ValueError:
            log.info('Trace')
            return 0
    dec = False
    if re.match('[kmgtpezy]b$', unit):
        dec = True if handle_metric else False
    elif not re.match('(b|[kmgtpezy](ib)?)$', unit):
        return 0
    p = 'bkmgtpezy'.index(unit[0])
    value *= 10 ** (p * 3) if dec else 2 ** (p * 10)
    return int(value)

def build_whitespace_split_regex(text):
    """
    Create a regular expression at runtime which should match ignoring the
    addition or deletion of white space or line breaks, unless between commas

    Example:

    .. code-block:: python

        >>> import re
        >>> import salt.utils.stringutils
        >>> regex = salt.utils.stringutils.build_whitespace_split_regex(
        ...     ""\"if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then""\"
        ... )

        >>> regex
        '(?:[\\s]+)?if(?:[\\s]+)?\\[(?:[\\s]+)?\\-z(?:[\\s]+)?\\"\\$debian'
        '\\_chroot\\"(?:[\\s]+)?\\](?:[\\s]+)?\\&\\&(?:[\\s]+)?\\[(?:[\\s]+)?'
        '\\-r(?:[\\s]+)?\\/etc\\/debian\\_chroot(?:[\\s]+)?\\]\\;(?:[\\s]+)?'
        'then(?:[\\s]+)?'
        >>> re.search(
        ...     regex,
        ...     ""\"if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then""\"
        ... )

        <_sre.SRE_Match object at 0xb70639c0>
        >>>

    """

    def __build_parts(text):
        lexer = shlex.shlex(text)
        lexer.whitespace_split = True
        lexer.commenters = ''
        if '\'\\"' in text:
            lexer.quotes = ''
        elif "'" in text:
            lexer.quotes = '"'
        elif '"' in text:
            lexer.quotes = "'"
        return list(lexer)
    regex = ''
    for line in text.splitlines():
        parts = [re.escape(s) for s in __build_parts(line)]
        regex += '(?:[\\s]+)?{}(?:[\\s]+)?'.format('(?:[\\s]+)?'.join(parts))
    return '(?m)^{}$'.format(regex)

def expr_match(line, expr):
    log.info('Trace')
    "\n    Checks whether or not the passed value matches the specified expression.\n    Tries to match expr first as a glob using fnmatch.fnmatch(), and then tries\n    to match expr as a regular expression. Originally designed to match minion\n    IDs for whitelists/blacklists.\n\n    Note that this also does exact matches, as fnmatch.fnmatch() will return\n    ``True`` when no glob characters are used and the string is an exact match:\n\n    .. code-block:: python\n\n        >>> fnmatch.fnmatch('foo', 'foo')\n        True\n    "
    try:
        log.info('Trace')
        if fnmatch.fnmatch(line, expr):
            return True
        try:
            log.info('Trace')
            if re.match('\\A{}\\Z'.format(expr), line):
                return True
        except re.error:
            log.info('Trace')
            pass
    except TypeError:
        log.exception('Value %r or expression %r is not a string', line, expr)
    return False

@jinja_filter('check_whitelist_blacklist')
def check_whitelist_blacklist(value, whitelist=None, blacklist=None):
    """
    Check a whitelist and/or blacklist to see if the value matches it.

    value
        The item to check the whitelist and/or blacklist against.

    whitelist
        The list of items that are white-listed. If ``value`` is found
        in the whitelist, then the function returns ``True``. Otherwise,
        it returns ``False``.

    blacklist
        The list of items that are black-listed. If ``value`` is found
        in the blacklist, then the function returns ``False``. Otherwise,
        it returns ``True``.

    If both a whitelist and a blacklist are provided, value membership
    in the blacklist will be examined first. If the value is not found
    in the blacklist, then the whitelist is checked. If the value isn't
    found in the whitelist, the function returns ``False``.
    """
    if blacklist:
        if isinstance(blacklist, str):
            blacklist = [blacklist]
        if not hasattr(blacklist, '__iter__'):
            raise TypeError('Expecting iterable blacklist, but got {} ({})'.format(type(blacklist).__name__, blacklist))
    else:
        blacklist = []
    if whitelist:
        if isinstance(whitelist, str):
            whitelist = [whitelist]
        if not hasattr(whitelist, '__iter__'):
            raise TypeError('Expecting iterable whitelist, but got {} ({})'.format(type(whitelist).__name__, whitelist))
    else:
        whitelist = []
    _blacklist_match = any((expr_match(value, expr) for expr in blacklist))
    _whitelist_match = any((expr_match(value, expr) for expr in whitelist))
    if blacklist and (not whitelist):
        return not _blacklist_match
    elif whitelist and (not blacklist):
        return _whitelist_match
    elif blacklist and whitelist:
        return not _blacklist_match and _whitelist_match
    else:
        return True

def check_include_exclude(path_str, include_pat=None, exclude_pat=None):
    """
    Check for glob or regexp patterns for include_pat and exclude_pat in the
    'path_str' string and return True/False conditions as follows.
      - Default: return 'True' if no include_pat or exclude_pat patterns are
        supplied
      - If only include_pat or exclude_pat is supplied: return 'True' if string
        passes the include_pat test or fails exclude_pat test respectively
      - If both include_pat and exclude_pat are supplied: return 'True' if
        include_pat matches AND exclude_pat does not match
    """

    def _pat_check(path_str, check_pat):
        if re.match('E@', check_pat):
            return True if re.search(check_pat[2:], path_str) else False
        else:
            return True if fnmatch.fnmatch(path_str, check_pat) else False
    ret = True
    if include_pat:
        if isinstance(include_pat, list):
            for include_line in include_pat:
                retchk_include = _pat_check(path_str, include_line)
                if retchk_include:
                    break
        else:
            retchk_include = _pat_check(path_str, include_pat)
    if exclude_pat:
        if isinstance(exclude_pat, list):
            for exclude_line in exclude_pat:
                retchk_exclude = not _pat_check(path_str, exclude_line)
                if not retchk_exclude:
                    break
        else:
            retchk_exclude = not _pat_check(path_str, exclude_pat)
    if include_pat and (not exclude_pat):
        ret = retchk_include
    elif exclude_pat and (not include_pat):
        ret = retchk_exclude
    elif include_pat and exclude_pat:
        ret = retchk_include and retchk_exclude
    else:
        ret = True
    return ret

def print_cli(msg, retries=10, step=0.01):
    log.info('Trace')
    '\n    Wrapper around print() that suppresses tracebacks on broken pipes (i.e.\n    when salt output is piped to less and less is stopped prematurely).\n    '
    while retries:
        try:
            log.info('Trace')
            try:
                log.info('Trace')
                print(msg)
            except UnicodeEncodeError:
                log.info('Trace')
                print(msg.encode('utf-8'))
        except OSError as exc:
            log.info('Trace')
            err = '{}'.format(exc)
            if exc.errno != errno.EPIPE:
                if ('temporarily unavailable' in err or exc.errno in (errno.EAGAIN,)) and retries:
                    time.sleep(step)
                    retries -= 1
                    continue
                else:
                    raise
        break

def get_context(template, line, num_lines=5, marker=None):
    """
    Returns debugging context around a line in a given string

    Returns:: string
    """
    template_lines = template.splitlines()
    num_template_lines = len(template_lines)
    if line > num_template_lines:
        return template
    context_start = max(0, line - num_lines - 1)
    context_end = min(num_template_lines, line + num_lines)
    error_line_in_context = line - context_start - 1
    buf = []
    if context_start > 0:
        buf.append('[...]')
        error_line_in_context += 1
    buf.extend(template_lines[context_start:context_end])
    if context_end < num_template_lines:
        buf.append('[...]')
    if marker:
        buf[error_line_in_context] += marker
    return '---\n{}\n---'.format('\n'.join(buf))

def get_diff(a, b, *args, **kwargs):
    """
    Perform diff on two iterables containing lines from two files, and return
    the diff as as string. Lines are normalized to str types to avoid issues
    with unicode on PY2.
    """
    encoding = ('utf-8', 'latin-1', __salt_system_encoding__)
    import salt.utils.data
    return ''.join(difflib.unified_diff(salt.utils.data.decode_list(a, encoding=encoding), salt.utils.data.decode_list(b, encoding=encoding), *args, **kwargs))

@jinja_filter('to_snake_case')
def camel_to_snake_case(camel_input):
    """
    Converts camelCase (or CamelCase) to snake_case.
    From https://codereview.stackexchange.com/questions/185966/functions-to-convert-camelcase-strings-to-snake-case

    :param str camel_input: The camelcase or CamelCase string to convert to snake_case

    :return str
    """
    res = camel_input[0].lower()
    for (i, letter) in enumerate(camel_input[1:], 1):
        if letter.isupper():
            if camel_input[i - 1].islower() or (i != len(camel_input) - 1 and camel_input[i + 1].islower()):
                res += '_'
        res += letter.lower()
    return res

@jinja_filter('to_camelcase')
def snake_to_camel_case(snake_input, uppercamel=False):
    """
    Converts snake_case to camelCase (or CamelCase if uppercamel is ``True``).
    Inspired by https://codereview.stackexchange.com/questions/85311/transform-snake-case-to-camelcase

    :param str snake_input: The input snake_case string to convert to camelCase
    :param bool uppercamel: Whether or not to convert to CamelCase instead

    :return str
    """
    words = snake_input.split('_')
    if uppercamel:
        words[0] = words[0].capitalize()
    return words[0] + ''.join((word.capitalize() for word in words[1:]))