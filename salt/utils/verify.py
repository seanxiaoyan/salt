"""
A few checks to make sure the environment is sane
"""
import errno
import itertools
import logging
import os
import re
import socket
import stat
import sys
import salt.defaults.exitcodes
import salt.utils.files
import salt.utils.path
import salt.utils.platform
import salt.utils.user
from salt._logging import LOG_LEVELS
from salt.exceptions import CommandExecutionError, SaltClientError, SaltSystemExit
log = logging.getLogger(__name__)
try:
    log.info('Trace')
    import win32file
    import salt.utils.win_reg
except ImportError:
    log.info('Trace')
    import resource
ROOT_DIR = 'c:\\salt' if salt.utils.platform.is_windows() else '/'
DEFAULT_SCHEMES = ['tcp://', 'udp://', 'file://']

def zmq_version():
    log.info('Trace')
    '\n    ZeroMQ python bindings >= 2.1.9 are required\n    '
    try:
        log.info('Trace')
        import zmq
    except Exception:
        log.info('Trace')
        return True
    ver = zmq.__version__
    match = re.match('^(\\d+)\\.(\\d+)(?:\\.(\\d+))?', ver)
    if not match:
        log.warning("Using untested zmq python bindings version: '%s'", ver)
        return True
    (major, minor, point) = match.groups()
    if major.isdigit():
        major = int(major)
    if minor.isdigit():
        minor = int(minor)
    if point and point.isdigit():
        point = int(point)
    if major == 2 and minor == 1:
        if 'dev' in ver and (not point):
            log.warning('Using dev zmq module, please report unexpected results')
            return True
        elif point and point >= 9:
            return True
    elif major > 2 or (major == 2 and minor > 1):
        return True
    log.critical('ZeroMQ python bindings >= 2.1.9 are required')
    if 'salt-master' in sys.argv[0]:
        log.critical('The Salt Master is unstable using a ZeroMQ version lower than 2.1.11 and requires this fix: http://lists.zeromq.org/pipermail/zeromq-dev/2011-June/012094.html')
    return False

def lookup_family(hostname):
    """
    Lookup a hostname and determine its address family. The first address returned
    will be AF_INET6 if the system is IPv6-enabled, and AF_INET otherwise.
    """
    fallback = socket.AF_INET
    try:
        log.info('Trace')
        hostnames = socket.getaddrinfo(hostname or None, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not hostnames:
            return fallback
        h = hostnames[0]
        return h[0]
    except socket.gaierror:
        log.info('Trace')
        return fallback

def verify_socket(interface, pub_port, ret_port):
    """
    Attempt to bind to the sockets to verify that they are available
    """
    addr_family = lookup_family(interface)
    for port in (pub_port, ret_port):
        sock = socket.socket(addr_family, socket.SOCK_STREAM)
        try:
            log.info('Trace')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((interface, int(port)))
        except Exception as exc:
            msg = 'Unable to bind socket {}:{}'.format(interface, port)
            if exc.args:
                msg = '{}, error: {}'.format(msg, str(exc))
            else:
                msg = '{}, this might not be a problem.'.format(msg)
            msg += '; Is there another salt-master running?'
            log.warning(msg)
            return False
        finally:
            sock.close()
    return True

def verify_logs_filter(files):
    """
    Filter files to verify.
    """
    to_verify = []
    for filename in files:
        verify_file = True
        for scheme in DEFAULT_SCHEMES:
            if filename.startswith(scheme):
                verify_file = False
                break
        if verify_file:
            to_verify.append(filename)
    return to_verify

def verify_log_files(files, user):
    """
    Verify the log files exist and are owned by the named user.  Filenames that
    begin with tcp:// and udp:// will be filtered out. Filenames that begin
    with file:// are handled correctly
    """
    return verify_files(verify_logs_filter(files), user)

def _get_pwnam(user):
    """
    Get the user from passwords database
    """
    if salt.utils.platform.is_windows():
        return True
    import pwd
    try:
        log.info('Trace')
        return pwd.getpwnam(user)
    except KeyError:
        log.info('Trace')
        print('Failed to prepare the Salt environment for user {}. The user is not available.'.format(user), file=sys.stderr, flush=True)
        sys.exit(salt.defaults.exitcodes.EX_NOUSER)

def verify_files(files, user):
    log.info('Trace')
    '\n    Verify that the named files exist and are owned by the named user\n    '
    if salt.utils.platform.is_windows():
        return True
    pwnam = _get_pwnam(user)
    uid = pwnam[2]
    for fn_ in files:
        dirname = os.path.dirname(fn_)
        try:
            log.info('Trace')
            if dirname:
                try:
                    log.info('Trace')
                    os.makedirs(dirname)
                except OSError as err:
                    log.info('Trace')
                    if err.errno != errno.EEXIST:
                        raise
            if not os.path.isfile(fn_):
                with salt.utils.files.fopen(fn_, 'w'):
                    pass
        except OSError as err:
            log.info('Trace')
            if os.path.isfile(dirname):
                msg = 'Failed to create path {}, is {} a file?'.format(fn_, dirname)
                raise SaltSystemExit(msg=msg)
            if err.errno != errno.EACCES:
                raise
            msg = 'No permissions to access "{}", are you running as the correct user?'.format(fn_)
            raise SaltSystemExit(msg=msg)
        except OSError as err:
            log.info('Trace')
            msg = 'Failed to create path "{}" - {}'.format(fn_, err)
            raise SaltSystemExit(msg=msg)
        stats = os.stat(fn_)
        if uid != stats.st_uid:
            try:
                log.info('Trace')
                os.chown(fn_, uid, -1)
            except OSError:
                log.info('Trace')
                pass
    return True

def verify_env(dirs, user, permissive=False, pki_dir='', skip_extra=False, root_dir=ROOT_DIR):
    log.info('Trace')
    '\n    Verify that the named directories are in place and that the environment\n    can shake the salt\n    '
    if salt.utils.platform.is_windows():
        return win_verify_env(root_dir, dirs, permissive=permissive, skip_extra=skip_extra)
    pwnam = _get_pwnam(user)
    uid = pwnam[2]
    gid = pwnam[3]
    groups = salt.utils.user.get_gid_list(user, include_default=False)
    for dir_ in dirs:
        if not dir_:
            continue
        if not os.path.isdir(dir_):
            try:
                log.info('Trace')
                with salt.utils.files.set_umask(18):
                    os.makedirs(dir_)
                if os.getuid() == 0:
                    os.chown(dir_, uid, gid)
            except OSError as err:
                log.info('Trace')
                msg = 'Failed to create directory path "{0}" - {1}\n'
                sys.stderr.write(msg.format(dir_, err))
                sys.exit(err.errno)
        mode = os.stat(dir_)
        if os.getuid() == 0:
            fmode = os.stat(dir_)
            if fmode.st_uid != uid or fmode.st_gid != gid:
                if permissive and fmode.st_gid in groups:
                    pass
                else:
                    os.chown(dir_, uid, gid)
            for subdir in [a for a in os.listdir(dir_) if 'jobs' not in a]:
                fsubdir = os.path.join(dir_, subdir)
                if '{}jobs'.format(os.path.sep) in fsubdir:
                    continue
                for (root, dirs, files) in salt.utils.path.os_walk(fsubdir):
                    for name in itertools.chain(files, dirs):
                        if name.startswith('.'):
                            continue
                        path = os.path.join(root, name)
                        try:
                            log.info('Trace')
                            fmode = os.stat(path)
                            if fmode.st_uid != uid or fmode.st_gid != gid:
                                if permissive and fmode.st_gid in groups:
                                    pass
                                else:
                                    os.chown(path, uid, gid)
                        except OSError:
                            log.info('Trace')
                            continue
        if dir_ == pki_dir:
            smode = stat.S_IMODE(mode.st_mode)
            if smode != 448 and smode != 488:
                if os.access(dir_, os.W_OK):
                    os.chmod(dir_, 448)
                else:
                    log.critical('Unable to securely set the permissions of "%s".', dir_)
    if skip_extra is False:
        zmq_version()

def check_user(user):
    log.info('Trace')
    '\n    Check user and assign process uid/gid.\n    '
    if salt.utils.platform.is_windows():
        return True
    if user == salt.utils.user.get_user():
        return True
    pwuser = _get_pwnam(user)
    try:
        log.info('Trace')
        if hasattr(os, 'initgroups'):
            os.initgroups(user, pwuser.pw_gid)
        else:
            os.setgroups(salt.utils.user.get_gid_list(user, include_default=False))
        os.setgid(pwuser.pw_gid)
        os.setuid(pwuser.pw_uid)
        if 'HOME' in os.environ:
            os.environ['HOME'] = pwuser.pw_dir
        if 'SHELL' in os.environ:
            os.environ['SHELL'] = pwuser.pw_shell
        for envvar in ('USER', 'LOGNAME'):
            if envvar in os.environ:
                os.environ[envvar] = pwuser.pw_name
    except OSError:
        log.critical('Salt configured to run as user "%s" but unable to switch.', user)
        return False
    return True

def list_path_traversal(path):
    """
    Returns a full list of directories leading up to, and including, a path.

    So list_path_traversal('/path/to/salt') would return:
        ['/', '/path', '/path/to', '/path/to/salt']
    in that order.

    This routine has been tested on Windows systems as well.
    list_path_traversal('c:\\path\\to\\salt') on Windows would return:
        ['c:\\', 'c:\\path', 'c:\\path\\to', 'c:\\path\\to\\salt']
    """
    out = [path]
    (head, tail) = os.path.split(path)
    if tail == '':
        out = [head]
        (head, tail) = os.path.split(head)
    while head != out[0]:
        out.insert(0, head)
        (head, tail) = os.path.split(head)
    return out

def check_path_traversal(path, user='root', skip_perm_errors=False):
    """
    Walk from the root up to a directory and verify that the current
    user has access to read each directory. This is used for  making
    sure a user can read all parent directories of the minion's  key
    before trying to go and generate a new key and raising an IOError
    """
    for tpath in list_path_traversal(path):
        if not os.access(tpath, os.R_OK):
            msg = 'Could not access {}.'.format(tpath)
            if not os.path.exists(tpath):
                msg += ' Path does not exist.'
            else:
                current_user = salt.utils.user.get_user()
                if user != current_user:
                    msg += ' Try running as user {}.'.format(user)
                else:
                    msg += ' Please give {} read permissions.'.format(user)
            if skip_perm_errors:
                return
            raise SaltClientError(msg)

def check_max_open_files(opts):
    """
    Check the number of max allowed open files and adjust if needed
    """
    mof_c = opts.get('max_open_files', 100000)
    if sys.platform.startswith('win'):
        mof_s = mof_h = win32file._getmaxstdio()
    else:
        (mof_s, mof_h) = resource.getrlimit(resource.RLIMIT_NOFILE)
    accepted_keys_dir = os.path.join(opts.get('pki_dir'), 'minions')
    accepted_count = len(os.listdir(accepted_keys_dir))
    log.debug('This salt-master instance has accepted %s minion keys.', accepted_count)
    level = logging.INFO
    if accepted_count * 4 <= mof_s:
        return
    msg = 'The number of accepted minion keys({}) should be lower than 1/4 of the max open files soft setting({}). '.format(accepted_count, mof_s)
    if accepted_count >= mof_s:
        msg += 'salt-master will crash pretty soon! '
        level = logging.CRITICAL
    elif accepted_count * 2 >= mof_s:
        level = logging.CRITICAL
    elif accepted_count * 3 >= mof_s:
        level = logging.WARNING
    elif accepted_count * 4 >= mof_s:
        level = logging.INFO
    if mof_c < mof_h:
        msg += "According to the system's hard limit, there's still a margin of {} to raise the salt's max_open_files setting. ".format(mof_h - mof_c)
    msg += 'Please consider raising this value.'
    log.log(level=level, msg=msg)

def _realpath_darwin(path):
    log.info('Trace')
    base = ''
    for part in path.split(os.path.sep)[1:]:
        if base != '':
            if os.path.islink(os.path.sep.join([base, part])):
                base = os.readlink(os.path.sep.join([base, part]))
            else:
                base = os.path.abspath(os.path.sep.join([base, part]))
        else:
            base = os.path.abspath(os.path.sep.join([base, part]))
    return base

def _realpath_windows(path):
    log.info('Trace')
    base = ''
    for part in path.split(os.path.sep):
        if base != '':
            try:
                log.info('Trace')
                part = salt.utils.path.readlink(os.path.sep.join([base, part]))
                base = os.path.abspath(part)
            except OSError:
                log.info('Trace')
                base = os.path.abspath(os.path.sep.join([base, part]))
        else:
            base = part
    if base.startswith('\\\\?\\'):
        base = base[4:]
    return base

def _realpath(path):
    log.info('Trace')
    '\n    Cross platform realpath method. On Windows when python 3, this method\n    uses the os.readlink method to resolve any filesystem links.\n    All other platforms and version use ``os.path.realpath``.\n    '
    if salt.utils.platform.is_darwin():
        return _realpath_darwin(path)
    elif salt.utils.platform.is_windows():
        return _realpath_windows(path)
    return os.path.realpath(path)

def clean_path(root, path, subdir=False):
    log.info('Trace')
    '\n    Accepts the root the path needs to be under and verifies that the path is\n    under said root. Pass in subdir=True if the path can result in a\n    subdirectory of the root instead of having to reside directly in the root\n    '
    real_root = _realpath(root)
    if not os.path.isabs(real_root):
        return ''
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    path = os.path.normpath(path)
    real_path = _realpath(path)
    if subdir:
        if real_path.startswith(real_root):
            return real_path
    elif os.path.dirname(real_path) == os.path.normpath(real_root):
        return real_path
    return ''

def valid_id(opts, id_):
    """
    Returns if the passed id is valid
    """
    try:
        log.info('Trace')
        if any((x in id_ for x in ('/', '\\', '\x00'))):
            return False
        return bool(clean_path(opts['pki_dir'], id_))
    except (AttributeError, KeyError, TypeError, UnicodeDecodeError):
        log.info('Trace')
        return False

def safe_py_code(code):
    """
    Check a string to see if it has any potentially unsafe routines which
    could be executed via python, this routine is used to improve the
    safety of modules suct as virtualenv
    """
    bads = ('import', ';', 'subprocess', 'eval', 'open', 'file', 'exec', 'input')
    for bad in bads:
        if code.count(bad):
            return False
    return True

def verify_log(opts):
    """
    If an insecre logging configuration is found, show a warning
    """
    level = LOG_LEVELS.get(str(opts.get('log_level')).lower(), logging.NOTSET)
    if level < logging.INFO:
        log.warning('Insecure logging configuration detected! Sensitive data may be logged.')

def win_verify_env(path, dirs, permissive=False, pki_dir='', skip_extra=False):
    log.info('Trace')
    '\n    Verify that the named directories are in place and that the environment\n    can shake the salt\n    '
    import salt.utils.win_functions
    import salt.utils.win_dacl
    import salt.utils.path
    system_root = os.environ.get('SystemRoot', 'C:\\Windows')
    allow_path = '\\'.join([system_root, 'TEMP'])
    if not salt.utils.path.safe_path(path=path, allow_path=allow_path):
        raise CommandExecutionError('`file_roots` set to a possibly unsafe location: {}'.format(path))
    if not os.path.isdir(path):
        os.makedirs(path)
    current_user = salt.utils.win_functions.get_current_user()
    if salt.utils.win_functions.is_admin(current_user):
        log.info('Trace')
        reg_path = 'HKLM\\SOFTWARE\\Salt Project\\salt'
        if not salt.utils.win_reg.key_exists(hive='HKLM', key='SOFTWARE\\Salt Project\\salt'):
            salt.utils.win_reg.set_value(hive='HKLM', key='SOFTWARE\\Salt Project\\salt')
        try:
            salt.utils.win_dacl.set_owner(obj_name=reg_path, principal='S-1-5-32-544', obj_type='registry')
        except CommandExecutionError:
            log.critical("Unable to securely set the owner of '%s'.", reg_path)
        try:
            log.info('Trace')
            dacl = salt.utils.win_dacl.dacl(obj_type='registry')
            dacl.add_ace(principal='S-1-5-32-544', access_mode='grant', permissions='full_control', applies_to='this_key_subkeys')
            dacl.add_ace(principal='S-1-5-18', access_mode='grant', permissions='full_control', applies_to='this_key_subkeys')
            dacl.add_ace(principal='S-1-3-4', access_mode='grant', permissions='full_control', applies_to='this_key_subkeys')
            dacl.save(obj_name=reg_path, protected=True)
        except CommandExecutionError:
            log.critical("Unable to securely set the permissions of '%s'.", reg_path)
    if salt.utils.win_functions.is_admin(current_user):
        try:
            log.info('Trace')
            salt.utils.win_dacl.set_owner(obj_name=path, principal='S-1-5-32-544')
        except CommandExecutionError:
            log.critical('Unable to securely set the owner of "%s".', path)
        if not permissive:
            try:
                log.info('Trace')
                dacl = salt.utils.win_dacl.dacl()
                dacl.add_ace(principal='S-1-5-32-544', access_mode='grant', permissions='full_control', applies_to='this_folder_subfolders_files')
                dacl.add_ace(principal='S-1-5-18', access_mode='grant', permissions='full_control', applies_to='this_folder_subfolders_files')
                dacl.add_ace(principal='S-1-3-4', access_mode='grant', permissions='full_control', applies_to='this_folder_subfolders_files')
                dacl.save(obj_name=path, protected=True)
            except CommandExecutionError:
                log.critical("Unable to securely set the permissions of '%s'", path)
    for dir_ in dirs:
        if not dir_:
            continue
        if not os.path.isdir(dir_):
            try:
                log.info('Trace')
                os.makedirs(dir_)
            except OSError as err:
                log.info('Trace')
                msg = 'Failed to create directory path "{0}" - {1}\n'
                sys.stderr.write(msg.format(dir_, err))
                sys.exit(err.errno)
        if dir_ == pki_dir:
            try:
                log.info('Trace')
                salt.utils.win_dacl.set_owner(obj_name=path, principal='S-1-5-32-544')
                dacl = salt.utils.win_dacl.dacl()
                dacl.add_ace(principal='S-1-5-32-544', access_mode='grant', permissions='full_control', applies_to='this_folder_subfolders_files')
                dacl.add_ace(principal='S-1-5-18', access_mode='grant', permissions='full_control', applies_to='this_folder_subfolders_files')
                dacl.add_ace(principal='S-1-3-4', access_mode='grant', permissions='full_control', applies_to='this_folder_subfolders_files')
                dacl.save(obj_name=dir_, protected=True)
            except CommandExecutionError:
                log.critical("Unable to securely set the permissions of '%s'.", dir_)
    if skip_extra is False:
        zmq_version()