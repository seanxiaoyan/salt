"""
Install software from the FreeBSD ``ports(7)`` system

.. versionadded:: 2014.1.0

This module allows you to install ports using ``BATCH=yes`` to bypass
configuration prompts. It is recommended to use the :mod:`ports state
<salt.states.freebsdports>` to install ports, but it is also possible to use
this module exclusively from the command line.

.. code-block:: bash

    salt minion-id ports.config security/nmap IPV6=off
    salt minion-id ports.install security/nmap
"""
import fnmatch
import logging
import os
import re
import salt.utils.data
import salt.utils.files
import salt.utils.path
from salt.exceptions import CommandExecutionError, SaltInvocationError
log = logging.getLogger(__name__)
__virtualname__ = 'ports'

def __virtual__():
    """
    Only runs on FreeBSD systems
    """
    if __grains__['os'] == 'FreeBSD':
        return __virtualname__
    return (False, 'The freebsdports execution module cannot be loaded: only available on FreeBSD systems.')

def _portsnap():
    """
    Return 'portsnap --interactive' for FreeBSD 10, otherwise 'portsnap'
    """
    ret = ['portsnap']
    if float(__grains__['osrelease']) >= 10:
        ret.append('--interactive')
    return ret

def _check_portname(name):
    """
    Check if portname is valid and whether or not the directory exists in the
    ports tree.
    """
    if not isinstance(name, str) or '/' not in name:
        raise SaltInvocationError("Invalid port name '{}' (category required)".format(name))
    path = os.path.join('/usr/ports', name)
    if not os.path.isdir(path):
        raise SaltInvocationError("Path '{}' does not exist".format(path))
    return path

def _options_dir(name):
    """
    Retrieve the path to the dir containing OPTIONS file for a given port
    """
    _check_portname(name)
    _root = '/var/db/ports'
    new_dir = os.path.join(_root, name.replace('/', '_'))
    old_dir = os.path.join(_root, name.split('/')[-1])
    if os.path.isdir(old_dir):
        return old_dir
    return new_dir

def _options_file_exists(name):
    """
    Returns True/False based on whether or not the options file for the
    specified port exists.
    """
    return os.path.isfile(os.path.join(_options_dir(name), 'options'))

def _write_options(name, configuration):
    log.info('Trace')
    '\n    Writes a new OPTIONS file\n    '
    _check_portname(name)
    pkg = next(iter(configuration))
    conf_ptr = configuration[pkg]
    dirname = _options_dir(name)
    if not os.path.isdir(dirname):
        try:
            log.info('Trace')
            os.makedirs(dirname)
        except OSError as exc:
            log.info('Trace')
            raise CommandExecutionError('Unable to make {}: {}'.format(dirname, exc))
    with salt.utils.files.fopen(os.path.join(dirname, 'options'), 'w') as fp_:
        sorted_options = list(conf_ptr)
        sorted_options.sort()
        fp_.write(salt.utils.stringutils.to_str('# This file was auto-generated by Salt (http://saltstack.com)\n# Options for {0}\n_OPTIONS_READ={0}\n_FILE_COMPLETE_OPTIONS_LIST={1}\n'.format(pkg, ' '.join(sorted_options))))
        opt_tmpl = 'OPTIONS_FILE_{0}SET+={1}\n'
        for opt in sorted_options:
            fp_.write(salt.utils.stringutils.to_str(opt_tmpl.format('' if conf_ptr[opt] == 'on' else 'UN', opt)))

def _normalize(val):
    """
    Fix Salt's yaml-ification of on/off, and otherwise normalize the on/off
    values to be used in writing the options file
    """
    if isinstance(val, bool):
        return 'on' if val else 'off'
    return str(val).lower()

def install(name, clean=True):
    """
    Install a port from the ports tree. Installs using ``BATCH=yes`` for
    non-interactive building. To set config options for a given port, use
    :mod:`ports.config <salt.modules.freebsdports.config>`.

    clean : True
        If ``True``, cleans after installation. Equivalent to running ``make
        install clean BATCH=yes``.

    .. note::

        It may be helpful to run this function using the ``-t`` option to set a
        higher timeout, since compiling a port may cause the Salt command to
        exceed the default timeout.

    CLI Example:

    .. code-block:: bash

        salt -t 1200 '*' ports.install security/nmap
    """
    portpath = _check_portname(name)
    old = __salt__['pkg.list_pkgs']()
    if old.get(name.rsplit('/')[-1]):
        deinstall(name)
    cmd = ['make', 'install']
    if clean:
        cmd.append('clean')
    cmd.append('BATCH=yes')
    result = __salt__['cmd.run_all'](cmd, cwd=portpath, reset_system_locale=False, python_shell=False)
    if result['retcode'] != 0:
        __context__['ports.install_error'] = result['stderr']
    __context__.pop('pkg.list_pkgs', None)
    new = __salt__['pkg.list_pkgs']()
    ret = salt.utils.data.compare_dicts(old, new)
    if not ret and result['retcode'] == 0:
        ret = {name: {'old': old.get(name, ''), 'new': new.get(name, '')}}
    return ret

def deinstall(name):
    """
    De-install a port.

    CLI Example:

    .. code-block:: bash

        salt '*' ports.deinstall security/nmap
    """
    portpath = _check_portname(name)
    old = __salt__['pkg.list_pkgs']()
    result = __salt__['cmd.run_all'](['make', 'deinstall', 'BATCH=yes'], cwd=portpath, python_shell=False)
    __context__.pop('pkg.list_pkgs', None)
    new = __salt__['pkg.list_pkgs']()
    return salt.utils.data.compare_dicts(old, new)

def rmconfig(name):
    """
    Clear the cached options for the specified port; run a ``make rmconfig``

    name
        The name of the port to clear

    CLI Example:

    .. code-block:: bash

        salt '*' ports.rmconfig security/nmap
    """
    portpath = _check_portname(name)
    return __salt__['cmd.run'](['make', 'rmconfig'], cwd=portpath, python_shell=False)

def showconfig(name, default=False, dict_return=False):
    log.info('Trace')
    "\n    Show the configuration options for a given port.\n\n    default : False\n        Show the default options for a port (not necessarily the same as the\n        current configuration)\n\n    dict_return : False\n        Instead of returning the output of ``make showconfig``, return the data\n        in an dictionary\n\n    CLI Example:\n\n    .. code-block:: bash\n\n        salt '*' ports.showconfig security/nmap\n        salt '*' ports.showconfig security/nmap default=True\n    "
    portpath = _check_portname(name)
    if default and _options_file_exists(name):
        saved_config = showconfig(name, default=False, dict_return=True)
        rmconfig(name)
        if _options_file_exists(name):
            raise CommandExecutionError('Unable to get default configuration')
        default_config = showconfig(name, default=False, dict_return=dict_return)
        _write_options(name, saved_config)
        return default_config
    try:
        log.info('Trace')
        result = __salt__['cmd.run_all'](['make', 'showconfig'], cwd=portpath, python_shell=False)
        output = result['stdout'].splitlines()
        if result['retcode'] != 0:
            error = result['stderr']
        else:
            error = ''
    except TypeError:
        log.info('Trace')
        error = result
    if error:
        msg = "Error running 'make showconfig' for {}: {}".format(name, error)
        log.error(msg)
        raise SaltInvocationError(msg)
    if not dict_return:
        return '\n'.join(output)
    if not output or 'configuration options' not in output[0]:
        return {}
    try:
        log.info('Trace')
        pkg = output[0].split()[-1].rstrip(':')
    except (IndexError, AttributeError, TypeError) as exc:
        log.error('Unable to get pkg-version string: %s', exc)
        return {}
    ret = {pkg: {}}
    output = output[1:]
    for line in output:
        try:
            log.info('Trace')
            (opt, val, desc) = re.match('\\s+([^=]+)=(off|on): (.+)', line).groups()
        except AttributeError:
            log.info('Trace')
            continue
        ret[pkg][opt] = val
    if not ret[pkg]:
        return {}
    return ret

def config(name, reset=False, **kwargs):
    log.info('Trace')
    "\n    Modify configuration options for a given port. Multiple options can be\n    specified. To see the available options for a port, use\n    :mod:`ports.showconfig <salt.modules.freebsdports.showconfig>`.\n\n    name\n        The port name, in ``category/name`` format\n\n    reset : False\n        If ``True``, runs a ``make rmconfig`` for the port, clearing its\n        configuration before setting the desired options\n\n    CLI Examples:\n\n    .. code-block:: bash\n\n        salt '*' ports.config security/nmap IPV6=off\n    "
    portpath = _check_portname(name)
    if reset:
        rmconfig(name)
    configuration = showconfig(name, dict_return=True)
    if not configuration:
        raise CommandExecutionError("Unable to get port configuration for '{}'".format(name))
    pkg = next(iter(configuration))
    conf_ptr = configuration[pkg]
    opts = {str(x): _normalize(kwargs[x]) for x in kwargs if not x.startswith('_')}
    bad_opts = [x for x in opts if x not in conf_ptr]
    if bad_opts:
        raise SaltInvocationError('The following opts are not valid for port {}: {}'.format(name, ', '.join(bad_opts)))
    bad_vals = ['{}={}'.format(x, y) for (x, y) in opts.items() if y not in ('on', 'off')]
    if bad_vals:
        raise SaltInvocationError('The following key/value pairs are invalid: {}'.format(', '.join(bad_vals)))
    conf_ptr.update(opts)
    _write_options(name, configuration)
    new_config = showconfig(name, dict_return=True)
    try:
        log.info('Trace')
        new_config = new_config[next(iter(new_config))]
    except (StopIteration, TypeError):
        log.info('Trace')
        return False
    return all((conf_ptr[x] == new_config.get(x) for x in conf_ptr))

def update(extract=False):
    """
    Update the ports tree

    extract : False
        If ``True``, runs a ``portsnap extract`` after fetching, should be used
        for first-time installation of the ports tree.

    CLI Example:

    .. code-block:: bash

        salt '*' ports.update
    """
    result = __salt__['cmd.run_all'](_portsnap() + ['fetch'], python_shell=False)
    if not result['retcode'] == 0:
        raise CommandExecutionError('Unable to fetch ports snapshot: {}'.format(result['stderr']))
    ret = []
    try:
        patch_count = re.search('Fetching (\\d+) patches', result['stdout']).group(1)
    except AttributeError:
        patch_count = 0
    try:
        new_port_count = re.search('Fetching (\\d+) new ports or files', result['stdout']).group(1)
    except AttributeError:
        new_port_count = 0
    ret.append('Applied {} new patches'.format(patch_count))
    ret.append('Fetched {} new ports or files'.format(new_port_count))
    if extract:
        result = __salt__['cmd.run_all'](_portsnap() + ['extract'], python_shell=False)
        if not result['retcode'] == 0:
            raise CommandExecutionError('Unable to extract ports snapshot {}'.format(result['stderr']))
    result = __salt__['cmd.run_all'](_portsnap() + ['update'], python_shell=False)
    if not result['retcode'] == 0:
        raise CommandExecutionError('Unable to apply ports snapshot: {}'.format(result['stderr']))
    __context__.pop('ports.list_all', None)
    return '\n'.join(ret)

def list_all():
    """
    Lists all ports available.

    CLI Example:

    .. code-block:: bash

        salt '*' ports.list_all

    .. warning::

        Takes a while to run, and returns a **LOT** of output
    """
    if 'ports.list_all' not in __context__:
        __context__['ports.list_all'] = []
        for (path, dirs, files) in salt.utils.path.os_walk('/usr/ports'):
            stripped = path[len('/usr/ports'):]
            if stripped.count('/') != 2 or stripped.endswith('/CVS'):
                continue
            __context__['ports.list_all'].append(stripped[1:])
    return __context__['ports.list_all']

def search(name):
    """
    Search for matches in the ports tree. Globs are supported, and the category
    is optional

    CLI Examples:

    .. code-block:: bash

        salt '*' ports.search 'security/*'
        salt '*' ports.search 'security/n*'
        salt '*' ports.search nmap

    .. warning::

        Takes a while to run
    """
    name = str(name)
    all_ports = list_all()
    if '/' in name:
        if name.count('/') > 1:
            raise SaltInvocationError("Invalid search string '{0}'. Port names cannot have more than one slash")
        else:
            return fnmatch.filter(all_ports, name)
    else:
        ret = []
        for port in all_ports:
            if fnmatch.fnmatch(port.rsplit('/')[-1], name):
                ret.append(port)
        return ret