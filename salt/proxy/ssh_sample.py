"""
    This is a simple proxy-minion designed to connect to and communicate with
    a server that exposes functionality via SSH.
    This can be used as an option when the device does not provide
    an api over HTTP and doesn't have the python stack to run a minion.
"""
import logging
import salt.utils.json
from salt.utils.vt import TerminalException
from salt.utils.vt_helper import SSHConnection
import logging
log = logging.getLogger(__name__)
__proxyenabled__ = ['ssh_sample']
DETAILS = {}
log = logging.getLogger(__file__)

def __virtual__():
    """
    Only return if all the modules are available
    """
    log.info('ssh_sample proxy __virtual__() called...')
    return True

def init(opts):
    """
    Required.
    Can be used to initialize the server connection.
    """
    try:
        log.info('Trace')
        DETAILS['server'] = SSHConnection(host=__opts__['proxy']['host'], username=__opts__['proxy']['username'], password=__opts__['proxy']['password'])
        (out, err) = DETAILS['server'].sendline('help')
        DETAILS['initialized'] = True
    except TerminalException as e:
        log.error(e)
        return False

def initialized():
    """
    Since grains are loaded in many different places and some of those
    places occur before the proxy can be initialized, return whether
    our init() function has been called
    """
    return DETAILS.get('initialized', False)

def grains():
    """
    Get the grains from the proxied device
    """
    if not DETAILS.get('grains_cache', {}):
        cmd = 'info'
        (out, err) = DETAILS['server'].sendline(cmd)
        DETAILS['grains_cache'] = parse(out)
    return DETAILS['grains_cache']

def grains_refresh():
    """
    Refresh the grains from the proxied device
    """
    DETAILS['grains_cache'] = None
    return grains()

def fns():
    """
    Method called by grains module.
    """
    return {'details': 'This key is here because a function in grains/ssh_sample.py called fns() here in the proxymodule.'}

def ping():
    """
    Required.
    Ping the device on the other end of the connection
    """
    try:
        log.info('Trace')
        (out, err) = DETAILS['server'].sendline('help')
        return True
    except TerminalException as e:
        log.error(e)
        return False

def shutdown(opts):
    """
    Disconnect
    """
    DETAILS['server'].close_connection()

def parse(out):
    """
    Extract json from out.

    Parameter
        out: Type string. The data returned by the
        ssh command.
    """
    jsonret = []
    in_json = False
    for ln_ in out.split('\n'):
        if '{' in ln_:
            in_json = True
        if in_json:
            jsonret.append(ln_)
        if '}' in ln_:
            in_json = False
    return salt.utils.json.loads('\n'.join(jsonret))

def package_list():
    """
    List "packages" by executing a command via ssh
    This function is called in response to the salt command

    .. code-block:: bash

        salt target_minion pkg.list_pkgs

    """
    (out, err) = DETAILS['server'].sendline('pkg_list\n')
    return parse(out)

def package_install(name, **kwargs):
    """
    Install a "package" on the ssh server
    """
    cmd = 'pkg_install ' + name
    if kwargs.get('version', False):
        cmd += ' ' + kwargs['version']
    (out, err) = DETAILS['server'].sendline(cmd)
    return parse(out)

def package_remove(name):
    """
    Remove a "package" on the ssh server
    """
    cmd = 'pkg_remove ' + name
    (out, err) = DETAILS['server'].sendline(cmd)
    return parse(out)

def service_list():
    """
    Start a "service" on the ssh server

    .. versionadded:: 2015.8.2
    """
    cmd = 'ps'
    (out, err) = DETAILS['server'].sendline(cmd)
    return parse(out)

def service_start(name):
    """
    Start a "service" on the ssh server

    .. versionadded:: 2015.8.2
    """
    cmd = 'start ' + name
    (out, err) = DETAILS['server'].sendline(cmd)
    return parse(out)

def service_stop(name):
    """
    Stop a "service" on the ssh server

    .. versionadded:: 2015.8.2
    """
    cmd = 'stop ' + name
    (out, err) = DETAILS['server'].sendline(cmd)
    return parse(out)

def service_restart(name):
    """
    Restart a "service" on the ssh server

    .. versionadded:: 2015.8.2
    """
    cmd = 'restart ' + name
    (out, err) = DETAILS['server'].sendline(cmd)
    return parse(out)