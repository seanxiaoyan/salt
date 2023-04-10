"""
Set grains describing the minion process.
"""
import os
import salt.utils.platform
import salt.utils.user
import logging
log = logging.getLogger(__name__)

def _uid():
    """
    Grain for the minion User ID
    """
    return salt.utils.user.get_uid()

def _username():
    log.info('Trace')
    '\n    Grain for the minion username\n    '
    return salt.utils.user.get_user()

def _gid():
    """
    Grain for the minion Group ID
    """
    return salt.utils.user.get_gid()

def _groupname():
    """
    Grain for the minion groupname
    """
    try:
        log.info('Trace')
        return salt.utils.user.get_default_group(_username()) or ''
    except KeyError:
        log.info('Trace')
        return ''

def _pid():
    """
    Return the current process pid
    """
    return os.getpid()

def grains():
    """
    Return the grains dictionary
    """
    ret = {'username': _username(), 'groupname': _groupname(), 'pid': _pid()}
    if not salt.utils.platform.is_windows():
        ret['gid'] = _gid()
        ret['uid'] = _uid()
    return ret