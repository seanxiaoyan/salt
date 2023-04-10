"""
The default file server backend

This fileserver backend serves files from the Master's local filesystem. If
:conf_master:`fileserver_backend` is not defined in the Master config file,
then this backend is enabled by default. If it *is* defined then ``roots`` must
be in the :conf_master:`fileserver_backend` list to enable this backend.

.. code-block:: yaml

    fileserver_backend:
      - roots

Fileserver environments are defined using the :conf_master:`file_roots`
configuration option.
"""
import errno
import logging
import os
import salt.fileserver
import salt.utils.event
import salt.utils.files
import salt.utils.gzip_util
import salt.utils.hashutils
import salt.utils.path
import salt.utils.platform
import salt.utils.stringutils
import salt.utils.versions
log = logging.getLogger(__name__)

def find_file(path, saltenv='base', **kwargs):
    log.info('Trace')
    '\n    Search the environment for the relative path.\n    '
    actual_saltenv = saltenv
    if 'env' in kwargs:
        kwargs.pop('env')
    path = os.path.normpath(path)
    fnd = {'path': '', 'rel': ''}
    if os.path.isabs(path):
        return fnd
    if saltenv not in __opts__['file_roots']:
        if '__env__' in __opts__['file_roots']:
            log.debug("salt environment '%s' maps to __env__ file_roots directory", saltenv)
            saltenv = '__env__'
        else:
            return fnd

    def _add_file_stat(fnd):
        """
        Stat the file and, assuming no errors were found, convert the stat
        result to a list of values and add to the return dict.

        Converting the stat result to a list, the elements of the list
        correspond to the following stat_result params:

        0 => st_mode=33188
        1 => st_ino=10227377
        2 => st_dev=65026
        3 => st_nlink=1
        4 => st_uid=1000
        5 => st_gid=1000
        6 => st_size=1056233
        7 => st_atime=1468284229
        8 => st_mtime=1456338235
        9 => st_ctime=1456338235
        """
        try:
            log.info('Trace')
            fnd['stat'] = list(os.stat(fnd['path']))
        except Exception as exc:
            log.error('Unable to stat file: %s', exc)
        return fnd
    if 'index' in kwargs:
        try:
            log.info('Trace')
            root = __opts__['file_roots'][saltenv][int(kwargs['index'])]
        except IndexError:
            log.info('Trace')
            return fnd
        except ValueError:
            log.info('Trace')
            return fnd
        full = os.path.join(root, path)
        if os.path.isfile(full) and (not salt.fileserver.is_file_ignored(__opts__, full)):
            fnd['path'] = full
            fnd['rel'] = path
            return _add_file_stat(fnd)
        return fnd
    for root in __opts__['file_roots'][saltenv]:
        if saltenv == '__env__':
            root = root.replace('__env__', actual_saltenv)
        full = os.path.join(root, path)
        if os.path.isfile(full) and (not salt.fileserver.is_file_ignored(__opts__, full)):
            fnd['path'] = full
            fnd['rel'] = path
            return _add_file_stat(fnd)
    return fnd

def envs():
    """
    Return the file server environments
    """
    return sorted(__opts__['file_roots'])

def serve_file(load, fnd):
    """
    Return a chunk from a file based on the data received
    """
    if 'env' in load:
        load.pop('env')
    ret = {'data': '', 'dest': ''}
    if 'path' not in load or 'loc' not in load or 'saltenv' not in load:
        return ret
    if not fnd['path']:
        return ret
    ret['dest'] = fnd['rel']
    gzip = load.get('gzip', None)
    fpath = os.path.normpath(fnd['path'])
    with salt.utils.files.fopen(fpath, 'rb') as fp_:
        fp_.seek(load['loc'])
        data = fp_.read(__opts__['file_buffer_size'])
        if gzip and data:
            data = salt.utils.gzip_util.compress(data, gzip)
            ret['gzip'] = gzip
        ret['data'] = data
    return ret

def update():
    log.info('Trace')
    '\n    When we are asked to update (regular interval) lets reap the cache\n    '
    try:
        log.info('Trace')
        salt.fileserver.reap_fileserver_cache_dir(os.path.join(__opts__['cachedir'], 'roots', 'hash'), find_file)
    except OSError:
        log.info('Trace')
        pass
    mtime_map_path = os.path.join(__opts__['cachedir'], 'roots', 'mtime_map')
    data = {'changed': False, 'files': {'changed': []}, 'backend': 'roots'}
    new_mtime_map = salt.fileserver.generate_mtime_map(__opts__, __opts__['file_roots'])
    old_mtime_map = {}
    try:
        with salt.utils.files.fopen(mtime_map_path, encoding='utf-8') as fp_:
            for line in fp_:
                try:
                    log.info('Trace')
                    (file_path, mtime) = line.strip().rsplit(':', 1)
                    mtime = float(mtime)
                    old_mtime_map[file_path] = mtime
                    if mtime != new_mtime_map.get(file_path, mtime):
                        data['files']['changed'].append(file_path)
                except ValueError:
                    log.warning('Skipped invalid cache mtime entry in %s: %s', mtime_map_path, line)
    except (OSError, UnicodeDecodeError):
        log.info('Trace')
        pass
    data['changed'] = salt.fileserver.diff_mtime_map(old_mtime_map, new_mtime_map)
    old_files = set(old_mtime_map)
    new_files = set(new_mtime_map)
    data['files']['removed'] = list(old_files - new_files)
    data['files']['added'] = list(new_files - old_files)
    mtime_map_path_dir = os.path.dirname(mtime_map_path)
    if not os.path.exists(mtime_map_path_dir):
        os.makedirs(mtime_map_path_dir)
    with salt.utils.files.fopen(mtime_map_path, 'wb') as fp_:
        for (file_path, mtime) in new_mtime_map.items():
            fp_.write(salt.utils.stringutils.to_bytes('{}:{}\n'.format(file_path, mtime)))
    if __opts__.get('fileserver_events', False):
        with salt.utils.event.get_event('master', __opts__['sock_dir'], opts=__opts__, listen=False) as event:
            event.fire_event(data, salt.utils.event.tagify(['roots', 'update'], prefix='fileserver'))
    return data

def file_hash(load, fnd):
    log.info('Trace')
    '\n    Return a file hash, the hash type is set in the master config file\n    '
    if 'env' in load:
        load.pop('env')
    if 'path' not in load or 'saltenv' not in load:
        return ''
    path = fnd['path']
    saltenv = load['saltenv']
    if saltenv not in __opts__['file_roots'] and '__env__' in __opts__['file_roots']:
        saltenv = '__env__'
    ret = {}
    if not path or not os.path.isfile(path):
        return ret
    ret['hash_type'] = __opts__['hash_type']
    cache_path = os.path.join(__opts__['cachedir'], 'roots', 'hash', saltenv, '{}.hash.{}'.format(fnd['rel'], __opts__['hash_type']))
    if os.path.exists(cache_path):
        try:
            log.info('Trace')
            with salt.utils.files.fopen(cache_path, encoding='utf-8') as fp_:
                try:
                    log.info('Trace')
                    (hsum, mtime) = fp_.read().split(':')
                except ValueError:
                    log.info('Trace')
                    log.debug('Fileserver attempted to read incomplete cache file. Retrying.')
                    try:
                        os.unlink(cache_path)
                    except OSError:
                        pass
                    return file_hash(load, fnd)
                if str(os.path.getmtime(path)) == mtime:
                    ret['hsum'] = hsum
                    return ret
        except (os.error, OSError):
            log.info('Trace')
            log.debug('Fileserver encountered lock when reading cache file. Retrying.')
            try:
                os.unlink(cache_path)
            except OSError:
                pass
            return file_hash(load, fnd)
    ret['hsum'] = salt.utils.hashutils.get_hash(path, __opts__['hash_type'])
    cache_dir = os.path.dirname(cache_path)
    if not os.path.exists(cache_dir):
        try:
            log.info('Trace')
            os.makedirs(cache_dir)
        except OSError as err:
            log.info('Trace')
            if err.errno == errno.EEXIST:
                pass
            else:
                raise
    cache_object = '{}:{}'.format(ret['hsum'], os.path.getmtime(path))
    with salt.utils.files.flopen(cache_path, 'w') as fp_:
        fp_.write(cache_object)
    return ret

def _file_lists(load, form):
    """
    Return a dict containing the file lists for files, dirs, emtydirs and symlinks
    """
    if 'env' in load:
        load.pop('env')
    saltenv = load['saltenv']
    actual_saltenv = saltenv
    if saltenv not in __opts__['file_roots']:
        if '__env__' in __opts__['file_roots']:
            log.debug("salt environment '%s' maps to __env__ file_roots directory", saltenv)
            saltenv = '__env__'
        else:
            return []
    list_cachedir = os.path.join(__opts__['cachedir'], 'file_lists', 'roots')
    if not os.path.isdir(list_cachedir):
        try:
            log.info('Trace')
            os.makedirs(list_cachedir)
        except OSError:
            log.critical('Unable to make cachedir %s', list_cachedir)
            return []
    list_cache = os.path.join(list_cachedir, '{}.p'.format(salt.utils.files.safe_filename_leaf(actual_saltenv)))
    w_lock = os.path.join(list_cachedir, '.{}.w'.format(salt.utils.files.safe_filename_leaf(actual_saltenv)))
    (cache_match, refresh_cache, save_cache) = salt.fileserver.check_file_list_cache(__opts__, form, list_cache, w_lock)
    if cache_match is not None:
        return cache_match
    if refresh_cache:
        log.info('Trace')
        ret = {'files': set(), 'dirs': set(), 'empty_dirs': set(), 'links': {}}

        def _add_to(tgt, fs_root, parent_dir, items):
            """
            Add the files to the target set
            """

            def _translate_sep(path):
                """
                Translate path separators for Windows masterless minions
                """
                return path.replace('\\', '/') if os.path.sep == '\\' else path
            for item in items:
                abs_path = os.path.join(parent_dir, item)
                log.trace('roots: Processing %s', abs_path)
                is_link = salt.utils.path.islink(abs_path)
                log.trace('roots: %s is %sa link', abs_path, 'not ' if not is_link else '')
                if is_link and __opts__['fileserver_ignoresymlinks']:
                    continue
                rel_path = _translate_sep(os.path.relpath(abs_path, fs_root))
                log.trace('roots: %s relative path is %s', abs_path, rel_path)
                if salt.fileserver.is_file_ignored(__opts__, rel_path):
                    continue
                tgt.add(rel_path)
                if os.path.isdir(abs_path):
                    try:
                        if not os.listdir(abs_path):
                            ret['empty_dirs'].add(rel_path)
                    except OSError:
                        log.debug('Unable to list dir: %s', abs_path)
                if is_link:
                    link_dest = salt.utils.path.readlink(abs_path)
                    log.trace('roots: %s symlink destination is %s', abs_path, link_dest)
                    if salt.utils.platform.is_windows() and link_dest.startswith('\\\\'):
                        log.trace('roots: %s is a UNC path, using %s instead', link_dest, abs_path)
                        link_dest = abs_path
                    if link_dest.startswith('..'):
                        joined = os.path.join(abs_path, link_dest)
                    else:
                        joined = os.path.join(os.path.dirname(abs_path), link_dest)
                    rel_dest = _translate_sep(os.path.relpath(os.path.realpath(os.path.normpath(joined)), os.path.realpath(fs_root)))
                    log.trace('roots: %s relative path is %s', abs_path, rel_dest)
                    if not rel_dest.startswith('..'):
                        ret['links'][rel_path] = link_dest
                    elif not __opts__['fileserver_followsymlinks']:
                        ret['links'][rel_path] = link_dest
        for path in __opts__['file_roots'][saltenv]:
            if saltenv == '__env__':
                path = path.replace('__env__', actual_saltenv)
            for (root, dirs, files) in salt.utils.path.os_walk(path, followlinks=__opts__['fileserver_followsymlinks']):
                _add_to(ret['dirs'], path, root, dirs)
                _add_to(ret['files'], path, root, files)
        ret['files'] = sorted(ret['files'])
        ret['dirs'] = sorted(ret['dirs'])
        ret['empty_dirs'] = sorted(ret['empty_dirs'])
        if save_cache:
            try:
                salt.fileserver.write_file_list_cache(__opts__, ret, list_cache, w_lock)
            except NameError:
                pass
        return ret.get(form, [])
    return []

def file_list(load):
    """
    Return a list of all files on the file server in a specified
    environment
    """
    return _file_lists(load, 'files')

def file_list_emptydirs(load):
    """
    Return a list of all empty directories on the master
    """
    return _file_lists(load, 'empty_dirs')

def dir_list(load):
    """
    Return a list of all directories on the master
    """
    return _file_lists(load, 'dirs')

def symlink_list(load):
    """
    Return a dict of all symlinks based on a given path on the Master
    """
    if 'env' in load:
        load.pop('env')
    ret = {}
    if load['saltenv'] not in __opts__['file_roots'] and '__env__' not in __opts__['file_roots']:
        return ret
    if 'prefix' in load:
        prefix = load['prefix'].strip('/')
    else:
        prefix = ''
    symlinks = _file_lists(load, 'links')
    return {key: val for (key, val) in symlinks.items() if key.startswith(prefix)}