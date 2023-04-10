"""
Operations on regular files, special files, directories, and symlinks
=====================================================================

Salt States can aggressively manipulate files on a system. There are a number
of ways in which files can be managed.

Regular files can be enforced with the :mod:`file.managed
<salt.states.file.managed>` state. This state downloads files from the salt
master and places them on the target system. Managed files can be rendered as a
jinja, mako, or wempy template, adding a dynamic component to file management.
An example of :mod:`file.managed <salt.states.file.managed>` which makes use of
the jinja templating system would look like this:

.. code-block:: jinja

    /etc/http/conf/http.conf:
      file.managed:
        - source: salt://apache/http.conf
        - user: root
        - group: root
        - mode: 644
        - attrs: ai
        - template: jinja
        - defaults:
            custom_var: "default value"
            other_var: 123
    {% if grains['os'] == 'Ubuntu' %}
        - context:
            custom_var: "override"
    {% endif %}

It is also possible to use the :mod:`py renderer <salt.renderers.py>` as a
templating option. The template would be a Python script which would need to
contain a function called ``run()``, which returns a string. All arguments
to the state will be made available to the Python script as globals. The
returned string will be the contents of the managed file. For example:

.. code-block:: python

    def run():
        lines = ['foo', 'bar', 'baz']
        lines.extend([source, name, user, context])  # Arguments as globals
        return '\\n\\n'.join(lines)

.. note::

    The ``defaults`` and ``context`` arguments require extra indentation (four
    spaces instead of the normal two) in order to create a nested dictionary.
    :ref:`More information <nested-dict-indentation>`.

If using a template, any user-defined template variables in the file defined in
``source`` must be passed in using the ``defaults`` and/or ``context``
arguments. The general best practice is to place default values in
``defaults``, with conditional overrides going into ``context``, as seen above.

The template will receive a variable ``custom_var``, which would be accessed in
the template using ``{{ custom_var }}``. If the operating system is Ubuntu, the
value of the variable ``custom_var`` would be *override*, otherwise it is the
default *default value*

The ``source`` parameter can be specified as a list. If this is done, then the
first file to be matched will be the one that is used. This allows you to have
a default file on which to fall back if the desired file does not exist on the
salt fileserver. Here's an example:

.. code-block:: jinja

    /etc/foo.conf:
      file.managed:
        - source:
          - salt://foo.conf.{{ grains['fqdn'] }}
          - salt://foo.conf.fallback
        - user: foo
        - group: users
        - mode: 644
        - attrs: i
        - backup: minion

.. note::

    Salt supports backing up managed files via the backup option. For more
    details on this functionality please review the
    :ref:`backup_mode documentation <file-state-backups>`.

The ``source`` parameter can also specify a file in another Salt environment.
In this example ``foo.conf`` in the ``dev`` environment will be used instead.

.. code-block:: yaml

    /etc/foo.conf:
      file.managed:
        - source:
          - 'salt://foo.conf?saltenv=dev'
        - user: foo
        - group: users
        - mode: '0644'
        - attrs: i

.. warning::

    When using a mode that includes a leading zero you must wrap the
    value in single quotes. If the value is not wrapped in quotes it
    will be read by YAML as an integer and evaluated as an octal.

The ``names`` parameter, which is part of the state compiler, can be used to
expand the contents of a single state declaration into multiple, single state
declarations. Each item in the ``names`` list receives its own individual state
``name`` and is converted into its own low-data structure. This is a convenient
way to manage several files with similar attributes.

.. code-block:: yaml

    salt_master_conf:
      file.managed:
        - user: root
        - group: root
        - mode: '0644'
        - names:
          - /etc/salt/master.d/master.conf:
            - source: salt://saltmaster/master.conf
          - /etc/salt/minion.d/minion-99.conf:
            - source: salt://saltmaster/minion.conf

.. note::

    There is more documentation about this feature in the :ref:`Names declaration
    <names-declaration>` section of the :ref:`Highstate docs <states-highstate>`.

Special files can be managed via the ``mknod`` function. This function will
create and enforce the permissions on a special file. The function supports the
creation of character devices, block devices, and FIFO pipes. The function will
create the directory structure up to the special file if it is needed on the
minion. The function will not overwrite or operate on (change major/minor
numbers) existing special files with the exception of user, group, and
permissions. In most cases the creation of some special files require root
permissions on the minion. This would require that the minion to be run as the
root user. Here is an example of a character device:

.. code-block:: yaml

    /var/named/chroot/dev/random:
      file.mknod:
        - ntype: c
        - major: 1
        - minor: 8
        - user: named
        - group: named
        - mode: 660

Here is an example of a block device:

.. code-block:: yaml

    /var/named/chroot/dev/loop0:
      file.mknod:
        - ntype: b
        - major: 7
        - minor: 0
        - user: named
        - group: named
        - mode: 660

Here is an example of a fifo pipe:

.. code-block:: yaml

    /var/named/chroot/var/log/logfifo:
      file.mknod:
        - ntype: p
        - user: named
        - group: named
        - mode: 660

Directories can be managed via the ``directory`` function. This function can
create and enforce the permissions on a directory. A directory statement will
look like this:

.. code-block:: yaml

    /srv/stuff/substuf:
      file.directory:
        - user: fred
        - group: users
        - mode: 755
        - makedirs: True

If you need to enforce user and/or group ownership or permissions recursively
on the directory's contents, you can do so by adding a ``recurse`` directive:

.. code-block:: yaml

    /srv/stuff/substuf:
      file.directory:
        - user: fred
        - group: users
        - mode: 755
        - makedirs: True
        - recurse:
          - user
          - group
          - mode

As a default, ``mode`` will resolve to ``dir_mode`` and ``file_mode``, to
specify both directory and file permissions, use this form:

.. code-block:: yaml

    /srv/stuff/substuf:
      file.directory:
        - user: fred
        - group: users
        - file_mode: 744
        - dir_mode: 755
        - makedirs: True
        - recurse:
          - user
          - group
          - mode

Symlinks can be easily created; the symlink function is very simple and only
takes a few arguments:

.. code-block:: yaml

    /etc/grub.conf:
      file.symlink:
        - target: /boot/grub/grub.conf

Recursive directory management can also be set via the ``recurse``
function. Recursive directory management allows for a directory on the salt
master to be recursively copied down to the minion. This is a great tool for
deploying large code and configuration systems. A state using ``recurse``
would look something like this:

.. code-block:: yaml

    /opt/code/flask:
      file.recurse:
        - source: salt://code/flask
        - include_empty: True

A more complex ``recurse`` example:

.. code-block:: jinja

    {% set site_user = 'testuser' %}
    {% set site_name = 'test_site' %}
    {% set project_name = 'test_proj' %}
    {% set sites_dir = 'test_dir' %}

    django-project:
      file.recurse:
        - name: {{ sites_dir }}/{{ site_name }}/{{ project_name }}
        - user: {{ site_user }}
        - dir_mode: 2775
        - file_mode: '0644'
        - template: jinja
        - source: salt://project/templates_dir
        - include_empty: True

Retention scheduling can be applied to manage contents of backup directories.
For example:

.. code-block:: yaml

    /var/backups/example_directory:
      file.retention_schedule:
        - strptime_format: example_name_%Y%m%dT%H%M%S.tar.bz2
        - retain:
            most_recent: 5
            first_of_hour: 4
            first_of_day: 14
            first_of_week: 6
            first_of_month: 6
            first_of_year: all

"""
import copy
import difflib
import itertools
import logging
import os
import posixpath
import re
import shutil
import sys
import time
import traceback
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from itertools import zip_longest
import salt.loader
import salt.payload
import salt.utils.data
import salt.utils.dateutils
import salt.utils.dictupdate
import salt.utils.files
import salt.utils.hashutils
import salt.utils.path
import salt.utils.platform
import salt.utils.stringutils
import salt.utils.templates
import salt.utils.url
import salt.utils.versions
from salt.exceptions import CommandExecutionError
from salt.serializers import DeserializationError
from salt.state import get_accumulator_dir as _get_accumulator_dir
from salt.utils.odict import OrderedDict
log = logging.getLogger(__name__)
if salt.utils.platform.is_windows():
    import salt.utils.win_dacl
    import salt.utils.win_functions
    import salt.utils.winapi
if salt.utils.platform.is_windows():
    import pywintypes
    import win32com.client
COMMENT_REGEX = '^([[:space:]]*){0}[[:space:]]?'
__NOT_FOUND = object()
__func_alias__ = {'copy_': 'copy'}

def _get_accumulator_filepath():
    log.info('Trace')
    '\n    Return accumulator data path.\n    '
    return os.path.join(_get_accumulator_dir(__opts__['cachedir']), __instance_id__)

def _load_accumulators():
    log.info('Trace')

    def _deserialize(path):
        ret = {'accumulators': {}, 'accumulators_deps': {}}
        try:
            log.info('Trace')
            with salt.utils.files.fopen(path, 'rb') as f:
                loaded = salt.payload.load(f)
                return loaded if loaded else ret
        except (OSError, NameError):
            log.info('Trace')
            return ret
    loaded = _deserialize(_get_accumulator_filepath())
    return (loaded['accumulators'], loaded['accumulators_deps'])

def _persist_accummulators(accumulators, accumulators_deps):
    accumm_data = {'accumulators': accumulators, 'accumulators_deps': accumulators_deps}
    try:
        log.info('Trace')
        with salt.utils.files.fopen(_get_accumulator_filepath(), 'w+b') as f:
            salt.payload.dump(accumm_data, f)
    except NameError:
        log.info('Trace')
        pass

def _check_user(user, group):
    """
    Checks if the named user and group are present on the minion
    """
    err = ''
    if user:
        uid = __salt__['file.user_to_uid'](user)
        if uid == '':
            err += 'User {} is not available '.format(user)
    if group:
        gid = __salt__['file.group_to_gid'](group)
        if gid == '':
            err += 'Group {} is not available'.format(group)
    return err

def _is_valid_relpath(relpath, maxdepth=None):
    """
    Performs basic sanity checks on a relative path.

    Requires POSIX-compatible paths (i.e. the kind obtained through
    cp.list_master or other such calls).

    Ensures that the path does not contain directory transversal, and
    that it does not exceed a stated maximum depth (if specified).
    """
    (sep, pardir) = (posixpath.sep, posixpath.pardir)
    if sep + pardir + sep in sep + relpath + sep:
        return False
    if maxdepth is not None:
        path_depth = relpath.strip(sep).count(sep)
        if path_depth > maxdepth:
            return False
    return True

def _salt_to_os_path(path):
    """
    Converts a path from the form received via salt master to the OS's native
    path format.
    """
    return os.path.normpath(path.replace(posixpath.sep, os.path.sep))

def _gen_recurse_managed_files(name, source, keep_symlinks=False, include_pat=None, exclude_pat=None, maxdepth=None, include_empty=False, **kwargs):
    """
    Generate the list of files managed by a recurse state
    """

    def full_path(master_relpath):
        return os.path.join(name, _salt_to_os_path(master_relpath))

    def process_symlinks(filenames, symlinks):
        for (lname, ltarget) in symlinks.items():
            srelpath = posixpath.relpath(lname, srcpath)
            if not _is_valid_relpath(srelpath, maxdepth=maxdepth):
                continue
            if not salt.utils.stringutils.check_include_exclude(srelpath, include_pat, exclude_pat):
                continue
            _filenames = list(filenames)
            for filename in _filenames:
                if filename.startswith(lname + os.sep):
                    log.debug('** skipping file ** %s, it intersects a symlink', filename)
                    filenames.remove(filename)
            managed_symlinks.add((srelpath, ltarget))
            keep.add(full_path(srelpath))
        vdir.update(keep)
        return filenames
    managed_files = set()
    managed_directories = set()
    managed_symlinks = set()
    keep = set()
    vdir = set()
    (srcpath, senv) = salt.utils.url.parse(source)
    if senv is None:
        senv = __env__
    if not srcpath.endswith(posixpath.sep):
        srcpath = srcpath + posixpath.sep
    fns_ = __salt__['cp.list_master'](senv, srcpath)
    if keep_symlinks:
        symlinks = __salt__['cp.list_master_symlinks'](senv, srcpath)
        fns_ = process_symlinks(fns_, symlinks)
    for fn_ in fns_:
        if not fn_.strip():
            continue
        relname = salt.utils.data.decode(posixpath.relpath(fn_, srcpath))
        if not _is_valid_relpath(relname, maxdepth=maxdepth):
            continue
        if not salt.utils.stringutils.check_include_exclude(relname, include_pat, exclude_pat):
            continue
        dest = full_path(relname)
        dirname = os.path.dirname(dest)
        keep.add(dest)
        if dirname not in vdir:
            managed_directories.add(dirname)
            vdir.add(dirname)
        src = salt.utils.url.create(fn_, saltenv=senv)
        managed_files.add((dest, src))
    if include_empty:
        mdirs = __salt__['cp.list_master_dirs'](senv, srcpath)
        for mdir in mdirs:
            relname = posixpath.relpath(mdir, srcpath)
            if not _is_valid_relpath(relname, maxdepth=maxdepth):
                continue
            if not salt.utils.stringutils.check_include_exclude(relname, include_pat, exclude_pat):
                continue
            mdest = full_path(relname)
            if keep_symlinks:
                islink = False
                for link in symlinks:
                    if mdir.startswith(link + os.sep, 0):
                        log.debug('** skipping empty dir ** %s, it intersects a symlink', mdir)
                        islink = True
                        break
                if islink:
                    log.info('Trace')
                    continue
            managed_directories.add(mdest)
            keep.add(mdest)
    return (managed_files, managed_directories, managed_symlinks, keep)

def _gen_keep_files(name, require, walk_d=None):
    """
    Generate the list of files that need to be kept when a dir based function
    like directory or recurse has a clean.
    """

    def _is_child(path, directory):
        """
        Check whether ``path`` is child of ``directory``
        """
        path = os.path.abspath(path)
        directory = os.path.abspath(directory)
        relative = os.path.relpath(path, directory)
        return not relative.startswith(os.pardir)

    def _add_current_path(path):
        _ret = set()
        if os.path.isdir(path):
            (dirs, files) = walk_d.get(path, ((), ()))
            _ret.add(path)
            for _name in files:
                _ret.add(os.path.join(path, _name))
            for _name in dirs:
                _ret.add(os.path.join(path, _name))
        return _ret

    def _process_by_walk_d(name, ret):
        if os.path.isdir(name):
            walk_ret.update(_add_current_path(name))
            (dirs, _) = walk_d.get(name, ((), ()))
            for _d in dirs:
                p = os.path.join(name, _d)
                walk_ret.update(_add_current_path(p))
                _process_by_walk_d(p, ret)

    def _process(name):
        ret = set()
        if os.path.isdir(name):
            for (root, dirs, files) in salt.utils.path.os_walk(name):
                ret.add(name)
                for name in files:
                    ret.add(os.path.join(root, name))
                for name in dirs:
                    ret.add(os.path.join(root, name))
        return ret
    keep = set()
    if isinstance(require, list):
        required_files = [comp for comp in require if 'file' in comp]
        for comp in required_files:
            for low in __lowstate__:
                if low['name'] == comp['file'] or low['__id__'] == comp['file']:
                    fn = low['name']
                    fun = low['fun']
                    if os.path.isdir(fn):
                        if _is_child(fn, name):
                            if fun == 'recurse':
                                fkeep = _gen_recurse_managed_files(**low)[3]
                                log.debug('Keep from %s: %s', fn, fkeep)
                                keep.update(fkeep)
                            elif walk_d:
                                walk_ret = set()
                                _process_by_walk_d(fn, walk_ret)
                                keep.update(walk_ret)
                            else:
                                keep.update(_process(fn))
                    else:
                        keep.add(fn)
    log.debug('Files to keep from required states: %s', list(keep))
    return list(keep)

def _check_file(name):
    ret = True
    msg = ''
    if not os.path.isabs(name):
        ret = False
        msg = 'Specified file {} is not an absolute path'.format(name)
    elif not os.path.exists(name):
        ret = False
        msg = '{}: file not found'.format(name)
    return (ret, msg)

def _find_keep_files(root, keep):
    """
    Compile a list of valid keep files (and directories).
    Used by _clean_dir()
    """
    real_keep = set()
    real_keep.add(root)
    if isinstance(keep, list):
        for fn_ in keep:
            if not os.path.isabs(fn_):
                continue
            fn_ = os.path.normcase(os.path.abspath(fn_))
            real_keep.add(fn_)
            while True:
                fn_ = os.path.abspath(os.path.dirname(fn_))
                real_keep.add(fn_)
                (drive, path) = os.path.splitdrive(fn_)
                if not path.lstrip(os.sep):
                    break
    return real_keep

def _clean_dir(root, keep, exclude_pat):
    log.info('Trace')
    '\n    Clean out all of the files and directories in a directory (root) while\n    preserving the files in a list (keep) and part of exclude_pat\n    '
    case_keep = None
    if salt.utils.files.case_insensitive_filesystem():
        case_keep = keep
    root = os.path.normcase(root)
    real_keep = _find_keep_files(root, keep)
    removed = set()

    def _delete_not_kept(nfn):
        if nfn not in real_keep:
            if not salt.utils.stringutils.check_include_exclude(os.path.relpath(nfn, root), None, exclude_pat):
                return
            if case_keep:
                for item in case_keep:
                    if item.casefold() == nfn.casefold():
                        return
            removed.add(nfn)
            if not __opts__['test']:
                try:
                    log.info('Trace')
                    os.remove(nfn)
                except OSError:
                    log.info('Trace')
                    __salt__['file.remove'](nfn)
    for (roots, dirs, files) in salt.utils.path.os_walk(root):
        for name in itertools.chain(dirs, files):
            _delete_not_kept(os.path.join(roots, name))
    return list(removed)

def _error(ret, err_msg):
    log.info('Trace')
    ret['result'] = False
    ret['comment'] = err_msg
    return ret

def _check_directory(name, user=None, group=None, recurse=False, dir_mode=None, file_mode=None, clean=False, require=False, exclude_pat=None, max_depth=None, follow_symlinks=False):
    log.info('Trace')
    '\n    Check what changes need to be made on a directory\n    '
    changes = {}
    if recurse or clean:
        assert max_depth is None or not clean
        walk_l = list(_depth_limited_walk(name, max_depth))
        walk_d = {}
        for i in walk_l:
            walk_d[i[0]] = (i[1], i[2])
    if recurse:
        try:
            log.info('Trace')
            recurse_set = _get_recurse_set(recurse)
        except (TypeError, ValueError) as exc:
            log.info('Trace')
            return (False, '{}'.format(exc), changes)
        if 'user' not in recurse_set:
            user = None
        if 'group' not in recurse_set:
            group = None
        if 'mode' not in recurse_set:
            dir_mode = None
            file_mode = None
        check_files = 'ignore_files' not in recurse_set
        check_dirs = 'ignore_dirs' not in recurse_set
        for (root, dirs, files) in walk_l:
            if check_files:
                for fname in files:
                    fchange = {}
                    path = os.path.join(root, fname)
                    stats = __salt__['file.stats'](path, None, follow_symlinks)
                    if user is not None and user != stats.get('user'):
                        fchange['user'] = user
                    if group is not None and group != stats.get('group'):
                        fchange['group'] = group
                    smode = salt.utils.files.normalize_mode(stats.get('mode'))
                    file_mode = salt.utils.files.normalize_mode(file_mode)
                    if file_mode is not None and file_mode != smode and (follow_symlinks or stats.get('type') != 'link' or (not salt.utils.platform.is_linux())):
                        fchange['mode'] = file_mode
                    if fchange:
                        changes[path] = fchange
            if check_dirs:
                for name_ in dirs:
                    path = os.path.join(root, name_)
                    fchange = _check_dir_meta(path, user, group, dir_mode, follow_symlinks)
                    if fchange:
                        changes[path] = fchange
    fchange = _check_dir_meta(name, user, group, dir_mode, follow_symlinks)
    if fchange:
        changes[name] = fchange
    if clean:
        keep = _gen_keep_files(name, require, walk_d)

        def _check_changes(fname):
            path = os.path.join(root, fname)
            if path in keep:
                return {}
            elif not salt.utils.stringutils.check_include_exclude(os.path.relpath(path, name), None, exclude_pat):
                return {}
            else:
                return {path: {'removed': 'Removed due to clean'}}
        for (root, dirs, files) in walk_l:
            for fname in files:
                changes.update(_check_changes(fname))
            for name_ in dirs:
                changes.update(_check_changes(name_))
    if not os.path.isdir(name):
        changes[name] = {'directory': 'new'}
    if changes:
        comments = ['The following files will be changed:\n']
        for fn_ in changes:
            for (key, val) in changes[fn_].items():
                comments.append('{}: {} - {}\n'.format(fn_, key, val))
        return (None, ''.join(comments), changes)
    return (True, 'The directory {} is in the correct state'.format(name), changes)

def _check_directory_win(name, win_owner=None, win_perms=None, win_deny_perms=None, win_inheritance=None, win_perms_reset=None):
    """
    Check what changes need to be made on a directory
    """
    if not os.path.isdir(name):
        changes = {name: {'directory': 'new'}}
    else:
        changes = salt.utils.win_dacl.check_perms(obj_name=name, obj_type='file', ret={}, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset, test_mode=True)['changes']
    if changes:
        return (None, 'The directory "{}" will be changed'.format(name), changes)
    return (True, 'The directory {} is in the correct state'.format(name), changes)

def _check_dir_meta(name, user, group, mode, follow_symlinks=False):
    log.info('Trace')
    '\n    Check the changes in directory metadata\n    '
    try:
        log.info('Trace')
        stats = __salt__['file.stats'](name, None, follow_symlinks)
    except CommandExecutionError:
        log.info('Trace')
        stats = {}
    changes = {}
    if not stats:
        changes['directory'] = 'new'
        return changes
    if user is not None and user != stats['user'] and (user != stats.get('uid')):
        changes['user'] = user
    if group is not None and group != stats['group'] and (group != stats.get('gid')):
        changes['group'] = group
    smode = salt.utils.files.normalize_mode(stats['mode'])
    mode = salt.utils.files.normalize_mode(mode)
    if mode is not None and mode != smode and (follow_symlinks or stats.get('type') != 'link' or (not salt.utils.platform.is_linux())):
        changes['mode'] = mode
    return changes

def _check_touch(name, atime, mtime):
    """
    Check to see if a file needs to be updated or created
    """
    ret = {'result': None, 'comment': '', 'changes': {'new': name}}
    if not os.path.exists(name):
        ret['comment'] = 'File {} is set to be created'.format(name)
    else:
        stats = __salt__['file.stats'](name, follow_symlinks=False)
        if atime is not None and str(atime) != str(stats['atime']) or (mtime is not None and str(mtime) != str(stats['mtime'])):
            ret['comment'] = 'Times set to be updated on file {}'.format(name)
            ret['changes'] = {'touched': name}
        else:
            ret['result'] = True
            ret['comment'] = 'File {} exists and has the correct times'.format(name)
    return ret

def _get_symlink_ownership(path):
    if salt.utils.platform.is_windows():
        owner = salt.utils.win_dacl.get_owner(path)
        return (owner, owner)
    else:
        return (__salt__['file.get_user'](path, follow_symlinks=False), __salt__['file.get_group'](path, follow_symlinks=False))

def _check_symlink_ownership(path, user, group, win_owner):
    """
    Check if the symlink ownership matches the specified user and group
    """
    (cur_user, cur_group) = _get_symlink_ownership(path)
    if salt.utils.platform.is_windows():
        return win_owner == cur_user
    else:
        return cur_user == user and cur_group == group

def _set_symlink_ownership(path, user, group, win_owner):
    """
    Set the ownership of a symlink and return a boolean indicating
    success/failure
    """
    if salt.utils.platform.is_windows():
        try:
            salt.utils.win_dacl.set_owner(path, win_owner)
        except CommandExecutionError:
            pass
    else:
        try:
            __salt__['file.lchown'](path, user, group)
        except OSError:
            pass
    return _check_symlink_ownership(path, user, group, win_owner)

def _symlink_check(name, target, force, user, group, win_owner):
    """
    Check the symlink function
    """
    changes = {}
    if not os.path.exists(name) and (not __salt__['file.is_link'](name)):
        changes['new'] = name
        return (None, 'Symlink {} to {} is set for creation'.format(name, target), changes)
    if __salt__['file.is_link'](name):
        if __salt__['file.readlink'](name) != target:
            changes['change'] = name
            return (None, 'Link {} target is set to be changed to {}'.format(name, target), changes)
        else:
            result = True
            msg = 'The symlink {} is present'.format(name)
            if not _check_symlink_ownership(name, user, group, win_owner):
                result = None
                changes['ownership'] = '{}:{}'.format(*_get_symlink_ownership(name))
                msg += ', but the ownership of the symlink would be changed from {2}:{3} to {0}:{1}'.format(user, group, *_get_symlink_ownership(name))
            return (result, msg, changes)
    else:
        if force:
            return (None, 'The file or directory {} is set for removal to make way for a new symlink targeting {}'.format(name, target), changes)
        return (False, 'File or directory exists where the symlink {} should be. Did you mean to use force?'.format(name), changes)

def _hardlink_same(name, target):
    """
    Check to see if the inodes match for the name and the target
    """
    res = __salt__['file.stats'](name, None, follow_symlinks=False)
    if 'inode' not in res:
        return False
    name_i = res['inode']
    res = __salt__['file.stats'](target, None, follow_symlinks=False)
    if 'inode' not in res:
        return False
    target_i = res['inode']
    return name_i == target_i

def _hardlink_check(name, target, force):
    """
    Check the hardlink function
    """
    changes = {}
    if not os.path.exists(target):
        msg = 'Target {} for hard link does not exist'.format(target)
        return (False, msg, changes)
    elif os.path.isdir(target):
        msg = 'Unable to hard link from directory {}'.format(target)
        return (False, msg, changes)
    if os.path.isdir(name):
        msg = 'Unable to hard link to directory {}'.format(name)
        return (False, msg, changes)
    elif not os.path.exists(name):
        msg = 'Hard link {} to {} is set for creation'.format(name, target)
        changes['new'] = name
        return (None, msg, changes)
    elif __salt__['file.is_hardlink'](name):
        if _hardlink_same(name, target):
            msg = 'The hard link {} is presently targetting {}'.format(name, target)
            return (True, msg, changes)
        msg = 'Link {} target is set to be changed to {}'.format(name, target)
        changes['change'] = name
        return (None, msg, changes)
    if force:
        msg = 'The file or directory {} is set for removal to make way for a new hard link targeting {}'.format(name, target)
        return (None, msg, changes)
    msg = 'File or directory exists where the hard link {} should be. Did you mean to use force?'.format(name)
    return (False, msg, changes)

def _test_owner(kwargs, user=None):
    """
    Convert owner to user, since other config management tools use owner,
    no need to punish people coming from other systems.
    PLEASE DO NOT DOCUMENT THIS! WE USE USER, NOT OWNER!!!!
    """
    if user:
        return user
    if 'owner' in kwargs:
        log.warning('Use of argument owner found, "owner" is invalid, please use "user"')
        return kwargs['owner']
    return user

def _unify_sources_and_hashes(source=None, source_hash=None, sources=None, source_hashes=None):
    """
    Silly little function to give us a standard tuple list for sources and
    source_hashes
    """
    if sources is None:
        sources = []
    if source_hashes is None:
        source_hashes = []
    if source and sources:
        return (False, 'source and sources are mutually exclusive', [])
    if source_hash and source_hashes:
        return (False, 'source_hash and source_hashes are mutually exclusive', [])
    if source:
        return (True, '', [(source, source_hash)])
    return (True, '', list(zip_longest(sources, source_hashes[:len(sources)])))

def _get_template_texts(source_list=None, template='jinja', defaults=None, context=None, **kwargs):
    """
    Iterate a list of sources and process them as templates.
    Returns a list of 'chunks' containing the rendered templates.
    """
    ret = {'name': '_get_template_texts', 'changes': {}, 'result': True, 'comment': '', 'data': []}
    if source_list is None:
        return _error(ret, '_get_template_texts called with empty source_list')
    txtl = []
    for (source, source_hash) in source_list:
        tmpctx = defaults if defaults else {}
        if context:
            tmpctx.update(context)
        rndrd_templ_fn = __salt__['cp.get_template'](source, '', template=template, saltenv=__env__, context=tmpctx, **kwargs)
        log.debug('cp.get_template returned %s (Called with: %s)', rndrd_templ_fn, source)
        if rndrd_templ_fn:
            tmplines = None
            with salt.utils.files.fopen(rndrd_templ_fn, 'rb') as fp_:
                tmplines = fp_.read()
                tmplines = salt.utils.stringutils.to_unicode(tmplines)
                tmplines = tmplines.splitlines(True)
            if not tmplines:
                msg = 'Failed to read rendered template file {} ({})'.format(rndrd_templ_fn, source)
                log.debug(msg)
                ret['name'] = source
                return _error(ret, msg)
            txtl.append(''.join(tmplines))
        else:
            msg = 'Failed to load template file {}'.format(source)
            log.debug(msg)
            ret['name'] = source
            return _error(ret, msg)
    ret['data'] = txtl
    return ret

def _validate_str_list(arg, encoding=None):
    log.info('Trace')
    '\n    ensure ``arg`` is a list of strings\n    '
    if isinstance(arg, bytes):
        ret = [salt.utils.stringutils.to_unicode(arg, encoding=encoding)]
    elif isinstance(arg, str):
        ret = [arg]
    elif isinstance(arg, Iterable) and (not isinstance(arg, Mapping)):
        ret = []
        for item in arg:
            if isinstance(item, str):
                ret.append(item)
            else:
                ret.append(str(item))
    else:
        ret = [str(arg)]
    return ret

def _get_shortcut_ownership(path):
    return __salt__['file.get_user'](path, follow_symlinks=False)

def _check_shortcut_ownership(path, user):
    """
    Check if the shortcut ownership matches the specified user
    """
    cur_user = _get_shortcut_ownership(path)
    return cur_user == user

def _set_shortcut_ownership(path, user):
    log.info('Trace')
    '\n    Set the ownership of a shortcut and return a boolean indicating\n    success/failure\n    '
    try:
        log.info('Trace')
        __salt__['file.lchown'](path, user)
    except OSError:
        log.info('Trace')
        pass
    return _check_shortcut_ownership(path, user)

def _shortcut_check(name, target, arguments, working_dir, description, icon_location, force, user):
    """
    Check the shortcut function
    """
    changes = {}
    if not os.path.exists(name):
        changes['new'] = name
        return (None, 'Shortcut "{}" to "{}" is set for creation'.format(name, target), changes)
    if os.path.isfile(name):
        with salt.utils.winapi.Com():
            shell = win32com.client.Dispatch('WScript.Shell')
            scut = shell.CreateShortcut(name)
            state_checks = [scut.TargetPath.lower() == target.lower()]
            if arguments is not None:
                state_checks.append(scut.Arguments == arguments)
            if working_dir is not None:
                state_checks.append(scut.WorkingDirectory.lower() == working_dir.lower())
            if description is not None:
                state_checks.append(scut.Description == description)
            if icon_location is not None:
                state_checks.append(scut.IconLocation.lower() == icon_location.lower())
        if not all(state_checks):
            changes['change'] = name
            return (None, 'Shortcut "{}" target is set to be changed to "{}"'.format(name, target), changes)
        else:
            result = True
            msg = 'The shortcut "{}" is present'.format(name)
            if not _check_shortcut_ownership(name, user):
                result = None
                changes['ownership'] = '{}'.format(_get_shortcut_ownership(name))
                msg += ', but the ownership of the shortcut would be changed from {1} to {0}'.format(user, _get_shortcut_ownership(name))
            return (result, msg, changes)
    else:
        if force:
            return (None, 'The link or directory "{}" is set for removal to make way for a new shortcut targeting "{}"'.format(name, target), changes)
        return (False, 'Link or directory exists where the shortcut "{}" should be. Did you mean to use force?'.format(name), changes)

def _makedirs(name, user=None, group=None, dir_mode=None, win_owner=None, win_perms=None, win_deny_perms=None, win_inheritance=None):
    log.info('Trace')
    '\n    Helper function for creating directories when the ``makedirs`` option is set\n    to ``True``. Handles Unix and Windows based systems\n\n    .. versionadded:: 2017.7.8\n\n    Args:\n        name (str): The directory path to create\n        user (str): The linux user to own the directory\n        group (str): The linux group to own the directory\n        dir_mode (str): The linux mode to apply to the directory\n        win_owner (str): The Windows user to own the directory\n        win_perms (dict): A dictionary of grant permissions for Windows\n        win_deny_perms (dict): A dictionary of deny permissions for Windows\n        win_inheritance (bool): True to inherit permissions on Windows\n\n    Returns:\n        bool: True if successful, otherwise False on Windows\n        str: Error messages on failure on Linux\n        None: On successful creation on Linux\n\n    Raises:\n        CommandExecutionError: If the drive is not mounted on Windows\n    '
    if salt.utils.platform.is_windows():
        (drive, path) = os.path.splitdrive(name)
        if not os.path.isdir(drive):
            raise CommandExecutionError(drive)
        win_owner = win_owner if win_owner else user
        return __salt__['file.makedirs'](path=name, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance)
    else:
        return __salt__['file.makedirs'](path=name, user=user, group=group, mode=dir_mode)

def hardlink(name, target, force=False, makedirs=False, user=None, group=None, dir_mode=None, **kwargs):
    log.info('Trace')
    '\n    Create a hard link\n    If the file already exists and is a hard link pointing to any location other\n    than the specified target, the hard link will be replaced. If the hard link\n    is a regular file or directory then the state will return False. If the\n    regular file is desired to be replaced with a hard link pass force: True\n\n    name\n        The location of the hard link to create\n    target\n        The location that the hard link points to\n    force\n        If the name of the hard link exists and force is set to False, the\n        state will fail. If force is set to True, the file or directory in the\n        way of the hard link file will be deleted to make room for the hard\n        link, unless backupname is set, when it will be renamed\n    makedirs\n        If the location of the hard link does not already have a parent directory\n        then the state will fail, setting makedirs to True will allow Salt to\n        create the parent directory\n    user\n        The user to own any directories made if makedirs is set to true. This\n        defaults to the user salt is running as on the minion\n    group\n        The group ownership set on any directories made if makedirs is set to\n        true. This defaults to the group salt is running as on the minion. On\n        Windows, this is ignored\n    dir_mode\n        If directories are to be created, passing this option specifies the\n        permissions for those directories.\n    '
    name = os.path.expanduser(name)
    dir_mode = salt.utils.files.normalize_mode(dir_mode)
    user = _test_owner(kwargs, user=user)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.hardlink')
    if user is None:
        user = __opts__['user']
    if salt.utils.platform.is_windows():
        if group is not None:
            log.warning('The group argument for %s has been ignored as this is a Windows system.', name)
        group = user
    if group is None:
        if 'user.info' in __salt__:
            group = __salt__['file.gid_to_group'](__salt__['user.info'](user).get('gid', 0))
        else:
            group = user
    preflight_errors = []
    uid = __salt__['file.user_to_uid'](user)
    gid = __salt__['file.group_to_gid'](group)
    if uid == '':
        preflight_errors.append('User {} does not exist'.format(user))
    if gid == '':
        preflight_errors.append('Group {} does not exist'.format(group))
    if not os.path.isabs(name):
        preflight_errors.append('Specified file {} is not an absolute path'.format(name))
    if not os.path.isabs(target):
        preflight_errors.append('Specified target {} is not an absolute path'.format(target))
    if preflight_errors:
        msg = '. '.join(preflight_errors)
        if len(preflight_errors) > 1:
            msg += '.'
        return _error(ret, msg)
    if __opts__['test']:
        (tresult, tcomment, tchanges) = _hardlink_check(name, target, force)
        ret['result'] = tresult
        ret['comment'] = tcomment
        ret['changes'] = tchanges
        return ret
    for (direction, item) in zip_longest(['to', 'from'], [name, target]):
        if os.path.isdir(item):
            msg = 'Unable to hard link {} directory {}'.format(direction, item)
            return _error(ret, msg)
    if not os.path.exists(target):
        msg = 'Target {} for hard link does not exist'.format(target)
        return _error(ret, msg)
    if not os.path.isdir(os.path.dirname(name)):
        if makedirs:
            __salt__['file.makedirs'](name, user=user, group=group, mode=dir_mode)
        else:
            return _error(ret, 'Directory {} for hard link is not present'.format(os.path.dirname(name)))
    if os.path.isfile(name) and (not __salt__['file.is_hardlink'](name)):
        if force:
            os.remove(name)
            ret['changes']['forced'] = 'File for hard link was forcibly replaced'
        else:
            return _error(ret, 'File exists where the hard link {} should be'.format(name))
    if __salt__['file.is_hardlink'](name):
        if _hardlink_same(name, target):
            ret['result'] = True
            ret['comment'] = 'Target of hard link {} is already pointing to {}'.format(name, target)
            return ret
        os.remove(name)
        try:
            log.info('Trace')
            __salt__['file.link'](target, name)
        except CommandExecutionError as E:
            log.info('Trace')
            ret['result'] = False
            ret['comment'] = 'Unable to set target of hard link {} -> {}: {}'.format(name, target, E)
            return ret
        ret['result'] = True
        ret['comment'] = 'Set target of hard link {} -> {}'.format(name, target)
        ret['changes']['new'] = name
    elif not os.path.exists(name):
        try:
            log.info('Trace')
            __salt__['file.link'](target, name)
        except CommandExecutionError as E:
            log.info('Trace')
            ret['result'] = False
            ret['comment'] = 'Unable to create new hard link {} -> {}: {}'.format(name, target, E)
            return ret
        ret['result'] = True
        ret['comment'] = 'Created new hard link {} -> {}'.format(name, target)
        ret['changes']['new'] = name
    return ret

def symlink(name, target, force=False, backupname=None, makedirs=False, user=None, group=None, mode=None, win_owner=None, win_perms=None, win_deny_perms=None, win_inheritance=None, **kwargs):
    log.info('Trace')
    "\n    Create a symbolic link (symlink, soft link)\n\n    If the file already exists and is a symlink pointing to any location other\n    than the specified target, the symlink will be replaced. If an entry with\n    the same name exists then the state will return False. If the existing\n    entry is desired to be replaced with a symlink pass force: True, if it is\n    to be renamed, pass a backupname.\n\n    name\n        The location of the symlink to create\n\n    target\n        The location that the symlink points to\n\n    force\n        If the name of the symlink exists and is not a symlink and\n        force is set to False, the state will fail. If force is set to\n        True, the existing entry in the way of the symlink file\n        will be deleted to make room for the symlink, unless\n        backupname is set, when it will be renamed\n\n        .. versionchanged:: 3000\n            Force will now remove all types of existing file system entries,\n            not just files, directories and symlinks.\n\n    backupname\n        If the name of the symlink exists and is not a symlink, it will be\n        renamed to the backupname. If the backupname already\n        exists and force is False, the state will fail. Otherwise, the\n        backupname will be removed first.\n        An absolute path OR a basename file/directory name must be provided.\n        The latter will be placed relative to the symlink destination's parent\n        directory.\n\n    makedirs\n        If the location of the symlink does not already have a parent directory\n        then the state will fail, setting makedirs to True will allow Salt to\n        create the parent directory\n\n    user\n        The user to own the file, this defaults to the user salt is running as\n        on the minion\n\n    group\n        The group ownership set for the file, this defaults to the group salt\n        is running as on the minion. On Windows, this is ignored\n\n    mode\n        The permissions to set on this file, aka 644, 0775, 4664. Not supported\n        on Windows.\n\n        The default mode for new files and directories corresponds umask of salt\n        process. For existing files and directories it's not enforced.\n\n    win_owner\n        The owner of the symlink and directories if ``makedirs`` is True. If\n        this is not passed, ``user`` will be used. If ``user`` is not passed,\n        the account under which Salt is running will be used.\n\n        .. versionadded:: 2017.7.7\n\n    win_perms\n        A dictionary containing permissions to grant\n\n        .. versionadded:: 2017.7.7\n\n    win_deny_perms\n        A dictionary containing permissions to deny\n\n        .. versionadded:: 2017.7.7\n\n    win_inheritance\n        True to inherit permissions from parent, otherwise False\n\n        .. versionadded:: 2017.7.7\n    "
    name = os.path.expanduser(name)
    mode = salt.utils.files.normalize_mode(mode)
    user = _test_owner(kwargs, user=user)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.symlink')
    if user is None:
        user = __opts__['user']
    if salt.utils.platform.is_windows():
        if not __salt__['user.info'](user):
            user = __salt__['user.current']()
            if not user:
                user = 'SYSTEM'
        if win_owner is None:
            win_owner = user if user else None
        if group is not None:
            log.warning('The group argument for %s has been ignored as this is a Windows system. Please use the `win_*` parameters to set permissions in Windows.', name)
        group = user
    if group is None:
        if 'user.info' in __salt__:
            group = __salt__['file.gid_to_group'](__salt__['user.info'](user).get('gid', 0))
        else:
            group = user
    preflight_errors = []
    if salt.utils.platform.is_windows():
        try:
            log.info('Trace')
            salt.utils.win_functions.get_sid_from_name(win_owner)
        except CommandExecutionError as exc:
            log.info('Trace')
            preflight_errors.append('User {} does not exist'.format(win_owner))
        if win_perms:
            for name_check in win_perms:
                try:
                    log.info('Trace')
                    salt.utils.win_functions.get_sid_from_name(name_check)
                except CommandExecutionError as exc:
                    log.info('Trace')
                    preflight_errors.append('User {} does not exist'.format(name_check))
        if win_deny_perms:
            for name_check in win_deny_perms:
                try:
                    log.info('Trace')
                    salt.utils.win_functions.get_sid_from_name(name_check)
                except CommandExecutionError as exc:
                    log.info('Trace')
                    preflight_errors.append('User {} does not exist'.format(name_check))
    else:
        uid = __salt__['file.user_to_uid'](user)
        gid = __salt__['file.group_to_gid'](group)
        if uid == '':
            preflight_errors.append('User {} does not exist'.format(user))
        if gid == '':
            preflight_errors.append('Group {} does not exist'.format(group))
    if not os.path.isabs(name):
        preflight_errors.append('Specified file {} is not an absolute path'.format(name))
    if preflight_errors:
        msg = '. '.join(preflight_errors)
        if len(preflight_errors) > 1:
            msg += '.'
        return _error(ret, msg)
    (tresult, tcomment, tchanges) = _symlink_check(name, target, force, user, group, win_owner)
    if not os.path.isdir(os.path.dirname(name)):
        if makedirs:
            if __opts__['test']:
                tcomment += '\n{} will be created'.format(os.path.dirname(name))
            else:
                try:
                    log.info('Trace')
                    _makedirs(name=name, user=user, group=group, dir_mode=mode, win_owner=win_owner, win_perms=win_perms, win_deny_perms=win_deny_perms, win_inheritance=win_inheritance)
                except CommandExecutionError as exc:
                    log.info('Trace')
                    return _error(ret, 'Drive {} is not mapped'.format(exc.message))
        elif __opts__['test']:
            tcomment += '\nDirectory {} for symlink is not present'.format(os.path.dirname(name))
        else:
            return _error(ret, 'Directory {} for symlink is not present'.format(os.path.dirname(name)))
    if __opts__['test']:
        ret['result'] = tresult
        ret['comment'] = tcomment
        ret['changes'] = tchanges
        return ret
    if __salt__['file.is_link'](name):
        if os.path.normpath(__salt__['file.readlink'](name)) != os.path.normpath(target):
            os.remove(name)
        else:
            if _check_symlink_ownership(name, user, group, win_owner):
                if salt.utils.platform.is_windows():
                    ret['comment'] = 'Symlink {} is present and owned by {}'.format(name, win_owner)
                else:
                    ret['comment'] = 'Symlink {} is present and owned by {}:{}'.format(name, user, group)
            elif _set_symlink_ownership(name, user, group, win_owner):
                if salt.utils.platform.is_windows():
                    ret['comment'] = 'Set ownership of symlink {} to {}'.format(name, win_owner)
                    ret['changes']['ownership'] = win_owner
                else:
                    ret['comment'] = 'Set ownership of symlink {} to {}:{}'.format(name, user, group)
                    ret['changes']['ownership'] = '{}:{}'.format(user, group)
            else:
                ret['result'] = False
                if salt.utils.platform.is_windows():
                    ret['comment'] += 'Failed to set ownership of symlink {} to {}'.format(name, win_owner)
                else:
                    ret['comment'] += 'Failed to set ownership of symlink {} to {}:{}'.format(name, user, group)
            return ret
    elif os.path.exists(name):
        if backupname is not None:
            if not os.path.isabs(backupname):
                if backupname == os.path.basename(backupname):
                    backupname = os.path.join(os.path.dirname(os.path.normpath(name)), backupname)
                else:
                    return _error(ret, 'Backupname must be an absolute path or a file name: {}'.format(backupname))
            if os.path.lexists(backupname):
                if not force:
                    return _error(ret, 'Symlink & backup dest exists and Force not set. {} -> {} - backup: {}'.format(name, target, backupname))
                else:
                    __salt__['file.remove'](backupname)
            try:
                log.info('Trace')
                __salt__['file.move'](name, backupname)
            except Exception as exc:
                ret['changes'] = {}
                log.debug('Encountered error renaming %s to %s', name, backupname, exc_info=True)
                return _error(ret, 'Unable to rename {} to backup {} -> : {}'.format(name, backupname, exc))
        elif force:
            if __salt__['file.is_link'](name):
                __salt__['file.remove'](name)
                ret['changes']['forced'] = 'Symlink was forcibly replaced'
            else:
                __salt__['file.remove'](name)
        else:
            fs_entry_type = 'File' if os.path.isfile(name) else 'Directory' if os.path.isdir(name) else 'File system entry'
            return _error(ret, '{} exists where the symlink {} should be'.format(fs_entry_type, name))
    if not os.path.exists(name):
        try:
            log.info('Trace')
            __salt__['file.symlink'](target, name)
        except OSError as exc:
            log.info('Trace')
            ret['result'] = False
            ret['comment'] = 'Unable to create new symlink {} -> {}: {}'.format(name, target, exc)
            return ret
        else:
            ret['comment'] = 'Created new symlink {} -> {}'.format(name, target)
            ret['changes']['new'] = name
        if not _check_symlink_ownership(name, user, group, win_owner):
            if not _set_symlink_ownership(name, user, group, win_owner):
                ret['result'] = False
                ret['comment'] += ', but was unable to set ownership to {}:{}'.format(user, group)
    return ret

def absent(name, **kwargs):
    log.info('Trace')
    '\n    Make sure that the named file or directory is absent. If it exists, it will\n    be deleted. This will work to reverse any of the functions in the file\n    state module. If a directory is supplied, it will be recursively deleted.\n\n    If only the contents of the directory need to be deleted but not the directory\n    itself, use :mod:`file.directory <salt.states.file.directory>` with ``clean=True``\n\n    name\n        The path which should be deleted\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.absent')
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if name == '/':
        return _error(ret, 'Refusing to make "/" absent')
    if os.path.isfile(name) or os.path.islink(name):
        if __opts__['test']:
            ret['result'] = None
            ret['changes']['removed'] = name
            ret['comment'] = 'File {} is set for removal'.format(name)
            return ret
        try:
            log.info('Trace')
            if salt.utils.platform.is_windows():
                __salt__['file.remove'](name, force=True)
            else:
                __salt__['file.remove'](name)
            ret['comment'] = 'Removed file {}'.format(name)
            ret['changes']['removed'] = name
            return ret
        except CommandExecutionError as exc:
            log.info('Trace')
            return _error(ret, '{}'.format(exc))
    elif os.path.isdir(name):
        if __opts__['test']:
            ret['result'] = None
            ret['changes']['removed'] = name
            ret['comment'] = 'Directory {} is set for removal'.format(name)
            return ret
        try:
            log.info('Trace')
            if salt.utils.platform.is_windows():
                __salt__['file.remove'](name, force=True)
            else:
                __salt__['file.remove'](name)
            ret['comment'] = 'Removed directory {}'.format(name)
            ret['changes']['removed'] = name
            return ret
        except OSError:
            log.info('Trace')
            return _error(ret, 'Failed to remove directory {}'.format(name))
    ret['comment'] = 'File {} is not present'.format(name)
    return ret

def tidied(name, age=0, matches=None, rmdirs=False, size=0, exclude=None, full_path_match=False, followlinks=False, time_comparison='atime', **kwargs):
    log.info('Trace')
    '\n    .. versionchanged:: 3005\n\n    Remove unwanted files based on specific criteria. Multiple criteria\n    are OR’d together, so a file that is too large but is not old enough\n    will still get tidied.\n\n    If neither age nor size is given all files which match a pattern in\n    matches will be removed.\n\n    NOTE: The regex patterns in this function are used in ``re.match()``, so\n    there is an implicit "beginning of string" anchor (``^``) in the regex and\n    it is unanchored at the other end unless explicitly entered (``$``).\n\n    name\n        The directory tree that should be tidied\n\n    age\n        Maximum age in days after which files are considered for removal\n\n    matches\n        List of regular expressions to restrict what gets removed.  Default: [\'.*\']\n\n    rmdirs\n        Whether or not it\'s allowed to remove directories\n\n    size\n        Maximum allowed file size. Files greater or equal to this size are\n        removed. Doesn\'t apply to directories or symbolic links\n\n    exclude\n        List of regular expressions to filter the ``matches`` parameter and better\n        control what gets removed.\n\n        .. versionadded:: 3005\n\n    full_path_match\n        Match the ``matches`` and ``exclude`` regex patterns against the entire\n        file path instead of just the file or directory name. Default: ``False``\n\n        .. versionadded:: 3005\n\n    followlinks\n        This module will not descend into subdirectories which are pointed to by\n        symbolic links. If you wish to force it to do so, you may give this\n        option the value ``True``. Default: ``False``\n\n        .. versionadded:: 3005\n\n    time_comparison\n        Default: ``atime``. Options: ``atime``/``mtime``/``ctime``. This value\n        is used to set the type of time comparison made using ``age``. The\n        default is to compare access times (atime) or the last time the file was\n        read. A comparison by modification time (mtime) uses the last time the\n        contents of the file was changed. The ctime parameter is the last time\n        the contents, owner,  or permissions of the file were changed.\n\n        .. versionadded:: 3005\n\n    .. code-block:: yaml\n\n        cleanup:\n          file.tidied:\n            - name: /tmp/salt_test\n            - rmdirs: True\n            - matches:\n              - foo\n              - b.*r\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if not os.path.isdir(name):
        return _error(ret, '{} does not exist or is not a directory.'.format(name))
    poss_comp = ['atime', 'ctime', 'mtime']
    if not isinstance(time_comparison, str) or time_comparison.lower() not in poss_comp:
        time_comparison = 'atime'
    time_comparison = time_comparison.lower()
    if isinstance(size, str):
        size = salt.utils.stringutils.human_to_bytes(size)
    todelete = []
    today = date.today()
    if matches is None:
        matches = ['.*']
    progs = []
    for regex in matches:
        progs.append(re.compile(regex))
    exes = []
    for regex in exclude or []:
        exes.append(re.compile(regex))

    def _matches(name):
        for prog in progs:
            if prog.match(name):
                for _ex in exes:
                    if _ex.match(name):
                        return False
                return True
        return False
    for (root, dirs, files) in os.walk(top=name, topdown=False, followlinks=followlinks):
        for elem in files + dirs:
            myage = 0
            mysize = 0
            deleteme = True
            path = os.path.join(root, elem)
            if os.path.islink(path):
                if time_comparison == 'ctime':
                    mytimestamp = os.lstat(path).st_ctime
                elif time_comparison == 'mtime':
                    mytimestamp = os.lstat(path).st_mtime
                else:
                    mytimestamp = os.lstat(path).st_atime
            else:
                if time_comparison == 'ctime':
                    mytimestamp = os.path.getctime(path)
                elif time_comparison == 'mtime':
                    mytimestamp = os.path.getmtime(path)
                else:
                    mytimestamp = os.path.getatime(path)
                if elem in dirs:
                    deleteme = rmdirs
                else:
                    mysize = os.path.getsize(path)
            myage = abs(today - date.fromtimestamp(mytimestamp))
            filename = elem
            if full_path_match:
                filename = path
            if (mysize >= size or myage.days >= age) and _matches(name=filename) and deleteme:
                todelete.append(path)
    if todelete:
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = '{} is set for tidy'.format(name)
            ret['changes'] = {'removed': todelete}
            return ret
        ret['changes']['removed'] = []
        try:
            log.info('Trace')
            for path in todelete:
                if salt.utils.platform.is_windows():
                    __salt__['file.remove'](path, force=True)
                else:
                    __salt__['file.remove'](path)
                ret['changes']['removed'].append(path)
        except CommandExecutionError as exc:
            log.info('Trace')
            return _error(ret, '{}'.format(exc))
        ret['comment'] = 'Removed {} files or directories from directory {}'.format(len(todelete), name)
    else:
        ret['comment'] = 'Nothing to remove from directory {}'.format(name)
    return ret

def exists(name, **kwargs):
    """
    Verify that the named file or directory is present or exists.
    Ensures pre-requisites outside of Salt's purview
    (e.g., keytabs, private keys, etc.) have been previously satisfied before
    deployment.

    This function does not create the file if it doesn't exist, it will return
    an error.

    name
        Absolute path which must exist
    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.exists')
    if not os.path.exists(name):
        return _error(ret, 'Specified path {} does not exist'.format(name))
    ret['comment'] = 'Path {} exists'.format(name)
    return ret

def missing(name, **kwargs):
    """
    Verify that the named file or directory is missing, this returns True only
    if the named file is missing but does not remove the file if it is present.

    name
        Absolute path which must NOT exist
    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.missing')
    if os.path.exists(name):
        return _error(ret, 'Specified path {} exists'.format(name))
    ret['comment'] = 'Path {} is missing'.format(name)
    return ret

def managed(name, source=None, source_hash='', source_hash_name=None, keep_source=True, user=None, group=None, mode=None, attrs=None, template=None, makedirs=False, dir_mode=None, context=None, replace=True, defaults=None, backup='', show_changes=True, create=True, contents=None, tmp_dir='', tmp_ext='', contents_pillar=None, contents_grains=None, contents_newline=True, contents_delimiter=':', encoding=None, encoding_errors='strict', allow_empty=True, follow_symlinks=True, check_cmd=None, skip_verify=False, selinux=None, win_owner=None, win_perms=None, win_deny_perms=None, win_inheritance=True, win_perms_reset=False, verify_ssl=True, use_etag=False, **kwargs):
    log.info('Trace')
    '\n    Manage a given file, this function allows for a file to be downloaded from\n    the salt master and potentially run through a templating system.\n\n    name\n        The location of the file to manage, as an absolute path.\n\n    source\n        The source file to download to the minion, this source file can be\n        hosted on either the salt master server (``salt://``), the salt minion\n        local file system (``/``), or on an HTTP or FTP server (``http(s)://``,\n        ``ftp://``).\n\n        Both HTTPS and HTTP are supported as well as downloading directly\n        from Amazon S3 compatible URLs with both pre-configured and automatic\n        IAM credentials. (see s3.get state documentation)\n        File retrieval from Openstack Swift object storage is supported via\n        swift://container/object_path URLs, see swift.get documentation.\n        For files hosted on the salt file server, if the file is located on\n        the master in the directory named spam, and is called eggs, the source\n        string is salt://spam/eggs. If source is left blank or None\n        (use ~ in YAML), the file will be created as an empty file and\n        the content will not be managed. This is also the case when a file\n        already exists and the source is undefined; the contents of the file\n        will not be changed or managed. If source is left blank or None, please\n        also set replaced to False to make your intention explicit.\n\n\n        If the file is hosted on a HTTP or FTP server then the source_hash\n        argument is also required.\n\n        A list of sources can also be passed in to provide a default source and\n        a set of fallbacks. The first source in the list that is found to exist\n        will be used and subsequent entries in the list will be ignored. Source\n        list functionality only supports local files and remote files hosted on\n        the salt master server or retrievable via HTTP, HTTPS, or FTP.\n\n        .. code-block:: yaml\n\n            file_override_example:\n              file.managed:\n                - source:\n                  - salt://file_that_does_not_exist\n                  - salt://file_that_exists\n\n    source_hash\n        This can be one of the following:\n            1. a source hash string\n            2. the URI of a file that contains source hash strings\n\n        The function accepts the first encountered long unbroken alphanumeric\n        string of correct length as a valid hash, in order from most secure to\n        least secure:\n\n        .. code-block:: text\n\n            Type    Length\n            ======  ======\n            sha512     128\n            sha384      96\n            sha256      64\n            sha224      56\n            sha1        40\n            md5         32\n\n        **Using a Source Hash File**\n            The file can contain several checksums for several files. Each line\n            must contain both the file name and the hash.  If no file name is\n            matched, the first hash encountered will be used, otherwise the most\n            secure hash with the correct source file name will be used.\n\n            When using a source hash file the source_hash argument needs to be a\n            url, the standard download urls are supported, ftp, http, salt etc:\n\n            Example:\n\n            .. code-block:: yaml\n\n                tomdroid-src-0.7.3.tar.gz:\n                  file.managed:\n                    - name: /tmp/tomdroid-src-0.7.3.tar.gz\n                    - source: https://launchpad.net/tomdroid/beta/0.7.3/+download/tomdroid-src-0.7.3.tar.gz\n                    - source_hash: https://launchpad.net/tomdroid/beta/0.7.3/+download/tomdroid-src-0.7.3.hash\n\n            The following lines are all supported formats:\n\n            .. code-block:: text\n\n                /etc/rc.conf ef6e82e4006dee563d98ada2a2a80a27\n                sha254c8525aee419eb649f0233be91c151178b30f0dff8ebbdcc8de71b1d5c8bcc06a  /etc/resolv.conf\n                ead48423703509d37c4a90e6a0d53e143b6fc268\n\n            Debian file type ``*.dsc`` files are also supported.\n\n        **Inserting the Source Hash in the SLS Data**\n\n        The source_hash can be specified as a simple checksum, like so:\n\n        .. code-block:: yaml\n\n            tomdroid-src-0.7.3.tar.gz:\n              file.managed:\n                - name: /tmp/tomdroid-src-0.7.3.tar.gz\n                - source: https://launchpad.net/tomdroid/beta/0.7.3/+download/tomdroid-src-0.7.3.tar.gz\n                - source_hash: 79eef25f9b0b2c642c62b7f737d4f53f\n\n        .. note::\n            Releases prior to 2016.11.0 must also include the hash type, like\n            in the below example:\n\n            .. code-block:: yaml\n\n                tomdroid-src-0.7.3.tar.gz:\n                  file.managed:\n                    - name: /tmp/tomdroid-src-0.7.3.tar.gz\n                    - source: https://launchpad.net/tomdroid/beta/0.7.3/+download/tomdroid-src-0.7.3.tar.gz\n                    - source_hash: md5=79eef25f9b0b2c642c62b7f737d4f53f\n\n        Known issues:\n            If the remote server URL has the hash file as an apparent\n            sub-directory of the source file, the module will discover that it\n            has already cached a directory where a file should be cached. For\n            example:\n\n            .. code-block:: yaml\n\n                tomdroid-src-0.7.3.tar.gz:\n                  file.managed:\n                    - name: /tmp/tomdroid-src-0.7.3.tar.gz\n                    - source: https://launchpad.net/tomdroid/beta/0.7.3/+download/tomdroid-src-0.7.3.tar.gz\n                    - source_hash: https://launchpad.net/tomdroid/beta/0.7.3/+download/tomdroid-src-0.7.3.tar.gz/+md5\n\n    source_hash_name\n        When ``source_hash`` refers to a hash file, Salt will try to find the\n        correct hash by matching the filename/URI associated with that hash. By\n        default, Salt will look for the filename being managed. When managing a\n        file at path ``/tmp/foo.txt``, then the following line in a hash file\n        would match:\n\n        .. code-block:: text\n\n            acbd18db4cc2f85cedef654fccc4a4d8    foo.txt\n\n        However, sometimes a hash file will include multiple similar paths:\n\n        .. code-block:: text\n\n            37b51d194a7513e45b56f6524f2d51f2    ./dir1/foo.txt\n            acbd18db4cc2f85cedef654fccc4a4d8    ./dir2/foo.txt\n            73feffa4b7f6bb68e44cf984c85f6e88    ./dir3/foo.txt\n\n        In cases like this, Salt may match the incorrect hash. This argument\n        can be used to tell Salt which filename to match, to ensure that the\n        correct hash is identified. For example:\n\n        .. code-block:: yaml\n\n            /tmp/foo.txt:\n              file.managed:\n                - source: https://mydomain.tld/dir2/foo.txt\n                - source_hash: https://mydomain.tld/hashes\n                - source_hash_name: ./dir2/foo.txt\n\n        .. note::\n            This argument must contain the full filename entry from the\n            checksum file, as this argument is meant to disambiguate matches\n            for multiple files that have the same basename. So, in the\n            example above, simply using ``foo.txt`` would not match.\n\n        .. versionadded:: 2016.3.5\n\n    keep_source\n        Set to ``False`` to discard the cached copy of the source file once the\n        state completes. This can be useful for larger files to keep them from\n        taking up space in minion cache. However, keep in mind that discarding\n        the source file will result in the state needing to re-download the\n        source file if the state is run again.\n\n        .. versionadded:: 2017.7.3\n\n    user\n        The user to own the file, this defaults to the user salt is running as\n        on the minion\n\n    group\n        The group ownership set for the file, this defaults to the group salt\n        is running as on the minion. On Windows, this is ignored\n\n    mode\n        The permissions to set on this file, e.g. ``644``, ``0775``, or\n        ``4664``.\n\n        The default mode for new files and directories corresponds to the\n        umask of the salt process. The mode of existing files and directories\n        will only be changed if ``mode`` is specified.\n\n        .. note::\n            This option is **not** supported on Windows.\n\n        .. versionchanged:: 2016.11.0\n            This option can be set to ``keep``, and Salt will keep the mode\n            from the Salt fileserver. This is only supported when the\n            ``source`` URL begins with ``salt://``, or for files local to the\n            minion. Because the ``source`` option cannot be used with any of\n            the ``contents`` options, setting the ``mode`` to ``keep`` is also\n            incompatible with the ``contents`` options.\n\n        .. note:: keep does not work with salt-ssh.\n\n            As a consequence of how the files are transferred to the minion, and\n            the inability to connect back to the master with salt-ssh, salt is\n            unable to stat the file as it exists on the fileserver and thus\n            cannot mirror the mode on the salt-ssh minion\n\n    attrs\n        The attributes to have on this file, e.g. ``a``, ``i``. The attributes\n        can be any or a combination of the following characters:\n        ``aAcCdDeijPsStTu``.\n\n        .. note::\n            This option is **not** supported on Windows.\n\n        .. versionadded:: 2018.3.0\n\n    template\n        If this setting is applied, the named templating engine will be used to\n        render the downloaded file. The following templates are supported:\n\n        - :mod:`cheetah<salt.renderers.cheetah>`\n        - :mod:`genshi<salt.renderers.genshi>`\n        - :mod:`jinja<salt.renderers.jinja>`\n        - :mod:`mako<salt.renderers.mako>`\n        - :mod:`py<salt.renderers.py>`\n        - :mod:`wempy<salt.renderers.wempy>`\n\n    makedirs\n        If set to ``True``, then the parent directories will be created to\n        facilitate the creation of the named file. If ``False``, and the parent\n        directory of the destination file doesn\'t exist, the state will fail.\n\n    dir_mode\n        If directories are to be created, passing this option specifies the\n        permissions for those directories. If this is not set, directories\n        will be assigned permissions by adding the execute bit to the mode of\n        the files.\n\n        The default mode for new files and directories corresponds umask of salt\n        process. For existing files and directories it\'s not enforced.\n\n    replace\n        If set to ``False`` and the file already exists, the file will not be\n        modified even if changes would otherwise be made. Permissions and\n        ownership will still be enforced, however.\n\n    context\n        Overrides default context variables passed to the template.\n\n    defaults\n        Default context passed to the template.\n\n    backup\n        Overrides the default backup mode for this specific file. See\n        :ref:`backup_mode documentation <file-state-backups>` for more details.\n\n    show_changes\n        Output a unified diff of the old file and the new file. If ``False``\n        return a boolean if any changes were made.\n\n    create\n        If set to ``False``, then the file will only be managed if the file\n        already exists on the system.\n\n    contents\n        Specify the contents of the file. Cannot be used in combination with\n        ``source``. Ignores hashes and does not use a templating engine.\n\n        This value can be either a single string, a multiline YAML string or a\n        list of strings.  If a list of strings, then the strings will be joined\n        together with newlines in the resulting file. For example, the below\n        two example states would result in identical file contents:\n\n        .. code-block:: yaml\n\n            /path/to/file1:\n              file.managed:\n                - contents:\n                  - This is line 1\n                  - This is line 2\n\n            /path/to/file2:\n              file.managed:\n                - contents: |\n                    This is line 1\n                    This is line 2\n\n\n    contents_pillar\n        .. versionadded:: 0.17.0\n        .. versionchanged:: 2016.11.0\n            contents_pillar can also be a list, and the pillars will be\n            concatenated together to form one file.\n\n\n        Operates like ``contents``, but draws from a value stored in pillar,\n        using the pillar path syntax used in :mod:`pillar.get\n        <salt.modules.pillar.get>`. This is useful when the pillar value\n        contains newlines, as referencing a pillar variable using a jinja/mako\n        template can result in YAML formatting issues due to the newlines\n        causing indentation mismatches.\n\n        For example, the following could be used to deploy an SSH private key:\n\n        .. code-block:: yaml\n\n            /home/deployer/.ssh/id_rsa:\n              file.managed:\n                - user: deployer\n                - group: deployer\n                - mode: 600\n                - attrs: a\n                - contents_pillar: userdata:deployer:id_rsa\n\n        This would populate ``/home/deployer/.ssh/id_rsa`` with the contents of\n        ``pillar[\'userdata\'][\'deployer\'][\'id_rsa\']``. An example of this pillar\n        setup would be like so:\n\n        .. code-block:: yaml\n\n            userdata:\n              deployer:\n                id_rsa: |\n                    -----BEGIN RSA PRIVATE KEY-----\n                    MIIEowIBAAKCAQEAoQiwO3JhBquPAalQF9qP1lLZNXVjYMIswrMe2HcWUVBgh+vY\n                    U7sCwx/dH6+VvNwmCoqmNnP+8gTPKGl1vgAObJAnMT623dMXjVKwnEagZPRJIxDy\n                    B/HaAre9euNiY3LvIzBTWRSeMfT+rWvIKVBpvwlgGrfgz70m0pqxu+UyFbAGLin+\n                    GpxzZAMaFpZw4sSbIlRuissXZj/sHpQb8p9M5IeO4Z3rjkCP1cxI\n                    -----END RSA PRIVATE KEY-----\n\n        .. note::\n            The private key above is shortened to keep the example brief, but\n            shows how to do multiline string in YAML. The key is followed by a\n            pipe character, and the multiline string is indented two more\n            spaces.\n\n            To avoid the hassle of creating an indented multiline YAML string,\n            the :mod:`file_tree external pillar <salt.pillar.file_tree>` can\n            be used instead. However, this will not work for binary files in\n            Salt releases before 2015.8.4.\n\n    contents_grains\n        .. versionadded:: 2014.7.0\n\n        Operates like ``contents``, but draws from a value stored in grains,\n        using the grains path syntax used in :mod:`grains.get\n        <salt.modules.grains.get>`. This functionality works similarly to\n        ``contents_pillar``, but with grains.\n\n        For example, the following could be used to deploy a "message of the day"\n        file:\n\n        .. code-block:: yaml\n\n            write_motd:\n              file.managed:\n                - name: /etc/motd\n                - contents_grains: motd\n\n        This would populate ``/etc/motd`` file with the contents of the ``motd``\n        grain. The ``motd`` grain is not a default grain, and would need to be\n        set prior to running the state:\n\n        .. code-block:: bash\n\n            salt \'*\' grains.set motd \'Welcome! This system is managed by Salt.\'\n\n    contents_newline\n        .. versionadded:: 2014.7.0\n        .. versionchanged:: 2015.8.4\n            This option is now ignored if the contents being deployed contain\n            binary data.\n\n        If ``True``, files managed using ``contents``, ``contents_pillar``, or\n        ``contents_grains`` will have a newline added to the end of the file if\n        one is not present. Setting this option to ``False`` will ensure the\n        final line, or entry, does not contain a new line. If the last line, or\n        entry in the file does contain a new line already, this option will not\n        remove it.\n\n    contents_delimiter\n        .. versionadded:: 2015.8.4\n\n        Can be used to specify an alternate delimiter for ``contents_pillar``\n        or ``contents_grains``. This delimiter will be passed through to\n        :py:func:`pillar.get <salt.modules.pillar.get>` or :py:func:`grains.get\n        <salt.modules.grains.get>` when retrieving the contents.\n\n    encoding\n        If specified, then the specified encoding will be used. Otherwise, the\n        file will be encoded using the system locale (usually UTF-8). See\n        https://docs.python.org/3/library/codecs.html#standard-encodings for\n        the list of available encodings.\n\n        .. versionadded:: 2017.7.0\n\n    encoding_errors\n        Error encoding scheme. Default is ```\'strict\'```.\n        See https://docs.python.org/2/library/codecs.html#codec-base-classes\n        for the list of available schemes.\n\n        .. versionadded:: 2017.7.0\n\n    allow_empty\n        .. versionadded:: 2015.8.4\n\n        If set to ``False``, then the state will fail if the contents specified\n        by ``contents_pillar`` or ``contents_grains`` are empty.\n\n    follow_symlinks\n        .. versionadded:: 2014.7.0\n\n        If the desired path is a symlink follow it and make changes to the\n        file to which the symlink points.\n\n    check_cmd\n        .. versionadded:: 2014.7.0\n\n        The specified command will be run with an appended argument of a\n        *temporary* file containing the new managed contents.  If the command\n        exits with a zero status the new managed contents will be written to\n        the managed destination. If the command exits with a nonzero exit\n        code, the state will fail and no changes will be made to the file.\n\n        For example, the following could be used to verify sudoers before making\n        changes:\n\n        .. code-block:: yaml\n\n            /etc/sudoers:\n              file.managed:\n                - user: root\n                - group: root\n                - mode: 0440\n                - attrs: i\n                - source: salt://sudoers/files/sudoers.jinja\n                - template: jinja\n                - check_cmd: /usr/sbin/visudo -c -f\n\n        **NOTE**: This ``check_cmd`` functions differently than the requisite\n        ``check_cmd``.\n\n    tmp_dir\n        Directory for temp file created by ``check_cmd``. Useful for checkers\n        dependent on config file location (e.g. daemons restricted to their\n        own config directories by an apparmor profile).\n\n        .. code-block:: yaml\n\n            /etc/dhcp/dhcpd.conf:\n              file.managed:\n                - user: root\n                - group: root\n                - mode: 0755\n                - tmp_dir: \'/etc/dhcp\'\n                - contents: "# Managed by Salt"\n                - check_cmd: dhcpd -t -cf\n\n    tmp_ext\n        Suffix for temp file created by ``check_cmd``. Useful for checkers\n        dependent on config file extension (e.g. the init-checkconf upstart\n        config checker).\n\n        .. code-block:: yaml\n\n            /etc/init/test.conf:\n              file.managed:\n                - user: root\n                - group: root\n                - mode: 0440\n                - tmp_ext: \'.conf\'\n                - contents:\n                  - \'description "Salt Minion"\'\n                  - \'start on started mountall\'\n                  - \'stop on shutdown\'\n                  - \'respawn\'\n                  - \'exec salt-minion\'\n                - check_cmd: init-checkconf -f\n\n    skip_verify\n        If ``True``, hash verification of remote file sources (``http://``,\n        ``https://``, ``ftp://``) will be skipped, and the ``source_hash``\n        argument will be ignored.\n\n        .. versionadded:: 2016.3.0\n\n    selinux\n        Allows setting the selinux user, role, type, and range of a managed file\n\n        .. code-block:: yaml\n\n            /tmp/selinux.test\n              file.managed:\n                - user: root\n                - selinux:\n                    seuser: system_u\n                    serole: object_r\n                    setype: system_conf_t\n                    seranage: s0\n\n        .. versionadded:: 3000\n\n    win_owner\n        The owner of the directory. If this is not passed, user will be used. If\n        user is not passed, the account under which Salt is running will be\n        used.\n\n        .. versionadded:: 2017.7.0\n\n    win_perms\n        A dictionary containing permissions to grant and their propagation. For\n        example: ``{\'Administrators\': {\'perms\': \'full_control\'}}`` Can be a\n        single basic perm or a list of advanced perms. ``perms`` must be\n        specified. ``applies_to`` does not apply to file objects.\n\n        .. versionadded:: 2017.7.0\n\n    win_deny_perms\n        A dictionary containing permissions to deny and their propagation. For\n        example: ``{\'Administrators\': {\'perms\': \'full_control\'}}`` Can be a\n        single basic perm or a list of advanced perms. ``perms`` must be\n        specified. ``applies_to`` does not apply to file objects.\n\n        .. versionadded:: 2017.7.0\n\n    win_inheritance\n        True to inherit permissions from the parent directory, False not to\n        inherit permission.\n\n        .. versionadded:: 2017.7.0\n\n    win_perms_reset\n        If ``True`` the existing DACL will be cleared and replaced with the\n        settings defined in this function. If ``False``, new entries will be\n        appended to the existing DACL. Default is ``False``.\n\n        .. versionadded:: 2018.3.0\n\n    Here\'s an example using the above ``win_*`` parameters:\n\n    .. code-block:: yaml\n\n        create_config_file:\n          file.managed:\n            - name: C:\\config\\settings.cfg\n            - source: salt://settings.cfg\n            - win_owner: Administrators\n            - win_perms:\n                # Basic Permissions\n                dev_ops:\n                  perms: full_control\n                # List of advanced permissions\n                appuser:\n                  perms:\n                    - read_attributes\n                    - read_ea\n                    - create_folders\n                    - read_permissions\n                joe_snuffy:\n                  perms: read\n            - win_deny_perms:\n                fred_snuffy:\n                  perms: full_control\n            - win_inheritance: False\n\n    verify_ssl\n        If ``False``, remote https file sources (``https://``) and source_hash\n        will not attempt to validate the servers certificate. Default is True.\n\n        .. versionadded:: 3002\n\n    use_etag\n        If ``True``, remote http/https file sources will attempt to use the\n        ETag header to determine if the remote file needs to be downloaded.\n        This provides a lightweight mechanism for promptly refreshing files\n        changed on a web server without requiring a full hash comparison via\n        the ``source_hash`` parameter.\n\n        .. versionadded:: 3005\n    '
    if 'env' in kwargs:
        kwargs.pop('env')
    name = os.path.expanduser(name)
    ret = {'changes': {}, 'comment': '', 'name': name, 'result': True}
    if not name:
        return _error(ret, 'Destination file name is required')
    if mode is not None and salt.utils.platform.is_windows():
        return _error(ret, "The 'mode' option is not supported on Windows")
    if attrs is not None and salt.utils.platform.is_windows():
        return _error(ret, "The 'attrs' option is not supported on Windows")
    if selinux is not None and (not salt.utils.platform.is_linux()):
        return _error(ret, "The 'selinux' option is only supported on Linux")
    if selinux:
        seuser = selinux.get('seuser', None)
        serole = selinux.get('serole', None)
        setype = selinux.get('setype', None)
        serange = selinux.get('serange', None)
    else:
        seuser = serole = setype = serange = None
    try:
        log.info('Trace')
        keep_mode = mode.lower() == 'keep'
        if keep_mode:
            mode = None
    except AttributeError:
        log.info('Trace')
        keep_mode = False
    mode = salt.utils.files.normalize_mode(mode)
    contents_count = len([x for x in (contents, contents_pillar, contents_grains) if x is not None])
    if source and contents_count > 0:
        return _error(ret, "'source' cannot be used in combination with 'contents', 'contents_pillar', or 'contents_grains'")
    elif keep_mode and contents_count > 0:
        return _error(ret, "Mode preservation cannot be used in combination with 'contents', 'contents_pillar', or 'contents_grains'")
    elif contents_count > 1:
        return _error(ret, "Only one of 'contents', 'contents_pillar', and 'contents_grains' is permitted")
    if not source and contents_count == 0 and replace:
        replace = False
        log.warning("State for file: %s - Neither 'source' nor 'contents' nor 'contents_pillar' nor 'contents_grains' was defined, yet 'replace' was set to 'True'. As there is no source to replace the file with, 'replace' has been set to 'False' to avoid reading the file unnecessarily.", name)
    if 'file_mode' in kwargs:
        ret.setdefault('warnings', []).append("The 'file_mode' argument will be ignored.  Please use 'mode' instead to set file permissions.")
    if contents_pillar is not None:
        if isinstance(contents_pillar, list):
            list_contents = []
            for nextp in contents_pillar:
                nextc = __salt__['pillar.get'](nextp, __NOT_FOUND, delimiter=contents_delimiter)
                if nextc is __NOT_FOUND:
                    return _error(ret, 'Pillar {} does not exist'.format(nextp))
                list_contents.append(nextc)
            use_contents = os.linesep.join(list_contents)
        else:
            use_contents = __salt__['pillar.get'](contents_pillar, __NOT_FOUND, delimiter=contents_delimiter)
            if use_contents is __NOT_FOUND:
                return _error(ret, 'Pillar {} does not exist'.format(contents_pillar))
    elif contents_grains is not None:
        if isinstance(contents_grains, list):
            list_contents = []
            for nextg in contents_grains:
                nextc = __salt__['grains.get'](nextg, __NOT_FOUND, delimiter=contents_delimiter)
                if nextc is __NOT_FOUND:
                    return _error(ret, 'Grain {} does not exist'.format(nextc))
                list_contents.append(nextc)
            use_contents = os.linesep.join(list_contents)
        else:
            use_contents = __salt__['grains.get'](contents_grains, __NOT_FOUND, delimiter=contents_delimiter)
            if use_contents is __NOT_FOUND:
                return _error(ret, 'Grain {} does not exist'.format(contents_grains))
    elif contents is not None:
        use_contents = contents
    else:
        use_contents = None
    if use_contents is not None:
        if not allow_empty and (not use_contents):
            if contents_pillar:
                contents_id = 'contents_pillar {}'.format(contents_pillar)
            elif contents_grains:
                contents_id = 'contents_grains {}'.format(contents_grains)
            else:
                contents_id = "'contents'"
            return _error(ret, '{} value would result in empty contents. Set allow_empty to True to allow the managed file to be empty.'.format(contents_id))
        try:
            log.info('Trace')
            validated_contents = _validate_str_list(use_contents, encoding=encoding)
            if not validated_contents:
                return _error(ret, 'Contents specified by contents/contents_pillar/contents_grains is not a string or list of strings, and is not binary data. SLS is likely malformed.')
            contents = ''
            for part in validated_contents:
                for line in part.splitlines():
                    contents += line.rstrip('\n').rstrip('\r') + os.linesep
            if not contents_newline:
                contents = contents.rstrip('\n').rstrip('\r')
        except UnicodeDecodeError:
            log.info('Trace')
            if template:
                return _error(ret, 'Contents specified by contents/contents_pillar/contents_grains appears to be binary data, and as will not be able to be treated as a Jinja template.')
            contents = use_contents
        if template:
            contents = __salt__['file.apply_template_on_contents'](contents, template=template, context=context, defaults=defaults, saltenv=__env__)
            if not isinstance(contents, str):
                if 'result' in contents:
                    ret['result'] = contents['result']
                else:
                    ret['result'] = False
                if 'comment' in contents:
                    ret['comment'] = contents['comment']
                else:
                    ret['comment'] = 'Error while applying template on contents'
                return ret
    user = _test_owner(kwargs, user=user)
    if salt.utils.platform.is_windows():
        if win_owner is None:
            win_owner = user if user else None
        if group is not None:
            log.warning('The group argument for %s has been ignored as this is a Windows system. Please use the `win_*` parameters to set permissions in Windows.', name)
        group = user
    if not create:
        if not os.path.isfile(name):
            ret['comment'] = 'File {} is not present and is not set for creation'.format(name)
            return ret
    u_check = _check_user(user, group)
    if u_check:
        return _error(ret, u_check)
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if os.path.isdir(name):
        ret['comment'] = 'Specified target {} is a directory'.format(name)
        ret['result'] = False
        return ret
    if context is None:
        context = {}
    elif not isinstance(context, dict):
        return _error(ret, 'Context must be formed as a dict')
    if defaults and (not isinstance(defaults, dict)):
        return _error(ret, 'Defaults must be formed as a dict')
    if not replace and os.path.exists(name):
        ret_perms = {}
        if salt.utils.platform.is_windows():
            ret = __salt__['file.check_perms'](path=name, ret=ret, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset)
        else:
            (ret, ret_perms) = __salt__['file.check_perms'](name, ret, user, group, mode, attrs, follow_symlinks, seuser=seuser, serole=serole, setype=setype, serange=serange)
        if __opts__['test']:
            if mode and isinstance(ret_perms, dict) and ('lmode' in ret_perms) and (mode != ret_perms['lmode']):
                ret['comment'] = 'File {} will be updated with permissions {} from its current state of {}'.format(name, mode, ret_perms['lmode'])
            else:
                ret['comment'] = 'File {} not updated'.format(name)
        elif not ret['changes'] and ret['result']:
            ret['comment'] = 'File {} exists with proper permissions. No changes made.'.format(name)
        return ret
    (accum_data, _) = _load_accumulators()
    if name in accum_data:
        if not context:
            context = {}
        context['accumulator'] = accum_data[name]
    try:
        log.info('Trace')
        if __opts__['test']:
            if 'file.check_managed_changes' in __salt__:
                ret['changes'] = __salt__['file.check_managed_changes'](name, source, source_hash, source_hash_name, user, group, mode, attrs, template, context, defaults, __env__, contents, skip_verify, keep_mode, seuser=seuser, serole=serole, setype=setype, serange=serange, verify_ssl=verify_ssl, follow_symlinks=follow_symlinks, **kwargs)
                if salt.utils.platform.is_windows():
                    try:
                        log.info('Trace')
                        ret = __salt__['file.check_perms'](path=name, ret=ret, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset)
                    except CommandExecutionError as exc:
                        log.info('Trace')
                        if exc.strerror.startswith('Path not found'):
                            ret['changes']['newfile'] = name
            if isinstance(ret['changes'], tuple):
                (ret['result'], ret['comment']) = ret['changes']
            elif ret['changes']:
                ret['result'] = None
                ret['comment'] = 'The file {} is set to be changed'.format(name)
                ret['comment'] += '\nNote: No changes made, actual changes may\nbe different due to other states.'
                if 'diff' in ret['changes'] and (not show_changes):
                    ret['changes']['diff'] = '<show_changes=False>'
            else:
                ret['result'] = True
                ret['comment'] = 'The file {} is in the correct state'.format(name)
            return ret
        (source, source_hash) = __salt__['file.source_list'](source, source_hash, __env__)
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = 'Unable to manage file: {}'.format(exc)
        return ret
    try:
        log.info('Trace')
        (sfn, source_sum, comment_) = __salt__['file.get_managed'](name, template, source, source_hash, source_hash_name, user, group, mode, attrs, __env__, context, defaults, skip_verify, verify_ssl=verify_ssl, use_etag=use_etag, **kwargs)
    except Exception as exc:
        ret['changes'] = {}
        log.debug(traceback.format_exc())
        return _error(ret, 'Unable to manage file: {}'.format(exc))
    tmp_filename = None
    if check_cmd:
        log.info('Trace')
        tmp_filename = salt.utils.files.mkstemp(suffix=tmp_ext, dir=tmp_dir)
        if __salt__['file.file_exists'](name):
            try:
                __salt__['file.copy'](name, tmp_filename)
            except Exception as exc:
                return _error(ret, 'Unable to copy file {} to {}: {}'.format(name, tmp_filename, exc))
        try:
            ret = __salt__['file.manage_file'](tmp_filename, sfn, ret, source, source_sum, user, group, mode, attrs, __env__, backup, makedirs, template, show_changes, contents, dir_mode, follow_symlinks, skip_verify, keep_mode, win_owner=win_owner, win_perms=win_perms, win_deny_perms=win_deny_perms, win_inheritance=win_inheritance, win_perms_reset=win_perms_reset, encoding=encoding, encoding_errors=encoding_errors, seuser=seuser, serole=serole, setype=setype, serange=serange, use_etag=use_etag, **kwargs)
        except Exception as exc:
            ret['changes'] = {}
            log.debug(traceback.format_exc())
            salt.utils.files.remove(tmp_filename)
            if not keep_source:
                if not sfn and source and (urllib.parse.urlparse(source).scheme == 'salt'):
                    sfn = __salt__['cp.is_cached'](source, __env__)
                if sfn:
                    salt.utils.files.remove(sfn)
            return _error(ret, 'Unable to check_cmd file: {}'.format(exc))
        if ret['changes']:
            ret = {'changes': {}, 'comment': '', 'name': name, 'result': True}
            check_cmd_opts = {}
            if 'shell' in __grains__:
                check_cmd_opts['shell'] = __grains__['shell']
            cret = mod_run_check_cmd(check_cmd, tmp_filename, **check_cmd_opts)
            if isinstance(cret, dict):
                ret.update(cret)
                salt.utils.files.remove(tmp_filename)
                return ret
            sfn = tmp_filename
        else:
            ret = {'changes': {}, 'comment': '', 'name': name, 'result': True}
    if comment_ and contents is None:
        return _error(ret, comment_)
    else:
        try:
            log.info('Trace')
            return __salt__['file.manage_file'](name, sfn, ret, source, source_sum, user, group, mode, attrs, __env__, backup, makedirs, template, show_changes, contents, dir_mode, follow_symlinks, skip_verify, keep_mode, win_owner=win_owner, win_perms=win_perms, win_deny_perms=win_deny_perms, win_inheritance=win_inheritance, win_perms_reset=win_perms_reset, encoding=encoding, encoding_errors=encoding_errors, seuser=seuser, serole=serole, setype=setype, serange=serange, use_etag=use_etag, **kwargs)
        except Exception as exc:
            ret['changes'] = {}
            log.debug(traceback.format_exc())
            return _error(ret, 'Unable to manage file: {}'.format(exc))
        finally:
            if tmp_filename:
                salt.utils.files.remove(tmp_filename)
            if not keep_source:
                if not sfn and source and (urllib.parse.urlparse(source).scheme == 'salt'):
                    sfn = __salt__['cp.is_cached'](source, __env__)
                if sfn:
                    salt.utils.files.remove(sfn)
_RECURSE_TYPES = ['user', 'group', 'mode', 'ignore_files', 'ignore_dirs', 'silent']

def _get_recurse_set(recurse):
    log.info('Trace')
    '\n    Converse *recurse* definition to a set of strings.\n\n    Raises TypeError or ValueError when *recurse* has wrong structure.\n    '
    if not recurse:
        return set()
    if not isinstance(recurse, list):
        raise TypeError('"recurse" must be formed as a list of strings')
    try:
        log.info('Trace')
        recurse_set = set(recurse)
    except TypeError:
        log.info('Trace')
        recurse_set = None
    if recurse_set is None or not set(_RECURSE_TYPES) >= recurse_set:
        raise ValueError('Types for "recurse" limited to {}.'.format(', '.join(('"{}"'.format(rtype) for rtype in _RECURSE_TYPES))))
    if 'ignore_files' in recurse_set and 'ignore_dirs' in recurse_set:
        raise ValueError('Must not specify "recurse" options "ignore_files" and "ignore_dirs" at the same time.')
    return recurse_set

def _depth_limited_walk(top, max_depth=None):
    """
    Walk the directory tree under root up till reaching max_depth.
    With max_depth=None (default), do not limit depth.
    """
    for (root, dirs, files) in salt.utils.path.os_walk(top):
        if max_depth is not None:
            rel_depth = root.count(os.path.sep) - top.count(os.path.sep)
            if rel_depth >= max_depth:
                del dirs[:]
        yield (str(root), list(dirs), list(files))

def directory(name, user=None, group=None, recurse=None, max_depth=None, dir_mode=None, file_mode=None, makedirs=False, clean=False, require=None, exclude_pat=None, follow_symlinks=False, force=False, backupname=None, allow_symlink=True, children_only=False, win_owner=None, win_perms=None, win_deny_perms=None, win_inheritance=True, win_perms_reset=False, **kwargs):
    log.info('Trace')
    '\n    Ensure that a named directory is present and has the right perms\n\n    name\n        The location to create or manage a directory, as an absolute path\n\n    user\n        The user to own the directory; this defaults to the user salt is\n        running as on the minion\n\n    group\n        The group ownership set for the directory; this defaults to the group\n        salt is running as on the minion. On Windows, this is ignored\n\n    recurse\n        Enforce user/group ownership and mode of directory recursively. Accepts\n        a list of strings representing what you would like to recurse.  If\n        ``mode`` is defined, will recurse on both ``file_mode`` and ``dir_mode`` if\n        they are defined.  If ``ignore_files`` or ``ignore_dirs`` is included, files or\n        directories will be left unchanged respectively.\n        directories will be left unchanged respectively. If ``silent`` is defined,\n        individual file/directory change notifications will be suppressed.\n\n        Example:\n\n        .. code-block:: yaml\n\n            /var/log/httpd:\n              file.directory:\n                - user: root\n                - group: root\n                - dir_mode: 755\n                - file_mode: 644\n                - recurse:\n                  - user\n                  - group\n                  - mode\n\n        Leave files or directories unchanged:\n\n        .. code-block:: yaml\n\n            /var/log/httpd:\n              file.directory:\n                - user: root\n                - group: root\n                - dir_mode: 755\n                - file_mode: 644\n                - recurse:\n                  - user\n                  - group\n                  - mode\n                  - ignore_dirs\n\n        .. versionadded:: 2015.5.0\n\n    max_depth\n        Limit the recursion depth. The default is no limit=None.\n        \'max_depth\' and \'clean\' are mutually exclusive.\n\n        .. versionadded:: 2016.11.0\n\n    dir_mode / mode\n        The permissions mode to set any directories created. Not supported on\n        Windows.\n\n        The default mode for new files and directories corresponds umask of salt\n        process. For existing files and directories it\'s not enforced.\n\n    file_mode\n        The permissions mode to set any files created if \'mode\' is run in\n        \'recurse\'. This defaults to dir_mode. Not supported on Windows.\n\n        The default mode for new files and directories corresponds umask of salt\n        process. For existing files and directories it\'s not enforced.\n\n    makedirs\n        If the directory is located in a path without a parent directory, then\n        the state will fail. If makedirs is set to True, then the parent\n        directories will be created to facilitate the creation of the named\n        file.\n\n    clean\n        Remove any files that are not referenced by a required ``file`` state.\n        See examples below for more info. If this option is set then everything\n        in this directory will be deleted unless it is required. \'clean\' and\n        \'max_depth\' are mutually exclusive.\n\n    require\n        Require other resources such as packages or files.\n\n    exclude_pat\n        When \'clean\' is set to True, exclude this pattern from removal list\n        and preserve in the destination.\n\n    follow_symlinks\n        If the desired path is a symlink (or ``recurse`` is defined and a\n        symlink is encountered while recursing), follow it and check the\n        permissions of the directory/file to which the symlink points.\n\n        .. versionadded:: 2014.1.4\n\n        .. versionchanged:: 3001.1\n            If set to False symlinks permissions are ignored on Linux systems\n            because it does not support permissions modification. Symlinks\n            permissions are always 0o777 on Linux.\n\n    force\n        If the name of the directory exists and is not a directory and\n        force is set to False, the state will fail. If force is set to\n        True, the file in the way of the directory will be deleted to\n        make room for the directory, unless backupname is set,\n        then it will be renamed.\n\n        .. versionadded:: 2014.7.0\n\n    backupname\n        If the name of the directory exists and is not a directory, it will be\n        renamed to the backupname. If the backupname already\n        exists and force is False, the state will fail. Otherwise, the\n        backupname will be removed first.\n\n        .. versionadded:: 2014.7.0\n\n    allow_symlink\n        If allow_symlink is True and the specified path is a symlink, it will be\n        allowed to remain if it points to a directory. If allow_symlink is False\n        then the state will fail, unless force is also set to True, in which case\n        it will be removed or renamed, depending on the value of the backupname\n        argument.\n\n        .. versionadded:: 2014.7.0\n\n    children_only\n        If children_only is True the base of a path is excluded when performing\n        a recursive operation. In case of /path/to/base, base will be ignored\n        while all of /path/to/base/* are still operated on.\n\n    win_owner\n        The owner of the directory. If this is not passed, user will be used. If\n        user is not passed, the account under which Salt is running will be\n        used.\n\n        .. versionadded:: 2017.7.0\n\n    win_perms\n        A dictionary containing permissions to grant and their propagation. For\n        example: ``{\'Administrators\': {\'perms\': \'full_control\', \'applies_to\':\n        \'this_folder_only\'}}`` Can be a single basic perm or a list of advanced\n        perms. ``perms`` must be specified. ``applies_to`` is optional and\n        defaults to ``this_folder_subfolder_files``.\n\n        .. versionadded:: 2017.7.0\n\n    win_deny_perms\n        A dictionary containing permissions to deny and their propagation. For\n        example: ``{\'Administrators\': {\'perms\': \'full_control\', \'applies_to\':\n        \'this_folder_only\'}}`` Can be a single basic perm or a list of advanced\n        perms.\n\n        .. versionadded:: 2017.7.0\n\n    win_inheritance\n        True to inherit permissions from the parent directory, False not to\n        inherit permission.\n\n        .. versionadded:: 2017.7.0\n\n    win_perms_reset\n        If ``True`` the existing DACL will be cleared and replaced with the\n        settings defined in this function. If ``False``, new entries will be\n        appended to the existing DACL. Default is ``False``.\n\n        .. versionadded:: 2018.3.0\n\n    Here\'s an example using the above ``win_*`` parameters:\n\n    .. code-block:: yaml\n\n        create_config_dir:\n          file.directory:\n            - name: \'C:\\config\\\'\n            - win_owner: Administrators\n            - win_perms:\n                # Basic Permissions\n                dev_ops:\n                  perms: full_control\n                # List of advanced permissions\n                appuser:\n                  perms:\n                    - read_attributes\n                    - read_ea\n                    - create_folders\n                    - read_permissions\n                  applies_to: this_folder_only\n                joe_snuffy:\n                  perms: read\n                  applies_to: this_folder_files\n            - win_deny_perms:\n                fred_snuffy:\n                  perms: full_control\n            - win_inheritance: False\n\n\n    For ``clean: True`` there is no mechanism that allows all states and\n    modules to enumerate the files that they manage, so for file.directory to\n    know what files are managed by Salt, a ``file`` state targeting managed\n    files is required. To use a contrived example, the following states will\n    always have changes, despite the file named ``okay`` being created by a\n    Salt state:\n\n    .. code-block:: yaml\n\n        silly_way_of_creating_a_file:\n          cmd.run:\n             - name: mkdir -p /tmp/dont/do/this && echo "seriously" > /tmp/dont/do/this/okay\n             - unless: grep seriously /tmp/dont/do/this/okay\n\n        will_always_clean:\n          file.directory:\n            - name: /tmp/dont/do/this\n            - clean: True\n\n    Because ``cmd.run`` has no way of communicating that it\'s creating a file,\n    ``will_always_clean`` will remove the newly created file. Of course, every\n    time the states run the same thing will happen - the\n    ``silly_way_of_creating_a_file`` will crete the file and\n    ``will_always_clean`` will always remove it. Over and over again, no matter\n    how many times you run it.\n\n    To make this example work correctly, we need to add a ``file`` state that\n    targets the file, and a ``require`` between the file states.\n\n    .. code-block:: yaml\n\n        silly_way_of_creating_a_file:\n          cmd.run:\n             - name: mkdir -p /tmp/dont/do/this && echo "seriously" > /tmp/dont/do/this/okay\n             - unless: grep seriously /tmp/dont/do/this/okay\n          file.managed:\n             - name: /tmp/dont/do/this/okay\n             - create: False\n             - replace: False\n             - require_in:\n               - file: will_always_clean\n\n    Now there is a ``file`` state that ``clean`` can check, so running those\n    states will work as expected. The file will be created with the specific\n    contents, and ``clean`` will ignore the file because it is being managed by\n    a salt ``file`` state. Note that if ``require_in`` was placed under\n    ``cmd.run``, it would **not** work, because the requisite is for the cmd,\n    not the file.\n\n    .. code-block:: yaml\n\n        silly_way_of_creating_a_file:\n          cmd.run:\n             - name: mkdir -p /tmp/dont/do/this && echo "seriously" > /tmp/dont/do/this/okay\n             - unless: grep seriously /tmp/dont/do/this/okay\n             # This part should be under file.managed\n             - require_in:\n               - file: will_always_clean\n          file.managed:\n             - name: /tmp/dont/do/this/okay\n             - create: False\n             - replace: False\n\n\n    Any other state that creates a file as a result, for example ``pkgrepo``,\n    must have the resulting files referenced in a file state in order for\n    ``clean: True`` to ignore them.  Also note that the requisite\n    (``require_in`` vs ``require``) works in both directions:\n\n    .. code-block:: yaml\n\n        clean_dir:\n          file.directory:\n            - name: /tmp/a/better/way\n            - require:\n              - file: a_better_way\n\n        a_better_way:\n          file.managed:\n            - name: /tmp/a/better/way/truely\n            - makedirs: True\n            - contents: a much better way\n\n    Works the same as this:\n\n    .. code-block:: yaml\n\n        clean_dir:\n          file.directory:\n            - name: /tmp/a/better/way\n            - clean: True\n\n        a_better_way:\n          file.managed:\n            - name: /tmp/a/better/way/truely\n            - makedirs: True\n            - contents: a much better way\n            - require_in:\n              - file: clean_dir\n\n    A common mistake here is to forget the state name and id are both required for requisites:\n\n    .. code-block:: yaml\n\n        # Correct:\n        /path/to/some/file:\n          file.managed:\n            - contents: Cool\n            - require_in:\n              - file: clean_dir\n\n        # Incorrect\n        /path/to/some/file:\n          file.managed:\n            - contents: Cool\n            - require_in:\n              # should be `- file: clean_dir`\n              - clean_dir\n\n        # Also incorrect\n        /path/to/some/file:\n          file.managed:\n            - contents: Cool\n            - require_in:\n              # should be `- file: clean_dir`\n              - file\n\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.directory')
    if name[-1] == '/' and name != '/':
        name = name[:-1]
    if max_depth is not None and clean:
        return _error(ret, 'Cannot specify both max_depth and clean')
    user = _test_owner(kwargs, user=user)
    if salt.utils.platform.is_windows():
        if win_owner is None:
            win_owner = user if user else salt.utils.win_functions.get_current_user()
        if group is not None:
            log.warning('The group argument for %s has been ignored as this is a Windows system. Please use the `win_*` parameters to set permissions in Windows.', name)
        group = user
    if 'mode' in kwargs and (not dir_mode):
        dir_mode = kwargs.get('mode', [])
    if not file_mode:
        file_mode = dir_mode
    dir_mode = salt.utils.files.normalize_mode(dir_mode)
    file_mode = salt.utils.files.normalize_mode(file_mode)
    if salt.utils.platform.is_windows():
        try:
            log.info('Trace')
            salt.utils.win_dacl.get_sid(win_owner)
        except CommandExecutionError as exc:
            log.info('Trace')
            return _error(ret, exc)
    else:
        u_check = _check_user(user, group)
        if u_check:
            if __opts__['test']:
                log.warning(u_check)
            else:
                return _error(ret, u_check)
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if os.path.isfile(name) or (not allow_symlink and os.path.islink(name)) or (force and os.path.islink(name)):
        if backupname is not None:
            if os.path.lexists(backupname):
                if not force:
                    return _error(ret, 'File exists where the backup target {} should go'.format(backupname))
                else:
                    __salt__['file.remove'](backupname)
            os.rename(name, backupname)
        elif force:
            if os.path.isfile(name):
                if __opts__['test']:
                    ret['changes']['forced'] = 'File would be forcibly replaced'
                else:
                    os.remove(name)
                    ret['changes']['forced'] = 'File was forcibly replaced'
            elif __salt__['file.is_link'](name):
                if __opts__['test']:
                    ret['changes']['forced'] = 'Symlink would be forcibly replaced'
                else:
                    __salt__['file.remove'](name)
                    ret['changes']['forced'] = 'Symlink was forcibly replaced'
            elif __opts__['test']:
                ret['changes']['forced'] = 'Directory would be forcibly replaced'
            else:
                __salt__['file.remove'](name)
                ret['changes']['forced'] = 'Directory was forcibly replaced'
        elif os.path.isfile(name):
            return _error(ret, 'Specified location {} exists and is a file'.format(name))
        elif os.path.islink(name):
            return _error(ret, 'Specified location {} exists and is a symlink'.format(name))
    if salt.utils.platform.is_windows():
        (tresult, tcomment, tchanges) = _check_directory_win(name=name, win_owner=win_owner, win_perms=win_perms, win_deny_perms=win_deny_perms, win_inheritance=win_inheritance, win_perms_reset=win_perms_reset)
    else:
        (tresult, tcomment, tchanges) = _check_directory(name, user, group, recurse or [], dir_mode, file_mode, clean, require, exclude_pat, max_depth, follow_symlinks)
    if tchanges:
        ret['changes'].update(tchanges)
    if __opts__['test'] or not ret['changes']:
        ret['result'] = tresult
        ret['comment'] = tcomment
        return ret
    if not os.path.isdir(name):
        if not os.path.isdir(os.path.dirname(name)):
            if makedirs:
                try:
                    log.info('Trace')
                    _makedirs(name=name, user=user, group=group, dir_mode=dir_mode, win_owner=win_owner, win_perms=win_perms, win_deny_perms=win_deny_perms, win_inheritance=win_inheritance)
                except CommandExecutionError as exc:
                    log.info('Trace')
                    return _error(ret, 'Drive {} is not mapped'.format(exc.message))
            else:
                return _error(ret, 'No directory to create {} in'.format(name))
        if salt.utils.platform.is_windows():
            __salt__['file.mkdir'](path=name, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset)
        else:
            __salt__['file.mkdir'](name, user=user, group=group, mode=dir_mode)
        if not os.path.isdir(name):
            return _error(ret, 'Failed to create directory {}'.format(name))
        ret['changes'][name] = {'directory': 'new'}
        return ret
    if not children_only:
        if salt.utils.platform.is_windows():
            ret = __salt__['file.check_perms'](path=name, ret=ret, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset)
        else:
            (ret, perms) = __salt__['file.check_perms'](name, ret, user, group, dir_mode, None, follow_symlinks)
    errors = []
    if recurse or clean:
        walk_l = list(_depth_limited_walk(name, max_depth))
        walk_d = {}
        for i in walk_l:
            walk_d[i[0]] = (i[1], i[2])
    recurse_set = None
    if recurse:
        try:
            log.info('Trace')
            recurse_set = _get_recurse_set(recurse)
        except (TypeError, ValueError) as exc:
            log.info('Trace')
            ret['result'] = False
            ret['comment'] = '{}'.format(exc)
    if recurse_set:
        if 'user' in recurse_set:
            if user or isinstance(user, int):
                uid = __salt__['file.user_to_uid'](user)
                if isinstance(uid, str):
                    ret['result'] = False
                    ret['comment'] = 'Failed to enforce ownership for user {} (user does not exist)'.format(user)
            else:
                ret['result'] = False
                ret['comment'] = 'user not specified, but configured as a target for recursive ownership management'
        else:
            user = None
        if 'group' in recurse_set:
            if group or isinstance(group, int):
                gid = __salt__['file.group_to_gid'](group)
                if isinstance(gid, str):
                    ret['result'] = False
                    ret['comment'] = 'Failed to enforce group ownership for group {}'.format(group)
            else:
                ret['result'] = False
                ret['comment'] = 'group not specified, but configured as a target for recursive ownership management'
        else:
            group = None
        if 'mode' not in recurse_set:
            file_mode = None
            dir_mode = None
        if 'silent' in recurse_set:
            ret['changes'] = {'recursion': 'Changes silenced'}
        check_files = 'ignore_files' not in recurse_set
        check_dirs = 'ignore_dirs' not in recurse_set
        for (root, dirs, files) in walk_l:
            if check_files:
                for fn_ in files:
                    full = os.path.join(root, fn_)
                    try:
                        log.info('Trace')
                        if salt.utils.platform.is_windows():
                            ret = __salt__['file.check_perms'](path=full, ret=ret, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset)
                        else:
                            (ret, _) = __salt__['file.check_perms'](full, ret, user, group, file_mode, None, follow_symlinks)
                    except CommandExecutionError as exc:
                        log.info('Trace')
                        if not exc.strerror.startswith('Path not found'):
                            errors.append(exc.strerror)
            if check_dirs:
                for dir_ in dirs:
                    full = os.path.join(root, dir_)
                    try:
                        log.info('Trace')
                        if salt.utils.platform.is_windows():
                            ret = __salt__['file.check_perms'](path=full, ret=ret, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance, reset=win_perms_reset)
                        else:
                            (ret, _) = __salt__['file.check_perms'](full, ret, user, group, dir_mode, None, follow_symlinks)
                    except CommandExecutionError as exc:
                        log.info('Trace')
                        if not exc.strerror.startswith('Path not found'):
                            errors.append(exc.strerror)
    if clean:
        keep = _gen_keep_files(name, require, walk_d)
        log.debug('List of kept files when use file.directory with clean: %s', keep)
        removed = _clean_dir(name, list(keep), exclude_pat)
        if removed:
            ret['changes']['removed'] = removed
            ret['comment'] = 'Files cleaned from directory {}'.format(name)
    if not ret['comment']:
        if children_only:
            ret['comment'] = 'Directory {}/* updated'.format(name)
        elif ret['changes']:
            ret['comment'] = 'Directory {} updated'.format(name)
    if __opts__['test']:
        ret['comment'] = 'Directory {} not updated'.format(name)
    elif not ret['changes'] and ret['result']:
        orig_comment = None
        if ret['comment']:
            orig_comment = ret['comment']
        ret['comment'] = 'Directory {} is in the correct state'.format(name)
        if orig_comment:
            ret['comment'] = '\n'.join([ret['comment'], orig_comment])
    if errors:
        ret['result'] = False
        ret['comment'] += '\n\nThe following errors were encountered:\n'
        for error in errors:
            ret['comment'] += '\n- {}'.format(error)
    return ret

def recurse(name, source, keep_source=True, clean=False, require=None, user=None, group=None, dir_mode=None, file_mode=None, sym_mode=None, template=None, context=None, replace=True, defaults=None, include_empty=False, backup='', include_pat=None, exclude_pat=None, maxdepth=None, keep_symlinks=False, force_symlinks=False, win_owner=None, win_perms=None, win_deny_perms=None, win_inheritance=True, **kwargs):
    """
    Recurse through a subdirectory on the master and copy said subdirectory
    over to the specified path.

    name
        The directory to set the recursion in

    source
        The source directory, this directory is located on the salt master file
        server and is specified with the salt:// protocol. If the directory is
        located on the master in the directory named spam, and is called eggs,
        the source string is salt://spam/eggs

    keep_source
        Set to ``False`` to discard the cached copy of the source file once the
        state completes. This can be useful for larger files to keep them from
        taking up space in minion cache. However, keep in mind that discarding
        the source file will result in the state needing to re-download the
        source file if the state is run again.

        .. versionadded:: 2017.7.3

    clean
        Make sure that only files that are set up by salt and required by this
        function are kept. If this option is set then everything in this
        directory will be deleted unless it is required.

    require
        Require other resources such as packages or files

    user
        The user to own the directory. This defaults to the user salt is
        running as on the minion

    group
        The group ownership set for the directory. This defaults to the group
        salt is running as on the minion. On Windows, this is ignored

    dir_mode
        The permissions mode to set on any directories created.

        The default mode for new files and directories corresponds umask of salt
        process. For existing files and directories it's not enforced.

        .. note::
            This option is **not** supported on Windows.

    file_mode
        The permissions mode to set on any files created.

        The default mode for new files and directories corresponds umask of salt
        process. For existing files and directories it's not enforced.

        .. note::
            This option is **not** supported on Windows.

        .. versionchanged:: 2016.11.0
            This option can be set to ``keep``, and Salt will keep the mode
            from the Salt fileserver. This is only supported when the
            ``source`` URL begins with ``salt://``, or for files local to the
            minion. Because the ``source`` option cannot be used with any of
            the ``contents`` options, setting the ``mode`` to ``keep`` is also
            incompatible with the ``contents`` options.

    sym_mode
        The permissions mode to set on any symlink created.

        The default mode for new files and directories corresponds umask of salt
        process. For existing files and directories it's not enforced.

        .. note::
            This option is **not** supported on Windows.

    template
        If this setting is applied, the named templating engine will be used to
        render the downloaded file. The following templates are supported:

        - :mod:`cheetah<salt.renderers.cheetah>`
        - :mod:`genshi<salt.renderers.genshi>`
        - :mod:`jinja<salt.renderers.jinja>`
        - :mod:`mako<salt.renderers.mako>`
        - :mod:`py<salt.renderers.py>`
        - :mod:`wempy<salt.renderers.wempy>`

        .. note::

            The template option is required when recursively applying templates.

    replace
        If set to ``False`` and the file already exists, the file will not be
        modified even if changes would otherwise be made. Permissions and
        ownership will still be enforced, however.

    context
        Overrides default context variables passed to the template.

    defaults
        Default context passed to the template.

    include_empty
        Set this to True if empty directories should also be created
        (default is False)

    backup
        Overrides the default backup mode for all replaced files. See
        :ref:`backup_mode documentation <file-state-backups>` for more details.

    include_pat
        When copying, include only this pattern, or list of patterns, from the
        source. Default is glob match; if prefixed with 'E@', then regexp match.
        Example:

        .. code-block:: text

          - include_pat: hello*       :: glob matches 'hello01', 'hello02'
                                         ... but not 'otherhello'
          - include_pat: E@hello      :: regexp matches 'otherhello',
                                         'hello01' ...

        .. versionchanged:: 3001

            List patterns are now supported

        .. code-block:: text

            - include_pat:
                - hello01
                - hello02

    exclude_pat
        Exclude this pattern, or list of patterns, from the source when copying.
        If both `include_pat` and `exclude_pat` are supplied, then it will apply
        conditions cumulatively. i.e. first select based on include_pat, and
        then within that result apply exclude_pat.

        Also, when 'clean=True', exclude this pattern from the removal
        list and preserve in the destination.
        Example:

        .. code-block:: text

          - exclude_pat: APPDATA*               :: glob matches APPDATA.01,
                                                   APPDATA.02,.. for exclusion
          - exclude_pat: E@(APPDATA)|(TEMPDATA) :: regexp matches APPDATA
                                                   or TEMPDATA for exclusion

        .. versionchanged:: 3001

            List patterns are now supported

        .. code-block:: text

            - exclude_pat:
                - APPDATA.01
                - APPDATA.02

    maxdepth
        When copying, only copy paths which are of depth `maxdepth` from the
        source path.
        Example:

        .. code-block:: text

          - maxdepth: 0      :: Only include files located in the source
                                directory
          - maxdepth: 1      :: Only include files located in the source
                                or immediate subdirectories

    keep_symlinks
        Keep symlinks when copying from the source. This option will cause
        the copy operation to terminate at the symlink. If desire behavior
        similar to rsync, then set this to True.

    force_symlinks
        Force symlink creation. This option will force the symlink creation.
        If a file or directory is obstructing symlink creation it will be
        recursively removed so that symlink creation can proceed. This
        option is usually not needed except in special circumstances.

    win_owner
        The owner of the symlink and directories if ``makedirs`` is True. If
        this is not passed, ``user`` will be used. If ``user`` is not passed,
        the account under which Salt is running will be used.

        .. versionadded:: 2017.7.7

    win_perms
        A dictionary containing permissions to grant

        .. versionadded:: 2017.7.7

    win_deny_perms
        A dictionary containing permissions to deny

        .. versionadded:: 2017.7.7

    win_inheritance
        True to inherit permissions from parent, otherwise False

        .. versionadded:: 2017.7.7

    """
    if 'env' in kwargs:
        kwargs.pop('env')
    name = os.path.expanduser(salt.utils.data.decode(name))
    user = _test_owner(kwargs, user=user)
    if salt.utils.platform.is_windows():
        if group is not None:
            log.warning('The group argument for %s has been ignored as this is a Windows system.', name)
        group = user
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': {}}
    if 'mode' in kwargs:
        ret['result'] = False
        ret['comment'] = "'mode' is not allowed in 'file.recurse'. Please use 'file_mode' and 'dir_mode'."
        return ret
    if any([x is not None for x in (dir_mode, file_mode, sym_mode)]) and salt.utils.platform.is_windows():
        return _error(ret, 'mode management is not supported on Windows')
    dir_mode = salt.utils.files.normalize_mode(dir_mode)
    try:
        keep_mode = file_mode.lower() == 'keep'
        if keep_mode:
            file_mode = None
    except AttributeError:
        keep_mode = False
    file_mode = salt.utils.files.normalize_mode(file_mode)
    u_check = _check_user(user, group)
    if u_check:
        return _error(ret, u_check)
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    source_list = _validate_str_list(source)
    for (idx, val) in enumerate(source_list):
        source_list[idx] = val.rstrip('/')
    for precheck in source_list:
        if not precheck.startswith('salt://'):
            return _error(ret, "Invalid source '{}' (must be a salt:// URI)".format(precheck))
    try:
        (source, source_hash) = __salt__['file.source_list'](source_list, '', __env__)
    except CommandExecutionError as exc:
        ret['result'] = False
        ret['comment'] = 'Recurse failed: {}'.format(exc)
        return ret
    (srcpath, senv) = salt.utils.url.parse(source)
    if senv is None:
        senv = __env__
    master_dirs = __salt__['cp.list_master_dirs'](saltenv=senv)
    if srcpath not in master_dirs and (not any((x for x in master_dirs if x.startswith(srcpath + '/')))):
        ret['result'] = False
        ret['comment'] = "The directory '{}' does not exist on the salt fileserver in saltenv '{}'".format(srcpath, senv)
        return ret
    if not os.path.isdir(name):
        if os.path.exists(name):
            return _error(ret, 'The path {} exists and is not a directory'.format(name))
        if not __opts__['test']:
            if salt.utils.platform.is_windows():
                win_owner = win_owner if win_owner else user
                __salt__['file.makedirs_perms'](path=name, owner=win_owner, grant_perms=win_perms, deny_perms=win_deny_perms, inheritance=win_inheritance)
            else:
                __salt__['file.makedirs_perms'](name=name, user=user, group=group, mode=dir_mode)

    def add_comment(path, comment):
        comments = ret['comment'].setdefault(path, [])
        if isinstance(comment, str):
            comments.append(comment)
        else:
            comments.extend(comment)

    def merge_ret(path, _ret):
        if _ret['result'] is False or ret['result'] is True:
            ret['result'] = _ret['result']
        if _ret['result'] is not True and _ret['comment']:
            add_comment(path, _ret['comment'])
        if _ret['changes']:
            ret['changes'][path] = _ret['changes']

    def manage_file(path, source, replace):
        if clean and os.path.exists(path) and os.path.isdir(path) and replace:
            _ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
            if __opts__['test']:
                _ret['comment'] = 'Replacing directory {} with a file'.format(path)
                _ret['result'] = None
                merge_ret(path, _ret)
                return
            else:
                __salt__['file.remove'](path)
                _ret['changes'] = {'diff': 'Replaced directory with a new file'}
                merge_ret(path, _ret)
        pass_kwargs = {}
        faults = ['mode', 'makedirs']
        for key in kwargs:
            if key not in faults:
                pass_kwargs[key] = kwargs[key]
        _ret = managed(path, source=source, keep_source=keep_source, user=user, group=group, mode='keep' if keep_mode else file_mode, attrs=None, template=template, makedirs=True, replace=replace, context=context, defaults=defaults, backup=backup, **pass_kwargs)
        merge_ret(path, _ret)

    def manage_directory(path):
        if os.path.basename(path) == '..':
            return
        if clean and os.path.exists(path) and (not os.path.isdir(path)):
            _ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
            if __opts__['test']:
                _ret['comment'] = 'Replacing {} with a directory'.format(path)
                _ret['result'] = None
                merge_ret(path, _ret)
                return
            else:
                __salt__['file.remove'](path)
                _ret['changes'] = {'diff': 'Replaced file with a directory'}
                merge_ret(path, _ret)
        _ret = directory(path, user=user, group=group, recurse=[], dir_mode=dir_mode, file_mode=None, makedirs=True, clean=False, require=None)
        merge_ret(path, _ret)
    (mng_files, mng_dirs, mng_symlinks, keep) = _gen_recurse_managed_files(name, source, keep_symlinks, include_pat, exclude_pat, maxdepth, include_empty)
    for (srelpath, ltarget) in mng_symlinks:
        _ret = symlink(os.path.join(name, srelpath), ltarget, makedirs=True, force=force_symlinks, user=user, group=group, mode=sym_mode)
        if not _ret:
            continue
        merge_ret(os.path.join(name, srelpath), _ret)
    for dirname in mng_dirs:
        manage_directory(dirname)
    for (dest, src) in mng_files:
        manage_file(dest, src, replace)
    if clean:
        keep.update(_gen_keep_files(name, require))
        removed = _clean_dir(name, list(keep), exclude_pat)
        if removed:
            if __opts__['test']:
                if ret['result']:
                    ret['result'] = None
                add_comment('removed', removed)
            else:
                ret['changes']['removed'] = removed
    ret['comment'] = '\n'.join(('\n#### {} ####\n{}'.format(k, v if isinstance(v, str) else '\n'.join(v)) for (k, v) in ret['comment'].items())).strip()
    if not ret['comment']:
        ret['comment'] = 'Recursively updated {}'.format(name)
    if not ret['changes'] and ret['result']:
        ret['comment'] = 'The directory {} is in the correct state'.format(name)
    return ret

def retention_schedule(name, retain, strptime_format=None, timezone=None):
    log.info('Trace')
    '\n    Apply retention scheduling to backup storage directory.\n\n    .. versionadded:: 2016.11.0\n\n    :param name:\n        The filesystem path to the directory containing backups to be managed.\n\n    :param retain:\n        Delete the backups, except for the ones we want to keep.\n        The N below should be an integer but may also be the special value of ``all``,\n        which keeps all files matching the criteria.\n        All of the retain options default to None,\n        which means to not keep files based on this criteria.\n\n        :most_recent N:\n            Keep the most recent N files.\n\n        :first_of_hour N:\n            For the last N hours from now, keep the first file after the hour.\n\n        :first_of_day N:\n            For the last N days from now, keep the first file after midnight.\n            See also ``timezone``.\n\n        :first_of_week N:\n            For the last N weeks from now, keep the first file after Sunday midnight.\n\n        :first_of_month N:\n            For the last N months from now, keep the first file after the start of the month.\n\n        :first_of_year N:\n            For the last N years from now, keep the first file after the start of the year.\n\n    :param strptime_format:\n        A python strptime format string used to first match the filenames of backups\n        and then parse the filename to determine the datetime of the file.\n        https://docs.python.org/2/library/datetime.html#datetime.datetime.strptime\n        Defaults to None, which considers all files in the directory to be backups eligible for deletion\n        and uses ``os.path.getmtime()`` to determine the datetime.\n\n    :param timezone:\n        The timezone to use when determining midnight.\n        This is only used when datetime is pulled from ``os.path.getmtime()``.\n        Defaults to ``None`` which uses the timezone from the locale.\n\n    Usage example:\n\n    .. code-block:: yaml\n\n        /var/backups/example_directory:\n          file.retention_schedule:\n            - retain:\n                most_recent: 5\n                first_of_hour: 4\n                first_of_day: 7\n                first_of_week: 6    # NotImplemented yet.\n                first_of_month: 6\n                first_of_year: all\n            - strptime_format: example_name_%Y%m%dT%H%M%S.tar.bz2\n            - timezone: None\n\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {'retained': [], 'deleted': [], 'ignored': []}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.retention_schedule')
    if not os.path.isdir(name):
        return _error(ret, 'Name provided to file.retention must be a directory')
    all_files = __salt__['file.readdir'](name)
    beginning_of_unix_time = datetime(1970, 1, 1)

    def get_file_time_from_strptime(f):
        try:
            log.info('Trace')
            ts = datetime.strptime(f, strptime_format)
            ts_epoch = salt.utils.dateutils.total_seconds(ts - beginning_of_unix_time)
            return (ts, ts_epoch)
        except ValueError:
            log.info('Trace')
            return (None, None)

    def get_file_time_from_mtime(f):
        if f == '.' or f == '..':
            return (None, None)
        lstat = __salt__['file.lstat'](os.path.join(name, f))
        if lstat:
            mtime = lstat['st_mtime']
            return (datetime.fromtimestamp(mtime, timezone), mtime)
        else:
            return (None, None)
    get_file_time = get_file_time_from_strptime if strptime_format else get_file_time_from_mtime

    def dict_maker():
        return defaultdict(dict_maker)
    files_by_ymd = dict_maker()
    files_by_y_week_dow = dict_maker()
    relevant_files = set()
    ignored_files = set()
    for f in all_files:
        (ts, ts_epoch) = get_file_time(f)
        if ts:
            files_by_ymd[ts.year][ts.month][ts.day][ts.hour][ts_epoch] = f
            week_of_year = ts.isocalendar()[1]
            files_by_y_week_dow[ts.year][week_of_year][ts.weekday()][ts_epoch] = f
            relevant_files.add(f)
        else:
            ignored_files.add(f)
    RETAIN_TO_DEPTH = {'first_of_year': 1, 'first_of_month': 2, 'first_of_day': 3, 'first_of_hour': 4, 'most_recent': 5}

    def get_first(fwt):
        if isinstance(fwt, dict):
            first_sub_key = sorted(fwt.keys())[0]
            return get_first(fwt[first_sub_key])
        else:
            return {fwt}

    def get_first_n_at_depth(fwt, depth, n):
        if depth <= 0:
            return get_first(fwt)
        else:
            result_set = set()
            for k in sorted(fwt.keys(), reverse=True):
                needed = n - len(result_set)
                if needed < 1:
                    break
                result_set |= get_first_n_at_depth(fwt[k], depth - 1, needed)
            return result_set
    retained_files = set()
    for (retention_rule, keep_count) in retain.items():
        keep_count = sys.maxsize if 'all' == keep_count else int(keep_count)
        if 'first_of_week' == retention_rule:
            first_of_week_depth = 2
            retained_files |= get_first_n_at_depth(files_by_y_week_dow, first_of_week_depth, keep_count + 1)
        else:
            retained_files |= get_first_n_at_depth(files_by_ymd, RETAIN_TO_DEPTH[retention_rule], keep_count)
    deletable_files = list(relevant_files - retained_files)
    deletable_files.sort(reverse=True)
    changes = {'retained': sorted(list(retained_files), reverse=True), 'deleted': deletable_files, 'ignored': sorted(list(ignored_files), reverse=True)}
    ret['changes'] = changes
    if __opts__['test']:
        ret['comment'] = '{} backups would have been removed from {}.\n'.format(len(deletable_files), name)
        if deletable_files:
            ret['result'] = None
    else:
        for f in deletable_files:
            __salt__['file.remove'](os.path.join(name, f))
        ret['comment'] = '{} backups were removed from {}.\n'.format(len(deletable_files), name)
        ret['changes'] = changes
    return ret

def line(name, content=None, match=None, mode=None, location=None, before=None, after=None, show_changes=True, backup=False, quiet=False, indent=True, create=False, user=None, group=None, file_mode=None):
    """
    Line-focused editing of a file.

    .. versionadded:: 2015.8.0

    .. note::

        ``file.line`` exists for historic reasons, and is not
        generally recommended. It has a lot of quirks.  You may find
        ``file.replace`` to be more suitable.

    ``file.line`` is most useful if you have single lines in a file,
    potentially a config file, that you would like to manage. It can
    remove, add, and replace lines.

    name
        Filesystem path to the file to be edited.

    content
        Content of the line. Allowed to be empty if mode=delete.

    match
        Match the target line for an action by
        a fragment of a string or regular expression.

        If neither ``before`` nor ``after`` are provided, and ``match``
        is also ``None``, match falls back to the ``content`` value.

    mode
        Defines how to edit a line. One of the following options is
        required:

        - ensure
            If line does not exist, it will be added. If ``before``
            and ``after`` are specified either zero lines, or lines
            that contain the ``content`` line are allowed to be in between
            ``before`` and ``after``. If there are lines, and none of
            them match then it will produce an error.
        - replace
            If line already exists, it will be replaced.
        - delete
            Delete the line, if found.
        - insert
            Nearly identical to ``ensure``. If a line does not exist,
            it will be added.

            The differences are that multiple (and non-matching) lines are
            alloweed between ``before`` and ``after``, if they are
            specified. The line will always be inserted right before
            ``before``. ``insert`` also allows the use of ``location`` to
            specify that the line should be added at the beginning or end of
            the file.

        .. note::

            If ``mode=insert`` is used, at least one of the following
            options must also be defined: ``location``, ``before``, or
            ``after``. If ``location`` is used, it takes precedence
            over the other two options.

    location
        In ``mode=insert`` only, whether to place the ``content`` at the
        beginning or end of a the file. If ``location`` is provided,
        ``before`` and ``after`` are ignored. Valid locations:

        - start
            Place the content at the beginning of the file.
        - end
            Place the content at the end of the file.

    before
        Regular expression or an exact case-sensitive fragment of the string.
        Will be tried as **both** a regex **and** a part of the line.  Must
        match **exactly** one line in the file.  This value is only used in
        ``ensure`` and ``insert`` modes. The ``content`` will be inserted just
        before this line, matching its ``indent`` unless ``indent=False``.

    after
        Regular expression or an exact case-sensitive fragment of the string.
        Will be tried as **both** a regex **and** a part of the line.  Must
        match **exactly** one line in the file.  This value is only used in
        ``ensure`` and ``insert`` modes. The ``content`` will be inserted
        directly after this line, unless ``before`` is also provided. If
        ``before`` is not matched, indentation will match this line, unless
        ``indent=False``.

    show_changes
        Output a unified diff of the old file and the new file.
        If ``False`` return a boolean if any changes were made.
        Default is ``True``

        .. note::
            Using this option will store two copies of the file in-memory
            (the original version and the edited version) in order to generate the diff.

    backup
        Create a backup of the original file with the extension:
        "Year-Month-Day-Hour-Minutes-Seconds".

    quiet
        Do not raise any exceptions. E.g. ignore the fact that the file that is
        tried to be edited does not exist and nothing really happened.

    indent
        Keep indentation with the previous line. This option is not considered when
        the ``delete`` mode is specified. Default is ``True``.

    create
        Create an empty file if doesn't exist.

        .. versionadded:: 2016.11.0

    user
        The user to own the file, this defaults to the user salt is running as
        on the minion.

        .. versionadded:: 2016.11.0

    group
        The group ownership set for the file, this defaults to the group salt
        is running as on the minion On Windows, this is ignored.

        .. versionadded:: 2016.11.0

    file_mode
        The permissions to set on this file, aka 644, 0775, 4664. Not supported
        on Windows.

        .. versionadded:: 2016.11.0

    If an equal sign (``=``) appears in an argument to a Salt command, it is
    interpreted as a keyword argument in the format of ``key=val``. That
    processing can be bypassed in order to pass an equal sign through to the
    remote shell command by manually specifying the kwarg:

    .. code-block:: yaml

       update_config:
         file.line:
           - name: /etc/myconfig.conf
           - mode: ensure
           - content: my key = my value
           - before: somekey.*?


    **Examples:**

    Here's a simple config file.

    .. code-block:: ini

        [some_config]
        # Some config file
        # this line will go away

        here=False
        away=True
        goodybe=away

    And an sls file:

    .. code-block:: yaml

        remove_lines:
          file.line:
            - name: /some/file.conf
            - mode: delete
            - match: away

    This will produce:

    .. code-block:: ini

        [some_config]
        # Some config file

        here=False
        away=True
        goodbye=away

    If that state is executed 2 more times, this will be the result:

    .. code-block:: ini

        [some_config]
        # Some config file

        here=False

    Given that original file with this state:

    .. code-block:: yaml

        replace_things:
          file.line:
            - name: /some/file.conf
            - mode: replace
            - match: away
            - content: here

    Three passes will this state will result in this file:

    .. code-block:: ini

        [some_config]
        # Some config file
        here

        here=False
        here
        here

    Each pass replacing the first line found.

    Given this file:

    .. code-block:: text

        insert after me
        something
        insert before me

    The following state:

    .. code-block:: yaml

        insert_a_line:
          file.line:
            - name: /some/file.txt
            - mode: insert
            - after: insert after me
            - before: insert before me
            - content: thrice

    If this state is executed 3 times, the result will be:

    .. code-block:: text

        insert after me
        something
        thrice
        thrice
        thrice
        insert before me

    If the mode is ensure instead, it will fail each time. To succeed, we need
    to remove the incorrect line between before and after:

    .. code-block:: text

        insert after me
        insert before me

    With an ensure mode, this will insert ``thrice`` the first time and
    make no changes for subsequent calls. For something simple this is
    fine, but if you have instead blocks like this:

    .. code-block:: text

        Begin SomeBlock
            foo = bar
        End

        Begin AnotherBlock
            another = value
        End

    And given this state:

    .. code-block:: yaml

        ensure_someblock:
          file.line:
            - name: /some/file.conf
            - mode: ensure
            - after: Begin SomeBlock
            - content: this = should be my content
            - before: End

    This will fail because there are multiple ``End`` lines. Without that
    problem, it still would fail because there is a non-matching line,
    ``foo = bar``. Ensure **only** allows either zero, or the matching
    line present to be present in between ``before`` and ``after``.
    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.line')
    managed(name, create=create, user=user, group=group, mode=file_mode, replace=False)
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        return _error(ret, check_msg)
    mode = mode and mode.lower() or mode
    if mode is None:
        return _error(ret, 'Mode was not defined. How to process the file?')
    modeswithemptycontent = ['delete']
    if mode not in modeswithemptycontent and content is None:
        return _error(ret, 'Content can only be empty if mode is {}'.format(modeswithemptycontent))
    del modeswithemptycontent
    changes = __salt__['file.line'](name, content, match=match, mode=mode, location=location, before=before, after=after, show_changes=show_changes, backup=backup, quiet=quiet, indent=indent)
    if changes:
        ret['changes']['diff'] = changes
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'Changes would be made'
        else:
            ret['result'] = True
            ret['comment'] = 'Changes were made'
    else:
        ret['result'] = True
        ret['comment'] = 'No changes needed to be made'
    return ret

def replace(name, pattern, repl, count=0, flags=8, bufsize=1, append_if_not_found=False, prepend_if_not_found=False, not_found_content=None, backup='.bak', show_changes=True, ignore_if_missing=False, backslash_literal=False):
    """
    Maintain an edit in a file.

    .. versionadded:: 0.17.0

    name
        Filesystem path to the file to be edited. If a symlink is specified, it
        will be resolved to its target.

    pattern
        A regular expression, to be matched using Python's
        :py:func:`re.search`.

        .. note::

            If you need to match a literal string that contains regex special
            characters, you may want to use salt's custom Jinja filter,
            ``regex_escape``.

            .. code-block:: jinja

                {{ 'http://example.com?foo=bar%20baz' | regex_escape }}

    repl
        The replacement text

    count
        Maximum number of pattern occurrences to be replaced.  Defaults to 0.
        If count is a positive integer n, no more than n occurrences will be
        replaced, otherwise all occurrences will be replaced.

    flags
        A list of flags defined in the ``re`` module documentation from the
        Python standard library. Each list item should be a string that will
        correlate to the human-friendly flag name. E.g., ``['IGNORECASE',
        'MULTILINE']``.  Optionally, ``flags`` may be an int, with a value
        corresponding to the XOR (``|``) of all the desired flags. Defaults to
        ``8`` (which equates to ``['MULTILINE']``).

        .. note::

            ``file.replace`` reads the entire file as a string to support
            multiline regex patterns. Therefore, when using anchors such as
            ``^`` or ``$`` in the pattern, those anchors may be relative to
            the line OR relative to the file. The default for ``file.replace``
            is to treat anchors as relative to the line, which is implemented
            by setting the default value of ``flags`` to ``['MULTILINE']``.
            When overriding the default value for ``flags``, if
            ``'MULTILINE'`` is not present then anchors will be relative to
            the file. If the desired behavior is for anchors to be relative to
            the line, then simply add ``'MULTILINE'`` to the list of flags.

    bufsize
        How much of the file to buffer into memory at once. The default value
        ``1`` processes one line at a time. The special value ``file`` may be
        specified which will read the entire file into memory before
        processing.

    append_if_not_found
        If set to ``True``, and pattern is not found, then the content will be
        appended to the file.

        .. versionadded:: 2014.7.0

    prepend_if_not_found
        If set to ``True`` and pattern is not found, then the content will be
        prepended to the file.

        .. versionadded:: 2014.7.0

    not_found_content
        Content to use for append/prepend if not found. If ``None`` (default),
        uses ``repl``. Useful when ``repl`` uses references to group in
        pattern.

        .. versionadded:: 2014.7.0

    backup
        The file extension to use for a backup of the file before editing. Set
        to ``False`` to skip making a backup.

    show_changes
        Output a unified diff of the old file and the new file. If ``False``
        return a boolean if any changes were made. Returns a boolean or a
        string.

        .. note:
            Using this option will store two copies of the file in memory (the
            original version and the edited version) in order to generate the
            diff. This may not normally be a concern, but could impact
            performance if used with large files.

    ignore_if_missing
        .. versionadded:: 2016.3.4

        Controls what to do if the file is missing. If set to ``False``, the
        state will display an error raised by the execution module. If set to
        ``True``, the state will simply report no changes.

    backslash_literal
        .. versionadded:: 2016.11.7

        Interpret backslashes as literal backslashes for the repl and not
        escape characters.  This will help when using append/prepend so that
        the backslashes are not interpreted for the repl on the second run of
        the state.

    For complex regex patterns, it can be useful to avoid the need for complex
    quoting and escape sequences by making use of YAML's multiline string
    syntax.

    .. code-block:: yaml

        complex_search_and_replace:
          file.replace:
            # <...snip...>
            - pattern: |
                CentOS \\(2.6.32[^\\\\n]+\\\\n\\s+root[^\\\\n]+\\\\n\\)+

    .. note::

       When using YAML multiline string syntax in ``pattern:``, make sure to
       also use that syntax in the ``repl:`` part, or you might loose line
       feeds.

    When regex capture groups are used in ``pattern:``, their captured value is
    available for reuse in the ``repl:`` part as a backreference (ex. ``\\1``).

    .. code-block:: yaml

        add_login_group_to_winbind_ssh_access_list:
          file.replace:
            - name: '/etc/security/pam_winbind.conf'
            - pattern: '^(require_membership_of = )(.*)$'
            - repl: '\\1\\2,append-new-group-to-line'

    .. note::

       The ``file.replace`` state uses Python's ``re`` module.
       For more advanced options, see https://docs.python.org/2/library/re.html
    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.replace')
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        if ignore_if_missing and 'file not found' in check_msg:
            ret['comment'] = 'No changes needed to be made'
            return ret
        else:
            return _error(ret, check_msg)
    changes = __salt__['file.replace'](name, pattern, repl, count=count, flags=flags, bufsize=bufsize, append_if_not_found=append_if_not_found, prepend_if_not_found=prepend_if_not_found, not_found_content=not_found_content, backup=backup, dry_run=__opts__['test'], show_changes=show_changes, ignore_if_missing=ignore_if_missing, backslash_literal=backslash_literal)
    if changes:
        ret['changes']['diff'] = changes
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'Changes would have been made'
        else:
            ret['result'] = True
            ret['comment'] = 'Changes were made'
    else:
        ret['result'] = True
        ret['comment'] = 'No changes needed to be made'
    return ret

def keyvalue(name, key=None, value=None, key_values=None, separator='=', append_if_not_found=False, prepend_if_not_found=False, search_only=False, show_changes=True, ignore_if_missing=False, count=1, uncomment=None, key_ignore_case=False, value_ignore_case=False):
    log.info('Trace')
    "\n    Key/Value based editing of a file.\n\n    .. versionadded:: 3001\n\n    This function differs from ``file.replace`` in that it is able to search for\n    keys, followed by a customizable separator, and replace the value with the\n    given value. Should the value be the same as the one already in the file, no\n    changes will be made.\n\n    Either supply both ``key`` and ``value`` parameters, or supply a dictionary\n    with key / value pairs. It is an error to supply both.\n\n    name\n        Name of the file to search/replace in.\n\n    key\n        Key to search for when ensuring a value. Use in combination with a\n        ``value`` parameter.\n\n    value\n        Value to set for a given key. Use in combination with a ``key``\n        parameter.\n\n    key_values\n        Dictionary of key / value pairs to search for and ensure values for.\n        Used to specify multiple key / values at once.\n\n    separator\n        Separator which separates key from value.\n\n    append_if_not_found\n        Append the key/value to the end of the file if not found. Note that this\n        takes precedence over ``prepend_if_not_found``.\n\n    prepend_if_not_found\n        Prepend the key/value to the beginning of the file if not found. Note\n        that ``append_if_not_found`` takes precedence.\n\n    show_changes\n        Show a diff of the resulting removals and inserts.\n\n    ignore_if_missing\n        Return with success even if the file is not found (or not readable).\n\n    count\n        Number of occurrences to allow (and correct), default is 1. Set to -1 to\n        replace all, or set to 0 to remove all lines with this key regardsless\n        of its value.\n\n    .. note::\n        Any additional occurrences after ``count`` are removed.\n        A count of -1 will only replace all occurrences that are currently\n        uncommented already. Lines commented out will be left alone.\n\n    uncomment\n        Disregard and remove supplied leading characters when finding keys. When\n        set to None, lines that are commented out are left for what they are.\n\n    .. note::\n        The argument to ``uncomment`` is not a prefix string. Rather; it is a\n        set of characters, each of which are stripped.\n\n    key_ignore_case\n        Keys are matched case insensitively. When a value is changed the matched\n        key is kept as-is.\n\n    value_ignore_case\n        Values are checked case insensitively, trying to set e.g. 'Yes' while\n        the current value is 'yes', will not result in changes when\n        ``value_ignore_case`` is set to True.\n\n    An example of using ``file.keyvalue`` to ensure sshd does not allow\n    for root to login with a password and at the same time setting the\n    login-gracetime to 1 minute and disabling all forwarding:\n\n    .. code-block:: yaml\n\n        sshd_config_harden:\n            file.keyvalue:\n              - name: /etc/ssh/sshd_config\n              - key_values:\n                  permitrootlogin: 'without-password'\n                  LoginGraceTime: '1m'\n                  DisableForwarding: 'yes'\n              - separator: ' '\n              - uncomment: '# '\n              - key_ignore_case: True\n              - append_if_not_found: True\n\n    The same example, except for only ensuring PermitRootLogin is set correctly.\n    Thus being able to use the shorthand ``key`` and ``value`` parameters\n    instead of ``key_values``.\n\n    .. code-block:: yaml\n\n        sshd_config_harden:\n            file.keyvalue:\n              - name: /etc/ssh/sshd_config\n              - key: PermitRootLogin\n              - value: without-password\n              - separator: ' '\n              - uncomment: '# '\n              - key_ignore_case: True\n              - append_if_not_found: True\n\n    .. note::\n        Notice how the key is not matched case-sensitively, this way it will\n        correctly identify both 'PermitRootLogin' as well as 'permitrootlogin'.\n\n    "
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': None, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.keyvalue')
    if key is not None and value is not None:
        if type(key_values) is dict:
            return _error(ret, 'file.keyvalue can not combine key_values with key and value')
        key_values = {str(key): value}
    elif not isinstance(key_values, dict) or not key_values:
        msg = 'is not a dictionary'
        if not key_values:
            msg = 'is empty'
        return _error(ret, 'file.keyvalue key and value not supplied and key_values ' + msg)
    file_contents = []
    try:
        log.info('Trace')
        with salt.utils.files.fopen(name, 'r') as fd:
            file_contents = fd.readlines()
    except OSError:
        log.info('Trace')
        ret['comment'] = 'unable to open {n}'.format(n=name)
        ret['result'] = True if ignore_if_missing else False
        return ret
    diff = []
    content = []
    tmpl = '{key}{sep}{value}' + os.linesep
    changes = 0
    diff_count = {k: count for k in key_values.keys()}
    for line in file_contents:
        test_line = line.lstrip(uncomment)
        did_uncomment = True if len(line) > len(test_line) else False
        if key_ignore_case:
            test_line = test_line.lower()
        for (key, value) in key_values.items():
            test_key = key.lower() if key_ignore_case else key
            if test_line.startswith(test_key):
                working_line = line.lstrip(uncomment) if did_uncomment else line
                (line_key, line_sep, line_value) = working_line.partition(separator)
                if line_sep != separator:
                    continue
                keys_match = False
                if key_ignore_case:
                    if line_key.lower() == test_key:
                        keys_match = True
                elif line_key == test_key:
                    keys_match = True
                if keys_match:
                    line_value = line_value.strip()
                    test_value = str(value).strip()
                    if value_ignore_case:
                        line_value = line_value.lower()
                        test_value = test_value.lower()
                    values_match = True if line_value == test_value else False
                    needs_changing = False
                    if did_uncomment:
                        if diff_count[key] > 0:
                            needs_changing = True
                        elif not values_match:
                            values_match = True
                    elif diff_count[key] == 0:
                        needs_changing = True
                    if not values_match or needs_changing:
                        diff.append('- {}'.format(line))
                        line = line[:0]
                        if diff_count[key] != 0:
                            line = str(tmpl.format(key=line_key, sep=line_sep, value=value))
                            if not isinstance(value, str):
                                diff.append('+ {} (from {} type){}'.format(line.rstrip(), type(value).__name__, os.linesep))
                            else:
                                diff.append('+ {}'.format(line))
                        changes += 1
                    if diff_count[key] > 0:
                        diff_count[key] -= 1
                    continue
        content.append(line)
    fd.close()
    if append_if_not_found:
        tmpdiff = []
        for (key, value) in key_values.items():
            if diff_count[key] > 0:
                line = tmpl.format(key=key, sep=separator, value=value)
                tmpdiff.append('+ {}'.format(line))
                content.append(line)
                changes += 1
        if tmpdiff:
            tmpdiff.insert(0, '- <EOF>' + os.linesep)
            tmpdiff.append('+ <EOF>' + os.linesep)
            diff.extend(tmpdiff)
    elif prepend_if_not_found:
        did_diff = False
        for (key, value) in key_values.items():
            if diff_count[key] > 0:
                line = tmpl.format(key=key, sep=separator, value=value)
                if not did_diff:
                    diff.insert(0, '  <SOF>' + os.linesep)
                    did_diff = True
                diff.insert(1, '+ {}'.format(line))
                content.insert(0, line)
                changes += 1
    if changes > 0:
        if __opts__['test']:
            ret['comment'] = 'File {n} is set to be changed ({c} lines)'.format(n=name, c=changes)
            if show_changes:
                ret['changes']['diff'] = ''.join(diff)
                ret['comment'] += '\nPredicted diff:\n\r\t\t'
                ret['comment'] += '\r\t\t'.join(diff)
                ret['result'] = None
        else:
            ret['comment'] = 'Changed {c} lines'.format(c=changes)
            if show_changes:
                ret['changes']['diff'] = ''.join(diff)
    else:
        ret['result'] = True
        return ret
    if not __opts__['test']:
        try:
            log.info('Trace')
            with salt.utils.files.fopen(name, 'w') as fd:
                fd.writelines(content)
                fd.close()
        except OSError:
            log.info('Trace')
            ret['comment'] = '{n} not writable'.format(n=name)
            ret['result'] = False
            return ret
        ret['result'] = True
    return ret

def blockreplace(name, marker_start='#-- start managed zone --', marker_end='#-- end managed zone --', source=None, source_hash=None, template='jinja', sources=None, source_hashes=None, defaults=None, context=None, content='', append_if_not_found=False, prepend_if_not_found=False, backup='.bak', show_changes=True, append_newline=None, insert_before_match=None, insert_after_match=None):
    log.info('Trace')
    '\n    Maintain an edit in a file in a zone delimited by two line markers\n\n    .. versionadded:: 2014.1.0\n    .. versionchanged:: 2017.7.5,2018.3.1\n        ``append_newline`` argument added. Additionally, to improve\n        idempotence, if the string represented by ``marker_end`` is found in\n        the middle of the line, the content preceding the marker will be\n        removed when the block is replaced. This allows one to remove\n        ``append_newline: False`` from the SLS and have the block properly\n        replaced if the end of the content block is immediately followed by the\n        ``marker_end`` (i.e. no newline before the marker).\n\n    A block of content delimited by comments can help you manage several lines\n    entries without worrying about old entries removal. This can help you\n    maintaining an un-managed file containing manual edits.\n\n    .. note::\n        This function will store two copies of the file in-memory (the original\n        version and the edited version) in order to detect changes and only\n        edit the targeted file if necessary.\n\n        Additionally, you can use :py:func:`file.accumulated\n        <salt.states.file.accumulated>` and target this state. All accumulated\n        data dictionaries\' content will be added in the content block.\n\n    name\n        Filesystem path to the file to be edited\n\n    marker_start\n        The line content identifying a line as the start of the content block.\n        Note that the whole line containing this marker will be considered, so\n        whitespace or extra content before or after the marker is included in\n        final output\n\n    marker_end\n        The line content identifying the end of the content block. As of\n        versions 2017.7.5 and 2018.3.1, everything up to the text matching the\n        marker will be replaced, so it\'s important to ensure that your marker\n        includes the beginning of the text you wish to replace.\n\n    content\n        The content to be used between the two lines identified by\n        ``marker_start`` and ``marker_end``\n\n    source\n        The source file to download to the minion, this source file can be\n        hosted on either the salt master server, or on an HTTP or FTP server.\n        Both HTTPS and HTTP are supported as well as downloading directly\n        from Amazon S3 compatible URLs with both pre-configured and automatic\n        IAM credentials. (see s3.get state documentation)\n        File retrieval from Openstack Swift object storage is supported via\n        swift://container/object_path URLs, see swift.get documentation.\n        For files hosted on the salt file server, if the file is located on\n        the master in the directory named spam, and is called eggs, the source\n        string is salt://spam/eggs. If source is left blank or None\n        (use ~ in YAML), the file will be created as an empty file and\n        the content will not be managed. This is also the case when a file\n        already exists and the source is undefined; the contents of the file\n        will not be changed or managed.\n\n        If the file is hosted on a HTTP or FTP server then the source_hash\n        argument is also required.\n\n        A list of sources can also be passed in to provide a default source and\n        a set of fallbacks. The first source in the list that is found to exist\n        will be used and subsequent entries in the list will be ignored.\n\n        .. code-block:: yaml\n\n            file_override_example:\n              file.blockreplace:\n                - name: /etc/example.conf\n                - source:\n                  - salt://file_that_does_not_exist\n                  - salt://file_that_exists\n\n    source_hash\n        This can be one of the following:\n            1. a source hash string\n            2. the URI of a file that contains source hash strings\n\n        The function accepts the first encountered long unbroken alphanumeric\n        string of correct length as a valid hash, in order from most secure to\n        least secure:\n\n        .. code-block:: text\n\n            Type    Length\n            ======  ======\n            sha512     128\n            sha384      96\n            sha256      64\n            sha224      56\n            sha1        40\n            md5         32\n\n        See the ``source_hash`` parameter description for :mod:`file.managed\n        <salt.states.file.managed>` function for more details and examples.\n\n    template\n        Templating engine to be used to render the downloaded file. The\n        following engines are supported:\n\n        - :mod:`cheetah <salt.renderers.cheetah>`\n        - :mod:`genshi <salt.renderers.genshi>`\n        - :mod:`jinja <salt.renderers.jinja>`\n        - :mod:`mako <salt.renderers.mako>`\n        - :mod:`py <salt.renderers.py>`\n        - :mod:`wempy <salt.renderers.wempy>`\n\n    context\n        Overrides default context variables passed to the template\n\n    defaults\n        Default context passed to the template\n\n    append_if_not_found\n        If markers are not found and this option is set to ``True``, the\n        content block will be appended to the file.\n\n    prepend_if_not_found\n        If markers are not found and this option is set to ``True``, the\n        content block will be prepended to the file.\n\n    insert_before_match\n        If markers are not found, this parameter can be set to a regex which will\n        insert the block before the first found occurrence in the file.\n\n        .. versionadded:: 3001\n\n    insert_after_match\n        If markers are not found, this parameter can be set to a regex which will\n        insert the block after the first found occurrence in the file.\n\n        .. versionadded:: 3001\n\n    backup\n        The file extension to use for a backup of the file if any edit is made.\n        Set this to ``False`` to skip making a backup.\n\n    dry_run\n        If ``True``, do not make any edits to the file and simply return the\n        changes that *would* be made.\n\n    show_changes\n        Controls how changes are presented. If ``True``, the ``Changes``\n        section of the state return will contain a unified diff of the changes\n        made. If False, then it will contain a boolean (``True`` if any changes\n        were made, otherwise ``False``).\n\n    append_newline\n        Controls whether or not a newline is appended to the content block. If\n        the value of this argument is ``True`` then a newline will be added to\n        the content block. If it is ``False``, then a newline will *not* be\n        added to the content block. If it is unspecified, then a newline will\n        only be added to the content block if it does not already end in a\n        newline.\n\n        .. versionadded:: 2017.7.5,2018.3.1\n\n    Example of usage with an accumulator and with a variable:\n\n    .. code-block:: jinja\n\n        {% set myvar = 42 %}\n        hosts-config-block-{{ myvar }}:\n          file.blockreplace:\n            - name: /etc/hosts\n            - marker_start: "# START managed zone {{ myvar }} -DO-NOT-EDIT-"\n            - marker_end: "# END managed zone {{ myvar }} --"\n            - content: \'First line of content\'\n            - append_if_not_found: True\n            - backup: \'.bak\'\n            - show_changes: True\n\n        hosts-config-block-{{ myvar }}-accumulated1:\n          file.accumulated:\n            - filename: /etc/hosts\n            - name: my-accumulator-{{ myvar }}\n            - text: "text 2"\n            - require_in:\n              - file: hosts-config-block-{{ myvar }}\n\n        hosts-config-block-{{ myvar }}-accumulated2:\n          file.accumulated:\n            - filename: /etc/hosts\n            - name: my-accumulator-{{ myvar }}\n            - text: |\n                 text 3\n                 text 4\n            - require_in:\n              - file: hosts-config-block-{{ myvar }}\n\n    will generate and maintain a block of content in ``/etc/hosts``:\n\n    .. code-block:: text\n\n        # START managed zone 42 -DO-NOT-EDIT-\n        First line of content\n        text 2\n        text 3\n        text 4\n        # END managed zone 42 --\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.blockreplace')
    if sources is None:
        sources = []
    if source_hashes is None:
        source_hashes = []
    (ok_, err, sl_) = _unify_sources_and_hashes(source=source, source_hash=source_hash, sources=sources, source_hashes=source_hashes)
    if not ok_:
        return _error(ret, err)
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        return _error(ret, check_msg)
    (accum_data, accum_deps) = _load_accumulators()
    if name in accum_data:
        accumulator = accum_data[name]
        deps = accum_deps.get(name, [])
        filtered = [a for a in deps if __low__['__id__'] in deps[a] and a in accumulator]
        if not filtered:
            filtered = [a for a in accumulator]
        for acc in filtered:
            acc_content = accumulator[acc]
            for line in acc_content:
                if content == '':
                    content = line
                else:
                    content += '\n' + line
    if sl_:
        tmpret = _get_template_texts(source_list=sl_, template=template, defaults=defaults, context=context)
        if not tmpret['result']:
            return tmpret
        text = tmpret['data']
        for (index, item) in enumerate(text):
            content += str(item)
    try:
        log.info('Trace')
        changes = __salt__['file.blockreplace'](name, marker_start, marker_end, content=content, append_if_not_found=append_if_not_found, prepend_if_not_found=prepend_if_not_found, insert_before_match=insert_before_match, insert_after_match=insert_after_match, backup=backup, dry_run=__opts__['test'], show_changes=show_changes, append_newline=append_newline)
    except Exception as exc:
        log.exception('Encountered error managing block')
        ret['comment'] = 'Encountered error managing block: {}. See the log for details.'.format(exc)
        return ret
    if changes:
        ret['changes']['diff'] = changes
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'Changes would be made'
        else:
            ret['result'] = True
            ret['comment'] = 'Changes were made'
    else:
        ret['result'] = True
        ret['comment'] = 'No changes needed to be made'
    return ret

def comment(name, regex, char='#', backup='.bak', ignore_missing=False):
    """
    .. versionadded:: 0.9.5
    .. versionchanged:: 3005

    Comment out specified lines in a file.

    name
        The full path to the file to be edited
    regex
        A regular expression used to find the lines that are to be commented;
        this pattern will be wrapped in parenthesis and will move any
        preceding/trailing ``^`` or ``$`` characters outside the parenthesis
        (e.g., the pattern ``^foo$`` will be rewritten as ``^(foo)$``)
        Note that you _need_ the leading ^, otherwise each time you run
        highstate, another comment char will be inserted.
    char
        The character to be inserted at the beginning of a line in order to
        comment it out
    backup
        The file will be backed up before edit with this file extension

        .. warning::

            This backup will be overwritten each time ``sed`` / ``comment`` /
            ``uncomment`` is called. Meaning the backup will only be useful
            after the first invocation.

        Set to False/None to not keep a backup.
    ignore_missing
        Ignore a failure to find the regex in the file. This is useful for
        scenarios where a line must only be commented if it is found in the
        file.

        .. versionadded:: 3005

    Usage:

    .. code-block:: yaml

        /etc/fstab:
          file.comment:
            - regex: ^bind 127.0.0.1

    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.comment')
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        return _error(ret, check_msg)
    unanchor_regex = re.sub('^(\\(\\?[iLmsux]\\))?\\^?(.*?)\\$?$', '\\2', regex)
    uncomment_regex = '^(?!\\s*{}).*'.format(char) + unanchor_regex
    comment_regex = char + unanchor_regex
    if not __salt__['file.search'](name, uncomment_regex, multiline=True):
        if __salt__['file.search'](name, comment_regex, multiline=True):
            ret['comment'] = 'Pattern already commented'
            ret['result'] = True
            return ret
        elif ignore_missing:
            ret['comment'] = 'Pattern not found and ignore_missing set to True'
            ret['result'] = True
            return ret
        else:
            return _error(ret, '{}: Pattern not found'.format(unanchor_regex))
    if __opts__['test']:
        ret['changes'][name] = 'updated'
        ret['comment'] = 'File {} is set to be updated'.format(name)
        ret['result'] = None
        return ret
    with salt.utils.files.fopen(name, 'rb') as fp_:
        slines = fp_.read()
        slines = slines.decode(__salt_system_encoding__)
        slines = slines.splitlines(True)
    __salt__['file.comment_line'](name, regex, char, True, backup)
    with salt.utils.files.fopen(name, 'rb') as fp_:
        nlines = fp_.read()
        nlines = nlines.decode(__salt_system_encoding__)
        nlines = nlines.splitlines(True)
    ret['result'] = __salt__['file.search'](name, comment_regex, multiline=True)
    if slines != nlines:
        if not __utils__['files.is_text'](name):
            ret['changes']['diff'] = 'Replace binary file'
        else:
            ret['changes']['diff'] = ''.join(difflib.unified_diff(slines, nlines))
    if ret['result']:
        ret['comment'] = 'Commented lines successfully'
    else:
        ret['comment'] = 'Expected commented lines not found'
    return ret

def uncomment(name, regex, char='#', backup='.bak'):
    """
    Uncomment specified commented lines in a file

    name
        The full path to the file to be edited
    regex
        A regular expression used to find the lines that are to be uncommented.
        This regex should not include the comment character. A leading ``^``
        character will be stripped for convenience (for easily switching
        between comment() and uncomment()).  The regex will be searched for
        from the beginning of the line, ignoring leading spaces (we prepend
        '^[ \\t]*')
    char
        The character to remove in order to uncomment a line
    backup
        The file will be backed up before edit with this file extension;

        .. warning::

            This backup will be overwritten each time ``sed`` / ``comment`` /
            ``uncomment`` is called. Meaning the backup will only be useful
            after the first invocation.

        Set to False/None to not keep a backup.

    Usage:

    .. code-block:: yaml

        /etc/adduser.conf:
          file.uncomment:
            - regex: EXTRA_GROUPS

    .. versionadded:: 0.9.5
    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.uncomment')
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        return _error(ret, check_msg)
    if __salt__['file.search'](name, '{}[ \t]*{}'.format(char, regex.lstrip('^')), multiline=True):
        pass
    elif __salt__['file.search'](name, '^[ \t]*{}'.format(regex.lstrip('^')), multiline=True):
        ret['comment'] = 'Pattern already uncommented'
        ret['result'] = True
        return ret
    else:
        return _error(ret, '{}: Pattern not found'.format(regex))
    if __opts__['test']:
        ret['changes'][name] = 'updated'
        ret['comment'] = 'File {} is set to be updated'.format(name)
        ret['result'] = None
        return ret
    with salt.utils.files.fopen(name, 'rb') as fp_:
        slines = salt.utils.data.decode(fp_.readlines())
    __salt__['file.comment_line'](name, regex, char, False, backup)
    with salt.utils.files.fopen(name, 'rb') as fp_:
        nlines = salt.utils.data.decode(fp_.readlines())
    ret['result'] = __salt__['file.search'](name, '^[ \t]*{}'.format(regex.lstrip('^')), multiline=True)
    if slines != nlines:
        if not __utils__['files.is_text'](name):
            ret['changes']['diff'] = 'Replace binary file'
        else:
            ret['changes']['diff'] = ''.join(difflib.unified_diff(slines, nlines))
    if ret['result']:
        ret['comment'] = 'Uncommented lines successfully'
    else:
        ret['comment'] = 'Expected uncommented lines not found'
    return ret

def append(name, text=None, makedirs=False, source=None, source_hash=None, template='jinja', sources=None, source_hashes=None, defaults=None, context=None, ignore_whitespace=True):
    log.info('Trace')
    '\n    Ensure that some text appears at the end of a file.\n\n    The text will not be appended if it already exists in the file.\n    A single string of text or a list of strings may be appended.\n\n    name\n        The location of the file to append to.\n\n    text\n        The text to be appended, which can be a single string or a list\n        of strings.\n\n    makedirs\n        If the file is located in a path without a parent directory,\n        then the state will fail. If makedirs is set to True, then\n        the parent directories will be created to facilitate the\n        creation of the named file. Defaults to False.\n\n    source\n        A single source file to append. This source file can be hosted on either\n        the salt master server, or on an HTTP or FTP server. Both HTTPS and\n        HTTP are supported as well as downloading directly from Amazon S3\n        compatible URLs with both pre-configured and automatic IAM credentials\n        (see s3.get state documentation). File retrieval from Openstack Swift\n        object storage is supported via swift://container/object_path URLs\n        (see swift.get documentation).\n\n        For files hosted on the salt file server, if the file is located on\n        the master in the directory named spam, and is called eggs, the source\n        string is salt://spam/eggs.\n\n        If the file is hosted on an HTTP or FTP server, the source_hash argument\n        is also required.\n\n    source_hash\n        This can be one of the following:\n            1. a source hash string\n            2. the URI of a file that contains source hash strings\n\n        The function accepts the first encountered long unbroken alphanumeric\n        string of correct length as a valid hash, in order from most secure to\n        least secure:\n\n        .. code-block:: text\n\n            Type    Length\n            ======  ======\n            sha512     128\n            sha384      96\n            sha256      64\n            sha224      56\n            sha1        40\n            md5         32\n\n        See the ``source_hash`` parameter description for :mod:`file.managed\n        <salt.states.file.managed>` function for more details and examples.\n\n    template\n        The named templating engine will be used to render the appended-to file.\n        Defaults to ``jinja``. The following templates are supported:\n\n        - :mod:`cheetah<salt.renderers.cheetah>`\n        - :mod:`genshi<salt.renderers.genshi>`\n        - :mod:`jinja<salt.renderers.jinja>`\n        - :mod:`mako<salt.renderers.mako>`\n        - :mod:`py<salt.renderers.py>`\n        - :mod:`wempy<salt.renderers.wempy>`\n\n    sources\n        A list of source files to append. If the files are hosted on an HTTP or\n        FTP server, the source_hashes argument is also required.\n\n    source_hashes\n        A list of source_hashes corresponding to the sources list specified in\n        the sources argument.\n\n    defaults\n        Default context passed to the template.\n\n    context\n        Overrides default context variables passed to the template.\n\n    ignore_whitespace\n        .. versionadded:: 2015.8.4\n\n        Spaces and Tabs in text are ignored by default, when searching for the\n        appending content, one space or multiple tabs are the same for salt.\n        Set this option to ``False`` if you want to change this behavior.\n\n    Multi-line example:\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file.append:\n            - text: |\n                Thou hadst better eat salt with the Philosophers of Greece,\n                than sugar with the Courtiers of Italy.\n                - Benjamin Franklin\n\n    Multiple lines of text:\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file.append:\n            - text:\n              - Trust no one unless you have eaten much salt with him.\n              - "Salt is born of the purest of parents: the sun and the sea."\n\n    Gather text from multiple template files:\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file:\n            - append\n            - template: jinja\n            - sources:\n              - salt://motd/devops-messages.tmpl\n              - salt://motd/hr-messages.tmpl\n              - salt://motd/general-messages.tmpl\n\n    .. versionadded:: 0.9.5\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.append')
    name = os.path.expanduser(name)
    if sources is None:
        sources = []
    if source_hashes is None:
        source_hashes = []
    (ok_, err, sl_) = _unify_sources_and_hashes(source=source, source_hash=source_hash, sources=sources, source_hashes=source_hashes)
    if not ok_:
        return _error(ret, err)
    if makedirs is True:
        dirname = os.path.dirname(name)
        if __opts__['test']:
            ret['comment'] = 'Directory {} is set to be updated'.format(dirname)
            ret['result'] = None
        elif not __salt__['file.directory_exists'](dirname):
            try:
                log.info('Trace')
                _makedirs(name=name)
            except CommandExecutionError as exc:
                log.info('Trace')
                return _error(ret, 'Drive {} is not mapped'.format(exc.message))
            (check_res, check_msg, check_changes) = _check_directory_win(dirname) if salt.utils.platform.is_windows() else _check_directory(dirname)
            if not check_res:
                ret['changes'] = check_changes
                return _error(ret, check_msg)
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        touch_ret = touch(name, makedirs=makedirs)
        if __opts__['test']:
            return touch_ret
        (retry_res, retry_msg) = _check_file(name)
        if not retry_res:
            return _error(ret, check_msg)
    if sl_:
        tmpret = _get_template_texts(source_list=sl_, template=template, defaults=defaults, context=context)
        if not tmpret['result']:
            return tmpret
        text = tmpret['data']
    text = _validate_str_list(text)
    with salt.utils.files.fopen(name, 'rb') as fp_:
        slines = fp_.read()
        slines = slines.decode(__salt_system_encoding__)
        slines = slines.splitlines()
    append_lines = []
    try:
        log.info('Trace')
        for chunk in text:
            if ignore_whitespace:
                if __salt__['file.search'](name, salt.utils.stringutils.build_whitespace_split_regex(chunk), multiline=True):
                    continue
            elif __salt__['file.search'](name, chunk, multiline=True):
                continue
            for line_item in chunk.splitlines():
                append_lines.append('{}'.format(line_item))
    except TypeError:
        log.info('Trace')
        return _error(ret, 'No text found to append. Nothing appended')
    if __opts__['test']:
        ret['comment'] = 'File {} is set to be updated'.format(name)
        ret['result'] = None
        nlines = list(slines)
        nlines.extend(append_lines)
        if slines != nlines:
            if not __utils__['files.is_text'](name):
                ret['changes']['diff'] = 'Replace binary file'
            else:
                ret['changes']['diff'] = '\n'.join(difflib.unified_diff(slines, nlines))
        else:
            ret['comment'] = 'File {} is in correct state'.format(name)
            ret['result'] = True
        return ret
    if append_lines:
        __salt__['file.append'](name, args=append_lines)
        ret['comment'] = 'Appended {} lines'.format(len(append_lines))
    else:
        ret['comment'] = 'File {} is in correct state'.format(name)
    with salt.utils.files.fopen(name, 'rb') as fp_:
        nlines = fp_.read()
        nlines = nlines.decode(__salt_system_encoding__)
        nlines = nlines.splitlines()
    if slines != nlines:
        if not __utils__['files.is_text'](name):
            ret['changes']['diff'] = 'Replace binary file'
        else:
            ret['changes']['diff'] = '\n'.join(difflib.unified_diff(slines, nlines))
    ret['result'] = True
    return ret

def prepend(name, text=None, makedirs=False, source=None, source_hash=None, template='jinja', sources=None, source_hashes=None, defaults=None, context=None, header=None):
    log.info('Trace')
    '\n    Ensure that some text appears at the beginning of a file\n\n    The text will not be prepended again if it already exists in the file. You\n    may specify a single line of text or a list of lines to append.\n\n    name\n        The location of the file to append to.\n\n    text\n        The text to be appended, which can be a single string or a list\n        of strings.\n\n    makedirs\n        If the file is located in a path without a parent directory,\n        then the state will fail. If makedirs is set to True, then\n        the parent directories will be created to facilitate the\n        creation of the named file. Defaults to False.\n\n    source\n        A single source file to append. This source file can be hosted on either\n        the salt master server, or on an HTTP or FTP server. Both HTTPS and\n        HTTP are supported as well as downloading directly from Amazon S3\n        compatible URLs with both pre-configured and automatic IAM credentials\n        (see s3.get state documentation). File retrieval from Openstack Swift\n        object storage is supported via swift://container/object_path URLs\n        (see swift.get documentation).\n\n        For files hosted on the salt file server, if the file is located on\n        the master in the directory named spam, and is called eggs, the source\n        string is salt://spam/eggs.\n\n        If the file is hosted on an HTTP or FTP server, the source_hash argument\n        is also required.\n\n    source_hash\n        This can be one of the following:\n            1. a source hash string\n            2. the URI of a file that contains source hash strings\n\n        The function accepts the first encountered long unbroken alphanumeric\n        string of correct length as a valid hash, in order from most secure to\n        least secure:\n\n        .. code-block:: text\n\n            Type    Length\n            ======  ======\n            sha512     128\n            sha384      96\n            sha256      64\n            sha224      56\n            sha1        40\n            md5         32\n\n        See the ``source_hash`` parameter description for :mod:`file.managed\n        <salt.states.file.managed>` function for more details and examples.\n\n    template\n        The named templating engine will be used to render the appended-to file.\n        Defaults to ``jinja``. The following templates are supported:\n\n        - :mod:`cheetah<salt.renderers.cheetah>`\n        - :mod:`genshi<salt.renderers.genshi>`\n        - :mod:`jinja<salt.renderers.jinja>`\n        - :mod:`mako<salt.renderers.mako>`\n        - :mod:`py<salt.renderers.py>`\n        - :mod:`wempy<salt.renderers.wempy>`\n\n    sources\n        A list of source files to append. If the files are hosted on an HTTP or\n        FTP server, the source_hashes argument is also required.\n\n    source_hashes\n        A list of source_hashes corresponding to the sources list specified in\n        the sources argument.\n\n    defaults\n        Default context passed to the template.\n\n    context\n        Overrides default context variables passed to the template.\n\n    ignore_whitespace\n        .. versionadded:: 2015.8.4\n\n        Spaces and Tabs in text are ignored by default, when searching for the\n        appending content, one space or multiple tabs are the same for salt.\n        Set this option to ``False`` if you want to change this behavior.\n\n    Multi-line example:\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file.prepend:\n            - text: |\n                Thou hadst better eat salt with the Philosophers of Greece,\n                than sugar with the Courtiers of Italy.\n                - Benjamin Franklin\n\n    Multiple lines of text:\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file.prepend:\n            - text:\n              - Trust no one unless you have eaten much salt with him.\n              - "Salt is born of the purest of parents: the sun and the sea."\n\n    Optionally, require the text to appear exactly as specified\n    (order and position). Combine with multi-line or multiple lines of input.\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file.prepend:\n            - header: True\n            - text:\n              - This will be the very first line in the file.\n              - The 2nd line, regardless of duplicates elsewhere in the file.\n              - These will be written anew if they do not appear verbatim.\n\n    Gather text from multiple template files:\n\n    .. code-block:: yaml\n\n        /etc/motd:\n          file:\n            - prepend\n            - template: jinja\n            - sources:\n              - salt://motd/devops-messages.tmpl\n              - salt://motd/hr-messages.tmpl\n              - salt://motd/general-messages.tmpl\n\n    .. versionadded:: 2014.7.0\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.prepend')
    if sources is None:
        sources = []
    if source_hashes is None:
        source_hashes = []
    (ok_, err, sl_) = _unify_sources_and_hashes(source=source, source_hash=source_hash, sources=sources, source_hashes=source_hashes)
    if not ok_:
        return _error(ret, err)
    if makedirs is True:
        dirname = os.path.dirname(name)
        if __opts__['test']:
            ret['comment'] = 'Directory {} is set to be updated'.format(dirname)
            ret['result'] = None
        elif not __salt__['file.directory_exists'](dirname):
            try:
                log.info('Trace')
                _makedirs(name=name)
            except CommandExecutionError as exc:
                log.info('Trace')
                return _error(ret, 'Drive {} is not mapped'.format(exc.message))
            (check_res, check_msg, check_changes) = _check_directory_win(dirname) if salt.utils.platform.is_windows() else _check_directory(dirname)
            if not check_res:
                ret['changes'] = check_changes
                return _error(ret, check_msg)
    (check_res, check_msg) = _check_file(name)
    if not check_res:
        touch_ret = touch(name, makedirs=makedirs)
        if __opts__['test']:
            return touch_ret
        (retry_res, retry_msg) = _check_file(name)
        if not retry_res:
            return _error(ret, check_msg)
    if sl_:
        tmpret = _get_template_texts(source_list=sl_, template=template, defaults=defaults, context=context)
        if not tmpret['result']:
            return tmpret
        text = tmpret['data']
    text = _validate_str_list(text)
    with salt.utils.files.fopen(name, 'rb') as fp_:
        slines = fp_.read()
        slines = slines.decode(__salt_system_encoding__)
        slines = slines.splitlines(True)
    count = 0
    test_lines = []
    preface = []
    for chunk in text:
        if not header:
            if __salt__['file.search'](name, salt.utils.stringutils.build_whitespace_split_regex(chunk), multiline=True):
                continue
        lines = chunk.splitlines()
        for line in lines:
            if __opts__['test']:
                ret['comment'] = 'File {} is set to be updated'.format(name)
                ret['result'] = None
                test_lines.append('{}\n'.format(line))
            else:
                preface.append(line)
            count += 1
    if __opts__['test']:
        nlines = test_lines + slines
        if slines != nlines:
            if not __utils__['files.is_text'](name):
                ret['changes']['diff'] = 'Replace binary file'
            else:
                ret['changes']['diff'] = ''.join(difflib.unified_diff(slines, nlines))
            ret['result'] = None
        else:
            ret['comment'] = 'File {} is in correct state'.format(name)
            ret['result'] = True
        return ret
    if header:
        with salt.utils.files.fopen(name, 'rb') as fp_:
            contents = fp_.read()
            contents = contents.decode(__salt_system_encoding__)
            contents = contents.splitlines(True)
            target_head = contents[0:len(preface)]
            target_lines = []
            for chunk in target_head:
                target_lines += chunk.splitlines()
            if target_lines != preface:
                __salt__['file.prepend'](name, *preface)
            else:
                count = 0
    else:
        __salt__['file.prepend'](name, *preface)
    with salt.utils.files.fopen(name, 'rb') as fp_:
        nlines = fp_.read()
        nlines = nlines.decode(__salt_system_encoding__)
        nlines = nlines.splitlines(True)
    if slines != nlines:
        if not __utils__['files.is_text'](name):
            ret['changes']['diff'] = 'Replace binary file'
        else:
            ret['changes']['diff'] = ''.join(difflib.unified_diff(slines, nlines))
    if count:
        ret['comment'] = 'Prepended {} lines'.format(count)
    else:
        ret['comment'] = 'File {} is in correct state'.format(name)
    ret['result'] = True
    return ret

def patch(name, source=None, source_hash=None, source_hash_name=None, skip_verify=False, template=None, context=None, defaults=None, options='', reject_file=None, strip=None, saltenv=None, **kwargs):
    log.info('Trace')
    '\n    Ensure that a patch has been applied to the specified file or directory\n\n    .. versionchanged:: 2019.2.0\n        The ``hash`` and ``dry_run_first`` options are now ignored, as the\n        logic which determines whether or not the patch has already been\n        applied no longer requires them. Additionally, this state now supports\n        patch files that modify more than one file. To use these sort of\n        patches, specify a directory (and, if necessary, the ``strip`` option)\n        instead of a file.\n\n    .. note::\n        A suitable ``patch`` executable must be available on the minion. Also,\n        keep in mind that the pre-check this state does to determine whether or\n        not changes need to be made will create a temp file and send all patch\n        output to that file. This means that, in the event that the patch would\n        not have applied cleanly, the comment included in the state results will\n        reference a temp file that will no longer exist once the state finishes\n        running.\n\n    name\n        The file or directory to which the patch should be applied\n\n    source\n        The patch file to apply\n\n        .. versionchanged:: 2019.2.0\n            The source can now be from any file source supported by Salt\n            (``salt://``, ``http://``, ``https://``, ``ftp://``, etc.).\n            Templating is also now supported.\n\n    source_hash\n        Works the same way as in :py:func:`file.managed\n        <salt.states.file.managed>`.\n\n        .. versionadded:: 2019.2.0\n\n    source_hash_name\n        Works the same way as in :py:func:`file.managed\n        <salt.states.file.managed>`\n\n        .. versionadded:: 2019.2.0\n\n    skip_verify\n        Works the same way as in :py:func:`file.managed\n        <salt.states.file.managed>`\n\n        .. versionadded:: 2019.2.0\n\n    template\n        Works the same way as in :py:func:`file.managed\n        <salt.states.file.managed>`\n\n        .. versionadded:: 2019.2.0\n\n    context\n        Works the same way as in :py:func:`file.managed\n        <salt.states.file.managed>`\n\n        .. versionadded:: 2019.2.0\n\n    defaults\n        Works the same way as in :py:func:`file.managed\n        <salt.states.file.managed>`\n\n        .. versionadded:: 2019.2.0\n\n    options\n        Extra options to pass to patch. This should not be necessary in most\n        cases.\n\n        .. note::\n            For best results, short opts should be separate from one another.\n            The ``-N`` and ``-r``, and ``-o`` options are used internally by\n            this state and cannot be used here. Additionally, instead of using\n            ``-pN`` or ``--strip=N``, use the ``strip`` option documented\n            below.\n\n    reject_file\n        If specified, any rejected hunks will be written to this file. If not\n        specified, then they will be written to a temp file which will be\n        deleted when the state finishes running.\n\n        .. important::\n            The parent directory must exist. Also, this will overwrite the file\n            if it is already present.\n\n        .. versionadded:: 2019.2.0\n\n    strip\n        Number of directories to strip from paths in the patch file. For\n        example, using the below SLS would instruct Salt to use ``-p1`` when\n        applying the patch:\n\n        .. code-block:: yaml\n\n            /etc/myfile.conf:\n              file.patch:\n                - source: salt://myfile.patch\n                - strip: 1\n\n        .. versionadded:: 2019.2.0\n            In previous versions, ``-p1`` would need to be passed as part of\n            the ``options`` value.\n\n    saltenv\n        Specify the environment from which to retrieve the patch file indicated\n        by the ``source`` parameter. If not provided, this defaults to the\n        environment from which the state is being executed.\n\n        .. note::\n            Ignored when the patch file is from a non-``salt://`` source.\n\n    **Usage:**\n\n    .. code-block:: yaml\n\n        # Equivalent to ``patch --forward /opt/myfile.txt myfile.patch``\n        /opt/myfile.txt:\n          file.patch:\n            - source: salt://myfile.patch\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not salt.utils.path.which('patch'):
        ret['comment'] = 'patch executable not found on minion'
        return ret
    is_dir = False
    if not name:
        ret['comment'] = 'A file/directory to be patched is required'
        return ret
    else:
        try:
            log.info('Trace')
            name = os.path.expanduser(name)
        except Exception:
            log.info('Trace')
            ret['comment'] = "Invalid path '{}'".format(name)
            return ret
        else:
            if not os.path.isabs(name):
                ret['comment'] = '{} is not an absolute path'.format(name)
                return ret
            elif not os.path.exists(name):
                ret['comment'] = '{} does not exist'.format(name)
                return ret
            else:
                is_dir = os.path.isdir(name)
    for deprecated_arg in ('hash', 'dry_run_first'):
        if deprecated_arg in kwargs:
            ret.setdefault('warnings', []).append("The '{}' argument is no longer used and has been ignored.".format(deprecated_arg))
    if reject_file is not None:
        try:
            log.info('Trace')
            reject_file_parent = os.path.dirname(reject_file)
        except Exception:
            log.info('Trace')
            ret['comment'] = "Invalid path '{}' for reject_file".format(reject_file)
            return ret
        else:
            if not os.path.isabs(reject_file_parent):
                ret['comment'] = "'{}' is not an absolute path".format(reject_file)
                return ret
            elif not os.path.isdir(reject_file_parent):
                ret['comment'] = "Parent directory for reject_file '{}' either does not exist, or is not a directory".format(reject_file)
                return ret
    sanitized_options = []
    options = salt.utils.args.shlex_split(options)
    index = 0
    max_index = len(options) - 1
    blacklisted_options = []
    while index <= max_index:
        option = options[index]
        if not isinstance(option, str):
            option = str(option)
        for item in ('-N', '--forward', '-r', '--reject-file', '-o', '--output'):
            if option.startswith(item):
                blacklisted = option
                break
        else:
            blacklisted = None
        if blacklisted is not None:
            blacklisted_options.append(blacklisted)
        if option.startswith('-p'):
            try:
                log.info('Trace')
                strip = int(option[2:])
            except Exception:
                log.info('Trace')
                ret['comment'] = "Invalid format for '-p' CLI option. Consider using the 'strip' option for this state."
                return ret
        elif option.startswith('--strip'):
            if '=' in option:
                try:
                    log.info('Trace')
                    strip = int(option.rsplit('=', 1)[-1])
                except Exception:
                    log.info('Trace')
                    ret['comment'] = "Invalid format for '-strip' CLI option. Consider using the 'strip' option for this state."
                    return ret
            else:
                try:
                    log.info('Trace')
                    strip = int(options[index + 1])
                except Exception:
                    log.info('Trace')
                    ret['comment'] = "Invalid format for '-strip' CLI option. Consider using the 'strip' option for this state."
                    return ret
                else:
                    index += 1
        else:
            sanitized_options.append(option)
        index += 1
    if blacklisted_options:
        ret['comment'] = 'The following CLI options are not allowed: {}'.format(', '.join(blacklisted_options))
        return ret
    options = sanitized_options
    try:
        log.info('Trace')
        source_match = __salt__['file.source_list'](source, source_hash, __env__)[0]
    except CommandExecutionError as exc:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = exc.strerror
        return ret
    else:
        if saltenv is not None:
            (source_match_url, source_match_saltenv) = salt.utils.url.parse(source_match)
            if source_match_url.startswith('salt://'):
                if source_match_saltenv is not None and source_match_saltenv != saltenv:
                    ret.setdefault('warnings', []).append("Ignoring 'saltenv' option in favor of saltenv included in the source URL.")
                else:
                    source_match += '?saltenv={}'.format(saltenv)
    cleanup = []
    try:
        patch_file = salt.utils.files.mkstemp()
        cleanup.append(patch_file)
        try:
            orig_test = __opts__['test']
            __opts__['test'] = False
            sys.modules[__salt__['file.patch'].__module__].__opts__['test'] = False
            result = managed(patch_file, source=source_match, source_hash=source_hash, source_hash_name=source_hash_name, skip_verify=skip_verify, template=template, context=context, defaults=defaults)
        except Exception as exc:
            msg = 'Failed to cache patch file {}: {}'.format(salt.utils.url.redact_http_basic_auth(source_match), exc)
            log.exception(msg)
            ret['comment'] = msg
            return ret
        else:
            log.debug('file.managed: %s', result)
        finally:
            __opts__['test'] = orig_test
            sys.modules[__salt__['file.patch'].__module__].__opts__['test'] = orig_test
        if not orig_test and (not result['result']):
            log.debug('failed to download %s', salt.utils.url.redact_http_basic_auth(source_match))
            return result

        def _patch(patch_file, options=None, dry_run=False):
            patch_opts = copy.copy(sanitized_options)
            if options is not None:
                patch_opts.extend(options)
            return __salt__['file.patch'](name, patch_file, options=patch_opts, dry_run=dry_run)
        if reject_file is not None:
            patch_rejects = reject_file
        else:
            patch_rejects = salt.utils.files.mkstemp()
            cleanup.append(patch_rejects)
        patch_output = salt.utils.files.mkstemp()
        cleanup.append(patch_output)
        patch_opts = ['-N', '-r', patch_rejects, '-o', patch_output]
        if is_dir and strip is not None:
            patch_opts.append('-p{}'.format(strip))
        pre_check = _patch(patch_file, patch_opts)
        if pre_check['retcode'] != 0:
            reverse_pass = _patch(patch_rejects, ['-R', '-f'], dry_run=True)
            already_applied = reverse_pass['retcode'] == 0
            if pre_check['retcode'] == 2 and pre_check['stderr']:
                ret['comment'] = pre_check['stderr']
                ret['result'] = False
                return ret
            if already_applied:
                ret['comment'] = 'Patch was already applied'
                ret['result'] = True
                return ret
            else:
                ret['comment'] = 'Patch would not apply cleanly, no changes made. Results of dry-run are below.'
                if reject_file is None:
                    ret['comment'] += ' Run state again using the reject_file option to save rejects to a persistent file.'
                opts = copy.copy(__opts__)
                opts['color'] = False
                ret['comment'] += '\n\n' + salt.output.out_format(pre_check, 'nested', opts, nested_indent=14)
                return ret
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'The patch would be applied'
            ret['changes'] = pre_check
            return ret
        patch_opts = []
        if is_dir and strip is not None:
            patch_opts.append('-p{}'.format(strip))
        ret['changes'] = _patch(patch_file, patch_opts)
        if ret['changes']['retcode'] == 0:
            ret['comment'] = 'Patch successfully applied'
            ret['result'] = True
        else:
            ret['comment'] = 'Failed to apply patch'
        return ret
    finally:
        for path in cleanup:
            try:
                log.info('Trace')
                os.remove(path)
            except OSError as exc:
                if exc.errno != os.errno.ENOENT:
                    log.error('file.patch: Failed to remove temp file %s: %s', path, exc)

def touch(name, atime=None, mtime=None, makedirs=False):
    log.info('Trace')
    '\n    Replicate the \'nix "touch" command to create a new empty\n    file or update the atime and mtime of an existing file.\n\n    Note that if you just want to create a file and don\'t care about atime or\n    mtime, you should use ``file.managed`` instead, as it is more\n    feature-complete.  (Just leave out the ``source``/``template``/``contents``\n    arguments, and it will just create the file and/or check its permissions,\n    without messing with contents)\n\n    name\n        name of the file\n\n    atime\n        atime of the file\n\n    mtime\n        mtime of the file\n\n    makedirs\n        whether we should create the parent directory/directories in order to\n        touch the file\n\n    Usage:\n\n    .. code-block:: yaml\n\n        /var/log/httpd/logrotate.empty:\n          file.touch\n\n    .. versionadded:: 0.9.5\n    '
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}}
    if not name:
        return _error(ret, 'Must provide name to file.touch')
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if __opts__['test']:
        ret.update(_check_touch(name, atime, mtime))
        return ret
    if makedirs:
        try:
            log.info('Trace')
            _makedirs(name=name)
        except CommandExecutionError as exc:
            log.info('Trace')
            return _error(ret, 'Drive {} is not mapped'.format(exc.message))
    if not os.path.isdir(os.path.dirname(name)):
        return _error(ret, 'Directory not present to touch file {}'.format(name))
    extant = os.path.exists(name)
    ret['result'] = __salt__['file.touch'](name, atime, mtime)
    if not extant and ret['result']:
        ret['comment'] = 'Created empty file {}'.format(name)
        ret['changes']['new'] = name
    elif extant and ret['result']:
        ret['comment'] = 'Updated times on {} {}'.format('directory' if os.path.isdir(name) else 'file', name)
        ret['changes']['touched'] = name
    return ret

def copy_(name, source, force=False, makedirs=False, preserve=False, user=None, group=None, mode=None, subdir=False, **kwargs):
    log.info('Trace')
    '\n    If the file defined by the ``source`` option exists on the minion, copy it\n    to the named path. The file will not be overwritten if it already exists,\n    unless the ``force`` option is set to ``True``.\n\n    .. note::\n        This state only copies files from one location on a minion to another\n        location on the same minion. For copying files from the master, use a\n        :py:func:`file.managed <salt.states.file.managed>` state.\n\n    name\n        The location of the file to copy to\n\n    source\n        The location of the file to copy to the location specified with name\n\n    force\n        If the target location is present then the file will not be moved,\n        specify "force: True" to overwrite the target file\n\n    makedirs\n        If the target subdirectories don\'t exist create them\n\n    preserve\n        .. versionadded:: 2015.5.0\n\n        Set ``preserve: True`` to preserve user/group ownership and mode\n        after copying. Default is ``False``. If ``preserve`` is set to ``True``,\n        then user/group/mode attributes will be ignored.\n\n    user\n        .. versionadded:: 2015.5.0\n\n        The user to own the copied file, this defaults to the user salt is\n        running as on the minion. If ``preserve`` is set to ``True``, then\n        this will be ignored\n\n    group\n        .. versionadded:: 2015.5.0\n\n        The group to own the copied file, this defaults to the group salt is\n        running as on the minion. If ``preserve`` is set to ``True`` or on\n        Windows this will be ignored\n\n    mode\n        .. versionadded:: 2015.5.0\n\n        The permissions to set on the copied file, aka 644, \'0775\', \'4664\'.\n        If ``preserve`` is set to ``True``, then this will be ignored.\n        Not supported on Windows.\n\n        The default mode for new files and directories corresponds umask of salt\n        process. For existing files and directories it\'s not enforced.\n\n    subdir\n        .. versionadded:: 2015.5.0\n\n        If the name is a directory then place the file inside the named\n        directory\n\n    .. note::\n        The copy function accepts paths that are local to the Salt minion.\n        This function does not support salt://, http://, or the other\n        additional file paths that are supported by :mod:`states.file.managed\n        <salt.states.file.managed>` and :mod:`states.file.recurse\n        <salt.states.file.recurse>`.\n\n    Usage:\n\n    .. code-block:: yaml\n\n        # Use \'copy\', not \'copy_\'\n        /etc/example.conf:\n          file.copy:\n            - source: /tmp/example.conf\n    '
    name = os.path.expanduser(name)
    source = os.path.expanduser(source)
    ret = {'name': name, 'changes': {}, 'comment': 'Copied "{}" to "{}"'.format(source, name), 'result': True}
    if not name:
        return _error(ret, 'Must provide name to file.copy')
    changed = True
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if not os.path.exists(source):
        return _error(ret, 'Source file "{}" is not present'.format(source))
    if preserve:
        user = __salt__['file.get_user'](source)
        group = __salt__['file.get_group'](source)
        mode = __salt__['file.get_mode'](source)
    else:
        user = _test_owner(kwargs, user=user)
        if user is None:
            user = __opts__['user']
        if salt.utils.platform.is_windows():
            if group is not None:
                log.warning('The group argument for %s has been ignored as this is a Windows system.', name)
            group = user
        if group is None:
            if 'user.info' in __salt__:
                group = __salt__['file.gid_to_group'](__salt__['user.info'](user).get('gid', 0))
            else:
                group = user
        u_check = _check_user(user, group)
        if u_check:
            return _error(ret, u_check)
        if mode is None:
            mode = __salt__['file.get_mode'](source)
    if os.path.isdir(name) and subdir:
        name = os.path.join(name, os.path.basename(source))
    if os.path.lexists(source) and os.path.lexists(name):
        if force and os.path.isfile(name):
            hash1 = salt.utils.hashutils.get_hash(name)
            hash2 = salt.utils.hashutils.get_hash(source)
            if hash1 == hash2:
                changed = True
                ret['comment'] = ' '.join([ret['comment'], '- files are identical but force flag is set'])
        if not force:
            changed = False
        elif not __opts__['test'] and changed:
            try:
                log.info('Trace')
                __salt__['file.remove'](name)
            except OSError:
                log.info('Trace')
                return _error(ret, 'Failed to delete "{}" in preparation for forced move'.format(name))
    if __opts__['test']:
        if changed:
            ret['comment'] = 'File "{}" is set to be copied to "{}"'.format(source, name)
            ret['result'] = None
        else:
            ret['comment'] = 'The target file "{}" exists and will not be overwritten'.format(name)
            ret['result'] = True
        return ret
    if not changed:
        ret['comment'] = 'The target file "{}" exists and will not be overwritten'.format(name)
        ret['result'] = True
        return ret
    dname = os.path.dirname(name)
    if not os.path.isdir(dname):
        if makedirs:
            try:
                log.info('Trace')
                _makedirs(name=name, user=user, group=group, dir_mode=mode)
            except CommandExecutionError as exc:
                log.info('Trace')
                return _error(ret, 'Drive {} is not mapped'.format(exc.message))
        else:
            return _error(ret, 'The target directory {} is not present'.format(dname))
    try:
        log.info('Trace')
        if os.path.isdir(source):
            shutil.copytree(source, name, symlinks=True)
            for (root, dirs, files) in salt.utils.path.os_walk(name):
                for dir_ in dirs:
                    __salt__['file.lchown'](os.path.join(root, dir_), user, group)
                for file_ in files:
                    __salt__['file.lchown'](os.path.join(root, file_), user, group)
        else:
            shutil.copy(source, name)
        ret['changes'] = {name: source}
        if not preserve:
            if salt.utils.platform.is_windows():
                check_ret = __salt__['file.check_perms'](path=name, ret=ret, owner=user)
            else:
                (check_ret, perms) = __salt__['file.check_perms'](name, ret, user, group, mode)
            if not check_ret['result']:
                ret['result'] = check_ret['result']
                ret['comment'] = check_ret['comment']
    except OSError:
        log.info('Trace')
        return _error(ret, 'Failed to copy "{}" to "{}"'.format(source, name))
    return ret

def rename(name, source, force=False, makedirs=False, **kwargs):
    log.info('Trace')
    '\n    If the source file exists on the system, rename it to the named file. The\n    named file will not be overwritten if it already exists unless the force\n    option is set to True.\n\n    name\n        The location of the file to rename to\n\n    source\n        The location of the file to move to the location specified with name\n\n    force\n        If the target location is present then the file will not be moved,\n        specify "force: True" to overwrite the target file\n\n    makedirs\n        If the target subdirectories don\'t exist create them\n\n    '
    name = os.path.expanduser(name)
    name = os.path.expandvars(name)
    source = os.path.expanduser(source)
    source = os.path.expandvars(source)
    ret = {'name': name, 'changes': {}, 'comment': '', 'result': True}
    if not name:
        return _error(ret, 'Must provide name to file.rename')
    if not os.path.isabs(name):
        return _error(ret, 'Specified file {} is not an absolute path'.format(name))
    if not os.path.lexists(source):
        ret['comment'] = 'Source file "{}" has already been moved out of place'.format(source)
        return ret
    if os.path.lexists(source) and os.path.lexists(name):
        if not force:
            ret['comment'] = 'The target file "{}" exists and will not be overwritten'.format(name)
            return ret
        elif not __opts__['test']:
            try:
                log.info('Trace')
                __salt__['file.remove'](name)
            except OSError:
                log.info('Trace')
                return _error(ret, 'Failed to delete "{}" in preparation for forced move'.format(name))
    if __opts__['test']:
        ret['comment'] = 'File "{}" is set to be moved to "{}"'.format(source, name)
        ret['result'] = None
        return ret
    dname = os.path.dirname(name)
    if not os.path.isdir(dname):
        if makedirs:
            try:
                log.info('Trace')
                _makedirs(name=name)
            except CommandExecutionError as exc:
                log.info('Trace')
                return _error(ret, 'Drive {} is not mapped'.format(exc.message))
        else:
            return _error(ret, 'The target directory {} is not present'.format(dname))
    try:
        log.info('Trace')
        if os.path.islink(source):
            linkto = salt.utils.path.readlink(source)
            os.symlink(linkto, name)
            os.unlink(source)
        else:
            shutil.move(source, name)
    except OSError:
        log.info('Trace')
        return _error(ret, 'Failed to move "{}" to "{}"'.format(source, name))
    ret['comment'] = 'Moved "{}" to "{}"'.format(source, name)
    ret['changes'] = {name: source}
    return ret

def accumulated(name, filename, text, **kwargs):
    """
    Prepare accumulator which can be used in template in file.managed state.
    Accumulator dictionary becomes available in template. It can also be used
    in file.blockreplace.

    name
        Accumulator name

    filename
        Filename which would receive this accumulator (see file.managed state
        documentation about ``name``)

    text
        String or list for adding in accumulator

    require_in / watch_in
        One of them required for sure we fill up accumulator before we manage
        the file. Probably the same as filename

    Example:

    Given the following:

    .. code-block:: yaml

        animals_doing_things:
          file.accumulated:
            - filename: /tmp/animal_file.txt
            - text: ' jumps over the lazy dog.'
            - require_in:
              - file: animal_file

        animal_file:
          file.managed:
            - name: /tmp/animal_file.txt
            - source: salt://animal_file.txt
            - template: jinja

    One might write a template for ``animal_file.txt`` like the following:

    .. code-block:: jinja

        The quick brown fox{% for animal in accumulator['animals_doing_things'] %}{{ animal }}{% endfor %}

    Collectively, the above states and template file will produce:

    .. code-block:: text

        The quick brown fox jumps over the lazy dog.

    Multiple accumulators can be "chained" together.

    .. note::
        The 'accumulator' data structure is a Python dictionary.
        Do not expect any loop over the keys in a deterministic order!
    """
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not name:
        return _error(ret, 'Must provide name to file.accumulated')
    if text is None:
        ret['result'] = False
        ret['comment'] = 'No text supplied for accumulator'
        return ret
    require_in = __low__.get('require_in', [])
    watch_in = __low__.get('watch_in', [])
    deps = require_in + watch_in
    if not [x for x in deps if 'file' in x]:
        ret['result'] = False
        ret['comment'] = 'Orphaned accumulator {} in {}:{}'.format(name, __low__['__sls__'], __low__['__id__'])
        return ret
    if isinstance(text, str):
        text = (text,)
    elif isinstance(text, dict):
        text = (text,)
    (accum_data, accum_deps) = _load_accumulators()
    if filename not in accum_data:
        accum_data[filename] = {}
    if filename not in accum_deps:
        accum_deps[filename] = {}
    if name not in accum_deps[filename]:
        accum_deps[filename][name] = []
    for accumulator in deps:
        if isinstance(accumulator, (dict, OrderedDict)):
            accum_deps[filename][name].extend(accumulator.values())
        else:
            accum_deps[filename][name].extend(accumulator)
    if name not in accum_data[filename]:
        accum_data[filename][name] = []
    for chunk in text:
        if chunk not in accum_data[filename][name]:
            accum_data[filename][name].append(chunk)
            ret['comment'] = 'Accumulator {} for file {} was charged by text'.format(name, filename)
    _persist_accummulators(accum_data, accum_deps)
    return ret

def serialize(name, dataset=None, dataset_pillar=None, user=None, group=None, mode=None, backup='', makedirs=False, show_changes=True, create=True, merge_if_exists=False, encoding=None, encoding_errors='strict', serializer=None, serializer_opts=None, deserializer_opts=None, **kwargs):
    log.info('Trace')
    '\n    Serializes dataset and store it into managed file. Useful for sharing\n    simple configuration files.\n\n    name\n        The location of the file to create\n\n    dataset\n        The dataset that will be serialized\n\n    dataset_pillar\n        Operates like ``dataset``, but draws from a value stored in pillar,\n        using the pillar path syntax used in :mod:`pillar.get\n        <salt.modules.pillar.get>`. This is useful when the pillar value\n        contains newlines, as referencing a pillar variable using a jinja/mako\n        template can result in YAML formatting issues due to the newlines\n        causing indentation mismatches.\n\n        .. versionadded:: 2015.8.0\n\n    serializer (or formatter)\n        Write the data as this format. See the list of\n        :ref:`all-salt.serializers` for supported output formats.\n\n        .. versionchanged:: 3002\n            ``serializer`` argument added as an alternative to ``formatter``.\n            Both are accepted, but using both will result in an error.\n\n    encoding\n        If specified, then the specified encoding will be used. Otherwise, the\n        file will be encoded using the system locale (usually UTF-8). See\n        https://docs.python.org/3/library/codecs.html#standard-encodings for\n        the list of available encodings.\n\n        .. versionadded:: 2017.7.0\n\n    encoding_errors\n        Error encoding scheme. Default is ```\'strict\'```.\n        See https://docs.python.org/2/library/codecs.html#codec-base-classes\n        for the list of available schemes.\n\n        .. versionadded:: 2017.7.0\n\n    user\n        The user to own the directory, this defaults to the user salt is\n        running as on the minion\n\n    group\n        The group ownership set for the directory, this defaults to the group\n        salt is running as on the minion\n\n    mode\n        The permissions to set on this file, e.g. ``644``, ``0775``, or\n        ``4664``.\n\n        The default mode for new files and directories corresponds umask of salt\n        process. For existing files and directories it\'s not enforced.\n\n        .. note::\n            This option is **not** supported on Windows.\n\n    backup\n        Overrides the default backup mode for this specific file.\n\n    makedirs\n        Create parent directories for destination file.\n\n        .. versionadded:: 2014.1.3\n\n    show_changes\n        Output a unified diff of the old file and the new file. If ``False``\n        return a boolean if any changes were made.\n\n    create\n        Default is True, if create is set to False then the file will only be\n        managed if the file already exists on the system.\n\n    merge_if_exists\n        Default is False, if merge_if_exists is True then the existing file will\n        be parsed and the dataset passed in will be merged with the existing\n        content\n\n        .. versionadded:: 2014.7.0\n\n    serializer_opts\n        Pass through options to serializer. For example:\n\n        .. code-block:: yaml\n\n           /etc/dummy/package.yaml\n             file.serialize:\n               - serializer: yaml\n               - serializer_opts:\n                 - explicit_start: True\n                 - default_flow_style: True\n                 - indent: 4\n\n        The valid opts are the additional opts (i.e. not the data being\n        serialized) for the function used to serialize the data. Documentation\n        for the these functions can be found in the list below:\n\n        - For **yaml**: `yaml.dump()`_\n        - For **json**: `json.dumps()`_\n        - For **python**: `pprint.pformat()`_\n        - For **msgpack**: Run ``python -c \'import msgpack; help(msgpack.Packer)\'``\n          to see the available options (``encoding``, ``unicode_errors``, etc.)\n\n        .. _`yaml.dump()`: https://pyyaml.org/wiki/PyYAMLDocumentation\n        .. _`json.dumps()`: https://docs.python.org/2/library/json.html#json.dumps\n        .. _`pprint.pformat()`: https://docs.python.org/2/library/pprint.html#pprint.pformat\n\n    deserializer_opts\n        Like ``serializer_opts`` above, but only used when merging with an\n        existing file (i.e. when ``merge_if_exists`` is set to ``True``).\n\n        The options specified here will be passed to the deserializer to load\n        the existing data, before merging with the specified data and\n        re-serializing.\n\n        .. code-block:: yaml\n\n           /etc/dummy/package.yaml\n             file.serialize:\n               - serializer: yaml\n               - serializer_opts:\n                 - explicit_start: True\n                 - default_flow_style: True\n                 - indent: 4\n               - deserializer_opts:\n                 - encoding: latin-1\n               - merge_if_exists: True\n\n        The valid opts are the additional opts (i.e. not the data being\n        deserialized) for the function used to deserialize the data.\n        Documentation for the these functions can be found in the list below:\n\n        - For **yaml**: `yaml.load()`_\n        - For **json**: `json.loads()`_\n\n        .. _`yaml.load()`: https://pyyaml.org/wiki/PyYAMLDocumentation\n        .. _`json.loads()`: https://docs.python.org/2/library/json.html#json.loads\n\n        However, note that not all arguments are supported. For example, when\n        deserializing JSON, arguments like ``parse_float`` and ``parse_int``\n        which accept a callable object cannot be handled in an SLS file.\n\n        .. versionadded:: 2019.2.0\n\n    For example, this state:\n\n    .. code-block:: yaml\n\n        /etc/dummy/package.json:\n          file.serialize:\n            - dataset:\n                name: naive\n                description: A package using naive versioning\n                author: A confused individual <iam@confused.com>\n                dependencies:\n                  express: \'>= 1.2.0\'\n                  optimist: \'>= 0.1.0\'\n                engine: node 0.4.1\n            - serializer: json\n\n    will manage the file ``/etc/dummy/package.json``:\n\n    .. code-block:: json\n\n        {\n          "author": "A confused individual <iam@confused.com>",\n          "dependencies": {\n            "express": ">= 1.2.0",\n            "optimist": ">= 0.1.0"\n          },\n          "description": "A package using naive versioning",\n          "engine": "node 0.4.1",\n          "name": "naive"\n        }\n    '
    if 'env' in kwargs:
        kwargs.pop('env')
    name = os.path.expanduser(name)
    serializer_options = {'yaml.serialize': {'default_flow_style': False}, 'json.serialize': {'indent': 2, 'separators': (',', ': '), 'sort_keys': True}}
    deserializer_options = {'yaml.deserialize': {}, 'json.deserialize': {}}
    if encoding:
        serializer_options['yaml.serialize'].update({'allow_unicode': True})
        serializer_options['json.serialize'].update({'ensure_ascii': False})
    ret = {'changes': {}, 'comment': '', 'name': name, 'result': True}
    if not name:
        return _error(ret, 'Must provide name to file.serialize')
    if not create:
        if not os.path.isfile(name):
            ret['comment'] = 'File {} is not present and is not set for creation'.format(name)
            return ret
    formatter = kwargs.pop('formatter', None)
    if serializer and formatter:
        return _error(ret, 'Only one of serializer and formatter are allowed')
    serializer = str(serializer or formatter or 'yaml').lower()
    if len([x for x in (dataset, dataset_pillar) if x]) > 1:
        return _error(ret, "Only one of 'dataset' and 'dataset_pillar' is permitted")
    if dataset_pillar:
        dataset = __salt__['pillar.get'](dataset_pillar)
    if dataset is None:
        return _error(ret, "Neither 'dataset' nor 'dataset_pillar' was defined")
    if salt.utils.platform.is_windows():
        if group is not None:
            log.warning('The group argument for %s has been ignored as this is a Windows system.', name)
        group = user
    serializer_name = '{}.serialize'.format(serializer)
    deserializer_name = '{}.deserialize'.format(serializer)
    if serializer_name not in __serializers__:
        return {'changes': {}, 'comment': 'The {} serializer could not be found. It either does not exist or its prerequisites are not installed.'.format(serializer), 'name': name, 'result': False}
    if serializer_opts:
        serializer_options.setdefault(serializer_name, {}).update(salt.utils.data.repack_dictlist(serializer_opts))
    if deserializer_opts:
        deserializer_options.setdefault(deserializer_name, {}).update(salt.utils.data.repack_dictlist(deserializer_opts))
    if merge_if_exists:
        if os.path.isfile(name):
            if deserializer_name not in __serializers__:
                return {'changes': {}, 'comment': 'merge_if_exists is not supported for the {} serializer'.format(serializer), 'name': name, 'result': False}
            open_args = 'r'
            if serializer == 'plist':
                open_args += 'b'
            with salt.utils.files.fopen(name, open_args) as fhr:
                try:
                    log.info('Trace')
                    existing_data = __serializers__[deserializer_name](fhr, **deserializer_options.get(deserializer_name, {}))
                except (TypeError, DeserializationError) as exc:
                    log.info('Trace')
                    ret['result'] = False
                    ret['comment'] = 'Failed to deserialize existing data: {}'.format(exc)
                    return False
            if existing_data is not None:
                merged_data = salt.utils.dictupdate.merge_recurse(existing_data, dataset)
                if existing_data == merged_data:
                    ret['result'] = True
                    ret['comment'] = 'The file {} is in the correct state'.format(name)
                    return ret
                dataset = merged_data
    elif deserializer_opts:
        ret.setdefault('warnings', []).append("The 'deserializer_opts' option is ignored unless merge_if_exists is set to True.")
    contents = __serializers__[serializer_name](dataset, **serializer_options.get(serializer_name, {}))
    try:
        log.info('Trace')
        contents += '\n'
    except TypeError:
        log.info('Trace')
        pass
    mode = salt.utils.files.normalize_mode(mode)
    if __opts__['test']:
        ret['changes'] = __salt__['file.check_managed_changes'](name=name, source=None, source_hash={}, source_hash_name=None, user=user, group=group, mode=mode, attrs=None, template=None, context=None, defaults=None, saltenv=__env__, contents=contents, skip_verify=False, **kwargs)
        if ret['changes']:
            ret['result'] = None
            ret['comment'] = 'Dataset will be serialized and stored into {}'.format(name)
            if not show_changes:
                ret['changes']['diff'] = '<show_changes=False>'
        else:
            ret['result'] = True
            ret['comment'] = 'The file {} is in the correct state'.format(name)
        return ret
    return __salt__['file.manage_file'](name=name, sfn='', ret=ret, source=None, source_sum={}, user=user, group=group, mode=mode, attrs=None, saltenv=__env__, backup=backup, makedirs=makedirs, template=None, show_changes=show_changes, encoding=encoding, encoding_errors=encoding_errors, contents=contents)

def mknod(name, ntype, major=0, minor=0, user=None, group=None, mode='0600'):
    """
    Create a special file similar to the 'nix mknod command. The supported
    device types are ``p`` (fifo pipe), ``c`` (character device), and ``b``
    (block device). Provide the major and minor numbers when specifying a
    character device or block device. A fifo pipe does not require this
    information. The command will create the necessary dirs if needed. If a
    file of the same name not of the same type/major/minor exists, it will not
    be overwritten or unlinked (deleted). This is logically in place as a
    safety measure because you can really shoot yourself in the foot here and
    it is the behavior of 'nix ``mknod``. It is also important to note that not
    just anyone can create special devices. Usually this is only done as root.
    If the state is executed as none other than root on a minion, you may
    receive a permission error.

    name
        name of the file

    ntype
        node type 'p' (fifo pipe), 'c' (character device), or 'b'
        (block device)

    major
        major number of the device
        does not apply to a fifo pipe

    minor
        minor number of the device
        does not apply to a fifo pipe

    user
        owning user of the device/pipe

    group
        owning group of the device/pipe

    mode
        permissions on the device/pipe

    Usage:

    .. code-block:: yaml

        /dev/chr:
          file.mknod:
            - ntype: c
            - major: 180
            - minor: 31
            - user: root
            - group: root
            - mode: 660

        /dev/blk:
          file.mknod:
            - ntype: b
            - major: 8
            - minor: 999
            - user: root
            - group: root
            - mode: 660

        /dev/fifo:
          file.mknod:
            - ntype: p
            - user: root
            - group: root
            - mode: 660

    .. versionadded:: 0.17.0
    """
    name = os.path.expanduser(name)
    ret = {'name': name, 'changes': {}, 'comment': '', 'result': False}
    if not name:
        return _error(ret, 'Must provide name to file.mknod')
    if ntype == 'c':
        if __salt__['file.file_exists'](name):
            ret['comment'] = 'File {} exists and is not a character device. Refusing to continue'.format(name)
        elif not __salt__['file.is_chrdev'](name):
            if __opts__['test']:
                ret['comment'] = 'Character device {} is set to be created'.format(name)
                ret['result'] = None
            else:
                ret = __salt__['file.mknod'](name, ntype, major, minor, user, group, mode)
        else:
            (devmaj, devmin) = __salt__['file.get_devmm'](name)
            if (major, minor) != (devmaj, devmin):
                ret['comment'] = 'Character device {} exists and has a different major/minor {}/{}. Refusing to continue'.format(name, devmaj, devmin)
            else:
                ret = __salt__['file.check_perms'](name, None, user, group, mode)[0]
                if not ret['changes']:
                    ret['comment'] = 'Character device {} is in the correct state'.format(name)
    elif ntype == 'b':
        if __salt__['file.file_exists'](name):
            ret['comment'] = 'File {} exists and is not a block device. Refusing to continue'.format(name)
        elif not __salt__['file.is_blkdev'](name):
            if __opts__['test']:
                ret['comment'] = 'Block device {} is set to be created'.format(name)
                ret['result'] = None
            else:
                ret = __salt__['file.mknod'](name, ntype, major, minor, user, group, mode)
        else:
            (devmaj, devmin) = __salt__['file.get_devmm'](name)
            if (major, minor) != (devmaj, devmin):
                ret['comment'] = 'Block device {} exists and has a different major/minor {}/{}. Refusing to continue'.format(name, devmaj, devmin)
            else:
                ret = __salt__['file.check_perms'](name, None, user, group, mode)[0]
                if not ret['changes']:
                    ret['comment'] = 'Block device {} is in the correct state'.format(name)
    elif ntype == 'p':
        if __salt__['file.file_exists'](name):
            ret['comment'] = 'File {} exists and is not a fifo pipe. Refusing to continue'.format(name)
        elif not __salt__['file.is_fifo'](name):
            if __opts__['test']:
                ret['comment'] = 'Fifo pipe {} is set to be created'.format(name)
                ret['result'] = None
            else:
                ret = __salt__['file.mknod'](name, ntype, major, minor, user, group, mode)
        else:
            ret = __salt__['file.check_perms'](name, None, user, group, mode)[0]
            if not ret['changes']:
                ret['comment'] = 'Fifo pipe {} is in the correct state'.format(name)
    else:
        ret['comment'] = "Node type unavailable: '{}'. Available node types are character ('c'), block ('b'), and pipe ('p')".format(ntype)
    return ret

def mod_run_check_cmd(cmd, filename, **check_cmd_opts):
    """
    Execute the check_cmd logic.

    Return a result dict if ``check_cmd`` succeeds (check_cmd == 0)
    otherwise return True
    """
    log.debug('running our check_cmd')
    _cmd = '{} {}'.format(cmd, filename)
    cret = __salt__['cmd.run_all'](_cmd, **check_cmd_opts)
    if cret['retcode'] != 0:
        log.info('Trace')
        ret = {'comment': 'check_cmd execution failed', 'skip_watch': True, 'result': False}
        if cret.get('stdout'):
            ret['comment'] += '\n' + cret['stdout']
        if cret.get('stderr'):
            ret['comment'] += '\n' + cret['stderr']
        return ret
    return True

def decode(name, encoded_data=None, contents_pillar=None, encoding_type='base64', checksum='md5'):
    """
    Decode an encoded file and write it to disk

    .. versionadded:: 2016.3.0

    name
        Path of the file to be written.
    encoded_data
        The encoded file. Either this option or ``contents_pillar`` must be
        specified.
    contents_pillar
        A Pillar path to the encoded file. Uses the same path syntax as
        :py:func:`pillar.get <salt.modules.pillar.get>`. The
        :py:func:`hashutil.base64_encodefile
        <salt.modules.hashutil.base64_encodefile>` function can load encoded
        content into Pillar. Either this option or ``encoded_data`` must be
        specified.
    encoding_type
        The type of encoding.
    checksum
        The hashing algorithm to use to generate checksums. Wraps the
        :py:func:`hashutil.digest <salt.modules.hashutil.digest>` execution
        function.

    Usage:

    .. code-block:: yaml

        write_base64_encoded_string_to_a_file:
          file.decode:
            - name: /tmp/new_file
            - encoding_type: base64
            - contents_pillar: mypillar:thefile

        # or

        write_base64_encoded_string_to_a_file:
          file.decode:
            - name: /tmp/new_file
            - encoding_type: base64
            - encoded_data: |
                Z2V0IHNhbHRlZAo=

    Be careful with multi-line strings that the YAML indentation is correct.
    E.g.,

    .. code-block:: jinja

        write_base64_encoded_string_to_a_file:
          file.decode:
            - name: /tmp/new_file
            - encoding_type: base64
            - encoded_data: |
                {{ salt.pillar.get('path:to:data') | indent(8) }}
    """
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not (encoded_data or contents_pillar):
        raise CommandExecutionError("Specify either the 'encoded_data' or 'contents_pillar' argument.")
    elif encoded_data and contents_pillar:
        raise CommandExecutionError("Specify only one 'encoded_data' or 'contents_pillar' argument.")
    elif encoded_data:
        content = encoded_data
    elif contents_pillar:
        content = __salt__['pillar.get'](contents_pillar, False)
        if content is False:
            raise CommandExecutionError('Pillar data not found.')
    else:
        raise CommandExecutionError('No contents given.')
    dest_exists = __salt__['file.file_exists'](name)
    if dest_exists:
        instr = __salt__['hashutil.base64_decodestring'](content)
        insum = __salt__['hashutil.digest'](instr, checksum)
        del instr
        outsum = __salt__['hashutil.digest_file'](name, checksum)
        if insum != outsum:
            ret['changes'] = {'old': outsum, 'new': insum}
        if not ret['changes']:
            ret['comment'] = 'File is in the correct state.'
            ret['result'] = True
            return ret
    if __opts__['test'] is True:
        ret['comment'] = 'File is set to be updated.'
        ret['result'] = None
        return ret
    ret['result'] = __salt__['hashutil.base64_decodefile'](content, name)
    ret['comment'] = 'File was updated.'
    if not ret['changes']:
        ret['changes'] = {'old': None, 'new': __salt__['hashutil.digest_file'](name, checksum)}
    return ret

def shortcut(name, target, arguments=None, working_dir=None, description=None, icon_location=None, force=False, backupname=None, makedirs=False, user=None, **kwargs):
    """
    Create a Windows shortcut

    If the file already exists and is a shortcut pointing to any location other
    than the specified target, the shortcut will be replaced. If it is
    a regular file or directory then the state will return False. If the
    regular file or directory is desired to be replaced with a shortcut pass
    force: True, if it is to be renamed, pass a backupname.

    name
        The location of the shortcut to create. Must end with either
        ".lnk" or ".url"

    target
        The location that the shortcut points to

    arguments
        Any arguments to pass in the shortcut

    working_dir
        Working directory in which to execute target

    description
        Description to set on shortcut

    icon_location
        Location of shortcut's icon

    force
        If the name of the shortcut exists and is not a file and
        force is set to False, the state will fail. If force is set to
        True, the link or directory in the way of the shortcut file
        will be deleted to make room for the shortcut, unless
        backupname is set, when it will be renamed

    backupname
        If the name of the shortcut exists and is not a file, it will be
        renamed to the backupname. If the backupname already
        exists and force is False, the state will fail. Otherwise, the
        backupname will be removed first.

    makedirs
        If the location of the shortcut does not already have a parent
        directory then the state will fail, setting makedirs to True will
        allow Salt to create the parent directory. Setting this to True will
        also create the parent for backupname if necessary.

    user
        The user to own the file, this defaults to the user salt is running as
        on the minion

        The default mode for new files and directories corresponds umask of salt
        process. For existing files and directories it's not enforced.
    """
    salt.utils.versions.warn_until(version='Argon', message="This function is being deprecated in favor of 'shortcut.present'")
    user = _test_owner(kwargs, user=user)
    ret = {'name': name, 'changes': {}, 'result': True, 'comment': ''}
    if not salt.utils.platform.is_windows():
        return _error(ret, 'Shortcuts are only supported on Windows')
    if not name:
        return _error(ret, 'Must provide name to file.shortcut')
    if not name.endswith('.lnk') and (not name.endswith('.url')):
        return _error(ret, 'Name must end with either ".lnk" or ".url"')
    name = os.path.realpath(os.path.expanduser(name))
    if name.endswith('.lnk'):
        target = os.path.realpath(os.path.expanduser(target))
    if working_dir:
        working_dir = os.path.realpath(os.path.expanduser(working_dir))
    if icon_location:
        icon_location = os.path.realpath(os.path.expanduser(icon_location))
    if user is None:
        user = __opts__['user']
    if not __salt__['user.info'](user):
        user = __salt__['user.current']()
        if not user:
            user = 'SYSTEM'
    preflight_errors = []
    uid = __salt__['file.user_to_uid'](user)
    if uid == '':
        preflight_errors.append('User {} does not exist'.format(user))
    if not os.path.isabs(name):
        preflight_errors.append('Specified file {} is not an absolute path'.format(name))
    if preflight_errors:
        msg = '. '.join(preflight_errors)
        if len(preflight_errors) > 1:
            msg += '.'
        return _error(ret, msg)
    (tresult, tcomment, tchanges) = _shortcut_check(name, target, arguments, working_dir, description, icon_location, force, user)
    if __opts__['test']:
        ret['result'] = tresult
        ret['comment'] = tcomment
        ret['changes'] = tchanges
        return ret
    if not os.path.isdir(os.path.dirname(name)):
        if makedirs:
            try:
                _makedirs(name=name, user=user)
            except CommandExecutionError as exc:
                return _error(ret, 'Drive {} is not mapped'.format(exc.message))
        else:
            return _error(ret, 'Directory "{}" for shortcut is not present'.format(os.path.dirname(name)))
    if os.path.isdir(name) or os.path.islink(name):
        if backupname is not None:
            if os.path.lexists(backupname):
                if not force:
                    return _error(ret, 'File exists where the backup target {} should go'.format(backupname))
                else:
                    __salt__['file.remove'](backupname)
                    time.sleep(1)
            if not os.path.isdir(os.path.dirname(backupname)):
                if makedirs:
                    try:
                        _makedirs(name=backupname)
                    except CommandExecutionError as exc:
                        return _error(ret, 'Drive {} is not mapped'.format(exc.message))
                else:
                    return _error(ret, 'Directory does not exist for backup at "{}"'.format(os.path.dirname(backupname)))
            os.rename(name, backupname)
            time.sleep(1)
        elif force:
            __salt__['file.remove'](name)
            ret['changes']['forced'] = 'Shortcut was forcibly replaced'
            time.sleep(1)
        else:
            return _error(ret, 'Directory or symlink exists where the shortcut "{}" should be'.format(name))
    with salt.utils.winapi.Com():
        shell = win32com.client.Dispatch('WScript.Shell')
        scut = shell.CreateShortcut(name)
        state_checks = [scut.TargetPath.lower() == target.lower()]
        if arguments is not None:
            state_checks.append(scut.Arguments == arguments)
        if working_dir is not None:
            state_checks.append(scut.WorkingDirectory.lower() == working_dir.lower())
        if description is not None:
            state_checks.append(scut.Description == description)
        if icon_location is not None:
            state_checks.append(scut.IconLocation.lower() == icon_location.lower())
        if __salt__['file.file_exists'](name):
            if not all(state_checks):
                os.remove(name)
            else:
                if _check_shortcut_ownership(name, user):
                    ret['comment'] = 'Shortcut {} is present and owned by {}'.format(name, user)
                elif _set_shortcut_ownership(name, user):
                    ret['comment'] = 'Set ownership of shortcut {} to {}'.format(name, user)
                    ret['changes']['ownership'] = '{}'.format(user)
                else:
                    ret['result'] = False
                    ret['comment'] += 'Failed to set ownership of shortcut {} to {}'.format(name, user)
                return ret
        if not os.path.exists(name):
            try:
                scut.TargetPath = target
                if arguments is not None:
                    scut.Arguments = arguments
                if working_dir is not None:
                    scut.WorkingDirectory = working_dir
                if description is not None:
                    scut.Description = description
                if icon_location is not None:
                    scut.IconLocation = icon_location
                scut.Save()
            except (AttributeError, pywintypes.com_error) as exc:
                ret['result'] = False
                ret['comment'] = 'Unable to create new shortcut {} -> {}: {}'.format(name, target, exc)
                return ret
            else:
                ret['comment'] = 'Created new shortcut {} -> {}'.format(name, target)
                ret['changes']['new'] = name
            if not _check_shortcut_ownership(name, user):
                if not _set_shortcut_ownership(name, user):
                    ret['result'] = False
                    ret['comment'] += ', but was unable to set ownership to {}'.format(user)
    return ret

def cached(name, source_hash='', source_hash_name=None, skip_verify=False, saltenv='base', use_etag=False):
    """
    .. versionadded:: 2017.7.3
    .. versionchanged:: 3005

    Ensures that a file is saved to the minion's cache. This state is primarily
    invoked by other states to ensure that we do not re-download a source file
    if we do not need to.

    name
        The URL of the file to be cached. To cache a file from an environment
        other than ``base``, either use the ``saltenv`` argument or include the
        saltenv in the URL (e.g. ``salt://path/to/file.conf?saltenv=dev``).

        .. note::
            A list of URLs is not supported, this must be a single URL. If a
            local file is passed here, then the state will obviously not try to
            download anything, but it will compare a hash if one is specified.

    source_hash
        See the documentation for this same argument in the
        :py:func:`file.managed <salt.states.file.managed>` state.

        .. note::
            For remote files not originating from the ``salt://`` fileserver,
            such as http(s) or ftp servers, this state will not re-download the
            file if the locally-cached copy matches this hash. This is done to
            prevent unnecessary downloading on repeated runs of this state. To
            update the cached copy of a file, it is necessary to update this
            hash.

    source_hash_name
        See the documentation for this same argument in the
        :py:func:`file.managed <salt.states.file.managed>` state.

    skip_verify
        See the documentation for this same argument in the
        :py:func:`file.managed <salt.states.file.managed>` state.

        .. note::
            Setting this to ``True`` will result in a copy of the file being
            downloaded from a remote (http(s), ftp, etc.) source each time the
            state is run.

    saltenv
        Used to specify the environment from which to download a file from the
        Salt fileserver (i.e. those with ``salt://`` URL).

    use_etag
        If ``True``, remote http/https file sources will attempt to use the
        ETag header to determine if the remote file needs to be downloaded.
        This provides a lightweight mechanism for promptly refreshing files
        changed on a web server without requiring a full hash comparison via
        the ``source_hash`` parameter.

        .. versionadded:: 3005


    This state will in most cases not be useful in SLS files, but it is useful
    when writing a state or remote-execution module that needs to make sure
    that a file at a given URL has been downloaded to the cachedir. One example
    of this is in the :py:func:`archive.extracted <salt.states.file.extracted>`
    state:

    .. code-block:: python

        result = __states__['file.cached'](source_match,
                                           source_hash=source_hash,
                                           source_hash_name=source_hash_name,
                                           skip_verify=skip_verify,
                                           saltenv=__env__)

    This will return a dictionary containing the state's return data, including
    a ``result`` key which will state whether or not the state was successful.
    Note that this will not catch exceptions, so it is best used within a
    try/except.

    Once this state has been run from within another state or remote-execution
    module, the actual location of the cached file can be obtained using
    :py:func:`cp.is_cached <salt.modules.cp.is_cached>`:

    .. code-block:: python

        cached = __salt__['cp.is_cached'](source_match, saltenv=__env__)

    This function will return the cached path of the file, or an empty string
    if the file is not present in the minion cache.
    """
    ret = {'changes': {}, 'comment': '', 'name': name, 'result': False}
    try:
        parsed = urllib.parse.urlparse(name)
    except Exception:
        ret['comment'] = 'Only URLs or local file paths are valid input'
        return ret
    if not skip_verify and (not source_hash) and (not use_etag) and (parsed.scheme in salt.utils.files.REMOTE_PROTOS):
        ret['comment'] = 'Unable to verify upstream hash of source file {}, please set source_hash or set skip_verify or use_etag to True'.format(salt.utils.url.redact_http_basic_auth(name))
        return ret
    if source_hash:
        try:
            source_sum = __salt__['file.get_source_sum'](source=name, source_hash=source_hash, source_hash_name=source_hash_name, saltenv=saltenv)
        except CommandExecutionError as exc:
            ret['comment'] = exc.strerror
            return ret
        else:
            if not source_sum:
                ret['comment'] = 'Failed to get source hash from {}. This may be a bug. If this error persists, please report it and set skip_verify to True to work around it.'.format(source_hash)
                return ret
    else:
        source_sum = {}
    if parsed.scheme in salt.utils.files.LOCAL_PROTOS:
        full_path = os.path.realpath(os.path.expanduser(parsed.path))
        if os.path.exists(full_path):
            if not skip_verify and source_sum:
                local_hash = __salt__['file.get_hash'](full_path, source_sum.get('hash_type', __opts__['hash_type']))
                if local_hash == source_sum['hsum']:
                    ret['result'] = True
                    ret['comment'] = 'File {} is present on the minion and has hash {}'.format(full_path, local_hash)
                else:
                    ret['comment'] = 'File {} is present on the minion, but the hash ({}) does not match the specified hash ({})'.format(full_path, local_hash, source_sum['hsum'])
                return ret
            else:
                ret['result'] = True
                ret['comment'] = 'File {} is present on the minion'.format(full_path)
                return ret
        else:
            ret['comment'] = 'File {} is not present on the minion'.format(full_path)
            return ret
    local_copy = __salt__['cp.is_cached'](name, saltenv=saltenv)
    if local_copy:
        pre_hash = __salt__['file.get_hash'](local_copy, source_sum.get('hash_type', __opts__['hash_type']))
        if not skip_verify and source_sum:
            if pre_hash == source_sum['hsum']:
                ret['result'] = True
                ret['comment'] = 'File is already cached to {} with hash {}'.format(local_copy, pre_hash)
    else:
        pre_hash = None
    try:
        local_copy = __salt__['cp.cache_file'](name, saltenv=saltenv, source_hash=source_sum.get('hsum'), use_etag=use_etag)
    except Exception as exc:
        ret['comment'] = salt.utils.url.redact_http_basic_auth(exc.__str__())
        return ret
    if not local_copy:
        ret['comment'] = 'Failed to cache {}, check minion log for more information'.format(salt.utils.url.redact_http_basic_auth(name))
        return ret
    post_hash = __salt__['file.get_hash'](local_copy, source_sum.get('hash_type', __opts__['hash_type']))
    if pre_hash != post_hash:
        ret['changes']['hash'] = {'old': pre_hash, 'new': post_hash}
    if not skip_verify and source_sum:
        if post_hash == source_sum['hsum']:
            ret['result'] = True
            ret['comment'] = 'File is already cached to {} with hash {}'.format(local_copy, post_hash)
        else:
            ret['comment'] = 'File is cached to {}, but the hash ({}) does not match the specified hash ({})'.format(local_copy, post_hash, source_sum['hsum'])
        return ret
    ret['result'] = True
    ret['comment'] = 'File is cached to {}'.format(local_copy)
    return ret

def not_cached(name, saltenv='base'):
    log.info('Trace')
    "\n    .. versionadded:: 2017.7.3\n\n    Ensures that a file is not present in the minion's cache, deleting it\n    if found. This state is primarily invoked by other states to ensure\n    that a fresh copy is fetched.\n\n    name\n        The URL of the file to be removed from cache. To remove a file from\n        cache in an environment other than ``base``, either use the ``saltenv``\n        argument or include the saltenv in the URL (e.g.\n        ``salt://path/to/file.conf?saltenv=dev``).\n\n        .. note::\n            A list of URLs is not supported, this must be a single URL. If a\n            local file is passed here, the state will take no action.\n\n    saltenv\n        Used to specify the environment from which to download a file from the\n        Salt fileserver (i.e. those with ``salt://`` URL).\n    "
    ret = {'changes': {}, 'comment': '', 'name': name, 'result': False}
    try:
        log.info('Trace')
        parsed = urllib.parse.urlparse(name)
    except Exception:
        log.info('Trace')
        ret['comment'] = 'Only URLs or local file paths are valid input'
        return ret
    else:
        if parsed.scheme in salt.utils.files.LOCAL_PROTOS:
            full_path = os.path.realpath(os.path.expanduser(parsed.path))
            ret['result'] = True
            ret['comment'] = 'File {} is a local path, no action taken'.format(full_path)
            return ret
    local_copy = __salt__['cp.is_cached'](name, saltenv=saltenv)
    if local_copy:
        try:
            log.info('Trace')
            os.remove(local_copy)
        except Exception as exc:
            log.info('Trace')
            ret['comment'] = 'Failed to delete {}: {}'.format(local_copy, exc.__str__())
        else:
            ret['result'] = True
            ret['changes']['deleted'] = True
            ret['comment'] = '{} was deleted'.format(local_copy)
    else:
        ret['result'] = True
        ret['comment'] = '{} is not cached'.format(name)
    return ret

def mod_beacon(name, **kwargs):
    """
    Create a beacon to monitor a file based on a beacon state argument.

    .. note::
        This state exists to support special handling of the ``beacon``
        state argument for supported state functions. It should not be called directly.

    """
    sfun = kwargs.pop('sfun', None)
    supported_funcs = ['managed', 'directory']
    if sfun in supported_funcs:
        if kwargs.get('beacon'):
            beacon_module = 'inotify'
            data = {}
            _beacon_data = kwargs.get('beacon_data', {})
            default_mask = ['create', 'delete', 'modify']
            data['mask'] = _beacon_data.get('mask', default_mask)
            if sfun == 'directory':
                data['auto_add'] = _beacon_data.get('auto_add', True)
                data['recurse'] = _beacon_data.get('recurse', True)
                data['exclude'] = _beacon_data.get('exclude', [])
            beacon_name = 'beacon_{}_{}'.format(beacon_module, name)
            beacon_kwargs = {'name': beacon_name, 'files': {name: data}, 'interval': _beacon_data.get('interval', 60), 'coalesce': _beacon_data.get('coalesce', False), 'beacon_module': beacon_module}
            ret = __states__['beacon.present'](**beacon_kwargs)
            return ret
        else:
            return {'name': name, 'changes': {}, 'comment': 'Not adding beacon.', 'result': True}
    else:
        return {'name': name, 'changes': {}, 'comment': 'file.{} does not work with the beacon state function'.format(sfun), 'result': False}