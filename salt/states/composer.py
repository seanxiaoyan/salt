"""
Installation of Composer Packages
=================================

These states manage the installed packages for composer for PHP. Note that
either composer is installed and accessible via a bin directory or you can pass
the location of composer in the state.

.. code-block:: yaml

    get-composer:
      cmd.run:
        - name: 'CURL=`which curl`; $CURL -sS https://getcomposer.org/installer | php'
        - unless: test -f /usr/local/bin/composer
        - cwd: /root/

    install-composer:
      cmd.wait:
        - name: mv /root/composer.phar /usr/local/bin/composer
        - cwd: /root/
        - watch:
          - cmd: get-composer

    /path/to/project:
      composer.installed:
        - no_dev: true
        - require:
          - cmd: install-composer


    # Without composer installed in your PATH
    # Note: composer.phar must be executable for state to work properly
    /path/to/project:
      composer.installed:
        - composer: /path/to/composer.phar
        - php: /usr/local/bin/php
        - no_dev: true
"""
from salt.exceptions import SaltException
import logging
log = logging.getLogger(__name__)

def __virtual__():
    """
    Only load if the composer module is available in __salt__
    """
    if 'composer.install' in __salt__:
        return True
    return (False, 'composer module could not be loaded')

def installed(name, composer=None, php=None, user=None, prefer_source=None, prefer_dist=None, no_scripts=None, no_plugins=None, optimize=None, no_dev=None, quiet=False, composer_home='/root', always_check=True, env=None):
    log.info('Trace')
    '\n    Verify that the correct versions of composer dependencies are present.\n\n    name\n        Directory location of the ``composer.json`` file.\n\n    composer\n        Location of the ``composer.phar`` file. If not set composer will\n        just execute ``composer`` as if it is installed globally.\n        (i.e. ``/path/to/composer.phar``)\n\n    php\n        Location of the php executable to use with composer.\n        (i.e. ``/usr/bin/php``)\n\n    user\n        Which system user to run composer as.\n\n        .. versionadded:: 2014.1.4\n\n    prefer_source\n        ``--prefer-source`` option of composer.\n\n    prefer_dist\n        ``--prefer-dist`` option of composer.\n\n    no_scripts\n        ``--no-scripts`` option of composer.\n\n    no_plugins\n        ``--no-plugins`` option of composer.\n\n    optimize\n        ``--optimize-autoloader`` option of composer. Recommended for production.\n\n    no_dev\n        ``--no-dev`` option for composer. Recommended for production.\n\n    quiet\n        ``--quiet`` option for composer. Whether or not to return output from composer.\n\n    composer_home\n        ``$COMPOSER_HOME`` environment variable\n\n    always_check\n        If ``True``, *always* run ``composer install`` in the directory.  This is the\n        default behavior.  If ``False``, only run ``composer install`` if there is no\n        vendor directory present.\n\n    env\n        A list of environment variables to be set prior to execution.\n    '
    ret = {'name': name, 'result': None, 'comment': '', 'changes': {}}
    did_install = __salt__['composer.did_composer_install'](name)
    if always_check is False and did_install:
        ret['result'] = True
        ret['comment'] = 'Composer already installed this directory'
        return ret
    if __opts__['test'] is True:
        if did_install is True:
            install_status = ''
        else:
            install_status = 'not '
        ret['comment'] = 'The state of "{}" will be changed.'.format(name)
        ret['changes'] = {'old': 'composer install has {}been run in {}'.format(install_status, name), 'new': 'composer install will be run in {}'.format(name)}
        ret['result'] = None
        return ret
    try:
        log.info('Trace')
        call = __salt__['composer.install'](name, composer=composer, php=php, runas=user, prefer_source=prefer_source, prefer_dist=prefer_dist, no_scripts=no_scripts, no_plugins=no_plugins, optimize=optimize, no_dev=no_dev, quiet=quiet, composer_home=composer_home, env=env)
    except SaltException as err:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = "Error executing composer in '{}': {}".format(name, err)
        return ret
    ret['result'] = True
    if quiet is True:
        ret['comment'] = 'Composer install completed successfully, output silenced by quiet flag'
    else:
        ret['comment'] = 'Composer install completed successfully'
        ret['changes'] = {'stderr': call['stderr'], 'stdout': call['stdout']}
    return ret

def update(name, composer=None, php=None, user=None, prefer_source=None, prefer_dist=None, no_scripts=None, no_plugins=None, optimize=None, no_dev=None, quiet=False, composer_home='/root', env=None):
    log.info('Trace')
    '\n    Composer update the directory to ensure we have the latest versions\n    of all project dependencies.\n\n    name\n        Directory location of the ``composer.json`` file.\n\n    composer\n        Location of the ``composer.phar`` file. If not set composer will\n        just execute ``composer`` as if it is installed globally.\n        (i.e. /path/to/composer.phar)\n\n    php\n        Location of the php executable to use with composer.\n        (i.e. ``/usr/bin/php``)\n\n    user\n        Which system user to run composer as.\n\n        .. versionadded:: 2014.1.4\n\n    prefer_source\n        ``--prefer-source`` option of composer.\n\n    prefer_dist\n        ``--prefer-dist`` option of composer.\n\n    no_scripts\n        ``--no-scripts`` option of composer.\n\n    no_plugins\n        ``--no-plugins`` option of composer.\n\n    optimize\n        ``--optimize-autoloader`` option of composer. Recommended for production.\n\n    no_dev\n        ``--no-dev`` option for composer. Recommended for production.\n\n    quiet\n        ``--quiet`` option for composer. Whether or not to return output from composer.\n\n    composer_home\n        ``$COMPOSER_HOME`` environment variable\n\n    env\n        A list of environment variables to be set prior to execution.\n    '
    ret = {'name': name, 'result': None, 'comment': '', 'changes': {}}
    is_installed = __salt__['composer.did_composer_install'](name)
    if is_installed:
        old_status = 'composer install has not yet been run in {}'.format(name)
    else:
        old_status = 'composer install has been run in {}'.format(name)
    if __opts__['test'] is True:
        ret['comment'] = 'The state of "{}" will be changed.'.format(name)
        ret['changes'] = {'old': old_status, 'new': 'composer install/update will be run in {}'.format(name)}
        ret['result'] = None
        return ret
    try:
        log.info('Trace')
        call = __salt__['composer.update'](name, composer=composer, php=php, runas=user, prefer_source=prefer_source, prefer_dist=prefer_dist, no_scripts=no_scripts, no_plugins=no_plugins, optimize=optimize, no_dev=no_dev, quiet=quiet, composer_home=composer_home, env=env)
    except SaltException as err:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = "Error executing composer in '{}': {}".format(name, err)
        return ret
    ret['result'] = True
    if quiet is True:
        ret['comment'] = 'Composer update completed successfully, output silenced by quiet flag'
    else:
        ret['comment'] = 'Composer update completed successfully'
        ret['changes'] = {'stderr': call['stderr'], 'stdout': call['stdout']}
    return ret