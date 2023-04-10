"""
Execution of arbitrary commands
===============================

The cmd state module manages the enforcement of executed commands, this
state can tell a command to run under certain circumstances.


A simple example to execute a command:

.. code-block:: yaml

    # Store the current date in a file
    'date > /tmp/salt-run':
      cmd.run

Only run if another execution failed, in this case truncate syslog if there is
no disk space:

.. code-block:: yaml

    '> /var/log/messages/':
      cmd.run:
        - unless: echo 'foo' > /tmp/.test && rm -f /tmp/.test

Only run if the file specified by ``creates`` does not exist, in this case
touch /tmp/foo if it does not exist:

.. code-block:: yaml

    touch /tmp/foo:
      cmd.run:
        - creates: /tmp/foo

``creates`` also accepts a list of files, in which case this state will
run if **any** of the files do not exist:

.. code-block:: yaml

    "echo 'foo' | tee /tmp/bar > /tmp/baz":
      cmd.run:
        - creates:
          - /tmp/bar
          - /tmp/baz

.. note::

    The ``creates`` option was added to the cmd state in version 2014.7.0,
    and made a global requisite in 3001.

Sometimes when running a command that starts up a daemon, the init script
doesn't return properly which causes Salt to wait indefinitely for a response.
In situations like this try the following:

.. code-block:: yaml

    run_installer:
      cmd.run:
        - name: /tmp/installer.bin > /dev/null 2>&1

Salt determines whether the ``cmd`` state is successfully enforced based on the exit
code returned by the command. If the command returns a zero exit code, then salt
determines that the state was successfully enforced. If the script returns a non-zero
exit code, then salt determines that it failed to successfully enforce the state.
If a command returns a non-zero exit code but you wish to treat this as a success,
then you must place the command in a script and explicitly set the exit code of
the script to zero.

Please note that the success or failure of the state is not affected by whether a state
change occurred nor the stateful argument.

When executing a command or script, the state (i.e., changed or not)
of the command is unknown to Salt's state system. Therefore, by default, the
``cmd`` state assumes that any command execution results in a changed state.

This means that if a ``cmd`` state is watched by another state then the
state that's watching will always be executed due to the `changed` state in
the ``cmd`` state.

.. _stateful-argument:

Using the "Stateful" Argument
-----------------------------

Many state functions in this module now also accept a ``stateful`` argument.
If ``stateful`` is specified to be true then it is assumed that the command
or script will determine its own state and communicate it back by following
a simple protocol described below:

1. :strong:`If there's nothing in the stdout of the command, then assume no
   changes.` Otherwise, the stdout must be either in JSON or its `last`
   non-empty line must be a string of key=value pairs delimited by spaces (no
   spaces on either side of ``=``).

2. :strong:`If it's JSON then it must be a JSON object (e.g., {}).` If it's
   key=value pairs then quoting may be used to include spaces.  (Python's shlex
   module is used to parse the key=value string)

   Two special keys or attributes are recognized in the output::

    changed: bool (i.e., 'yes', 'no', 'true', 'false', case-insensitive)
    comment: str  (i.e., any string)

   So, only if ``changed`` is ``True`` then assume the command execution has
   changed the state, and any other key values or attributes in the output will
   be set as part of the changes.

3. :strong:`If there's a comment then it will be used as the comment of the
   state.`

   Here's an example of how one might write a shell script for use with a
   stateful command:

   .. code-block:: bash

       #!/bin/bash
       #
       echo "Working hard..."

       # writing the state line
       echo  # an empty line here so the next line will be the last.
       echo "changed=yes comment='something has changed' whatever=123"

   And an example SLS file using this module:

   .. code-block:: yaml

       Run myscript:
         cmd.run:
           - name: /path/to/myscript
           - cwd: /
           - stateful: True

       Run only if myscript changed something:
         cmd.run:
           - name: echo hello
           - cwd: /
           - onchanges:
               - cmd: Run myscript

   Note that if the second ``cmd.run`` state also specifies ``stateful: True`` it can
   then be watched by some other states as well.

4. :strong:`The stateful argument can optionally include a test_name parameter.`

   This is used to specify a command to run in test mode.  This command should
   return stateful data for changes that would be made by the command in the
   name parameter.

   .. versionadded:: 2015.2.0

   .. code-block:: yaml

       Run myscript:
         cmd.run:
           - name: /path/to/myscript
           - cwd: /
           - stateful:
             - test_name: /path/to/myscript test

       Run masterscript:
         cmd.script:
           - name: masterscript
           - source: salt://path/to/masterscript
           - cwd: /
           - stateful:
             - test_name: masterscript test


Should I use :mod:`cmd.run <salt.states.cmd.run>` or :mod:`cmd.wait <salt.states.cmd.wait>`?
--------------------------------------------------------------------------------------------

.. note::

    Use :mod:`cmd.run <salt.states.cmd.run>` together with :ref:`onchanges <requisites-onchanges>`
    instead of :mod:`cmd.wait <salt.states.cmd.wait>`.

These two states are often confused. The important thing to remember about them
is that :mod:`cmd.run <salt.states.cmd.run>` states are run each time the SLS
file that contains them is applied. If it is more desirable to have a command
that only runs after some other state changes, then :mod:`cmd.wait
<salt.states.cmd.wait>` does just that. :mod:`cmd.wait <salt.states.cmd.wait>`
is designed to :ref:`watch <requisites-watch>` other states, and is
executed when the state it is watching changes. Example:

.. code-block:: yaml

    /usr/local/bin/postinstall.sh:
      cmd.wait:
        - watch:
          - pkg: mycustompkg
      file.managed:
        - source: salt://utils/scripts/postinstall.sh

    mycustompkg:
      pkg.installed:
        - require:
          - file: /usr/local/bin/postinstall.sh

``cmd.wait`` itself do not do anything; all functionality is inside its ``mod_watch``
function, which is called by ``watch`` on changes.

The preferred format is using the :ref:`onchanges Requisite <requisites-onchanges>`, which
works on ``cmd.run`` as well as on any other state. The example would then look as follows:

.. code-block:: yaml

    /usr/local/bin/postinstall.sh:
      cmd.run:
        - onchanges:
          - pkg: mycustompkg
      file.managed:
        - source: salt://utils/scripts/postinstall.sh

    mycustompkg:
      pkg.installed:
        - require:
          - file: /usr/local/bin/postinstall.sh

How do I create an environment from a pillar map?
-------------------------------------------------

The map that comes from a pillar can be directly consumed by the env option!
To use it, one may pass it like this. Example:

.. code-block:: yaml

    printenv:
      cmd.run:
        - env: {{ salt['pillar.get']('example:key', {}) }}

"""
import copy
import logging
import os
import salt.utils.args
import salt.utils.functools
import salt.utils.json
import salt.utils.platform
from salt.exceptions import CommandExecutionError, SaltRenderError
log = logging.getLogger(__name__)

def _reinterpreted_state(state):
    log.info('Trace')
    '\n    Re-interpret the state returned by salt.state.run using our protocol.\n    '
    ret = state['changes']
    state['changes'] = {}
    state['comment'] = ''
    out = ret.get('stdout')
    if not out:
        if ret.get('stderr'):
            state['comment'] = ret['stderr']
        return state
    is_json = False
    try:
        log.info('Trace')
        data = salt.utils.json.loads(out)
        if not isinstance(data, dict):
            return _failout(state, 'script JSON output must be a JSON object (e.g., {})!')
        is_json = True
    except ValueError:
        log.info('Trace')
        idx = out.rstrip().rfind('\n')
        if idx != -1:
            out = out[idx + 1:]
        data = {}
        try:
            log.info('Trace')
            for item in salt.utils.args.shlex_split(out):
                (key, val) = item.split('=')
                data[key] = val
        except ValueError:
            log.info('Trace')
            state = _failout(state, 'Failed parsing script output! Stdout must be JSON or a line of name=value pairs.')
            state['changes'].update(ret)
            return state
    changed = _is_true(data.get('changed', 'no'))
    if 'comment' in data:
        state['comment'] = data['comment']
        del data['comment']
    if changed:
        for key in ret:
            data.setdefault(key, ret[key])
        data['stdout'] = '' if is_json else data.get('stdout', '')[:idx]
        state['changes'] = data
    return state

def _failout(state, msg):
    log.info('Trace')
    state['comment'] = msg
    state['result'] = False
    return state

def _is_true(val):
    if val and str(val).lower() in ('true', 'yes', '1'):
        return True
    elif str(val).lower() in ('false', 'no', '0'):
        return False
    raise ValueError('Failed parsing boolean value: {}'.format(val))

def wait(name, cwd=None, root=None, runas=None, shell=None, env=(), stateful=False, umask=None, output_loglevel='debug', hide_output=False, use_vt=False, success_retcodes=None, success_stdout=None, success_stderr=None, **kwargs):
    """
    Run the given command only if the watch statement calls it.

    .. note::

        Use :mod:`cmd.run <salt.states.cmd.run>` together with :mod:`onchanges </ref/states/requisites#onchanges>`
        instead of :mod:`cmd.wait <salt.states.cmd.wait>`.

    name
        The command to execute, remember that the command will execute with the
        path and permissions of the salt-minion.

    cwd
        The current working directory to execute the command in, defaults to
        /root

    root
        Path to the root of the jail to use. If this parameter is set, the command
        will run inside a chroot

    runas
        The user name to run the command as

    shell
        The shell to use for execution, defaults to /bin/sh

    env
        A list of environment variables to be set prior to execution.
        Example:

        .. code-block:: yaml

            script-foo:
              cmd.wait:
                - env:
                  - BATCH: 'yes'

        .. warning::

            The above illustrates a common PyYAML pitfall, that **yes**,
            **no**, **on**, **off**, **true**, and **false** are all loaded as
            boolean ``True`` and ``False`` values, and must be enclosed in
            quotes to be used as strings. More info on this (and other) PyYAML
            idiosyncrasies can be found :ref:`here <yaml-idiosyncrasies>`.

        Variables as values are not evaluated. So $PATH in the following
        example is a literal '$PATH':

        .. code-block:: yaml

            script-bar:
              cmd.wait:
                - env: "PATH=/some/path:$PATH"

        One can still use the existing $PATH by using a bit of Jinja:

        .. code-block:: jinja

            {% set current_path = salt['environ.get']('PATH', '/bin:/usr/bin') %}

            mycommand:
              cmd.run:
                - name: ls -l /
                - env:
                  - PATH: {{ [current_path, '/my/special/bin']|join(':') }}

        .. note::
            When using environment variables on Windows, case-sensitivity
            matters, i.e. Windows uses `Path` as opposed to `PATH` for other
            systems.

    umask
         The umask (in octal) to use when running the command.

    stateful
        The command being executed is expected to return data about executing
        a state. For more information, see the :ref:`stateful-argument` section.

    creates
        Only run if the file specified by ``creates`` do not exist. If you
        specify a list of files then this state will only run if **any** of
        the files do not exist.

        .. versionadded:: 2014.7.0

    output_loglevel : debug
        Control the loglevel at which the output from the command is logged to
        the minion log.

        .. note::
            The command being run will still be logged at the ``debug``
            loglevel regardless, unless ``quiet`` is used for this value.

    hide_output : False
        Suppress stdout and stderr in the state's results.

        .. note::
            This is separate from ``output_loglevel``, which only handles how
            Salt logs to the minion log.

        .. versionadded:: 2018.3.0

    use_vt
        Use VT utils (saltstack) to stream the command output more
        interactively to the console and the logs.
        This is experimental.

    success_retcodes: This parameter will allow a list of
        non-zero return codes that should be considered a success.  If the
        return code returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 2019.2.0

    success_stdout: This parameter will allow a list of
        strings that when found in standard out should be considered a success.
        If stdout returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 3004

    success_stderr: This parameter will allow a list of
        strings that when found in standard error should be considered a success.
        If stderr returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 3004
    """
    return {'name': name, 'changes': {}, 'result': True, 'comment': ''}
watch = salt.utils.functools.alias_function(wait, 'watch')

def wait_script(name, source=None, template=None, cwd=None, runas=None, shell=None, env=None, stateful=False, umask=None, use_vt=False, output_loglevel='debug', hide_output=False, success_retcodes=None, success_stdout=None, success_stderr=None, **kwargs):
    """
    Download a script from a remote source and execute it only if a watch
    statement calls it.

    source
        The source script being downloaded to the minion, this source script is
        hosted on the salt master server.  If the file is located on the master
        in the directory named spam, and is called eggs, the source string is
        salt://spam/eggs

    template
        If this setting is applied then the named templating engine will be
        used to render the downloaded file, currently jinja, mako, and wempy
        are supported

    name
        The command to execute, remember that the command will execute with the
        path and permissions of the salt-minion.

    cwd
        The current working directory to execute the command in, defaults to
        /root

    runas
        The user name to run the command as

    shell
        The shell to use for execution, defaults to the shell grain

    env
        A list of environment variables to be set prior to execution.
        Example:

        .. code-block:: yaml

            salt://scripts/foo.sh:
              cmd.wait_script:
                - env:
                  - BATCH: 'yes'

        .. warning::

            The above illustrates a common PyYAML pitfall, that **yes**,
            **no**, **on**, **off**, **true**, and **false** are all loaded as
            boolean ``True`` and ``False`` values, and must be enclosed in
            quotes to be used as strings. More info on this (and other) PyYAML
            idiosyncrasies can be found :ref:`here <yaml-idiosyncrasies>`.

        Variables as values are not evaluated. So $PATH in the following
        example is a literal '$PATH':

        .. code-block:: yaml

            salt://scripts/bar.sh:
              cmd.wait_script:
                - env: "PATH=/some/path:$PATH"

        One can still use the existing $PATH by using a bit of Jinja:

        .. code-block:: jinja

            {% set current_path = salt['environ.get']('PATH', '/bin:/usr/bin') %}

            mycommand:
              cmd.run:
                - name: ls -l /
                - env:
                  - PATH: {{ [current_path, '/my/special/bin']|join(':') }}

        .. note::
            When using environment variables on Windows, case-sensitivity
            matters, i.e. Windows uses `Path` as opposed to `PATH` for other
            systems.

    umask
         The umask (in octal) to use when running the command.

    stateful
        The command being executed is expected to return data about executing
        a state. For more information, see the :ref:`stateful-argument` section.

    use_vt
        Use VT utils (saltstack) to stream the command output more
        interactively to the console and the logs.
        This is experimental.

    output_loglevel : debug
        Control the loglevel at which the output from the command is logged to
        the minion log.

        .. note::
            The command being run will still be logged at the ``debug``
            loglevel regardless, unless ``quiet`` is used for this value.

    hide_output : False
        Suppress stdout and stderr in the state's results.

        .. note::
            This is separate from ``output_loglevel``, which only handles how
            Salt logs to the minion log.

        .. versionadded:: 2018.3.0

    success_retcodes: This parameter will allow a list of
        non-zero return codes that should be considered a success.  If the
        return code returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 2019.2.0

    success_stdout: This parameter will allow a list of
        strings that when found in standard out should be considered a success.
        If stdout returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 3004

    success_stderr: This parameter will allow a list of
        strings that when found in standard error should be considered a success.
        If stderr returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 3004
    """
    return {'name': name, 'changes': {}, 'result': True, 'comment': ''}

def run(name, cwd=None, root=None, runas=None, shell=None, env=None, prepend_path=None, stateful=False, umask=None, output_loglevel='debug', hide_output=False, timeout=None, ignore_timeout=False, use_vt=False, success_retcodes=None, success_stdout=None, success_stderr=None, **kwargs):
    log.info('Trace')
    '\n    Run a command if certain circumstances are met.  Use ``cmd.wait`` if you\n    want to use the ``watch`` requisite.\n\n    .. note::\n\n       The ``**kwargs`` of ``cmd.run`` are passed down to one of the following\n       exec modules:\n\n       * ``cmdmod.run_all``: If used with default ``runas``\n       * ``cmdmod.run_chroot``: If used with non-``root`` value for ``runas``\n\n       For more information on what args are available for either of these,\n       refer to the :ref:`cmdmod documentation <cmdmod-module>`.\n\n    name\n        The command to execute, remember that the command will execute with the\n        path and permissions of the salt-minion.\n\n    cwd\n        The current working directory to execute the command in, defaults to\n        /root\n\n    root\n        Path to the root of the jail to use. If this parameter is set, the command\n        will run inside a chroot\n\n    runas\n        The user name (or uid) to run the command as\n\n    shell\n        The shell to use for execution, defaults to the shell grain\n\n    env\n        A list of environment variables to be set prior to execution.\n        Example:\n\n        .. code-block:: yaml\n\n            script-foo:\n              cmd.run:\n                - env:\n                  - BATCH: \'yes\'\n\n        .. warning::\n\n            The above illustrates a common PyYAML pitfall, that **yes**,\n            **no**, **on**, **off**, **true**, and **false** are all loaded as\n            boolean ``True`` and ``False`` values, and must be enclosed in\n            quotes to be used as strings. More info on this (and other) PyYAML\n            idiosyncrasies can be found :ref:`here <yaml-idiosyncrasies>`.\n\n        Variables as values are not evaluated. So $PATH in the following\n        example is a literal \'$PATH\':\n\n        .. code-block:: yaml\n\n            script-bar:\n              cmd.run:\n                - env: "PATH=/some/path:$PATH"\n\n        One can still use the existing $PATH by using a bit of Jinja:\n\n        .. code-block:: jinja\n\n            {% set current_path = salt[\'environ.get\'](\'PATH\', \'/bin:/usr/bin\') %}\n\n            mycommand:\n              cmd.run:\n                - name: ls -l /\n                - env:\n                  - PATH: {{ [current_path, \'/my/special/bin\']|join(\':\') }}\n\n        .. note::\n            When using environment variables on Windows, case-sensitivity\n            matters, i.e. Windows uses `Path` as opposed to `PATH` for other\n            systems.\n\n    prepend_path\n        $PATH segment to prepend (trailing \':\' not necessary) to $PATH. This is\n        an easier alternative to the Jinja workaround.\n\n        .. versionadded:: 2018.3.0\n\n    stateful\n        The command being executed is expected to return data about executing\n        a state. For more information, see the :ref:`stateful-argument` section.\n\n    umask\n        The umask (in octal) to use when running the command.\n\n    output_loglevel : debug\n        Control the loglevel at which the output from the command is logged to\n        the minion log.\n\n        .. note::\n            The command being run will still be logged at the ``debug``\n            loglevel regardless, unless ``quiet`` is used for this value.\n\n    hide_output : False\n        Suppress stdout and stderr in the state\'s results.\n\n        .. note::\n            This is separate from ``output_loglevel``, which only handles how\n            Salt logs to the minion log.\n\n        .. versionadded:: 2018.3.0\n\n    timeout\n        If the command has not terminated after timeout seconds, send the\n        subprocess sigterm, and if sigterm is ignored, follow up with sigkill\n\n    ignore_timeout\n        Ignore the timeout of commands, which is useful for running nohup\n        processes.\n\n        .. versionadded:: 2015.8.0\n\n    creates\n        Only run if the file specified by ``creates`` do not exist. If you\n        specify a list of files then this state will only run if **any** of\n        the files do not exist.\n\n        .. versionadded:: 2014.7.0\n\n    use_vt : False\n        Use VT utils (saltstack) to stream the command output more\n        interactively to the console and the logs.\n        This is experimental.\n\n    bg : False\n        If ``True``, run command in background and do not await or deliver its\n        results.\n\n        .. versionadded:: 2016.3.6\n\n    success_retcodes: This parameter will allow a list of\n        non-zero return codes that should be considered a success.  If the\n        return code returned from the run matches any in the provided list,\n        the return code will be overridden with zero.\n\n      .. versionadded:: 2019.2.0\n\n    success_stdout: This parameter will allow a list of\n        strings that when found in standard out should be considered a success.\n        If stdout returned from the run matches any in the provided list,\n        the return code will be overridden with zero.\n\n      .. versionadded:: 3004\n\n    success_stderr: This parameter will allow a list of\n        strings that when found in standard error should be considered a success.\n        If stderr returned from the run matches any in the provided list,\n        the return code will be overridden with zero.\n\n      .. versionadded:: 3004\n\n    .. note::\n\n        cmd.run supports the usage of ``reload_modules``. This functionality\n        allows you to force Salt to reload all modules. You should only use\n        ``reload_modules`` if your cmd.run does some sort of installation\n        (such as ``pip``), if you do not reload the modules future items in\n        your state which rely on the software being installed will fail.\n\n        .. code-block:: yaml\n\n            getpip:\n              cmd.run:\n                - name: /usr/bin/python /usr/local/sbin/get-pip.py\n                - unless: which pip\n                - require:\n                  - pkg: python\n                  - file: /usr/local/sbin/get-pip.py\n                - reload_modules: True\n\n    '
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    test_name = None
    if not isinstance(stateful, list):
        stateful = stateful is True
    elif isinstance(stateful, list) and 'test_name' in stateful[0]:
        test_name = stateful[0]['test_name']
    if __opts__['test'] and test_name:
        name = test_name
    if env is not None and (not isinstance(env, (list, dict))):
        ret['comment'] = "Invalidly-formatted 'env' parameter. See documentation."
        return ret
    cmd_kwargs = copy.deepcopy(kwargs)
    cmd_kwargs.update({'cwd': cwd, 'root': root, 'runas': runas, 'use_vt': use_vt, 'shell': shell or __grains__['shell'], 'env': env, 'prepend_path': prepend_path, 'umask': umask, 'output_loglevel': output_loglevel, 'hide_output': hide_output, 'success_retcodes': success_retcodes, 'success_stdout': success_stdout, 'success_stderr': success_stderr})
    if __opts__['test'] and (not test_name):
        ret['result'] = None
        ret['comment'] = 'Command "{}" would have been executed'.format(name)
        return _reinterpreted_state(ret) if stateful else ret
    if cwd and (not os.path.isdir(cwd)):
        ret['comment'] = 'Desired working directory "{}" is not available'.format(cwd)
        return ret
    try:
        log.info('Trace')
        run_cmd = 'cmd.run_all' if not root else 'cmd.run_chroot'
        cmd_all = __salt__[run_cmd](cmd=name, timeout=timeout, python_shell=True, **cmd_kwargs)
    except Exception as err:
        log.info('Trace')
        ret['comment'] = str(err)
        return ret
    ret['changes'] = cmd_all
    ret['result'] = not bool(cmd_all['retcode'])
    ret['comment'] = 'Command "{}" run'.format(name)
    if ignore_timeout:
        trigger = 'Timed out after'
        if ret['changes'].get('retcode') == 1 and trigger in ret['changes'].get('stdout'):
            ret['changes']['retcode'] = 0
            ret['result'] = True
    if stateful:
        ret = _reinterpreted_state(ret)
    if __opts__['test'] and cmd_all['retcode'] == 0 and ret['changes']:
        ret['result'] = None
    return ret

def script(name, source=None, template=None, cwd=None, runas=None, password=None, shell=None, env=None, stateful=False, umask=None, timeout=None, use_vt=False, output_loglevel='debug', hide_output=False, defaults=None, context=None, success_retcodes=None, success_stdout=None, success_stderr=None, **kwargs):
    log.info('Trace')
    '\n    Download a script and execute it with specified arguments.\n\n    source\n        The location of the script to download. If the file is located on the\n        master in the directory named spam, and is called eggs, the source\n        string is salt://spam/eggs\n\n    template\n        If this setting is applied then the named templating engine will be\n        used to render the downloaded file. Currently jinja, mako, and wempy\n        are supported\n\n    name\n        Either "cmd arg1 arg2 arg3..." (cmd is not used) or a source\n        "salt://...".\n\n    cwd\n        The current working directory to execute the command in, defaults to\n        /root\n\n    runas\n        Specify an alternate user to run the command. The default\n        behavior is to run as the user under which Salt is running. If running\n        on a Windows minion you must also use the ``password`` argument, and\n        the target user account must be in the Administrators group.\n\n        .. note::\n\n            For Windows users, specifically Server users, it may be necessary\n            to specify your runas user using the User Logon Name instead of the\n            legacy logon name. Traditionally, logons would be in the following\n            format.\n\n                ``Domain/user``\n\n            In the event this causes issues when executing scripts, use the UPN\n            format which looks like the following.\n\n                ``user@domain.local``\n\n            More information <https://github.com/saltstack/salt/issues/55080>\n\n    password\n\n    .. versionadded:: 3000\n\n        Windows only. Required when specifying ``runas``. This\n        parameter will be ignored on non-Windows platforms.\n\n    shell\n        The shell to use for execution. The default is set in grains[\'shell\']\n\n    env\n        A list of environment variables to be set prior to execution.\n        Example:\n\n        .. code-block:: yaml\n\n            salt://scripts/foo.sh:\n              cmd.script:\n                - env:\n                  - BATCH: \'yes\'\n\n        .. warning::\n\n            The above illustrates a common PyYAML pitfall, that **yes**,\n            **no**, **on**, **off**, **true**, and **false** are all loaded as\n            boolean ``True`` and ``False`` values, and must be enclosed in\n            quotes to be used as strings. More info on this (and other) PyYAML\n            idiosyncrasies can be found :ref:`here <yaml-idiosyncrasies>`.\n\n        Variables as values are not evaluated. So $PATH in the following\n        example is a literal \'$PATH\':\n\n        .. code-block:: yaml\n\n            salt://scripts/bar.sh:\n              cmd.script:\n                - env: "PATH=/some/path:$PATH"\n\n        One can still use the existing $PATH by using a bit of Jinja:\n\n        .. code-block:: jinja\n\n            {% set current_path = salt[\'environ.get\'](\'PATH\', \'/bin:/usr/bin\') %}\n\n            mycommand:\n              cmd.run:\n                - name: ls -l /\n                - env:\n                  - PATH: {{ [current_path, \'/my/special/bin\']|join(\':\') }}\n\n        .. note::\n            When using environment variables on Windows, case-sensitivity\n            matters, i.e. Windows uses `Path` as opposed to `PATH` for other\n            systems.\n\n    saltenv : ``base``\n        The Salt environment to use\n\n    umask\n         The umask (in octal) to use when running the command.\n\n    stateful\n        The command being executed is expected to return data about executing\n        a state. For more information, see the :ref:`stateful-argument` section.\n\n    timeout\n        If the command has not terminated after timeout seconds, send the\n        subprocess sigterm, and if sigterm is ignored, follow up with sigkill\n\n    args\n        String of command line args to pass to the script.  Only used if no\n        args are specified as part of the `name` argument. To pass a string\n        containing spaces in YAML, you will need to doubly-quote it:  "arg1\n        \'arg two\' arg3"\n\n    creates\n        Only run if the file specified by ``creates`` do not exist. If you\n        specify a list of files then this state will only run if **any** of\n        the files do not exist.\n\n        .. versionadded:: 2014.7.0\n\n    use_vt\n        Use VT utils (saltstack) to stream the command output more\n        interactively to the console and the logs.\n        This is experimental.\n\n    context\n        .. versionadded:: 2016.3.0\n\n        Overrides default context variables passed to the template.\n\n    defaults\n        .. versionadded:: 2016.3.0\n\n        Default context passed to the template.\n\n    output_loglevel : debug\n        Control the loglevel at which the output from the command is logged to\n        the minion log.\n\n        .. note::\n            The command being run will still be logged at the ``debug``\n            loglevel regardless, unless ``quiet`` is used for this value.\n\n    hide_output : False\n        Suppress stdout and stderr in the state\'s results.\n\n        .. note::\n            This is separate from ``output_loglevel``, which only handles how\n            Salt logs to the minion log.\n\n        .. versionadded:: 2018.3.0\n\n    success_retcodes: This parameter will allow a list of\n        non-zero return codes that should be considered a success.  If the\n        return code returned from the run matches any in the provided list,\n        the return code will be overridden with zero.\n\n      .. versionadded:: 2019.2.0\n\n    success_stdout: This parameter will allow a list of\n        strings that when found in standard out should be considered a success.\n        If stdout returned from the run matches any in the provided list,\n        the return code will be overridden with zero.\n\n      .. versionadded:: 3004\n\n    success_stderr: This parameter will allow a list of\n        strings that when found in standard error should be considered a success.\n        If stderr returned from the run matches any in the provided list,\n        the return code will be overridden with zero.\n\n      .. versionadded:: 3004\n    '
    test_name = None
    if not isinstance(stateful, list):
        stateful = stateful is True
    elif isinstance(stateful, list) and 'test_name' in stateful[0]:
        test_name = stateful[0]['test_name']
    if __opts__['test'] and test_name:
        name = test_name
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if env is not None and (not isinstance(env, (list, dict))):
        ret['comment'] = "Invalidly-formatted 'env' parameter. See documentation."
        return ret
    if context and (not isinstance(context, dict)):
        ret['comment'] = "Invalidly-formatted 'context' parameter. Must be formed as a dict."
        return ret
    if defaults and (not isinstance(defaults, dict)):
        ret['comment'] = "Invalidly-formatted 'defaults' parameter. Must be formed as a dict."
        return ret
    if runas and salt.utils.platform.is_windows() and (not password):
        ret['comment'] = 'Must supply a password if runas argument is used on Windows.'
        return ret
    tmpctx = defaults if defaults else {}
    if context:
        tmpctx.update(context)
    cmd_kwargs = copy.deepcopy(kwargs)
    cmd_kwargs.update({'runas': runas, 'password': password, 'shell': shell or __grains__['shell'], 'env': env, 'cwd': cwd, 'template': template, 'umask': umask, 'timeout': timeout, 'output_loglevel': output_loglevel, 'hide_output': hide_output, 'use_vt': use_vt, 'context': tmpctx, 'saltenv': __env__, 'success_retcodes': success_retcodes, 'success_stdout': success_stdout, 'success_stderr': success_stderr})
    run_check_cmd_kwargs = {'cwd': cwd, 'runas': runas, 'shell': shell or __grains__['shell']}
    if source is None:
        source = name
    if not cmd_kwargs.get('args', None) and len(name.split()) > 1:
        cmd_kwargs.update({'args': name.split(' ', 1)[1]})
    if __opts__['test'] and (not test_name):
        ret['result'] = None
        ret['comment'] = "Command '{}' would have been executed".format(name)
        return _reinterpreted_state(ret) if stateful else ret
    if cwd and (not os.path.isdir(cwd)):
        ret['comment'] = 'Desired working directory "{}" is not available'.format(cwd)
        return ret
    try:
        log.info('Trace')
        cmd_all = __salt__['cmd.script'](source, python_shell=True, **cmd_kwargs)
    except (CommandExecutionError, SaltRenderError, OSError) as err:
        log.info('Trace')
        ret['comment'] = str(err)
        return ret
    ret['changes'] = cmd_all
    if kwargs.get('retcode', False):
        ret['result'] = not bool(cmd_all)
    else:
        ret['result'] = not bool(cmd_all['retcode'])
    if ret.get('changes', {}).get('cache_error'):
        ret['comment'] = "Unable to cache script {} from saltenv '{}'".format(source, __env__)
    else:
        ret['comment'] = "Command '{}' run".format(name)
    if stateful:
        ret = _reinterpreted_state(ret)
    if __opts__['test'] and cmd_all['retcode'] == 0 and ret['changes']:
        ret['result'] = None
    return ret

def call(name, func, args=(), kws=None, output_loglevel='debug', hide_output=False, use_vt=False, **kwargs):
    """
    Invoke a pre-defined Python function with arguments specified in the state
    declaration. This function is mainly used by the
    :mod:`salt.renderers.pydsl` renderer.

    In addition, the ``stateful`` argument has no effects here.

    The return value of the invoked function will be interpreted as follows.

    If it's a dictionary then it will be passed through to the state system,
    which expects it to have the usual structure returned by any salt state
    function.

    Otherwise, the return value (denoted as ``result`` in the code below) is
    expected to be a JSON serializable object, and this dictionary is returned:

    .. code-block:: python

        {
            'name': name
            'changes': {'retval': result},
            'result': True if result is None else bool(result),
            'comment': result if isinstance(result, str) else ''
        }
    """
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    cmd_kwargs = {'cwd': kwargs.get('cwd'), 'runas': kwargs.get('user'), 'shell': kwargs.get('shell') or __grains__['shell'], 'env': kwargs.get('env'), 'use_vt': use_vt, 'output_loglevel': output_loglevel, 'hide_output': hide_output, 'umask': kwargs.get('umask')}
    if not kws:
        kws = {}
    result = func(*args, **kws)
    if isinstance(result, dict):
        ret.update(result)
        return ret
    else:
        ret['changes'] = {'retval': result}
        ret['result'] = True if result is None else bool(result)
        if isinstance(result, str):
            ret['comment'] = result
        return ret

def wait_call(name, func, args=(), kws=None, stateful=False, use_vt=False, output_loglevel='debug', hide_output=False, **kwargs):
    return {'name': name, 'changes': {}, 'result': True, 'comment': ''}

def mod_watch(name, **kwargs):
    """
    Execute a cmd function based on a watch call

    .. note::
        This state exists to support special handling of the ``watch``
        :ref:`requisite <requisites>`. It should not be called directly.

        Parameters for this function should be set by the state being triggered.
    """
    if kwargs['sfun'] in ('wait', 'run', 'watch'):
        if kwargs.get('stateful'):
            kwargs.pop('stateful')
            return _reinterpreted_state(run(name, **kwargs))
        return run(name, **kwargs)
    elif kwargs['sfun'] == 'wait_script' or kwargs['sfun'] == 'script':
        if kwargs.get('stateful'):
            kwargs.pop('stateful')
            return _reinterpreted_state(script(name, **kwargs))
        return script(name, **kwargs)
    elif kwargs['sfun'] == 'wait_call' or kwargs['sfun'] == 'call':
        if kwargs.get('func'):
            func = kwargs.pop('func')
            return call(name, func, **kwargs)
        else:
            return {'name': name, 'changes': {}, 'comment': 'cmd.{0[sfun]} needs a named parameter func'.format(kwargs), 'result': False}
    return {'name': name, 'changes': {}, 'comment': 'cmd.{0[sfun]} does not work with the watch requisite, please use cmd.wait or cmd.wait_script'.format(kwargs), 'result': False}