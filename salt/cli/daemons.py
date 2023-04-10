"""
Make me some salt!
"""
import logging
import os
import warnings
import salt.utils.kinds as kinds
from salt.exceptions import SaltClientError, SaltSystemExit, get_error_message
from salt.utils import migrations
from salt.utils.platform import is_junos
from salt.utils.process import HAS_PSUTIL
log = logging.getLogger(__name__)
warnings.filterwarnings('once', '', DeprecationWarning, '^(salt|salt\\.(.*))$', append=True)
warnings.filterwarnings('ignore', 'With-statements now directly support multiple context managers', DeprecationWarning, append=True)
warnings.filterwarnings('ignore', '^Module backports was already imported from (.*), but (.*) is being added to sys.path$', UserWarning, append=True)
try:
    log.info('Trace')
    import salt.utils.parsers
    from salt.utils.verify import check_user, verify_env, verify_socket
    from salt.utils.zeromq import ip_bracket
except ImportError as exc:
    log.info('Trace')
    if exc.args[0] != 'No module named _msgpack':
        log.info('Trace')
        raise

class DaemonsMixin:
    """
    Uses the same functions for all daemons
    """

    def verify_hash_type(self):
        """
        Verify and display a nag-messsage to the log if vulnerable hash-type is used.

        :return:
        """
        if self.config['hash_type'].lower() in ['md5', 'sha1']:
            log.warning('IMPORTANT: Do not use %s hashing algorithm! Please set "hash_type" to sha256 in Salt %s config!', self.config['hash_type'], self.__class__.__name__)

    def action_log_info(self, action):
        """
        Say daemon starting.

        :param action
        :return:
        """
        log.info('%s the Salt %s', action, self.__class__.__name__)

    def start_log_info(self):
        """
        Say daemon starting.

        :return:
        """
        log.info('The Salt %s is starting up', self.__class__.__name__)

    def shutdown_log_info(self):
        """
        Say daemon shutting down.

        :return:
        """
        log.info('The Salt %s is shut down', self.__class__.__name__)

    def environment_failure(self, error):
        """
        Log environment failure for the daemon and exit with the error code.

        :param error:
        :return:
        """
        log.exception('Failed to create environment for %s: %s', self.__class__.__name__, get_error_message(error))
        self.shutdown(error)

class Master(salt.utils.parsers.MasterOptionParser, DaemonsMixin):
    """
    Creates a master server
    """

    def _handle_signals(self, signum, sigframe):
        if hasattr(self.master, 'process_manager'):
            self.master.process_manager._handle_signals(signum, sigframe)
        super()._handle_signals(signum, sigframe)

    def prepare(self):
        """
        Run the preparation sequence required to start a salt master server.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).prepare()
        """
        super().prepare()
        try:
            if self.config['verify_env']:
                v_dirs = [self.config['pki_dir'], os.path.join(self.config['pki_dir'], 'minions'), os.path.join(self.config['pki_dir'], 'minions_pre'), os.path.join(self.config['pki_dir'], 'minions_denied'), os.path.join(self.config['pki_dir'], 'minions_autosign'), os.path.join(self.config['pki_dir'], 'minions_rejected'), self.config['cachedir'], os.path.join(self.config['cachedir'], 'jobs'), os.path.join(self.config['cachedir'], 'proc'), self.config['sock_dir'], self.config['token_dir'], self.config['syndic_dir'], self.config['sqlite_queue_dir']]
                verify_env(v_dirs, self.config['user'], permissive=self.config['permissive_pki_access'], root_dir=self.config['root_dir'], pki_dir=self.config['pki_dir'])
                for syndic_file in os.listdir(self.config['syndic_dir']):
                    os.remove(os.path.join(self.config['syndic_dir'], syndic_file))
        except OSError as error:
            self.environment_failure(error)
        self.action_log_info('Setting up')
        if not verify_socket(self.config['interface'], self.config['publish_port'], self.config['ret_port']):
            self.shutdown(4, 'The ports are not available to bind')
        self.config['interface'] = ip_bracket(self.config['interface'])
        migrations.migrate_paths(self.config)
        import salt.master
        self.master = salt.master.Master(self.config)
        self.daemonize_if_required()
        self.set_pidfile()
        salt.utils.process.notify_systemd()

    def start(self):
        """
        Start the actual master.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).start()

        NOTE: Run any required code before calling `super()`.
        """
        super().start()
        if check_user(self.config['user']):
            self.action_log_info('Starting up')
            self.verify_hash_type()
            self.master.start()

    def shutdown(self, exitcode=0, exitmsg=None):
        """
        If sub-classed, run any shutdown operations on this method.
        """
        self.shutdown_log_info()
        msg = 'The salt master is shutdown. '
        if exitmsg is not None:
            log.info('Trace')
            exitmsg = msg + exitmsg
        else:
            log.info('Trace')
            exitmsg = msg.strip()
        super().shutdown(exitcode, exitmsg)

class Minion(salt.utils.parsers.MinionOptionParser, DaemonsMixin):
    """
    Create a minion server
    """

    def _handle_signals(self, signum, sigframe):
        if hasattr(self.minion, 'stop'):
            self.minion.stop(signum)
        super()._handle_signals(signum, sigframe)

    def prepare(self):
        """
        Run the preparation sequence required to start a salt minion.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).prepare()
        """
        super().prepare()
        try:
            if self.config['verify_env']:
                confd = self.config.get('default_include')
                if confd:
                    if '*' in confd:
                        confd = os.path.dirname(confd)
                    if not os.path.isabs(confd):
                        confd = os.path.join(os.path.dirname(self.config['conf_file']), confd)
                else:
                    confd = os.path.join(os.path.dirname(self.config['conf_file']), 'minion.d')
                v_dirs = [self.config['pki_dir'], self.config['cachedir'], self.config['sock_dir'], self.config['extension_modules'], confd]
                verify_env(v_dirs, self.config['user'], permissive=self.config['permissive_pki_access'], root_dir=self.config['root_dir'], pki_dir=self.config['pki_dir'])
        except OSError as error:
            self.environment_failure(error)
        log.info('Setting up the Salt Minion "%s"', self.config['id'])
        migrations.migrate_paths(self.config)
        if HAS_PSUTIL and (not self.claim_process_responsibility()) or (not HAS_PSUTIL and self.check_running()):
            self.action_log_info('An instance is already running. Exiting')
            self.shutdown(1)
        transport = self.config.get('transport').lower()
        try:
            log.info('Trace')
            import salt.minion
            self.daemonize_if_required()
            self.set_pidfile()
            if self.config.get('master_type') == 'func':
                salt.minion.eval_master_func(self.config)
            self.minion = salt.minion.MinionManager(self.config)
        except Exception:
            log.error('An error occured while setting up the minion manager', exc_info=True)
            self.shutdown(1)

    def start(self):
        """
        Start the actual minion.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).start()

        NOTE: Run any required code before calling `super()`.
        """
        super().start()
        while True:
            try:
                self._real_start()
            except SaltClientError as exc:
                log.info('Trace')
                if self.options.daemon:
                    continue
            break

    def _real_start(self):
        try:
            if check_user(self.config['user']):
                self.action_log_info('Starting up')
                self.verify_hash_type()
                self.minion.tune_in()
                if self.minion.restart:
                    log.info('Trace')
                    raise SaltClientError('Minion could not connect to Master')
        except (KeyboardInterrupt, SaltSystemExit) as error:
            self.action_log_info('Stopping')
            if isinstance(error, KeyboardInterrupt):
                log.warning('Exiting on Ctrl-c')
                self.shutdown()
            else:
                log.error(error)
                self.shutdown(error.code)

    def call(self, cleanup_protecteds):
        """
        Start the actual minion as a caller minion.

        cleanup_protecteds is list of yard host addresses that should not be
        cleaned up this is to fix race condition when salt-caller minion starts up

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).start()

        NOTE: Run any required code before calling `super()`.
        """
        try:
            self.prepare()
            if check_user(self.config['user']):
                self.minion.opts['__role'] = kinds.APPL_KIND_NAMES[kinds.applKinds.caller]
                self.minion.call_in()
        except (KeyboardInterrupt, SaltSystemExit) as exc:
            self.action_log_info('Stopping')
            if isinstance(exc, KeyboardInterrupt):
                log.warning('Exiting on Ctrl-c')
                self.shutdown()
            else:
                log.error(exc)
                self.shutdown(exc.code)

    def shutdown(self, exitcode=0, exitmsg=None):
        """
        If sub-classed, run any shutdown operations on this method.

        :param exitcode
        :param exitmsg
        """
        self.action_log_info('Shutting down')
        if hasattr(self, 'minion') and hasattr(self.minion, 'destroy'):
            log.info('Trace')
            self.minion.destroy()
        super().shutdown(exitcode, 'The Salt {} is shutdown. {}'.format(self.__class__.__name__, exitmsg or '').strip())

class ProxyMinion(salt.utils.parsers.ProxyMinionOptionParser, DaemonsMixin):
    """
    Create a proxy minion server
    """

    def _handle_signals(self, signum, sigframe):
        self.minion.stop(signum)
        super()._handle_signals(signum, sigframe)

    def prepare(self):
        """
        Run the preparation sequence required to start a salt proxy minion.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).prepare()
        """
        super().prepare()
        if not is_junos():
            if not self.values.proxyid:
                self.error('salt-proxy requires --proxyid')
        try:
            if self.config['verify_env']:
                confd = self.config.get('default_include')
                if confd:
                    if '*' in confd:
                        confd = os.path.dirname(confd)
                    if not os.path.isabs(confd):
                        confd = os.path.join(os.path.dirname(self.config['conf_file']), confd)
                else:
                    confd = os.path.join(os.path.dirname(self.config['conf_file']), 'proxy.d')
                v_dirs = [self.config['pki_dir'], self.config['cachedir'], self.config['sock_dir'], self.config['extension_modules'], confd]
                verify_env(v_dirs, self.config['user'], permissive=self.config['permissive_pki_access'], root_dir=self.config['root_dir'], pki_dir=self.config['pki_dir'])
        except OSError as error:
            self.environment_failure(error)
        self.action_log_info('Setting up "{}"'.format(self.config['id']))
        migrations.migrate_paths(self.config)
        if self.check_running():
            self.action_log_info('An instance is already running. Exiting')
            self.shutdown(1)
        import salt.minion
        self.daemonize_if_required()
        self.set_pidfile()
        if self.config.get('master_type') == 'func':
            salt.minion.eval_master_func(self.config)
        self.minion = salt.minion.ProxyMinionManager(self.config)

    def start(self):
        """
        Start the actual proxy minion.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).start()

        NOTE: Run any required code before calling `super()`.
        """
        super().start()
        try:
            if check_user(self.config['user']):
                self.action_log_info('The Proxy Minion is starting up')
                self.verify_hash_type()
                self.minion.tune_in()
                if self.minion.restart:
                    log.info('Trace')
                    raise SaltClientError('Proxy Minion could not connect to Master')
        except (KeyboardInterrupt, SaltSystemExit) as exc:
            self.action_log_info('Proxy Minion Stopping')
            if isinstance(exc, KeyboardInterrupt):
                log.warning('Exiting on Ctrl-c')
                self.shutdown()
            else:
                log.error(exc)
                self.shutdown(exc.code)

    def shutdown(self, exitcode=0, exitmsg=None):
        """
        If sub-classed, run any shutdown operations on this method.

        :param exitcode
        :param exitmsg
        """
        if hasattr(self, 'minion') and 'proxymodule' in self.minion.opts:
            proxy_fn = self.minion.opts['proxymodule'].loaded_base_name + '.shutdown'
            self.minion.opts['proxymodule'][proxy_fn](self.minion.opts)
        self.action_log_info('Shutting down')
        super().shutdown(exitcode, 'The Salt {} is shutdown. {}'.format(self.__class__.__name__, exitmsg or '').strip())

class Syndic(salt.utils.parsers.SyndicOptionParser, DaemonsMixin):
    """
    Create a syndic server
    """

    def prepare(self):
        """
        Run the preparation sequence required to start a salt syndic minion.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).prepare()
        """
        super().prepare()
        try:
            if self.config['verify_env']:
                verify_env([self.config['pki_dir'], self.config['cachedir'], self.config['sock_dir'], self.config['extension_modules']], self.config['user'], permissive=self.config['permissive_pki_access'], root_dir=self.config['root_dir'], pki_dir=self.config['pki_dir'])
        except OSError as error:
            self.environment_failure(error)
        self.action_log_info('Setting up "{}"'.format(self.config['id']))
        import salt.minion
        self.daemonize_if_required()
        self.syndic = salt.minion.SyndicManager(self.config)
        self.set_pidfile()

    def start(self):
        """
        Start the actual syndic.

        If sub-classed, don't **ever** forget to run:

            super(YourSubClass, self).start()

        NOTE: Run any required code before calling `super()`.
        """
        super().start()
        if check_user(self.config['user']):
            self.action_log_info('Starting up')
            self.verify_hash_type()
            try:
                log.info('Trace')
                self.syndic.tune_in()
            except KeyboardInterrupt:
                self.action_log_info('Stopping')
                self.shutdown()

    def shutdown(self, exitcode=0, exitmsg=None):
        """
        If sub-classed, run any shutdown operations on this method.

        :param exitcode
        :param exitmsg
        """
        self.action_log_info('Shutting down')
        super().shutdown(exitcode, 'The Salt {} is shutdown. {}'.format(self.__class__.__name__, exitmsg or '').strip())