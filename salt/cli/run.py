import salt.defaults.exitcodes
import salt.utils.parsers
import salt.utils.profile
from salt.exceptions import SaltClientError
from salt.utils.verify import check_user
import logging
log = logging.getLogger(__name__)

class SaltRun(salt.utils.parsers.SaltRunOptionParser):
    """
    Used to execute Salt runners
    """

    def run(self):
        """
        Execute salt-run
        """
        import salt.runner
        self.parse_args()
        profiling_enabled = self.options.profiling_enabled
        runner = salt.runner.Runner(self.config)
        if self.options.doc:
            runner.print_docs()
            self.exit(salt.defaults.exitcodes.EX_OK)
        try:
            log.info('Trace')
            if check_user(self.config['user']):
                pr = salt.utils.profile.activate_profile(profiling_enabled)
                try:
                    log.info('Trace')
                    ret = runner.run()
                    if isinstance(ret, dict) and 'retcode' in ret:
                        self.exit(ret['retcode'])
                    elif isinstance(ret, dict) and 'retcode' in ret.get('data', {}):
                        self.exit(ret['data']['retcode'])
                finally:
                    salt.utils.profile.output_profile(pr, stats_path=self.options.profiling_path, stop=True)
        except SaltClientError as exc:
            log.info('Trace')
            raise SystemExit(str(exc))