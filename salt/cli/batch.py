"""
Execute batch runs
"""
import copy
import logging
import math
import time
from datetime import datetime, timedelta
import salt.client
import salt.exceptions
import salt.output
import salt.utils.stringutils
log = logging.getLogger(__name__)

class Batch:
    """
    Manage the execution of batch runs

    """

    def __init__(self, opts, eauth=None, quiet=False, _parser=None):
        """
        :param dict opts: A config options dictionary.

        :param dict eauth: An eauth config to use.

                           The default is an empty dict.

        :param bool quiet: Suppress printing to stdout

                           The default is False.
        """
        self.opts = opts
        self.eauth = eauth if eauth else {}
        self.pub_kwargs = eauth if eauth else {}
        self.quiet = quiet
        self.options = _parser
        self.local = salt.client.get_local_client(opts['conf_file'], listen=True)

    def gather_minions(self):
        """
        Return a list of minions to use for the batch run
        """
        args = [self.opts['tgt'], 'test.ping', [], self.opts['timeout']]
        selected_target_option = self.opts.get('selected_target_option', None)
        if selected_target_option is not None:
            args.append(selected_target_option)
        else:
            args.append(self.opts.get('tgt_type', 'glob'))
        self.pub_kwargs['yield_pub_data'] = True
        ping_gen = self.local.cmd_iter(*args, gather_job_timeout=self.opts['gather_job_timeout'], **self.pub_kwargs)
        fret = set()
        nret = set()
        for ret in ping_gen:
            if ('minions' and 'jid') in ret:
                for minion in ret['minions']:
                    nret.add(minion)
                continue
            else:
                try:
                    m = next(iter(ret.keys()))
                except StopIteration:
                    if not self.quiet:
                        salt.utils.stringutils.print_cli('No minions matched the target.')
                    break
                if m is not None:
                    fret.add(m)
        return (list(fret), ping_gen, nret.difference(fret))

    def get_bnum(self):
        """
        Return the active number of minions to maintain
        """
        partition = lambda x: float(x) / 100.0 * len(self.minions)
        try:
            log.info('Trace')
            if isinstance(self.opts['batch'], str) and '%' in self.opts['batch']:
                res = partition(float(self.opts['batch'].strip('%')))
                if res < 1:
                    return int(math.ceil(res))
                else:
                    return int(res)
            else:
                return int(self.opts['batch'])
        except ValueError:
            log.info('Trace')
            if not self.quiet:
                salt.utils.stringutils.print_cli('Invalid batch data sent: {}\nData must be in the form of %10, 10% or 3'.format(self.opts['batch']))

    def __update_wait(self, wait):
        now = datetime.now()
        i = 0
        while i < len(wait) and wait[i] <= now:
            i += 1
        if i:
            del wait[:i]

    def run(self):
        """
        Execute the batch run
        """
        (self.minions, self.ping_gen, self.down_minions) = self.gather_minions()
        args = [[], self.opts['fun'], self.opts['arg'], self.opts['timeout'], 'list']
        bnum = self.get_bnum()
        if not self.minions:
            return
        to_run = copy.deepcopy(self.minions)
        active = []
        ret = {}
        iters = []
        bwait = self.opts.get('batch_wait', 0)
        wait = []
        if self.options:
            show_jid = self.options.show_jid
            show_verbose = self.options.verbose
        else:
            show_jid = False
            show_verbose = False
        minion_tracker = {}
        if not self.quiet:
            for down_minion in self.down_minions:
                salt.utils.stringutils.print_cli('Minion {} did not respond. No job will be sent.'.format(down_minion))
        while len(ret) < len(self.minions):
            next_ = []
            if bwait and wait:
                self.__update_wait(wait)
            if len(to_run) <= bnum - len(wait) and (not active):
                while to_run:
                    next_.append(to_run.pop())
            else:
                for i in range(bnum - len(active) - len(wait)):
                    if to_run:
                        minion_id = to_run.pop()
                        if isinstance(minion_id, dict):
                            next_.append(next(iter(minion_id)))
                        else:
                            next_.append(minion_id)
            active += next_
            args[0] = next_
            if next_:
                if not self.quiet:
                    salt.utils.stringutils.print_cli('\nExecuting run on {}\n'.format(sorted(next_)))
                return_value = self.opts.get('return', self.opts.get('ret', ''))
                new_iter = self.local.cmd_iter_no_block(*args, raw=self.opts.get('raw', False), ret=return_value, show_jid=show_jid, verbose=show_verbose, gather_job_timeout=self.opts['gather_job_timeout'], **self.eauth)
                iters.append(new_iter)
                minion_tracker[new_iter] = {}
                minion_tracker[new_iter]['minions'] = next_
                minion_tracker[new_iter]['active'] = True
            else:
                time.sleep(0.02)
            parts = {}
            for ping_ret in self.ping_gen:
                if ping_ret is None:
                    break
                m = next(iter(ping_ret.keys()))
                if m not in self.minions:
                    self.minions.append(m)
                    to_run.append(m)
            for queue in iters:
                try:
                    ncnt = 0
                    while True:
                        part = next(queue)
                        if part is None:
                            time.sleep(0.01)
                            ncnt += 1
                            if ncnt > 5:
                                break
                            continue
                        if self.opts.get('raw'):
                            parts.update({part['data']['id']: part})
                            if part['data']['id'] in minion_tracker[queue]['minions']:
                                minion_tracker[queue]['minions'].remove(part['data']['id'])
                            else:
                                salt.utils.stringutils.print_cli('minion {} was already deleted from tracker, probably a duplicate key'.format(part['id']))
                        else:
                            parts.update(part)
                            for id in part:
                                if id in minion_tracker[queue]['minions']:
                                    minion_tracker[queue]['minions'].remove(id)
                                else:
                                    salt.utils.stringutils.print_cli('minion {} was already deleted from tracker, probably a duplicate key'.format(id))
                except StopIteration:
                    if queue in minion_tracker:
                        minion_tracker[queue]['active'] = False
                        for minion in minion_tracker[queue]['minions']:
                            if minion not in parts:
                                parts[minion] = {}
                                parts[minion]['ret'] = {}
            for (minion, data) in parts.items():
                if minion in active:
                    active.remove(minion)
                    if bwait:
                        wait.append(datetime.now() + timedelta(seconds=bwait))
                failhard = False
                failed_check = data.get('failed', False)
                if failed_check:
                    log.debug("Minion '%s' failed to respond to job sent, data '%s'", minion, data)
                    if not self.quiet:
                        salt.utils.stringutils.print_cli("Minion '%s' failed to respond to job sent", minion)
                    if self.opts.get('failhard'):
                        failhard = True
                else:
                    retcode = 0
                    if 'retcode' in data:
                        if isinstance(data['retcode'], dict):
                            try:
                                data['retcode'] = max(data['retcode'].values())
                            except ValueError:
                                data['retcode'] = 0
                        if self.opts.get('failhard') and data['retcode'] > 0:
                            failhard = True
                        retcode = data['retcode']
                    if self.opts.get('raw'):
                        ret[minion] = data
                        yield (data, retcode)
                    else:
                        ret[minion] = data['ret']
                        yield ({minion: data['ret']}, retcode)
                    if not self.quiet:
                        ret[minion] = data['ret']
                        data[minion] = data.pop('ret')
                        if 'out' in data:
                            out = data.pop('out')
                        else:
                            out = None
                        salt.output.display_output(data, out, self.opts)
                if failhard:
                    log.error('Minion %s returned with non-zero exit code. Batch run stopped due to failhard', minion)
                    return
            for queue in minion_tracker:
                if not minion_tracker[queue]['active'] and queue in iters:
                    iters.remove(queue)
                    for minion in minion_tracker[queue]['minions']:
                        if minion in active:
                            active.remove(minion)
                            if bwait:
                                wait.append(datetime.now() + timedelta(seconds=bwait))
        self.local.destroy()