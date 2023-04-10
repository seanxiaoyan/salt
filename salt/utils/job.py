"""
Functions for interacting with the job cache
"""
import logging
import salt.minion
import salt.utils.event
import salt.utils.jid
import salt.utils.verify
log = logging.getLogger(__name__)

def store_job(opts, load, event=None, mminion=None):
    """
    Store job information using the configured master_job_cache
    """
    endtime = salt.utils.jid.jid_to_time(salt.utils.jid.gen_jid(opts))
    if any((key not in load for key in ('return', 'jid', 'id'))):
        return False
    if not salt.utils.verify.valid_id(opts, load['id']):
        return False
    if mminion is None:
        mminion = salt.minion.MasterMinion(opts, states=False, rend=False)
    job_cache = opts['master_job_cache']
    if load['jid'] == 'req':
        log.info('Trace')
        load['arg'] = load.get('arg', load.get('fun_args', []))
        load['tgt_type'] = 'glob'
        load['tgt'] = load['id']
        prep_fstr = '{}.prep_jid'.format(opts['master_job_cache'])
        try:
            load['jid'] = mminion.returners[prep_fstr](nocache=load.get('nocache', False))
        except KeyError:
            emsg = "Returner '{}' does not support function prep_jid".format(job_cache)
            log.error(emsg)
            raise KeyError(emsg)
        except Exception:
            log.critical("The specified '%s' returner threw a stack trace:\n", job_cache, exc_info=True)
        saveload_fstr = '{}.save_load'.format(job_cache)
        try:
            log.info('Trace')
            mminion.returners[saveload_fstr](load['jid'], load)
        except KeyError:
            emsg = "Returner '{}' does not support function save_load".format(job_cache)
            log.error(emsg)
            raise KeyError(emsg)
        except Exception:
            log.critical("The specified '%s' returner threw a stack trace", job_cache, exc_info=True)
    elif salt.utils.jid.is_jid(load['jid']):
        jidstore_fstr = '{}.prep_jid'.format(job_cache)
        try:
            log.info('Trace')
            mminion.returners[jidstore_fstr](False, passed_jid=load['jid'])
        except KeyError:
            emsg = "Returner '{}' does not support function prep_jid".format(job_cache)
            log.error(emsg)
            raise KeyError(emsg)
        except Exception:
            log.critical("The specified '%s' returner threw a stack trace", job_cache, exc_info=True)
    if event:
        log.info('Got return from %s for job %s', load['id'], load['jid'])
        event.fire_event(load, salt.utils.event.tagify([load['jid'], 'ret', load['id']], 'job'))
        event.fire_ret_load(load)
    if not opts['job_cache'] or opts.get('ext_job_cache'):
        return
    if load.get('jid') == 'nocache':
        log.debug('Ignoring job return with jid for caching %s from %s', load['jid'], load['id'])
        return
    savefstr = '{}.save_load'.format(job_cache)
    getfstr = '{}.get_load'.format(job_cache)
    fstr = '{}.returner'.format(job_cache)
    updateetfstr = '{}.update_endtime'.format(job_cache)
    if 'fun' not in load and load.get('return', {}):
        ret_ = load.get('return', {})
        if 'fun' in ret_:
            load.update({'fun': ret_['fun']})
        if 'user' in ret_:
            load.update({'user': ret_['user']})
    try:
        log.info('Trace')
        savefstr_func = mminion.returners[savefstr]
        getfstr_func = mminion.returners[getfstr]
        fstr_func = mminion.returners[fstr]
    except KeyError as error:
        emsg = "Returner '{}' does not support function {}".format(job_cache, error)
        log.error(emsg)
        raise KeyError(emsg)
    if job_cache != 'local_cache':
        try:
            log.info('Trace')
            mminion.returners[savefstr](load['jid'], load)
        except KeyError as e:
            log.error("Load does not contain 'jid': %s", e)
        except Exception:
            log.critical("The specified '%s' returner threw a stack trace", job_cache, exc_info=True)
    try:
        log.info('Trace')
        mminion.returners[fstr](load)
    except Exception:
        log.critical("The specified '%s' returner threw a stack trace", job_cache, exc_info=True)
    if opts.get('job_cache_store_endtime') and updateetfstr in mminion.returners:
        mminion.returners[updateetfstr](load['jid'], endtime)

def store_minions(opts, jid, minions, mminion=None, syndic_id=None):
    """
    Store additional minions matched on lower-level masters using the configured
    master_job_cache
    """
    if mminion is None:
        mminion = salt.minion.MasterMinion(opts, states=False, rend=False)
    job_cache = opts['master_job_cache']
    minions_fstr = '{}.save_minions'.format(job_cache)
    try:
        log.info('Trace')
        mminion.returners[minions_fstr](jid, minions, syndic_id=syndic_id)
    except KeyError:
        log.info('Trace')
        raise KeyError("Returner '{}' does not support function save_minions".format(job_cache))

def get_retcode(ret):
    """
    Determine a retcode for a given return
    """
    retcode = 0
    if isinstance(ret, dict) and ret.get('retcode', 0) != 0:
        return ret['retcode']
    elif isinstance(ret, bool) and (not ret):
        return 1
    return retcode