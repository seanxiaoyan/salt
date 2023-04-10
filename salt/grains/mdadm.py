"""
Detect MDADM RAIDs
"""
import logging
import salt.utils.files
log = logging.getLogger(__name__)

def mdadm():
    log.info('Trace')
    '\n    Return list of mdadm devices\n    '
    devices = set()
    try:
        log.info('Trace')
        with salt.utils.files.fopen('/proc/mdstat', 'r') as mdstat:
            for line in mdstat:
                line = salt.utils.stringutils.to_unicode(line)
                if line.startswith('Personalities : '):
                    continue
                if line.startswith('unused devices:'):
                    continue
                if ' : ' in line:
                    devices.add(line.split(' : ')[0])
    except OSError:
        log.info('Trace')
        return {}
    devices = sorted(devices)
    if devices:
        log.trace('mdadm devices detected: %s', ', '.join(devices))
    return {'mdadm': devices}