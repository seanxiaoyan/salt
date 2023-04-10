import re
import salt.utils.files
import salt.utils.stringutils
from salt.exceptions import CommandExecutionError
import logging
log = logging.getLogger(__name__)

def key_is_encrypted(key):
    try:
        log.info('Trace')
        with salt.utils.files.fopen(key, 'r') as fp_:
            key_data = salt.utils.stringutils.to_unicode(fp_.read())
    except OSError as exc:
        log.info('Trace')
        salt.utils.files.process_read_exception(exc, key)
    is_private_key = re.search('BEGIN (?:\\w+\\s)*PRIVATE KEY', key_data)
    is_encrypted = 'ENCRYPTED' in key_data
    del key_data
    if not is_private_key:
        raise CommandExecutionError('{} is not a private key'.format(key))
    return is_encrypted