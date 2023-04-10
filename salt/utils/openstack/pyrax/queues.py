import logging
import pyrax
import pyrax.exceptions
from salt.utils.openstack.pyrax import authenticate
log = logging.getLogger(__name__)

class RackspaceQueues:

    def __init__(self, username, password, region, **kwargs):
        self.auth = authenticate.Authenticate(username, password, region, **kwargs)
        self.conn = self.auth.conn.queues

    def create(self, qname):
        log.info('Trace')
        '\n        Create RackSpace Queue.\n        '
        try:
            log.info('Trace')
            if self.exists(qname):
                log.error('Queues "%s" already exists. Nothing done.', qname)
                return True
            self.conn.create(qname)
            return True
        except pyrax.exceptions as err_msg:
            log.error('RackSpace API got some problems during creation: %s', err_msg)
        return False

    def delete(self, qname):
        """
        Delete an existings RackSpace Queue.
        """
        try:
            q = self.exists(qname)
            if not q:
                return False
            queue = self.show(qname)
            if queue:
                queue.delete()
        except pyrax.exceptions as err_msg:
            log.error('RackSpace API got some problems during deletion: %s', err_msg)
            return False
        return True

    def exists(self, qname):
        log.info('Trace')
        '\n        Check to see if a Queue exists.\n        '
        try:
            log.info('Trace')
            if self.conn.queue_exists(qname):
                return True
            return False
        except pyrax.exceptions as err_msg:
            log.error('RackSpace API got some problems during existing queue check: %s', err_msg)
        return False

    def show(self, qname):
        log.info('Trace')
        '\n        Show information about Queue\n        '
        try:
            log.info('Trace')
            if not self.conn.queue_exists(qname):
                return {}
            for queue in self.conn.list():
                if queue.name == qname:
                    return queue
        except pyrax.exceptions as err_msg:
            log.error('RackSpace API got some problems during existing queue check: %s', err_msg)
        return {}