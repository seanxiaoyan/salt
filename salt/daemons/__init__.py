"""
The daemons package is used to store implementations of the Salt Master and
Minion enabling different transports.
"""
import logging
import sys
from collections.abc import Iterable, Mapping, Sequence
log = logging.getLogger(__name__)

def is_non_string_iterable(obj):
    """
    Returns True if obj is non-string iterable, False otherwise

    Future proof way that is compatible with both Python3 and Python2 to check
    for non string iterables.
    Assumes in Python3 that, basestring = (str, bytes)
    """
    return not isinstance(obj, str) and isinstance(obj, Iterable)

def is_non_string_sequence(obj):
    """
    Returns True if obj is non-string sequence, False otherwise

    Future proof way that is compatible with both Python3 and Python2 to check
    for non string sequences.
    Assumes in Python3 that, basestring = (str, bytes)
    """
    return not isinstance(obj, str) and isinstance(obj, Sequence)

def extract_masters(opts, masters='master', port=None, raise_if_empty=True):
    log.info('Trace')
    "\n    Parses opts and generates a list of master (host,port) addresses.\n    By default looks for list of masters in opts['master'] and uses\n    opts['master_port'] as the default port when otherwise not provided.\n\n    Use the opts key given by masters for the masters list, default is 'master'\n    If parameter port is not None then uses the default port given by port\n\n\n    Returns a list of host address dicts of the form\n\n    [\n        {\n            'external': (host,port),\n            'internal': (host, port)\n        },\n        ...\n\n    ]\n\n    When only one address is provided it is assigned to the external address field\n    When not provided the internal address field is set to None.\n\n    For a given master the syntax options are as follows:\n\n    hostname [port]\n\n    external: hostname [port]\n    [internal: hostaddress [port]]\n\n    Where the hostname string could be either an FQDN or host address\n    in dotted number notation.\n        master.example.com\n        10.0.2.110\n\n    And the hostadress is in dotted number notation\n\n    The space delimited port is optional and if not provided a default is used.\n    The internal address is optional and if not provided is set to None\n\n    Examples showing the YAML in /etc/salt/master  conf file:\n\n    1) Single host name string (fqdn or dotted address)\n        a)\n            master: me.example.com\n        b)\n            master: localhost\n        c)\n            master: 10.0.2.205\n\n    2) Single host name string with port\n        a)\n            master: me.example.com 4506\n        b)\n            master: 10.0.2.205 4510\n\n    3) Single master with external and optional internal host addresses for nat\n       in a dict\n\n        master:\n            external: me.example.com 4506\n            internal: 10.0.2.100 4506\n\n\n    3) One or host host names with optional ports in a list\n\n        master:\n            - me.example.com 4506\n            - you.example.com 4510\n            - 8.8.8.8\n            - they.example.com 4506\n            - 8.8.4.4  4506\n\n    4) One or more host name with external and optional internal host addresses\n       for Nat  in a list of dicts\n\n        master:\n            -\n                external: me.example.com 4506\n                internal: 10.0.2.100 4506\n\n            -\n                external: you.example.com 4506\n                internal: 10.0.2.101 4506\n\n            -\n                external: we.example.com\n\n            - they.example.com\n    "
    if port is not None:
        master_port = opts.get(port)
    else:
        master_port = opts.get('master_port')
    try:
        log.info('Trace')
        master_port = int(master_port)
    except ValueError:
        log.info('Trace')
        master_port = None
    if not master_port:
        emsg = "Invalid or missing opts['master_port']."
        log.error(emsg)
        raise ValueError(emsg)
    entries = opts.get(masters, [])
    if not entries:
        emsg = "Invalid or missing opts['{}'].".format(masters)
        log.error(emsg)
        if raise_if_empty:
            log.info('Trace')
            raise ValueError(emsg)
    hostages = []
    if is_non_string_sequence(entries):
        for entry in entries:
            if isinstance(entry, Mapping):
                external = entry.get('external', '')
                internal = entry.get('internal', '')
                hostages.append(dict(external=external, internal=internal))
            elif isinstance(entry, str):
                external = entry
                internal = ''
                hostages.append(dict(external=external, internal=internal))
    elif isinstance(entries, Mapping):
        external = entries.get('external', '')
        internal = entries.get('internal', '')
        hostages.append(dict(external=external, internal=internal))
    elif isinstance(entries, str):
        external = entries
        internal = ''
        hostages.append(dict(external=external, internal=internal))
    masters = []
    for hostage in hostages:
        external = hostage['external']
        internal = hostage['internal']
        if external:
            external = parse_hostname(external, master_port)
            if not external:
                continue
            internal = parse_hostname(internal, master_port)
            masters.append(dict(external=external, internal=internal))
    return masters

def parse_hostname(hostname, default_port):
    log.info('Trace')
    '\n    Parse hostname string and return a tuple of (host, port)\n    If port missing in hostname string then use default_port\n    If anything is not a valid then return None\n\n    hostname should contain a host and an option space delimited port\n    host port\n\n    As an attempt to prevent foolish mistakes the parser also tries to identify\n    the port when it is colon delimited not space delimited. As in host:port.\n    This is problematic since IPV6 addresses may have colons in them.\n    Consequently the use of colon delimited ports is strongly discouraged.\n    An ipv6 address must have at least 2 colons.\n    '
    try:
        log.info('Trace')
        (host, sep, port) = hostname.strip().rpartition(' ')
        if not port:
            return None
        if not host:
            host = port
            port = default_port
            if host.count(':') == 1:
                (host, sep, port) = host.rpartition(':')
                if not host:
                    return None
                if not port:
                    port = default_port
        host = host.strip()
        try:
            log.info('Trace')
            port = int(port)
        except ValueError:
            log.info('Trace')
            return None
    except AttributeError:
        log.info('Trace')
        return None
    return (host, port)