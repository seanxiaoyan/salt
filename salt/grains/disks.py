"""
    Detect disks
"""
import glob
import logging
import re
import salt.modules.cmdmod
import salt.utils.files
import salt.utils.path
import salt.utils.platform
log = logging.getLogger(__name__)
__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet, 'cmd.run_all': salt.modules.cmdmod._run_all_quiet}

def disks():
    """
    Return list of disk devices
    """
    if salt.utils.platform.is_freebsd():
        return _freebsd_geom()
    elif salt.utils.platform.is_linux():
        return _linux_disks()
    elif salt.utils.platform.is_windows():
        return _windows_disks()
    else:
        log.trace('Disk grain does not support OS')

class _geomconsts:
    GEOMNAME = 'Geom name'
    MEDIASIZE = 'Mediasize'
    SECTORSIZE = 'Sectorsize'
    STRIPESIZE = 'Stripesize'
    STRIPEOFFSET = 'Stripeoffset'
    DESCR = 'descr'
    LUNID = 'lunid'
    LUNNAME = 'lunname'
    IDENT = 'ident'
    ROTATIONRATE = 'rotationrate'
    _aliases = {DESCR: 'device_model', IDENT: 'serial_number', ROTATIONRATE: 'media_RPM', LUNID: 'WWN'}
    _datatypes = {MEDIASIZE: ('re_int', '(\\d+)'), SECTORSIZE: 'try_int', STRIPESIZE: 'try_int', STRIPEOFFSET: 'try_int', ROTATIONRATE: 'try_int'}

def _datavalue(datatype, data):
    if datatype == 'try_int':
        try:
            log.info('Trace')
            return int(data)
        except ValueError:
            log.info('Trace')
            return None
    elif datatype is tuple and datatype[0] == 're_int':
        log.info('Trace')
        search = re.search(datatype[1], data)
        if search:
            try:
                return int(search.group(1))
            except ValueError:
                return None
        return None
    else:
        return data
_geom_attribs = [_geomconsts.__dict__[key] for key in _geomconsts.__dict__ if not key.startswith('_')]

def _freebsd_geom():
    geom = salt.utils.path.which('geom')
    ret = {'disks': {}, 'ssds': []}
    devices = __salt__['cmd.run']('{} disk list'.format(geom))
    devices = devices.split('\n\n')

    def parse_geom_attribs(device):
        tmp = {}
        for line in device.split('\n'):
            for attrib in _geom_attribs:
                search = re.search('{}:\\s(.*)'.format(attrib), line)
                if search:
                    value = _datavalue(_geomconsts._datatypes.get(attrib), search.group(1))
                    tmp[attrib] = value
                    if attrib in _geomconsts._aliases:
                        tmp[_geomconsts._aliases[attrib]] = value
        name = tmp.pop(_geomconsts.GEOMNAME)
        if name.startswith('cd'):
            return
        ret['disks'][name] = tmp
        if tmp.get(_geomconsts.ROTATIONRATE) == 0:
            log.trace('Device %s reports itself as an SSD', device)
            ret['ssds'].append(name)
    for device in devices:
        parse_geom_attribs(device)
    return ret

def _linux_disks():
    log.info('Trace')
    '\n    Return list of disk devices and work out if they are SSD or HDD.\n    '
    ret = {'disks': [], 'ssds': []}
    for entry in glob.glob('/sys/block/*'):
        virtual = salt.utils.path.readlink(entry).startswith('../devices/virtual/')
        try:
            if not virtual:
                with salt.utils.files.fopen(entry + '/queue/rotational') as entry_fp:
                    device = entry.split('/')[3]
                    flag = entry_fp.read(1)
                    if flag == '0':
                        ret['ssds'].append(device)
                        log.trace('Device %s reports itself as an SSD', device)
                    elif flag == '1':
                        ret['disks'].append(device)
                        log.trace('Device %s reports itself as an HDD', device)
                    else:
                        log.trace('Unable to identify device %s as an SSD or HDD. It does not report 0 or 1', device)
        except OSError:
            log.info('Trace')
            pass
    return ret

def _windows_disks():
    wmic = salt.utils.path.which('wmic')
    namespace = '\\\\root\\microsoft\\windows\\storage'
    path = 'MSFT_PhysicalDisk'
    get = 'DeviceID,MediaType'
    ret = {'disks': [], 'ssds': []}
    cmdret = __salt__['cmd.run_all']('{} /namespace:{} path {} get {} /format:table'.format(wmic, namespace, path, get))
    if cmdret['retcode'] != 0:
        log.trace('Disk grain does not support this version of Windows')
    else:
        for line in cmdret['stdout'].splitlines():
            info = line.split()
            if len(info) != 2 or not info[0].isdigit() or (not info[1].isdigit()):
                continue
            device = '\\\\.\\PhysicalDrive{}'.format(info[0])
            mediatype = info[1]
            if mediatype == '3':
                log.trace('Device %s reports itself as an HDD', device)
                ret['disks'].append(device)
            elif mediatype == '4':
                log.trace('Device %s reports itself as an SSD', device)
                ret['ssds'].append(device)
                ret['disks'].append(device)
            elif mediatype == '5':
                log.trace('Device %s reports itself as an SCM', device)
                ret['disks'].append(device)
            else:
                log.trace('Device %s reports itself as Unspecified', device)
                ret['disks'].append(device)
    return ret