"""
The static grains, these are the core, or built in grains.

When grains are loaded they are not loaded in the same way that modules are
loaded, grain functions are detected and executed, the functions MUST
return a dict which will be applied to the main grains dict. This module
will always be executed first, so that any grains loaded here in the core
module can be overwritten just by returning dict keys with the same value
as those returned here
"""
import datetime
import hashlib
import locale
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
import uuid
from errno import EACCES, EPERM
import distro
import salt.exceptions
import salt.modules.cmdmod
import salt.modules.network
import salt.modules.smbios
import salt.utils.args
import salt.utils.dns
import salt.utils.files
import salt.utils.network
import salt.utils.path
import salt.utils.pkg.rpm
import salt.utils.platform
import salt.utils.stringutils
from salt.utils.network import _clear_interfaces, _get_interfaces
log = logging.getLogger(__name__)

def _linux_distribution():
    return (distro.id(), distro.version(best=True), distro.codename())

def __init__(opts):
    _clear_interfaces()
try:
    import dateutil.tz
    _DATEUTIL_TZ = True
except ImportError:
    _DATEUTIL_TZ = False
HAS_WMI = False
if salt.utils.platform.is_windows():
    import salt.utils.win_osinfo
    try:
        import win32api
        import wmi
        import salt.utils.win_reg
        import salt.utils.winapi
        HAS_WMI = True
    except ImportError:
        log.exception('Unable to import Python wmi module, some core grains will be missing')
__proxyenabled__ = ['*']
__FQDN__ = None
__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet, 'cmd.retcode': salt.modules.cmdmod._retcode_quiet, 'cmd.run_all': salt.modules.cmdmod._run_all_quiet, 'smbios.records': salt.modules.smbios.records, 'smbios.get': salt.modules.smbios.get, 'network.fqdns': salt.modules.network.fqdns}
HAS_UNAME = hasattr(os, 'uname')
HOST_NOT_FOUND = 1
NO_DATA = 4

def _parse_junos_showver(txt):
    showver = {}
    for l in txt.splitlines():
        decoded_line = l.decode('utf-8')
        if decoded_line.startswith('Model'):
            showver['model'] = decoded_line.split(' ')[1]
        if decoded_line.startswith('Junos'):
            showver['osrelease'] = decoded_line.split(' ')[1]
            showver['osmajorrelease'] = decoded_line.split('.')[0]
            showver['osrelease_info'] = decoded_line.split('.')
        if decoded_line.startswith('JUNOS OS Kernel'):
            showver['kernelversion'] = decoded_line
            relno = re.search('\\[(.*)\\]', decoded_line)
            if relno:
                showver['kernelrelease'] = relno.group(1)
    return showver

def _windows_cpudata():
    log.info('Trace')
    '\n    Return some CPU information on Windows minions\n    '
    grains = {}
    if 'NUMBER_OF_PROCESSORS' in os.environ:
        try:
            log.info('Trace')
            grains['num_cpus'] = int(os.environ['NUMBER_OF_PROCESSORS'])
        except ValueError:
            log.info('Trace')
            grains['num_cpus'] = 1
    grains['cpu_model'] = salt.utils.win_reg.read_value(hive='HKEY_LOCAL_MACHINE', key='HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', vname='ProcessorNameString').get('vdata')
    return grains

def _linux_cpudata():
    """
    Return some CPU information for Linux minions
    """
    grains = {}
    cpuinfo = '/proc/cpuinfo'
    if os.path.isfile(cpuinfo):
        with salt.utils.files.fopen(cpuinfo, 'r') as _fp:
            for line in _fp:
                comps = line.split(':')
                if not len(comps) > 1:
                    continue
                key = comps[0].strip()
                val = comps[1].strip()
                if key == 'processor':
                    grains['num_cpus'] = int(val) + 1
                elif key == '# processors':
                    grains['num_cpus'] = int(val)
                elif key == 'vendor_id':
                    grains['cpu_model'] = val
                elif key == 'model name':
                    grains['cpu_model'] = val
                elif key == 'flags':
                    grains['cpu_flags'] = val.split()
                elif key == 'Features':
                    grains['cpu_flags'] = val.split()
                elif key == 'Processor':
                    grains['cpu_model'] = val.split('-')[0]
                    grains['num_cpus'] = 1
    if 'num_cpus' not in grains:
        grains['num_cpus'] = 0
    if 'cpu_model' not in grains:
        grains['cpu_model'] = 'Unknown'
    if 'cpu_flags' not in grains:
        grains['cpu_flags'] = []
    return grains

def _linux_gpu_data():
    log.info('Trace')
    '\n    num_gpus: int\n    gpus:\n      - vendor: nvidia|amd|ati|...\n        model: string\n    '
    if __opts__.get('enable_lspci', True) is False:
        return {}
    if __opts__.get('enable_gpu_grains', True) is False:
        return {}
    lspci = salt.utils.path.which('lspci')
    if not lspci:
        log.debug('The `lspci` binary is not available on the system. GPU grains will not be available.')
        return {}
    known_vendors = ['nvidia', 'amd', 'ati', 'intel', 'cirrus logic', 'vmware', 'matrox', 'aspeed']
    gpu_classes = ('vga compatible controller', '3d controller', 'display controller')
    devs = []
    try:
        lspci_out = __salt__['cmd.run']('{} -vmm'.format(lspci))
        cur_dev = {}
        error = False
        lspci_list = lspci_out.splitlines()
        lspci_list.append('')
        for line in lspci_list:
            if line == '':
                if cur_dev.get('Class', '').lower() in gpu_classes:
                    devs.append(cur_dev)
                cur_dev = {}
                continue
            if re.match('^\\w+:\\s+.*', line):
                (key, val) = line.split(':', 1)
                cur_dev[key.strip()] = val.strip()
            else:
                error = True
                log.debug("Unexpected lspci output: '%s'", line)
        if error:
            log.warning('Error loading grains, unexpected linux_gpu_data output, check that you have a valid shell configured and permissions to run lspci command')
    except OSError:
        log.info('Trace')
        pass
    gpus = []
    for gpu in devs:
        vendor_strings = re.split('[^A-Za-z0-9]', gpu['Vendor'].lower())
        vendor = 'unknown'
        for name in known_vendors:
            if name in vendor_strings:
                vendor = name
                break
        gpus.append({'vendor': vendor, 'model': gpu['Device']})
    grains = {}
    grains['num_gpus'] = len(gpus)
    grains['gpus'] = gpus
    return grains

def _netbsd_gpu_data():
    log.info('Trace')
    '\n    num_gpus: int\n    gpus:\n      - vendor: nvidia|amd|ati|...\n        model: string\n    '
    known_vendors = ['nvidia', 'amd', 'ati', 'intel', 'cirrus logic', 'vmware', 'matrox', 'aspeed']
    gpus = []
    try:
        log.info('Trace')
        pcictl_out = __salt__['cmd.run']('pcictl pci0 list')
        for line in pcictl_out.splitlines():
            for vendor in known_vendors:
                vendor_match = re.match('[0-9:]+ ({}) (.+) \\(VGA .+\\)'.format(vendor), line, re.IGNORECASE)
                if vendor_match:
                    gpus.append({'vendor': vendor_match.group(1), 'model': vendor_match.group(2)})
    except OSError:
        log.info('Trace')
        pass
    grains = {}
    grains['num_gpus'] = len(gpus)
    grains['gpus'] = gpus
    return grains

def _osx_gpudata():
    log.info('Trace')
    '\n    num_gpus: int\n    gpus:\n      - vendor: nvidia|amd|ati|...\n        model: string\n    '
    gpus = []
    try:
        log.info('Trace')
        pcictl_out = __salt__['cmd.run']('system_profiler SPDisplaysDataType')
        for line in pcictl_out.splitlines():
            (fieldname, _, fieldval) = line.partition(': ')
            if fieldname.strip() == 'Chipset Model':
                (vendor, _, model) = fieldval.partition(' ')
                vendor = vendor.lower()
                gpus.append({'vendor': vendor, 'model': model})
    except OSError:
        log.info('Trace')
        pass
    grains = {}
    grains['num_gpus'] = len(gpus)
    grains['gpus'] = gpus
    return grains

def _bsd_cpudata(osdata):
    log.info('Trace')
    '\n    Return CPU information for BSD-like systems\n    '
    sysctl = salt.utils.path.which('sysctl')
    arch = salt.utils.path.which('arch')
    cmds = {}
    if sysctl:
        cmds.update({'num_cpus': '{} -n hw.ncpu'.format(sysctl), 'cpuarch': '{} -n hw.machine'.format(sysctl), 'cpu_model': '{} -n hw.model'.format(sysctl)})
    if arch and osdata['kernel'] == 'OpenBSD':
        cmds['cpuarch'] = '{} -s'.format(arch)
    if osdata['kernel'] == 'Darwin':
        cmds['cpu_model'] = '{} -n machdep.cpu.brand_string'.format(sysctl)
        cmds['cpu_flags'] = '{} -n machdep.cpu.features'.format(sysctl)
    grains = {k: __salt__['cmd.run'](v) for (k, v) in cmds.items()}
    if 'cpu_flags' in grains and isinstance(grains['cpu_flags'], str):
        grains['cpu_flags'] = grains['cpu_flags'].split(' ')
    if osdata['kernel'] == 'NetBSD':
        grains['cpu_flags'] = []
        for line in __salt__['cmd.run']('cpuctl identify 0').splitlines():
            cpu_match = re.match('cpu[0-9]:\\ features[0-9]?\\ .+<(.+)>', line)
            if cpu_match:
                flag = cpu_match.group(1).split(',')
                grains['cpu_flags'].extend(flag)
    if osdata['kernel'] == 'FreeBSD' and os.path.isfile('/var/run/dmesg.boot'):
        grains['cpu_flags'] = []
        with salt.utils.files.fopen('/var/run/dmesg.boot', 'r') as _fp:
            cpu_here = False
            for line in _fp:
                if line.startswith('CPU: '):
                    cpu_here = True
                    continue
                if cpu_here:
                    if not line.startswith(' '):
                        break
                    if 'Features' in line:
                        start = line.find('<')
                        end = line.find('>')
                        if start > 0 and end > 0:
                            flag = line[start + 1:end].split(',')
                            grains['cpu_flags'].extend(flag)
    try:
        log.info('Trace')
        grains['num_cpus'] = int(grains['num_cpus'])
    except ValueError:
        log.info('Trace')
        grains['num_cpus'] = 1
    return grains

def _sunos_cpudata():
    """
    Return the CPU information for Solaris-like systems
    """
    grains = {}
    grains['cpu_flags'] = []
    grains['cpuarch'] = __salt__['cmd.run']('isainfo -k')
    psrinfo = '/usr/sbin/psrinfo 2>/dev/null'
    grains['num_cpus'] = len(__salt__['cmd.run'](psrinfo, python_shell=True).splitlines())
    kstat_info = 'kstat -p cpu_info:*:*:brand'
    for line in __salt__['cmd.run'](kstat_info).splitlines():
        match = re.match('(\\w+:\\d+:\\w+\\d+:\\w+)\\s+(.+)', line)
        if match:
            grains['cpu_model'] = match.group(2)
    isainfo = 'isainfo -n -v'
    for line in __salt__['cmd.run'](isainfo).splitlines():
        match = re.match('^\\s+(.+)', line)
        if match:
            cpu_flags = match.group(1).split()
            grains['cpu_flags'].extend(cpu_flags)
    return grains

def _aix_cpudata():
    """
    Return CPU information for AIX systems
    """
    grains = {}
    cmd = salt.utils.path.which('prtconf')
    if cmd:
        data = __salt__['cmd.run']('{}'.format(cmd)) + os.linesep
        for (dest, regstring) in (('cpuarch', '(?im)^\\s*Processor\\s+Type:\\s+(\\S+)'), ('cpu_flags', '(?im)^\\s*Processor\\s+Version:\\s+(\\S+)'), ('cpu_model', '(?im)^\\s*Processor\\s+Implementation\\s+Mode:\\s+(.*)'), ('num_cpus', '(?im)^\\s*Number\\s+Of\\s+Processors:\\s+(\\S+)')):
            for regex in [re.compile(r) for r in [regstring]]:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    grains[dest] = res.group(1).strip().replace("'", '')
    else:
        log.error("The 'prtconf' binary was not found in $PATH.")
    return grains

def _linux_memdata():
    """
    Return the memory information for Linux-like systems
    """
    grains = {'mem_total': 0, 'swap_total': 0}
    meminfo = '/proc/meminfo'
    if os.path.isfile(meminfo):
        with salt.utils.files.fopen(meminfo, 'r') as ifile:
            for line in ifile:
                comps = line.rstrip('\n').split(':')
                if not len(comps) > 1:
                    continue
                if comps[0].strip() == 'MemTotal':
                    grains['mem_total'] = int(comps[1].split()[0]) // 1024
                if comps[0].strip() == 'SwapTotal':
                    grains['swap_total'] = int(comps[1].split()[0]) // 1024
    return grains

def _osx_memdata():
    """
    Return the memory information for BSD-like systems
    """
    grains = {'mem_total': 0, 'swap_total': 0}
    sysctl = salt.utils.path.which('sysctl')
    if sysctl:
        mem = __salt__['cmd.run']('{} -n hw.memsize'.format(sysctl))
        swap_total = __salt__['cmd.run']('{} -n vm.swapusage'.format(sysctl)).split()[2].replace(',', '.')
        if swap_total.endswith('K'):
            _power = 2 ** 10
        elif swap_total.endswith('M'):
            _power = 2 ** 20
        elif swap_total.endswith('G'):
            _power = 2 ** 30
        swap_total = float(swap_total[:-1]) * _power
        grains['mem_total'] = int(mem) // 1024 // 1024
        grains['swap_total'] = int(swap_total) // 1024 // 1024
    return grains

def _bsd_memdata(osdata):
    """
    Return the memory information for BSD-like systems
    """
    grains = {'mem_total': 0, 'swap_total': 0}
    sysctl = salt.utils.path.which('sysctl')
    if sysctl:
        mem = __salt__['cmd.run']('{} -n hw.physmem'.format(sysctl))
        if osdata['kernel'] == 'NetBSD' and mem.startswith('-'):
            mem = __salt__['cmd.run']('{} -n hw.physmem64'.format(sysctl))
        grains['mem_total'] = int(mem) // 1024 // 1024
        if osdata['kernel'] in ['OpenBSD', 'NetBSD']:
            swapctl = salt.utils.path.which('swapctl')
            swap_data = __salt__['cmd.run']('{} -sk'.format(swapctl))
            if swap_data == 'no swap devices configured':
                swap_total = 0
            else:
                swap_total = swap_data.split(' ')[1]
        else:
            swap_total = __salt__['cmd.run']('{} -n vm.swap_total'.format(sysctl))
        grains['swap_total'] = int(swap_total) // 1024 // 1024
    return grains

def _sunos_memdata():
    log.info('Trace')
    '\n    Return the memory information for SunOS-like systems\n    '
    grains = {'mem_total': 0, 'swap_total': 0}
    prtconf = '/usr/sbin/prtconf 2>/dev/null'
    for line in __salt__['cmd.run'](prtconf, python_shell=True).splitlines():
        comps = line.split(' ')
        if comps[0].strip() == 'Memory' and comps[1].strip() == 'size:':
            grains['mem_total'] = int(comps[2].strip())
    swap_cmd = salt.utils.path.which('swap')
    swap_data = __salt__['cmd.run']('{} -s'.format(swap_cmd)).split()
    try:
        log.info('Trace')
        swap_avail = int(swap_data[-2][:-1])
        swap_used = int(swap_data[-4][:-1])
        swap_total = (swap_avail + swap_used) // 1024
    except ValueError:
        log.info('Trace')
        swap_total = None
    grains['swap_total'] = swap_total
    return grains

def _aix_memdata():
    """
    Return the memory information for AIX systems
    """
    grains = {'mem_total': 0, 'swap_total': 0}
    prtconf = salt.utils.path.which('prtconf')
    if prtconf:
        for line in __salt__['cmd.run'](prtconf, python_shell=True).splitlines():
            comps = [x for x in line.strip().split(' ') if x]
            if len(comps) > 2 and 'Memory' in comps[0] and ('Size' in comps[1]):
                grains['mem_total'] = int(comps[2])
                break
    else:
        log.error("The 'prtconf' binary was not found in $PATH.")
    swap_cmd = salt.utils.path.which('swap')
    if swap_cmd:
        log.info('Trace')
        swap_data = __salt__['cmd.run']('{} -s'.format(swap_cmd)).split()
        try:
            swap_total = (int(swap_data[-2]) + int(swap_data[-6])) * 4
        except ValueError:
            swap_total = None
        grains['swap_total'] = swap_total
    else:
        log.error("The 'swap' binary was not found in $PATH.")
    return grains

def _windows_memdata():
    """
    Return the memory information for Windows systems
    """
    grains = {'mem_total': 0}
    tot_bytes = win32api.GlobalMemoryStatusEx()['TotalPhys']
    grains['mem_total'] = int(tot_bytes / 1024 ** 2)
    return grains

def _memdata(osdata):
    """
    Gather information about the system memory
    """
    grains = {'mem_total': 0}
    if osdata['kernel'] == 'Linux':
        grains.update(_linux_memdata())
    elif osdata['kernel'] in ('FreeBSD', 'OpenBSD', 'NetBSD'):
        grains.update(_bsd_memdata(osdata))
    elif osdata['kernel'] == 'Darwin':
        grains.update(_osx_memdata())
    elif osdata['kernel'] == 'SunOS':
        grains.update(_sunos_memdata())
    elif osdata['kernel'] == 'AIX':
        grains.update(_aix_memdata())
    elif osdata['kernel'] == 'Windows' and HAS_WMI:
        grains.update(_windows_memdata())
    return grains

def _aix_get_machine_id():
    """
    Parse the output of lsattr -El sys0 for os_uuid
    """
    grains = {}
    cmd = salt.utils.path.which('lsattr')
    if cmd:
        data = __salt__['cmd.run']('{} -El sys0'.format(cmd)) + os.linesep
        uuid_regexes = [re.compile('(?im)^\\s*os_uuid\\s+(\\S+)\\s+(.*)')]
        for regex in uuid_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                grains['machine_id'] = res.group(1).strip()
                break
    else:
        log.error("The 'lsattr' binary was not found in $PATH.")
    return grains

def _windows_virtual(osdata):
    """
    Returns what type of virtual hardware is under the hood, kvm or physical
    """
    grains = dict()
    if osdata['kernel'] != 'Windows':
        return grains
    grains['virtual'] = osdata.get('virtual', 'physical')
    manufacturer = osdata.get('manufacturer', '')
    if manufacturer is None:
        manufacturer = ''
    productname = osdata.get('productname', '')
    if productname is None:
        productname = ''
    if 'QEMU' in manufacturer:
        grains['virtual'] = 'kvm'
    if 'Bochs' in manufacturer:
        grains['virtual'] = 'kvm'
    elif 'oVirt' in productname:
        grains['virtual'] = 'kvm'
        grains['virtual_subtype'] = 'oVirt'
    elif 'RHEV Hypervisor' in productname:
        grains['virtual'] = 'kvm'
        grains['virtual_subtype'] = 'rhev'
    elif 'VirtualBox' in productname:
        grains['virtual'] = 'VirtualBox'
    elif 'VMware' in productname:
        grains['virtual'] = 'VMware'
    elif 'Microsoft' in manufacturer and 'Virtual Machine' in productname:
        grains['virtual'] = 'VirtualPC'
    elif 'Parallels' in manufacturer:
        grains['virtual'] = 'Parallels'
    elif 'CloudStack KVM Hypervisor' in productname:
        grains['virtual'] = 'kvm'
        grains['virtual_subtype'] = 'cloudstack'
    return grains

def _virtual(osdata):
    log.info('Trace')
    '\n    Returns what type of virtual hardware is under the hood, kvm or physical\n    '
    grains = {'virtual': osdata.get('virtual', 'physical')}
    skip_cmds = ('AIX',)
    _cmds = ['systemd-detect-virt', 'virt-what', 'dmidecode']
    if not salt.utils.platform.is_windows() and osdata['kernel'] not in skip_cmds:
        if salt.utils.path.which('virt-what'):
            _cmds = ['virt-what']
    if __opts__.get('enable_lspci', True) is True:
        if os.path.exists('/proc/bus/pci'):
            _cmds += ['lspci']
    if osdata['kernel'] in skip_cmds:
        _cmds = ()
    if HAS_UNAME and osdata['kernel'] == 'Linux' and ('BrandZ virtual linux' in os.uname()):
        grains['virtual'] = 'zone'
        return grains
    failed_commands = set()
    for command in _cmds:
        args = []
        if osdata['kernel'] == 'Darwin':
            command = 'system_profiler'
            args = ['SPDisplaysDataType']
        elif osdata['kernel'] == 'SunOS':
            virtinfo = salt.utils.path.which('virtinfo')
            if virtinfo:
                try:
                    log.info('Trace')
                    ret = __salt__['cmd.run_all'](virtinfo)
                except salt.exceptions.CommandExecutionError:
                    log.info('Trace')
                    failed_commands.add(virtinfo)
                else:
                    if ret['stdout'].endswith('not supported'):
                        command = 'prtdiag'
                    else:
                        command = 'virtinfo'
                        args.append('-c current list -H -o name')
            else:
                command = 'prtdiag'
        cmd = salt.utils.path.which(command)
        if not cmd:
            continue
        cmd = '{} {}'.format(cmd, ' '.join(args))
        try:
            log.info('Trace')
            ret = __salt__['cmd.run_all'](cmd)
            if ret['retcode'] > 0:
                if salt.utils.platform.is_windows() or 'systemd-detect-virt' in cmd or 'prtdiag' in cmd:
                    continue
                failed_commands.add(command)
                continue
        except salt.exceptions.CommandExecutionError:
            log.info('Trace')
            if salt.utils.platform.is_windows():
                continue
            failed_commands.add(command)
            continue
        output = ret['stdout']
        if command == 'system_profiler':
            macoutput = output.lower()
            if '0x1ab8' in macoutput:
                grains['virtual'] = 'Parallels'
            if 'parallels' in macoutput:
                grains['virtual'] = 'Parallels'
            if 'vmware' in macoutput:
                grains['virtual'] = 'VMware'
            if '0x15ad' in macoutput:
                grains['virtual'] = 'VMware'
            if 'virtualbox' in macoutput:
                grains['virtual'] = 'VirtualBox'
            break
        elif command == 'systemd-detect-virt':
            if output in ('qemu', 'kvm', 'oracle', 'xen', 'bochs', 'chroot', 'uml', 'systemd-nspawn'):
                grains['virtual'] = output
                break
            elif 'vmware' in output:
                grains['virtual'] = 'VMware'
                break
            elif 'microsoft' in output:
                grains['virtual'] = 'VirtualPC'
                break
            elif 'lxc' in output:
                grains['virtual'] = 'container'
                grains['virtual_subtype'] = 'LXC'
                break
        elif command == 'virt-what':
            for line in output.splitlines():
                if line in ('kvm', 'qemu', 'uml', 'xen'):
                    grains['virtual'] = line
                    break
                elif 'lxc' in line:
                    grains['virtual'] = 'container'
                    grains['virtual_subtype'] = 'LXC'
                    break
                elif 'vmware' in line:
                    grains['virtual'] = 'VMware'
                    break
                elif 'parallels' in line:
                    grains['virtual'] = 'Parallels'
                    break
                elif 'hyperv' in line:
                    grains['virtual'] = 'HyperV'
                    break
            break
        elif command == 'dmidecode':
            if 'Vendor: QEMU' in output:
                grains['virtual'] = 'kvm'
            if 'Manufacturer: QEMU' in output:
                grains['virtual'] = 'kvm'
            if 'Vendor: Bochs' in output:
                grains['virtual'] = 'kvm'
            if 'Manufacturer: Bochs' in output:
                grains['virtual'] = 'kvm'
            if 'BHYVE' in output:
                grains['virtual'] = 'bhyve'
            elif 'Manufacturer: oVirt' in output:
                grains['virtual'] = 'kvm'
                grains['virtual_subtype'] = 'ovirt'
            elif 'Product Name: RHEV Hypervisor' in output:
                grains['virtual'] = 'kvm'
                grains['virtual_subtype'] = 'rhev'
            elif 'VirtualBox' in output:
                grains['virtual'] = 'VirtualBox'
            elif 'VMware' in output:
                grains['virtual'] = 'VMware'
            elif ': Microsoft' in output and 'Virtual Machine' in output:
                grains['virtual'] = 'VirtualPC'
            elif 'Parallels Software' in output:
                grains['virtual'] = 'Parallels'
            elif 'Manufacturer: Google' in output:
                grains['virtual'] = 'kvm'
            elif 'Vendor: SeaBIOS' in output:
                grains['virtual'] = 'kvm'
            break
        elif command == 'lspci':
            model = output.lower()
            if 'vmware' in model:
                grains['virtual'] = 'VMware'
            elif 'virtualbox' in model:
                grains['virtual'] = 'VirtualBox'
            elif 'qemu' in model:
                grains['virtual'] = 'kvm'
            elif 'virtio' in model:
                grains['virtual'] = 'kvm'
            break
        elif command == 'prtdiag':
            model = output.lower().split('\n')[0]
            if 'vmware' in model:
                grains['virtual'] = 'VMware'
            elif 'virtualbox' in model:
                grains['virtual'] = 'VirtualBox'
            elif 'qemu' in model:
                grains['virtual'] = 'kvm'
            elif 'joyent smartdc hvm' in model:
                grains['virtual'] = 'kvm'
            break
        elif command == 'virtinfo':
            if output == 'logical-domain':
                grains['virtual'] = 'LDOM'
                roles = []
                for role in ('control', 'io', 'root', 'service'):
                    subtype_cmd = '{} -c current get -H -o value {}-role'.format(command, role)
                    ret = __salt__['cmd.run']('{}'.format(subtype_cmd))
                    if ret == 'true':
                        roles.append(role)
                if roles:
                    grains['virtual_subtype'] = roles
            elif output == 'non-global-zone':
                grains['virtual'] = 'zone'
                grains['virtual_subtype'] = 'non-global'
            elif output == 'kernel-zone':
                grains['virtual'] = 'zone'
                grains['virtual_subtype'] = 'kernel'
            elif output == 'vmware':
                grains['virtual'] = 'VMware'
            break
    choices = ('Linux', 'HP-UX')
    isdir = os.path.isdir
    sysctl = salt.utils.path.which('sysctl')
    if osdata['kernel'] in choices:
        if os.path.isdir('/proc'):
            try:
                log.info('Trace')
                self_root = os.stat('/')
                init_root = os.stat('/proc/1/root/.')
                if self_root != init_root:
                    grains['virtual_subtype'] = 'chroot'
            except OSError:
                log.info('Trace')
                pass
        if isdir('/proc/vz'):
            if os.path.isfile('/proc/vz/version'):
                grains['virtual'] = 'openvzhn'
            elif os.path.isfile('/proc/vz/veinfo'):
                grains['virtual'] = 'openvzve'
                failed_commands.discard('lspci')
                failed_commands.discard('dmidecode')
        if os.path.isfile('/proc/self/status'):
            with salt.utils.files.fopen('/proc/self/status') as status_file:
                vz_re = re.compile('^envID:\\s+(\\d+)$')
                for line in status_file:
                    vz_match = vz_re.match(line.rstrip('\n'))
                    if vz_match and int(vz_match.groups()[0]) != 0:
                        grains['virtual'] = 'openvzve'
                    elif vz_match and int(vz_match.groups()[0]) == 0:
                        grains['virtual'] = 'openvzhn'
        if isdir('/proc/sys/xen') or isdir('/sys/bus/xen') or isdir('/proc/xen'):
            if os.path.isfile('/proc/xen/xsd_kva'):
                grains['virtual_subtype'] = 'Xen Dom0'
            elif osdata.get('productname', '') == 'HVM domU':
                grains['virtual_subtype'] = 'Xen HVM DomU'
            elif os.path.isfile('/proc/xen/capabilities') and os.access('/proc/xen/capabilities', os.R_OK):
                with salt.utils.files.fopen('/proc/xen/capabilities') as fhr:
                    if 'control_d' not in fhr.read():
                        grains['virtual_subtype'] = 'Xen PV DomU'
                    else:
                        grains['virtual_subtype'] = 'Xen Dom0'
            elif isdir('/sys/bus/xen'):
                if os.path.isdir('/sys/bus/xen/drivers/xenconsole'):
                    grains['virtual_subtype'] = 'Xen PV DomU'
                elif 'xen:' in __salt__['cmd.run']('dmesg').lower():
                    grains['virtual_subtype'] = 'Xen PV DomU'
            if 'dom' in grains.get('virtual_subtype', '').lower():
                grains['virtual'] = 'xen'
        if os.path.isfile('/proc/cpuinfo'):
            with salt.utils.files.fopen('/proc/cpuinfo', 'r') as fhr:
                if 'QEMU Virtual CPU' in fhr.read():
                    grains['virtual'] = 'kvm'
        if os.path.isfile('/sys/devices/virtual/dmi/id/product_name'):
            try:
                log.info('Trace')
                with salt.utils.files.fopen('/sys/devices/virtual/dmi/id/product_name', 'rb') as fhr:
                    output = salt.utils.stringutils.to_unicode(fhr.read(), errors='replace')
                    if 'VirtualBox' in output:
                        grains['virtual'] = 'VirtualBox'
                    elif 'RHEV Hypervisor' in output:
                        grains['virtual'] = 'kvm'
                        grains['virtual_subtype'] = 'rhev'
                    elif 'oVirt Node' in output:
                        grains['virtual'] = 'kvm'
                        grains['virtual_subtype'] = 'ovirt'
                    elif 'Google' in output:
                        grains['virtual'] = 'gce'
                    elif 'BHYVE' in output:
                        grains['virtual'] = 'bhyve'
            except UnicodeDecodeError:
                log.debug('The content in /sys/devices/virtual/dmi/id/product_name is not valid')
            except OSError:
                log.info('Trace')
                pass
        if os.path.isfile('/proc/1/cgroup'):
            try:
                log.info('Trace')
                with salt.utils.files.fopen('/proc/1/cgroup', 'r') as fhr:
                    fhr_contents = fhr.read()
                if ':/lxc/' in fhr_contents:
                    grains['virtual'] = 'container'
                    grains['virtual_subtype'] = 'LXC'
                elif ':/kubepods/' in fhr_contents:
                    grains['virtual_subtype'] = 'kubernetes'
                elif ':/libpod_parent/' in fhr_contents:
                    grains['virtual_subtype'] = 'libpod'
                elif any((x in fhr_contents for x in (':/system.slice/docker', ':/docker/', ':/docker-ce/'))):
                    grains['virtual'] = 'container'
                    grains['virtual_subtype'] = 'Docker'
            except OSError:
                log.info('Trace')
                pass
        if 'virtual_subtype' not in grains or grains['virtual_subtype'] != 'LXC':
            if os.path.isfile('/proc/1/environ'):
                try:
                    log.info('Trace')
                    with salt.utils.files.fopen('/proc/1/environ', 'r') as fhr:
                        fhr_contents = fhr.read()
                    if 'container=lxc' in fhr_contents:
                        grains['virtual'] = 'container'
                        grains['virtual_subtype'] = 'LXC'
                except OSError:
                    log.info('Trace')
                    pass
    elif osdata['kernel'] == 'FreeBSD':
        kenv = salt.utils.path.which('kenv')
        if kenv:
            product = __salt__['cmd.run']('{} smbios.system.product'.format(kenv))
            maker = __salt__['cmd.run']('{} smbios.system.maker'.format(kenv))
            if product.startswith('VMware'):
                grains['virtual'] = 'VMware'
            if product.startswith('VirtualBox'):
                grains['virtual'] = 'VirtualBox'
            if maker.startswith('Xen'):
                grains['virtual_subtype'] = '{} {}'.format(maker, product)
                grains['virtual'] = 'xen'
            if maker.startswith('Microsoft') and product.startswith('Virtual'):
                grains['virtual'] = 'VirtualPC'
            if maker.startswith('OpenStack'):
                grains['virtual'] = 'OpenStack'
            if maker.startswith('Bochs'):
                grains['virtual'] = 'kvm'
            if maker.startswith('Amazon EC2'):
                grains['virtual'] = 'Nitro'
        if sysctl:
            hv_vendor = __salt__['cmd.run']('{} -n hw.hv_vendor'.format(sysctl))
            model = __salt__['cmd.run']('{} -n hw.model'.format(sysctl))
            jail = __salt__['cmd.run']('{} -n security.jail.jailed'.format(sysctl))
            if 'bhyve' in hv_vendor:
                grains['virtual'] = 'bhyve'
            elif 'QEMU Virtual CPU' in model:
                grains['virtual'] = 'kvm'
            if jail == '1':
                grains['virtual_subtype'] = 'jail'
    elif osdata['kernel'] == 'OpenBSD':
        if 'manufacturer' in osdata:
            if osdata['manufacturer'] in ['QEMU', 'Red Hat', 'Joyent']:
                grains['virtual'] = 'kvm'
            if osdata['manufacturer'] == 'OpenBSD':
                grains['virtual'] = 'vmm'
    elif osdata['kernel'] == 'NetBSD':
        if sysctl:
            if 'QEMU Virtual CPU' in __salt__['cmd.run']('{} -n machdep.cpu_brand'.format(sysctl)):
                grains['virtual'] = 'kvm'
            elif 'invalid' not in __salt__['cmd.run']('{} -n machdep.xen.suspend'.format(sysctl)):
                grains['virtual'] = 'Xen PV DomU'
            elif 'VMware' in __salt__['cmd.run']('{} -n machdep.dmi.system-vendor'.format(sysctl)):
                grains['virtual'] = 'VMware'
            elif __salt__['cmd.run']('{} -n machdep.idle-mechanism'.format(sysctl)) == 'xen':
                if os.path.isfile('/var/run/xenconsoled.pid'):
                    grains['virtual_subtype'] = 'Xen Dom0'
    elif osdata['kernel'] == 'SunOS':
        zonename = salt.utils.path.which('zonename')
        if zonename:
            zone = __salt__['cmd.run']('{}'.format(zonename))
            if zone != 'global':
                grains['virtual'] = 'zone'
        elif os.path.isdir('/.SUNWnative'):
            grains['virtual'] = 'zone'
    if grains.get('virtual_subtype') and grains['virtual'] == 'physical':
        grains['virtual'] = 'virtual'
    for command in failed_commands:
        log.info("Although '%s' was found in path, the current user cannot execute it. Grains output might not be accurate.", command)
    return grains

def _virtual_hv(osdata):
    log.info('Trace')
    '\n    Returns detailed hypervisor information from sysfs\n    Currently this seems to be used only by Xen\n    '
    grains = {}
    try:
        log.info('Trace')
        if 'xen' not in osdata['virtual']:
            return grains
    except KeyError:
        log.info('Trace')
        return grains
    try:
        log.info('Trace')
        version = {}
        for fn in ('major', 'minor', 'extra'):
            with salt.utils.files.fopen('/sys/hypervisor/version/{}'.format(fn), 'r') as fhr:
                version[fn] = salt.utils.stringutils.to_unicode(fhr.read().strip())
        grains['virtual_hv_version'] = '{}.{}{}'.format(version['major'], version['minor'], version['extra'])
        grains['virtual_hv_version_info'] = [version['major'], version['minor'], version['extra']]
    except (OSError, KeyError):
        log.info('Trace')
        pass
    xen_feature_table = {0: 'writable_page_tables', 1: 'writable_descriptor_tables', 2: 'auto_translated_physmap', 3: 'supervisor_mode_kernel', 4: 'pae_pgdir_above_4gb', 5: 'mmu_pt_update_preserve_ad', 7: 'gnttab_map_avail_bits', 8: 'hvm_callback_vector', 9: 'hvm_safe_pvclock', 10: 'hvm_pirqs', 11: 'dom0', 12: 'grant_map_identity', 13: 'memory_op_vnode_supported', 14: 'ARM_SMCCC_supported'}
    try:
        log.info('Trace')
        with salt.utils.files.fopen('/sys/hypervisor/properties/features', 'r') as fhr:
            features = salt.utils.stringutils.to_unicode(fhr.read().strip())
        enabled_features = []
        for (bit, feat) in xen_feature_table.items():
            if int(features, 16) & 1 << bit:
                enabled_features.append(feat)
        grains['virtual_hv_features'] = features
        grains['virtual_hv_features_list'] = enabled_features
    except (OSError, KeyError):
        log.info('Trace')
        pass
    return grains

def _ps(osdata):
    """
    Return the ps grain
    """
    grains = {}
    bsd_choices = ('FreeBSD', 'NetBSD', 'OpenBSD', 'MacOS')
    if osdata['os'] in bsd_choices:
        grains['ps'] = 'ps auxwww'
    elif osdata['os_family'] == 'Solaris':
        grains['ps'] = '/usr/ucb/ps auxwww'
    elif osdata['os'] == 'Windows':
        grains['ps'] = 'tasklist.exe'
    elif osdata.get('virtual', '') == 'openvzhn':
        grains['ps'] = 'ps -fH -p $(grep -l "^envID:[[:space:]]*0\\$" /proc/[0-9]*/status | sed -e "s=/proc/\\([0-9]*\\)/.*=\\1=")  | awk \'{ $7=""; print }\''
    elif osdata['os_family'] == 'AIX':
        grains['ps'] = '/usr/bin/ps auxww'
    elif osdata['os_family'] == 'NILinuxRT':
        grains['ps'] = 'ps -o user,pid,ppid,tty,time,comm'
    else:
        grains['ps'] = 'ps -efHww'
    return grains

def _clean_value(key, val):
    """
    Clean out well-known bogus values.
    If it isn't clean (for example has value 'None'), return None.
    Otherwise, return the original value.

    NOTE: This logic also exists in the smbios module. This function is
          for use when not using smbios to retrieve the value.
    """
    if val is None or not val or re.match('none', val, flags=re.IGNORECASE):
        return None
    elif 'uuid' in key:
        log.info('Trace')
        for uuidver in range(1, 5):
            try:
                uuid.UUID(val, version=uuidver)
                return val
            except ValueError:
                continue
        log.trace('HW %s value %s is an invalid UUID', key, val.replace('\n', ' '))
        return None
    elif re.search('serial|part|version', key):
        if re.match('^[0]+$', val) or re.match('[0]?1234567[8]?[9]?[0]?', val) or re.search('sernum|part[_-]?number|specified|filled|applicable', val, flags=re.IGNORECASE):
            return None
    elif re.search('asset|manufacturer', key):
        if re.search('manufacturer|to be filled|available|asset|^no(ne|t)', val, flags=re.IGNORECASE):
            return None
    elif re.search('to be filled', val, flags=re.IGNORECASE) or re.search('un(known|specified)|no(t|ne)? (asset|provided|defined|available|present|specified)', val, flags=re.IGNORECASE):
        return None
    return val

def _windows_os_release_grain(caption, product_type):
    """
    helper function for getting the osrelease grain
    :return:
    """
    version = 'Unknown'
    release = ''
    if 'Server' in caption:
        if re.match('^Microsoft Hyper-V Server$', caption):
            version = '2019'
        else:
            for item in caption.split(' '):
                if re.match('\\d+', item):
                    version = item
                if re.match('^R\\d+$', item):
                    release = item
        os_release = '{}Server{}'.format(version, release)
    else:
        for item in caption.split(' '):
            if re.match('^(\\d+(\\.\\d+)?)|Thin|Vista|XP$', item):
                version = item
        os_release = version
    if os_release in ['Unknown']:
        os_release = platform.release()
        server = {'Vista': '2008Server', '7': '2008ServerR2', '8': '2012Server', '8.1': '2012ServerR2', '10': '2016Server'}
        if product_type > 1 and os_release in server:
            os_release = server[os_release]
    return os_release

def _windows_platform_data():
    """
    Use the platform module for as much as we can.
    """
    if not HAS_WMI:
        return {}
    with salt.utils.winapi.Com():
        wmi_c = wmi.WMI()
        systeminfo = wmi_c.Win32_ComputerSystem()[0]
        osinfo = wmi_c.Win32_OperatingSystem()[0]
        biosinfo = wmi_c.Win32_BIOS()[0]
        timeinfo = wmi_c.Win32_TimeZone()[0]
        csproductinfo = wmi_c.Win32_ComputerSystemProduct()[0]
        motherboard = {'product': None, 'serial': None}
        try:
            log.info('Trace')
            motherboardinfo = wmi_c.Win32_BaseBoard()[0]
            motherboard['product'] = motherboardinfo.Product
            motherboard['serial'] = motherboardinfo.SerialNumber
        except IndexError:
            log.debug('Motherboard info not available on this system')
        kernel_version = platform.version()
        info = salt.utils.win_osinfo.get_os_version_info()
        net_info = salt.utils.win_osinfo.get_join_info()
        service_pack = None
        if info['ServicePackMajor'] > 0:
            service_pack = ''.join(['SP', str(info['ServicePackMajor'])])
        os_release = _windows_os_release_grain(caption=osinfo.Caption, product_type=osinfo.ProductType)
        grains = {'kernelrelease': _clean_value('kernelrelease', osinfo.Version), 'kernelversion': _clean_value('kernelversion', kernel_version), 'osversion': _clean_value('osversion', osinfo.Version), 'osrelease': _clean_value('osrelease', os_release), 'osservicepack': _clean_value('osservicepack', service_pack), 'osmanufacturer': _clean_value('osmanufacturer', osinfo.Manufacturer), 'manufacturer': _clean_value('manufacturer', systeminfo.Manufacturer), 'productname': _clean_value('productname', systeminfo.Model), 'biosversion': _clean_value('biosversion', biosinfo.Name.strip()), 'serialnumber': _clean_value('serialnumber', biosinfo.SerialNumber), 'osfullname': _clean_value('osfullname', osinfo.Caption), 'timezone': _clean_value('timezone', timeinfo.Description), 'uuid': _clean_value('uuid', csproductinfo.UUID.lower()), 'windowsdomain': _clean_value('windowsdomain', net_info['Domain']), 'windowsdomaintype': _clean_value('windowsdomaintype', net_info['DomainType']), 'motherboard': {'productname': _clean_value('motherboard.productname', motherboard['product']), 'serialnumber': _clean_value('motherboard.serialnumber', motherboard['serial'])}}
        if 'VRTUAL' in biosinfo.Version:
            grains['virtual'] = 'HyperV'
        elif 'A M I' in biosinfo.Version:
            grains['virtual'] = 'VirtualPC'
        elif 'VMware' in systeminfo.Model:
            grains['virtual'] = 'VMware'
        elif 'VirtualBox' in systeminfo.Model:
            grains['virtual'] = 'VirtualBox'
        elif 'Xen' in biosinfo.Version:
            grains['virtual'] = 'Xen'
            if 'HVM domU' in systeminfo.Model:
                grains['virtual_subtype'] = 'HVM domU'
        elif 'OpenStack' in systeminfo.Model:
            grains['virtual'] = 'OpenStack'
        elif 'AMAZON' in biosinfo.Version:
            grains['virtual'] = 'EC2'
    return grains

def _osx_platform_data():
    """
    Additional data for macOS systems
    Returns: A dictionary containing values for the following:
        - model_name
        - boot_rom_version
        - smc_version
        - system_serialnumber
    """
    cmd = 'system_profiler SPHardwareDataType'
    hardware = __salt__['cmd.run'](cmd)
    grains = {}
    for line in hardware.splitlines():
        (field_name, _, field_val) = line.partition(': ')
        if field_name.strip() == 'Model Name':
            key = 'model_name'
            grains[key] = _clean_value(key, field_val)
        if field_name.strip() == 'Boot ROM Version':
            key = 'boot_rom_version'
            grains[key] = _clean_value(key, field_val)
        if field_name.strip() == 'SMC Version (system)':
            key = 'smc_version'
            grains[key] = _clean_value(key, field_val)
        if field_name.strip() == 'Serial Number (system)':
            key = 'system_serialnumber'
            grains[key] = _clean_value(key, field_val)
    return grains

def id_():
    """
    Return the id
    """
    return {'id': __opts__.get('id', '')}
_REPLACE_LINUX_RE = re.compile('\\W(?:gnu/)?linux', re.IGNORECASE)
_OS_NAME_MAP = {'redhatente': 'RedHat', 'gentoobase': 'Gentoo', 'archarm': 'Arch ARM', 'arch': 'Arch', 'debian': 'Debian', 'Junos': 'Junos', 'raspbian': 'Raspbian', 'fedoraremi': 'Fedora', 'chapeau': 'Chapeau', 'korora': 'Korora', 'amazonami': 'Amazon', 'alt': 'ALT', 'enterprise': 'OEL', 'oracleserv': 'OEL', 'cloudserve': 'CloudLinux', 'cloudlinux': 'CloudLinux', 'almalinux': 'AlmaLinux', 'pidora': 'Fedora', 'scientific': 'ScientificLinux', 'synology': 'Synology', 'nilrt': 'NILinuxRT', 'poky': 'Poky', 'manjaro': 'Manjaro', 'manjarolin': 'Manjaro', 'univention': 'Univention', 'antergos': 'Antergos', 'sles': 'SUSE', 'void': 'Void', 'slesexpand': 'RES', 'linuxmint': 'Mint', 'neon': 'KDE neon', 'pop': 'Pop', 'rocky': 'Rocky', 'alibabaclo': 'Alinux', 'mendel': 'Mendel'}
_OS_FAMILY_MAP = {'Ubuntu': 'Debian', 'Fedora': 'RedHat', 'Chapeau': 'RedHat', 'Korora': 'RedHat', 'FedBerry': 'RedHat', 'CentOS': 'RedHat', 'CentOS Stream': 'RedHat', 'GoOSe': 'RedHat', 'Scientific': 'RedHat', 'Amazon': 'RedHat', 'CloudLinux': 'RedHat', 'AlmaLinux': 'RedHat', 'OVS': 'RedHat', 'OEL': 'RedHat', 'XCP': 'RedHat', 'XCP-ng': 'RedHat', 'XenServer': 'RedHat', 'RES': 'RedHat', 'Sangoma': 'RedHat', 'VMware Photon OS': 'RedHat', 'Mandrake': 'Mandriva', 'ESXi': 'VMware', 'Mint': 'Debian', 'VMwareESX': 'VMware', 'Bluewhite64': 'Bluewhite', 'Slamd64': 'Slackware', 'SLES': 'Suse', 'SUSE Enterprise Server': 'Suse', 'SUSE  Enterprise Server': 'Suse', 'SLED': 'Suse', 'openSUSE': 'Suse', 'SUSE': 'Suse', 'openSUSE Leap': 'Suse', 'openSUSE Tumbleweed': 'Suse', 'SLES_SAP': 'Suse', 'Solaris': 'Solaris', 'SmartOS': 'Solaris', 'OmniOS': 'Solaris', 'OpenIndiana Development': 'Solaris', 'OpenIndiana': 'Solaris', 'OpenSolaris Development': 'Solaris', 'OpenSolaris': 'Solaris', 'Oracle Solaris': 'Solaris', 'Arch ARM': 'Arch', 'Manjaro': 'Arch', 'Antergos': 'Arch', 'ALT': 'RedHat', 'Trisquel': 'Debian', 'GCEL': 'Debian', 'Linaro': 'Debian', 'elementary OS': 'Debian', 'elementary': 'Debian', 'Univention': 'Debian', 'ScientificLinux': 'RedHat', 'Raspbian': 'Debian', 'Devuan': 'Debian', 'antiX': 'Debian', 'Kali': 'Debian', 'neon': 'Debian', 'Cumulus': 'Debian', 'Deepin': 'Debian', 'NILinuxRT': 'NILinuxRT', 'KDE neon': 'Debian', 'Void': 'Void', 'IDMS': 'Debian', 'Funtoo': 'Gentoo', 'AIX': 'AIX', 'TurnKey': 'Debian', 'Pop': 'Debian', 'Rocky': 'RedHat', 'AstraLinuxCE': 'Debian', 'AstraLinuxSE': 'Debian', 'Alinux': 'RedHat', 'Mendel': 'Debian'}
_LSB_REGEX = re.compile('^(DISTRIB_(?:ID|RELEASE|CODENAME|DESCRIPTION))=(?:\'|")?([\\w\\s\\.\\-_]+)(?:\'|")?')

def _linux_bin_exists(binary):
    log.info('Trace')
    '\n    Does a binary exist in linux (depends on which, type, or whereis)\n    '
    for search_cmd in ('which', 'type -ap'):
        try:
            log.info('Trace')
            return __salt__['cmd.retcode']('{} {}'.format(search_cmd, binary)) == 0
        except salt.exceptions.CommandExecutionError:
            log.info('Trace')
            pass
    try:
        log.info('Trace')
        return len(__salt__['cmd.run_all']('whereis -b {}'.format(binary))['stdout'].split()) > 1
    except salt.exceptions.CommandExecutionError:
        log.info('Trace')
        return False

def _parse_lsb_release():
    log.info('Trace')
    ret = {}
    try:
        log.trace('Attempting to parse /etc/lsb-release')
        with salt.utils.files.fopen('/etc/lsb-release') as ifile:
            for line in ifile:
                try:
                    log.info('Trace')
                    (key, value) = _LSB_REGEX.match(line.rstrip('\n')).groups()[:2]
                except AttributeError:
                    log.info('Trace')
                    pass
                else:
                    ret['lsb_{}'.format(key.lower())] = value.rstrip()
    except OSError as exc:
        log.trace('Failed to parse /etc/lsb-release: %s', exc)
    return ret

def _parse_os_release(*os_release_files):
    log.info('Trace')
    '\n    Parse os-release and return a parameter dictionary\n\n    See http://www.freedesktop.org/software/systemd/man/os-release.html\n    for specification of the file format.\n    '
    ret = {}
    for filename in os_release_files:
        try:
            log.info('Trace')
            with salt.utils.files.fopen(filename) as ifile:
                regex = re.compile('^([\\w]+)=(?:\'|")?(.*?)(?:\'|")?$')
                for line in ifile:
                    match = regex.match(line.strip())
                    if match:
                        ret[match.group(1)] = re.sub('\\\\([$"\\\'\\\\`])', '\\1', match.group(2))
            break
        except OSError:
            log.info('Trace')
            pass
    return ret

def _parse_cpe_name(cpe):
    """
    Parse CPE_NAME data from the os-release

    Info: https://csrc.nist.gov/projects/security-content-automation-protocol/scap-specifications/cpe

    Note: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
          however some OS's do not have the full 13 elements, for example:
                CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2"

    :param cpe:
    :return:
    """
    part = {'o': 'operating system', 'h': 'hardware', 'a': 'application'}
    ret = {}
    cpe = (cpe or '').split(':')
    if len(cpe) > 4 and cpe[0] == 'cpe':
        if cpe[1].startswith('/'):
            (ret['vendor'], ret['product'], ret['version']) = cpe[2:5]
            ret['phase'] = cpe[5] if len(cpe) > 5 else None
            ret['part'] = part.get(cpe[1][1:])
        elif len(cpe) == 6 and cpe[1] == '2.3':
            (ret['vendor'], ret['product'], ret['version']) = (x if x != '*' else None for x in cpe[3:6])
            ret['phase'] = None
            ret['part'] = part.get(cpe[2])
        elif len(cpe) > 7 and len(cpe) <= 13 and (cpe[1] == '2.3'):
            (ret['vendor'], ret['product'], ret['version'], ret['phase']) = (x if x != '*' else None for x in cpe[3:7])
            ret['part'] = part.get(cpe[2])
    return ret

def os_data():
    log.info('Trace')
    '\n    Return grains pertaining to the operating system\n    '
    grains = {'num_gpus': 0, 'gpus': []}
    (grains['kernel'], grains['nodename'], grains['kernelrelease'], grains['kernelversion'], grains['cpuarch'], _) = platform.uname()
    if salt.utils.platform.is_junos():
        grains['kernel'] = 'Junos'
        grains['osfullname'] = 'Junos'
        grains['os'] = 'Junos'
        grains['os_family'] = 'FreeBSD'
        showver = _parse_junos_showver(subprocess.run(['/usr/sbin/cli', 'show', 'version'], stdout=subprocess.PIPE, check=True).stdout)
        grains.update(showver)
    elif salt.utils.platform.is_proxy():
        grains['kernel'] = 'proxy'
        grains['kernelrelease'] = 'proxy'
        grains['kernelversion'] = 'proxy'
        grains['osrelease'] = 'proxy'
        grains['os'] = 'proxy'
        grains['os_family'] = 'proxy'
        grains['osfullname'] = 'proxy'
    elif salt.utils.platform.is_windows():
        log.info('Trace')
        grains['os'] = 'Windows'
        grains['os_family'] = 'Windows'
        grains.update(_memdata(grains))
        grains.update(_windows_platform_data())
        grains.update(_windows_cpudata())
        grains.update(_windows_virtual(grains))
        grains.update(_ps(grains))
        if 'Server' in grains['osrelease']:
            osrelease_info = grains['osrelease'].split('Server', 1)
            osrelease_info[1] = osrelease_info[1].lstrip('R')
        else:
            osrelease_info = grains['osrelease'].split('.')
        for (idx, value) in enumerate(osrelease_info):
            if not value.isdigit():
                continue
            osrelease_info[idx] = int(value)
        grains['osrelease_info'] = tuple(osrelease_info)
        grains['osfinger'] = '{os}-{ver}'.format(os=grains['os'], ver=grains['osrelease'])
        grains['init'] = 'Windows'
        return grains
    elif salt.utils.platform.is_linux():
        if _linux_bin_exists('selinuxenabled'):
            log.trace('Adding selinux grains')
            grains['selinux'] = {}
            grains['selinux']['enabled'] = __salt__['cmd.retcode']('selinuxenabled') == 0
            if _linux_bin_exists('getenforce'):
                log.info('Trace')
                grains['selinux']['enforced'] = __salt__['cmd.run']('getenforce').strip()
        if _linux_bin_exists('systemctl') and _linux_bin_exists('localectl'):
            log.trace('Adding systemd grains')
            grains['systemd'] = {}
            systemd_info = __salt__['cmd.run']('systemctl --version').splitlines()
            grains['systemd']['version'] = systemd_info[0].split()[1]
            grains['systemd']['features'] = systemd_info[1]
        grains['init'] = 'unknown'
        log.trace('Adding init grain')
        try:
            log.info('Trace')
            os.stat('/run/systemd/system')
            grains['init'] = 'systemd'
        except OSError:
            log.info('Trace')
            try:
                log.info('Trace')
                with salt.utils.files.fopen('/proc/1/cmdline') as fhr:
                    init_cmdline = fhr.read().replace('\x00', ' ').split()
            except OSError:
                log.info('Trace')
                pass
            else:
                try:
                    init_bin = salt.utils.path.which(init_cmdline[0])
                except IndexError:
                    init_bin = None
                    log.warning('Unable to fetch data from /proc/1/cmdline')
                if init_bin is not None and init_bin.endswith('bin/init'):
                    supported_inits = (b'upstart', b'sysvinit', b'systemd')
                    edge_len = max((len(x) for x in supported_inits)) - 1
                    try:
                        buf_size = __opts__['file_buffer_size']
                    except KeyError:
                        buf_size = 262144
                    try:
                        with salt.utils.files.fopen(init_bin, 'rb') as fp_:
                            edge = b''
                            buf = fp_.read(buf_size).lower()
                            while buf:
                                buf = edge + buf
                                for item in supported_inits:
                                    if item in buf:
                                        item = item.decode('utf-8')
                                        grains['init'] = item
                                        buf = b''
                                        break
                                edge = buf[-edge_len:]
                                buf = fp_.read(buf_size).lower()
                    except OSError as exc:
                        log.error('Unable to read from init_bin (%s): %s', init_bin, exc)
                elif salt.utils.path.which('supervisord') in init_cmdline:
                    grains['init'] = 'supervisord'
                elif salt.utils.path.which('dumb-init') in init_cmdline:
                    grains['init'] = 'dumb-init'
                elif salt.utils.path.which('tini') in init_cmdline:
                    grains['init'] = 'tini'
                elif init_cmdline == ['runit']:
                    grains['init'] = 'runit'
                elif '/sbin/my_init' in init_cmdline:
                    grains['init'] = 'runit'
                else:
                    log.debug('Could not determine init system from command line: (%s)', ' '.join(init_cmdline))
        try:
            log.trace('Getting lsb_release distro information')
            import lsb_release
            release = lsb_release.get_distro_information()
            for (key, value) in release.items():
                key = key.lower()
                lsb_param = 'lsb_{}{}'.format('' if key.startswith('distrib_') else 'distrib_', key)
                grains[lsb_param] = value
        except (ImportError, NameError):
            log.trace('lsb_release python bindings not available')
            grains.update(_parse_lsb_release())
            if grains.get('lsb_distrib_description', '').lower().startswith('antergos'):
                grains['osfullname'] = 'Antergos Linux'
            elif 'lsb_distrib_id' not in grains:
                log.trace('Failed to get lsb_distrib_id, trying to parse os-release')
                os_release = _parse_os_release('/etc/os-release', '/usr/lib/os-release')
                if os_release:
                    if 'NAME' in os_release:
                        grains['lsb_distrib_id'] = os_release['NAME'].strip()
                    if 'VERSION_ID' in os_release:
                        grains['lsb_distrib_release'] = os_release['VERSION_ID']
                    if 'VERSION_CODENAME' in os_release:
                        grains['lsb_distrib_codename'] = os_release['VERSION_CODENAME']
                    elif 'PRETTY_NAME' in os_release:
                        codename = os_release['PRETTY_NAME']
                        if os_release['ID'] == 'debian':
                            codename_match = re.search('\\((\\w+)\\)$', codename)
                            if codename_match:
                                codename = codename_match.group(1)
                        grains['lsb_distrib_codename'] = codename
                    if 'CPE_NAME' in os_release:
                        cpe = _parse_cpe_name(os_release['CPE_NAME'])
                        if not cpe:
                            log.error('Broken CPE_NAME format in /etc/os-release!')
                        elif cpe.get('vendor', '').lower() in ['suse', 'opensuse']:
                            grains['os'] = 'SUSE'
                            if os_release.get('NAME') == 'openSUSE Leap':
                                grains['osfullname'] = 'Leap'
                            elif os_release.get('VERSION') == 'Tumbleweed':
                                grains['osfullname'] = os_release['VERSION']
                            if cpe.get('version') and cpe.get('vendor') == 'opensuse':
                                grains['lsb_distrib_release'] = cpe['version']
                elif os.path.isfile('/etc/SuSE-release'):
                    log.info('Trace')
                    log.trace('Parsing distrib info from /etc/SuSE-release')
                    grains['lsb_distrib_id'] = 'SUSE'
                    version = ''
                    patch = ''
                    with salt.utils.files.fopen('/etc/SuSE-release') as fhr:
                        for line in fhr:
                            if 'enterprise' in line.lower():
                                grains['lsb_distrib_id'] = 'SLES'
                                grains['lsb_distrib_codename'] = re.sub('\\(.+\\)', '', line).strip()
                            elif 'version' in line.lower():
                                version = re.sub('[^0-9]', '', line)
                            elif 'patchlevel' in line.lower():
                                patch = re.sub('[^0-9]', '', line)
                    grains['lsb_distrib_release'] = version
                    if patch:
                        grains['lsb_distrib_release'] += '.' + patch
                        patchstr = 'SP' + patch
                        if grains['lsb_distrib_codename'] and patchstr not in grains['lsb_distrib_codename']:
                            grains['lsb_distrib_codename'] += ' ' + patchstr
                    if not grains.get('lsb_distrib_codename'):
                        log.info('Trace')
                        grains['lsb_distrib_codename'] = 'n.a'
                elif os.path.isfile('/etc/altlinux-release'):
                    log.trace('Parsing distrib info from /etc/altlinux-release')
                    grains['lsb_distrib_id'] = 'altlinux'
                    with salt.utils.files.fopen('/etc/altlinux-release') as ifile:
                        for line in ifile:
                            comps = line.split()
                            if comps[0] == 'ALT':
                                grains['lsb_distrib_release'] = comps[2]
                                grains['lsb_distrib_codename'] = comps[3].replace('(', '').replace(')', '')
                elif os.path.isfile('/etc/centos-release'):
                    log.trace('Parsing distrib info from /etc/centos-release')
                    grains['lsb_distrib_id'] = 'CentOS'
                    with salt.utils.files.fopen('/etc/centos-release') as ifile:
                        for line in ifile:
                            find_release = re.compile('\\d+\\.\\d+')
                            find_codename = re.compile('(?<=\\()(.*?)(?=\\))')
                            release = find_release.search(line)
                            codename = find_codename.search(line)
                            if release is not None:
                                grains['lsb_distrib_release'] = release.group()
                            if codename is not None:
                                grains['lsb_distrib_codename'] = codename.group()
                elif os.path.isfile('/etc.defaults/VERSION') and os.path.isfile('/etc.defaults/synoinfo.conf'):
                    grains['osfullname'] = 'Synology'
                    log.trace('Parsing Synology distrib info from /etc/.defaults/VERSION')
                    with salt.utils.files.fopen('/etc.defaults/VERSION', 'r') as fp_:
                        synoinfo = {}
                        for line in fp_:
                            try:
                                log.info('Trace')
                                (key, val) = line.rstrip('\n').split('=')
                            except ValueError:
                                log.info('Trace')
                                continue
                            if key in ('majorversion', 'minorversion', 'buildnumber'):
                                synoinfo[key] = val.strip('"')
                        if len(synoinfo) != 3:
                            log.warning('Unable to determine Synology version info. Please report this, as it is likely a bug.')
                        else:
                            grains['osrelease'] = '{majorversion}.{minorversion}-{buildnumber}'.format(**synoinfo)
        log.trace('Getting OS name, release, and codename from distro id, version, codename')
        (osname, osrelease, oscodename) = (x.strip('"').strip("'") for x in _linux_distribution())
        if 'osfullname' not in grains:
            log.info('Trace')
            if grains.get('lsb_distrib_id', '').lower().startswith('nilrt'):
                grains['osfullname'] = 'nilrt'
            else:
                grains['osfullname'] = grains.get('lsb_distrib_id', osname).strip()
        if 'osrelease' not in grains:
            log.info('Trace')
            if any((os in grains.get('lsb_distrib_codename', '') for os in ['CentOS Linux 7', 'CentOS Linux 8'])):
                grains.pop('lsb_distrib_release', None)
            grains['osrelease'] = grains.get('lsb_distrib_release', osrelease).strip()
        grains['oscodename'] = grains.get('lsb_distrib_codename', '').strip() or oscodename
        if 'Red Hat' in grains['oscodename']:
            log.info('Trace')
            grains['oscodename'] = oscodename
        distroname = _REPLACE_LINUX_RE.sub('', grains['osfullname']).strip()
        shortname = distroname.replace(' ', '').lower()[:10]
        if 'os' not in grains:
            log.info('Trace')
            grains['os'] = _OS_NAME_MAP.get(shortname, distroname)
        grains.update(_linux_cpudata())
        grains.update(_linux_gpu_data())
    elif grains['kernel'] == 'SunOS':
        if salt.utils.platform.is_smartos():
            if HAS_UNAME:
                uname_v = os.uname()[3]
            else:
                uname_v = os.name
            uname_v = uname_v[uname_v.index('_') + 1:]
            grains['os'] = grains['osfullname'] = 'SmartOS'
            grains['osrelease'] = '.'.join([uname_v.split('T')[0][0:4], uname_v.split('T')[0][4:6], uname_v.split('T')[0][6:8]])
            grains['osrelease_stamp'] = uname_v
        elif os.path.isfile('/etc/release'):
            with salt.utils.files.fopen('/etc/release', 'r') as fp_:
                rel_data = fp_.read()
                try:
                    log.info('Trace')
                    release_re = re.compile('((?:Open|Oracle )?Solaris|OpenIndiana|OmniOS) (Development)?\\s*(\\d+\\.?\\d*|v\\d+)\\s?[A-Z]*\\s?(r\\d+|\\d+\\/\\d+|oi_\\S+|snv_\\S+)?')
                    (osname, development, osmajorrelease, osminorrelease) = release_re.search(rel_data).groups()
                except AttributeError:
                    log.info('Trace')
                    grains['os'] = grains['osfullname'] = 'Solaris'
                    grains['osrelease'] = ''
                else:
                    if development is not None:
                        osname = ' '.join((osname, development))
                    if HAS_UNAME:
                        uname_v = os.uname()[3]
                    else:
                        uname_v = os.name
                    grains['os'] = grains['osfullname'] = osname
                    if osname in ['Oracle Solaris'] and uname_v.startswith(osmajorrelease):
                        grains['osrelease'] = uname_v
                    elif osname in ['OmniOS']:
                        osrelease = []
                        osrelease.append(osmajorrelease[1:])
                        osrelease.append(osminorrelease[1:])
                        grains['osrelease'] = '.'.join(osrelease)
                        grains['osrelease_stamp'] = uname_v
                    else:
                        osrelease = []
                        osrelease.append(osmajorrelease)
                        if osminorrelease:
                            osrelease.append(osminorrelease)
                        grains['osrelease'] = '.'.join(osrelease)
                        grains['osrelease_stamp'] = uname_v
        grains.update(_sunos_cpudata())
    elif grains['kernel'] == 'VMkernel':
        grains['os'] = 'ESXi'
    elif grains['kernel'] == 'Darwin':
        osrelease = __salt__['cmd.run']('sw_vers -productVersion')
        osname = __salt__['cmd.run']('sw_vers -productName')
        osbuild = __salt__['cmd.run']('sw_vers -buildVersion')
        grains['os'] = 'MacOS'
        grains['os_family'] = 'MacOS'
        grains['osfullname'] = '{} {}'.format(osname, osrelease)
        grains['osrelease'] = osrelease
        grains['osbuild'] = osbuild
        grains['init'] = 'launchd'
        grains.update(_bsd_cpudata(grains))
        grains.update(_osx_gpudata())
        grains.update(_osx_platform_data())
    elif grains['kernel'] == 'AIX':
        osrelease = __salt__['cmd.run']('oslevel')
        osrelease_techlevel = __salt__['cmd.run']('oslevel -r')
        osname = __salt__['cmd.run']('uname')
        grains['os'] = 'AIX'
        grains['osfullname'] = osname
        grains['osrelease'] = osrelease
        grains['osrelease_techlevel'] = osrelease_techlevel
        grains.update(_aix_cpudata())
    else:
        grains['os'] = grains['kernel']
    if grains['kernel'] == 'FreeBSD':
        log.info('Trace')
        grains['osfullname'] = grains['os']
        try:
            grains['osrelease'] = __salt__['cmd.run']('freebsd-version -u').split('-')[0]
        except salt.exceptions.CommandExecutionError:
            grains['osrelease'] = grains['kernelrelease'].split('-')[0]
        grains.update(_bsd_cpudata(grains))
    if grains['kernel'] in ('OpenBSD', 'NetBSD'):
        log.info('Trace')
        grains.update(_bsd_cpudata(grains))
        grains['osrelease'] = grains['kernelrelease'].split('-')[0]
        if grains['kernel'] == 'NetBSD':
            grains.update(_netbsd_gpu_data())
    if not grains['os']:
        log.info('Trace')
        grains['os'] = 'Unknown {}'.format(grains['kernel'])
        grains['os_family'] = 'Unknown'
    else:
        log.info('Trace')
        grains['os_family'] = _OS_FAMILY_MAP.get(grains['os'], grains['os'])
    if grains.get('os_family') == 'Debian':
        log.info('Trace')
        osarch = __salt__['cmd.run']('dpkg --print-architecture').strip()
    elif grains.get('os_family') in ['RedHat', 'Suse']:
        osarch = salt.utils.pkg.rpm.get_osarch()
    elif grains.get('os_family') in ('NILinuxRT', 'Poky'):
        archinfo = {}
        for line in __salt__['cmd.run']('opkg print-architecture').splitlines():
            if line.startswith('arch'):
                (_, arch, priority) = line.split()
                archinfo[arch.strip()] = int(priority.strip())
        osarch = sorted(archinfo, key=archinfo.get, reverse=True)
    else:
        osarch = grains['cpuarch']
    grains['osarch'] = osarch
    grains.update(_memdata(grains))
    grains.update(_hw_data(grains))
    grains.update(_virtual(grains))
    grains.update(_virtual_hv(grains))
    grains.update(_ps(grains))
    if grains.get('osrelease', ''):
        log.info('Trace')
        osrelease_info = grains['osrelease'].split('.')
        for (idx, value) in enumerate(osrelease_info):
            if not value.isdigit():
                continue
            osrelease_info[idx] = int(value)
        grains['osrelease_info'] = tuple(osrelease_info)
        try:
            grains['osmajorrelease'] = int(grains['osrelease_info'][0])
        except (IndexError, TypeError, ValueError):
            log.debug("Unable to derive osmajorrelease from osrelease_info '%s'. The osmajorrelease grain will not be set.", grains['osrelease_info'])
        os_name = grains['os' if grains.get('os') in ('Debian', 'FreeBSD', 'OpenBSD', 'NetBSD', 'Mac', 'Raspbian') else 'osfullname']
        grains['osfinger'] = '{}-{}'.format(os_name, grains['osrelease'] if os_name in ('Ubuntu',) else grains['osrelease_info'][0])
    return grains

def locale_info():
    log.info('Trace')
    '\n    Provides\n        defaultlanguage\n        defaultencoding\n    '
    grains = {}
    grains['locale_info'] = {}
    if salt.utils.platform.is_proxy():
        return grains
    try:
        log.info('Trace')
        (grains['locale_info']['defaultlanguage'], grains['locale_info']['defaultencoding']) = locale.getdefaultlocale()
    except Exception:
        log.info('Trace')
        grains['locale_info']['defaultlanguage'] = 'unknown'
        grains['locale_info']['defaultencoding'] = 'unknown'
    grains['locale_info']['detectedencoding'] = __salt_system_encoding__
    grains['locale_info']['timezone'] = 'unknown'
    if _DATEUTIL_TZ:
        try:
            log.info('Trace')
            grains['locale_info']['timezone'] = datetime.datetime.now(dateutil.tz.tzlocal()).tzname()
        except UnicodeDecodeError:
            log.info('Trace')
            if salt.utils.platform.is_windows():
                grains['locale_info']['timezone'] = time.tzname[0].decode('mbcs')
    return grains

def hostname():
    """
    Return fqdn, hostname, domainname

    .. note::
        On Windows the ``domain`` grain may refer to the dns entry for the host
        instead of the Windows domain to which the host is joined. It may also
        be empty if not a part of any domain. Refer to the ``windowsdomain``
        grain instead
    """
    global __FQDN__
    grains = {}
    if salt.utils.platform.is_proxy():
        return grains
    grains['localhost'] = socket.gethostname()
    if __FQDN__ is None:
        __FQDN__ = salt.utils.network.get_fqhostname()
    if __FQDN__ is None:
        log.error('Having trouble getting a hostname.  Does this machine have its hostname and domain set properly?')
        __FQDN__ = 'localhost.localdomain'
    grains['fqdn'] = __FQDN__
    (grains['host'], grains['domain']) = grains['fqdn'].partition('.')[::2]
    return grains

def append_domain():
    """
    Return append_domain if set
    """
    grain = {}
    if salt.utils.platform.is_proxy():
        return grain
    if 'append_domain' in __opts__:
        grain['append_domain'] = __opts__['append_domain']
    return grain

def fqdns():
    """
    Return all known FQDNs for the system by enumerating all interfaces and
    then trying to reverse resolve them (excluding 'lo' interface).
    To disable the fqdns grain, set enable_fqdns_grains: False in the minion configuration file.
    """
    opt = {'fqdns': []}
    if __opts__.get('enable_fqdns_grains', False if salt.utils.platform.is_windows() or salt.utils.platform.is_proxy() or salt.utils.platform.is_sunos() or salt.utils.platform.is_aix() or salt.utils.platform.is_junos() else True):
        opt = __salt__['network.fqdns']()
    return opt

def ip_fqdn():
    """
    Return ip address and FQDN grains
    """
    if salt.utils.platform.is_proxy():
        return {}
    ret = {}
    ret['ipv4'] = salt.utils.network.ip_addrs(include_loopback=True)
    ret['ipv6'] = salt.utils.network.ip_addrs6(include_loopback=True)
    _fqdn = hostname()['fqdn']
    for (socket_type, ipv_num) in ((socket.AF_INET, '4'), (socket.AF_INET6, '6')):
        key = 'fqdn_ip' + ipv_num
        if not ret['ipv' + ipv_num]:
            ret[key] = []
        else:
            try:
                log.info('Trace')
                start_time = datetime.datetime.utcnow()
                info = socket.getaddrinfo(_fqdn, None, socket_type)
                ret[key] = list({item[4][0] for item in info})
            except (OSError, UnicodeError):
                timediff = datetime.datetime.utcnow() - start_time
                if timediff.seconds > 5 and __opts__['__role'] == 'master':
                    log.warning('Unable to find IPv%s record for "%s" causing a %s second timeout when rendering grains. Set the dns or /etc/hosts for IPv%s to clear this.', ipv_num, _fqdn, timediff, ipv_num)
                ret[key] = []
    return ret

def ip_interfaces():
    """
    Provide a dict of the connected interfaces and their ip addresses
    The addresses will be passed as a list for each interface
    """
    if salt.utils.platform.is_proxy():
        return {}
    ret = {}
    ifaces = _get_interfaces()
    for face in ifaces:
        iface_ips = []
        for inet in ifaces[face].get('inet', []):
            if 'address' in inet:
                iface_ips.append(inet['address'])
        for inet in ifaces[face].get('inet6', []):
            if 'address' in inet:
                iface_ips.append(inet['address'])
        for secondary in ifaces[face].get('secondary', []):
            if 'address' in secondary:
                iface_ips.append(secondary['address'])
        ret[face] = iface_ips
    return {'ip_interfaces': ret}

def ip4_interfaces():
    """
    Provide a dict of the connected interfaces and their ip4 addresses
    The addresses will be passed as a list for each interface
    """
    if salt.utils.platform.is_proxy():
        return {}
    ret = {}
    ifaces = _get_interfaces()
    for face in ifaces:
        iface_ips = []
        for inet in ifaces[face].get('inet', []):
            if 'address' in inet:
                iface_ips.append(inet['address'])
        for secondary in ifaces[face].get('secondary', []):
            if 'address' in secondary and secondary.get('type') == 'inet':
                iface_ips.append(secondary['address'])
        ret[face] = iface_ips
    return {'ip4_interfaces': ret}

def ip6_interfaces():
    """
    Provide a dict of the connected interfaces and their ip6 addresses
    The addresses will be passed as a list for each interface
    """
    if salt.utils.platform.is_proxy():
        return {}
    ret = {}
    ifaces = _get_interfaces()
    for face in ifaces:
        iface_ips = []
        for inet in ifaces[face].get('inet6', []):
            if 'address' in inet:
                iface_ips.append(inet['address'])
        for secondary in ifaces[face].get('secondary', []):
            if 'address' in secondary and secondary.get('type') == 'inet6':
                iface_ips.append(secondary['address'])
        ret[face] = iface_ips
    return {'ip6_interfaces': ret}

def hwaddr_interfaces():
    """
    Provide a dict of the connected interfaces and their
    hw addresses (Mac Address)
    """
    ret = {}
    ifaces = _get_interfaces()
    for face in ifaces:
        if 'hwaddr' in ifaces[face]:
            ret[face] = ifaces[face]['hwaddr']
    return {'hwaddr_interfaces': ret}

def dns():
    """
    Parse the resolver configuration file

     .. versionadded:: 2016.3.0
    """
    if salt.utils.platform.is_windows() or 'proxyminion' in __opts__:
        return {}
    if os.path.exists('/run/systemd/resolve/resolv.conf'):
        resolv = salt.utils.dns.parse_resolv('/run/systemd/resolve/resolv.conf')
    else:
        resolv = salt.utils.dns.parse_resolv()
    for key in ('nameservers', 'ip4_nameservers', 'ip6_nameservers', 'sortlist'):
        if key in resolv:
            resolv[key] = [str(i) for i in resolv[key]]
    return {'dns': resolv} if resolv else {}

def get_machine_id():
    """
    Provide the machine-id for machine/virtualization combination
    """
    if platform.system() == 'AIX':
        return _aix_get_machine_id()
    locations = ['/etc/machine-id', '/var/lib/dbus/machine-id']
    existing_locations = [loc for loc in locations if os.path.exists(loc)]
    if not existing_locations:
        return {}
    else:
        with salt.utils.files.fopen(existing_locations[0]) as machineid:
            return {'machine_id': machineid.read().strip()}

def cwd():
    """
    Current working directory
    """
    return {'cwd': os.getcwd()}

def path():
    """
    Return the path
    """
    _path = salt.utils.stringutils.to_unicode(os.environ.get('PATH', '').strip())
    return {'path': _path, 'systempath': _path.split(os.path.pathsep)}

def pythonversion():
    """
    Return the Python version
    """
    return {'pythonversion': list(sys.version_info)}

def pythonpath():
    """
    Return the Python path
    """
    return {'pythonpath': sys.path}

def pythonexecutable():
    """
    Return the python executable in use
    """
    return {'pythonexecutable': sys.executable}

def saltpath():
    """
    Return the path of the salt module
    """
    salt_path = os.path.abspath(os.path.join(__file__, os.path.pardir))
    return {'saltpath': os.path.dirname(salt_path)}

def saltversion():
    """
    Return the version of salt
    """
    from salt.version import __version__
    return {'saltversion': __version__}

def zmqversion():
    """
    Return the zeromq version
    """
    try:
        log.info('Trace')
        import zmq
        return {'zmqversion': zmq.zmq_version()}
    except ImportError:
        log.info('Trace')
        return {}

def saltversioninfo():
    """
    Return the version_info of salt

     .. versionadded:: 0.17.0
    """
    from salt.version import __version_info__
    return {'saltversioninfo': list(__version_info__)}

def _hw_data(osdata):
    log.info('Trace')
    '\n    Get system specific hardware data from dmidecode\n\n    Provides\n        biosversion\n        productname\n        manufacturer\n        serialnumber\n        biosreleasedate\n        uuid\n\n    .. versionadded:: 0.9.5\n    '
    if salt.utils.platform.is_proxy():
        return {}
    grains = {}
    if osdata['kernel'] == 'Linux' and os.path.exists('/sys/class/dmi/id'):
        sysfs_firmware_info = {'biosversion': 'bios_version', 'productname': 'product_name', 'manufacturer': 'sys_vendor', 'biosreleasedate': 'bios_date', 'uuid': 'product_uuid', 'serialnumber': 'product_serial'}
        for (key, fw_file) in sysfs_firmware_info.items():
            contents_file = os.path.join('/sys/class/dmi/id', fw_file)
            if os.path.exists(contents_file):
                try:
                    log.info('Trace')
                    with salt.utils.files.fopen(contents_file, 'rb') as ifile:
                        grains[key] = salt.utils.stringutils.to_unicode(ifile.read().strip(), errors='replace')
                        if key == 'uuid':
                            grains['uuid'] = grains['uuid'].lower()
                except UnicodeDecodeError:
                    log.debug('The content in /sys/devices/virtual/dmi/id/product_name is not valid')
                except OSError as err:
                    log.info('Trace')
                    if err.errno == EACCES or err.errno == EPERM:
                        pass
    elif salt.utils.path.which_bin(['dmidecode', 'smbios']) is not None and (not (salt.utils.platform.is_smartos() or (osdata['kernel'] == 'SunOS' and osdata['cpuarch'].startswith('sparc')))):
        grains = {'biosversion': __salt__['smbios.get']('bios-version'), 'productname': __salt__['smbios.get']('system-product-name'), 'manufacturer': __salt__['smbios.get']('system-manufacturer'), 'biosreleasedate': __salt__['smbios.get']('bios-release-date'), 'uuid': __salt__['smbios.get']('system-uuid')}
        grains = {key: val for (key, val) in grains.items() if val is not None}
        uuid = __salt__['smbios.get']('system-uuid')
        if uuid is not None:
            grains['uuid'] = uuid.lower()
        for serial in ('system-serial-number', 'chassis-serial-number', 'baseboard-serial-number'):
            serial = __salt__['smbios.get'](serial)
            if serial is not None:
                grains['serialnumber'] = serial
                break
    elif salt.utils.path.which_bin(['fw_printenv']) is not None:
        hwdata = {'manufacturer': 'manufacturer', 'serialnumber': 'serial#', 'productname': 'DeviceDesc'}
        for (grain_name, cmd_key) in hwdata.items():
            result = __salt__['cmd.run_all']('fw_printenv {}'.format(cmd_key))
            if result['retcode'] == 0:
                uboot_keyval = result['stdout'].split('=')
                grains[grain_name] = _clean_value(grain_name, uboot_keyval[1])
    elif osdata['kernel'] == 'FreeBSD':
        kenv = salt.utils.path.which('kenv')
        if kenv:
            fbsd_hwdata = {'biosversion': 'smbios.bios.version', 'manufacturer': 'smbios.system.maker', 'serialnumber': 'smbios.system.serial', 'productname': 'smbios.system.product', 'biosreleasedate': 'smbios.bios.reldate', 'uuid': 'smbios.system.uuid'}
            for (key, val) in fbsd_hwdata.items():
                value = __salt__['cmd.run']('{} {}'.format(kenv, val))
                grains[key] = _clean_value(key, value)
    elif osdata['kernel'] == 'OpenBSD':
        sysctl = salt.utils.path.which('sysctl')
        hwdata = {'biosversion': 'hw.version', 'manufacturer': 'hw.vendor', 'productname': 'hw.product', 'serialnumber': 'hw.serialno', 'uuid': 'hw.uuid'}
        for (key, oid) in hwdata.items():
            value = __salt__['cmd.run']('{} -n {}'.format(sysctl, oid))
            if not value.endswith(' value is not available'):
                grains[key] = _clean_value(key, value)
    elif osdata['kernel'] == 'NetBSD':
        sysctl = salt.utils.path.which('sysctl')
        nbsd_hwdata = {'biosversion': 'machdep.dmi.board-version', 'manufacturer': 'machdep.dmi.system-vendor', 'serialnumber': 'machdep.dmi.system-serial', 'productname': 'machdep.dmi.system-product', 'biosreleasedate': 'machdep.dmi.bios-date', 'uuid': 'machdep.dmi.system-uuid'}
        for (key, oid) in nbsd_hwdata.items():
            result = __salt__['cmd.run_all']('{} -n {}'.format(sysctl, oid))
            if result['retcode'] == 0:
                grains[key] = _clean_value(key, result['stdout'])
    elif osdata['kernel'] == 'Darwin':
        grains['manufacturer'] = 'Apple Inc.'
        sysctl = salt.utils.path.which('sysctl')
        hwdata = {'productname': 'hw.model'}
        for (key, oid) in hwdata.items():
            value = __salt__['cmd.run']('{} -b {}'.format(sysctl, oid))
            if not value.endswith(' is invalid'):
                grains[key] = _clean_value(key, value)
    elif osdata['kernel'] == 'SunOS' and osdata['cpuarch'].startswith('sparc'):
        data = ''
        for (cmd, args) in (('/usr/sbin/prtdiag', '-v'), ('/usr/sbin/prtconf', '-vp'), ('/usr/sbin/virtinfo', '-a')):
            if salt.utils.path.which(cmd):
                data += __salt__['cmd.run']('{} {}'.format(cmd, args))
                data += '\n'
        sn_regexes = [re.compile(r) for r in ['(?im)^\\s*Chassis\\s+Serial\\s+Number\\n-+\\n(\\S+)', '(?im)^\\s*chassis-sn:\\s*(\\S+)', '(?im)^\\s*Chassis\\s+Serial#:\\s*(\\S+)']]
        obp_regexes = [re.compile(r) for r in ['(?im)^\\s*System\\s+PROM\\s+revisions.*\\nVersion\\n-+\\nOBP\\s+(\\S+)\\s+(\\S+)', "(?im)^\\s*version:\\s*\\'OBP\\s+(\\S+)\\s+(\\S+)"]]
        fw_regexes = [re.compile(r) for r in ['(?im)^\\s*Sun\\s+System\\s+Firmware\\s+(\\S+)\\s+(\\S+)']]
        uuid_regexes = [re.compile(r) for r in ['(?im)^\\s*Domain\\s+UUID:\\s*(\\S+)']]
        manufacturer_regexes = [re.compile(r) for r in ['(?im)^\\s*System\\s+Configuration:\\s*(.*)(?=sun)']]
        product_regexes = [re.compile(r) for r in ['(?im)^\\s*System\\s+Configuration:\\s*.*?sun\\d\\S+[^\\S\\r\\n]*(.*)', '(?im)^[^\\S\\r\\n]*banner-name:[^\\S\\r\\n]*(.*)', '(?im)^[^\\S\\r\\n]*product-name:[^\\S\\r\\n]*(.*)']]
        sn_regexes = [re.compile(r) for r in ['(?im)Chassis\\s+Serial\\s+Number\\n-+\\n(\\S+)', '(?i)Chassis\\s+Serial#:\\s*(\\S+)', '(?i)chassis-sn:\\s*(\\S+)']]
        obp_regexes = [re.compile(r) for r in ['(?im)System\\s+PROM\\s+revisions.*\\nVersion\\n-+\\nOBP\\s+(\\S+)\\s+(\\S+)', "(?im)version:\\s*\\'OBP\\s+(\\S+)\\s+(\\S+)"]]
        fw_regexes = [re.compile(r) for r in ['(?i)Sun\\s+System\\s+Firmware\\s+(\\S+)\\s+(\\S+)']]
        uuid_regexes = [re.compile(r) for r in ['(?i)Domain\\s+UUID:\\s+(\\S+)']]
        for regex in sn_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                grains['serialnumber'] = res.group(1).strip().replace("'", '')
                break
        for regex in obp_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                (obp_rev, obp_date) = res.groups()[0:2]
                grains['biosversion'] = obp_rev.strip().replace("'", '')
                grains['biosreleasedate'] = obp_date.strip().replace("'", '')
        for regex in fw_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                (fw_rev, fw_date) = res.groups()[0:2]
                grains['systemfirmware'] = fw_rev.strip().replace("'", '')
                grains['systemfirmwaredate'] = fw_date.strip().replace("'", '')
                break
        for regex in uuid_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                grains['uuid'] = res.group(1).strip().replace("'", '')
                break
        for regex in manufacturer_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                grains['manufacturer'] = res.group(1).strip().replace("'", '')
                grains['manufacture'] = grains['manufacturer']
                break
        for regex in product_regexes:
            res = regex.search(data)
            if res and len(res.groups()) >= 1:
                t_productname = res.group(1).strip().replace("'", '')
                if t_productname:
                    grains['product'] = t_productname
                    grains['productname'] = t_productname
                    break
    elif osdata['kernel'] == 'AIX':
        cmd = salt.utils.path.which('prtconf')
        if cmd:
            data = __salt__['cmd.run']('{}'.format(cmd)) + os.linesep
            for (dest, regstring) in (('serialnumber', '(?im)^\\s*Machine\\s+Serial\\s+Number:\\s+(\\S+)'), ('systemfirmware', '(?im)^\\s*Firmware\\s+Version:\\s+(.*)')):
                for regex in [re.compile(r) for r in [regstring]]:
                    res = regex.search(data)
                    if res and len(res.groups()) >= 1:
                        grains[dest] = res.group(1).strip().replace("'", '')
            product_regexes = [re.compile('(?im)^\\s*System\\s+Model:\\s+(\\S+)')]
            for regex in product_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    (grains['manufacturer'], grains['productname']) = res.group(1).strip().replace("'", '').split(',')
                    break
        else:
            log.error("The 'prtconf' binary was not found in $PATH.")
    return grains

def get_server_id():
    """
    Provides an integer based on the FQDN of a machine.
    Useful as server-id in MySQL replication or anywhere else you'll need an ID
    like this.
    """
    if salt.utils.platform.is_proxy():
        return {}
    id_ = __opts__.get('id', '')
    hash_ = int(hashlib.sha256(id_.encode()).hexdigest(), 16)
    return {'server_id': abs(hash_ % 2 ** 31)}

def get_master():
    """
    Provides the minion with the name of its master.
    This is useful in states to target other services running on the master.
    """
    return {'master': __opts__.get('master', '')}

def default_gateway():
    log.info('Trace')
    '\n    Populates grains which describe whether a server has a default gateway\n    configured or not. Uses `ip -4 route show` and `ip -6 route show` and greps\n    for a `default` at the beginning of any line. Assuming the standard\n    `default via <ip>` format for default gateways, it will also parse out the\n    ip address of the default gateway, and put it in ip4_gw or ip6_gw.\n\n    If the `ip` command is unavailable, no grains will be populated.\n\n    Currently does not support multiple default gateways. The grains will be\n    set to the first default gateway found.\n\n    List of grains:\n\n        ip4_gw: True  # ip/True/False if default ipv4 gateway\n        ip6_gw: True  # ip/True/False if default ipv6 gateway\n        ip_gw: True   # True if either of the above is True, False otherwise\n    '
    grains = {}
    ip_bin = salt.utils.path.which('ip')
    if not ip_bin:
        return {}
    grains['ip_gw'] = False
    grains['ip4_gw'] = False
    grains['ip6_gw'] = False
    for ip_version in ('4', '6'):
        try:
            log.info('Trace')
            out = __salt__['cmd.run']([ip_bin, '-' + ip_version, 'route', 'show'])
            for line in out.splitlines():
                if line.startswith('default'):
                    log.info('Trace')
                    grains['ip_gw'] = True
                    grains['ip{}_gw'.format(ip_version)] = True
                    try:
                        (via, gw_ip) = line.split()[1:3]
                    except ValueError:
                        pass
                    else:
                        if via == 'via':
                            grains['ip{}_gw'.format(ip_version)] = gw_ip
                    break
        except Exception:
            log.info('Trace')
            continue
    return grains

def kernelparams():
    """
    Return the kernel boot parameters
    """
    if salt.utils.platform.is_windows():
        return {}
    else:
        try:
            log.info('Trace')
            with salt.utils.files.fopen('/proc/cmdline', 'r') as fhr:
                cmdline = fhr.read()
                grains = {'kernelparams': []}
                for data in [item.split('=') for item in salt.utils.args.shlex_split(cmdline)]:
                    value = None
                    if len(data) == 2:
                        value = data[1].strip('"')
                    grains['kernelparams'] += [(data[0], value)]
        except FileNotFoundError:
            log.info('Trace')
            grains = {}
        except OSError as exc:
            grains = {}
            log.debug('Failed to read /proc/cmdline: %s', exc)
        return grains