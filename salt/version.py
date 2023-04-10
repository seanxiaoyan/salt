"""
Set up the version of Salt
"""
import operator
import platform
import re
import sys
from collections import namedtuple
from functools import total_ordering
import logging
log = logging.getLogger(__name__)
MAX_SIZE = sys.maxsize
VERSION_LIMIT = MAX_SIZE - 200

@total_ordering
class SaltVersion(namedtuple('SaltVersion', 'name, info, released')):
    __slots__ = ()

    def __new__(cls, name, info, released=False):
        if isinstance(info, int):
            info = (info,)
        return super().__new__(cls, name, info, released)

    def __eq__(self, other):
        return self.info == other.info

    def __gt__(self, other):
        return self.info > other.info

class SaltVersionsInfo(type):
    _sorted_versions = ()
    _current_release = None
    _previous_release = None
    _next_release = None
    HYDROGEN = SaltVersion('Hydrogen', info=(2014, 1), released=True)
    HELIUM = SaltVersion('Helium', info=(2014, 7), released=True)
    LITHIUM = SaltVersion('Lithium', info=(2015, 5), released=True)
    BERYLLIUM = SaltVersion('Beryllium', info=(2015, 8), released=True)
    BORON = SaltVersion('Boron', info=(2016, 3), released=True)
    CARBON = SaltVersion('Carbon', info=(2016, 11), released=True)
    NITROGEN = SaltVersion('Nitrogen', info=(2017, 7), released=True)
    OXYGEN = SaltVersion('Oxygen', info=(2018, 3), released=True)
    FLUORINE = SaltVersion('Fluorine', info=(2019, 2), released=True)
    NEON = SaltVersion('Neon', info=3000, released=True)
    SODIUM = SaltVersion('Sodium', info=3001, released=True)
    MAGNESIUM = SaltVersion('Magnesium', info=3002, released=True)
    ALUMINIUM = SaltVersion('Aluminium', info=3003, released=True)
    SILICON = SaltVersion('Silicon', info=3004, released=True)
    PHOSPHORUS = SaltVersion('Phosphorus', info=3005)
    SULFUR = SaltVersion('Sulfur', info=3006)
    CHLORINE = SaltVersion('Chlorine', info=3007)
    ARGON = SaltVersion('Argon', info=3008)
    POTASSIUM = SaltVersion('Potassium', info=3009)
    CALCIUM = SaltVersion('Calcium', info=3010)
    SCANDIUM = SaltVersion('Scandium', info=3011)
    TITANIUM = SaltVersion('Titanium', info=3012)
    VANADIUM = SaltVersion('Vanadium', info=3013)
    CHROMIUM = SaltVersion('Chromium', info=3014)
    MANGANESE = SaltVersion('Manganese', info=3015)
    IRON = SaltVersion('Iron', info=3016)
    COBALT = SaltVersion('Cobalt', info=3017)
    NICKEL = SaltVersion('Nickel', info=3018)
    COPPER = SaltVersion('Copper', info=3019)
    ZINC = SaltVersion('Zinc', info=3020)
    GALLIUM = SaltVersion('Gallium', info=3021)
    GERMANIUM = SaltVersion('Germanium', info=3022)
    ARSENIC = SaltVersion('Arsenic', info=3023)
    SELENIUM = SaltVersion('Selenium', info=3024)
    BROMINE = SaltVersion('Bromine', info=3025)
    KRYPTON = SaltVersion('Krypton', info=3026)
    RUBIDIUM = SaltVersion('Rubidium', info=3027)
    STRONTIUM = SaltVersion('Strontium', info=3028)
    YTTRIUM = SaltVersion('Yttrium', info=3029)
    ZIRCONIUM = SaltVersion('Zirconium', info=3030)
    NIOBIUM = SaltVersion('Niobium', info=3031)
    MOLYBDENUM = SaltVersion('Molybdenum', info=3032)
    TECHNETIUM = SaltVersion('Technetium', info=3033)
    RUTHENIUM = SaltVersion('Ruthenium', info=3034)
    RHODIUM = SaltVersion('Rhodium', info=3035)
    PALLADIUM = SaltVersion('Palladium', info=3036)
    SILVER = SaltVersion('Silver', info=3037)
    CADMIUM = SaltVersion('Cadmium', info=3038)
    INDIUM = SaltVersion('Indium', info=3039)
    TIN = SaltVersion('Tin', info=3040)
    ANTIMONY = SaltVersion('Antimony', info=3041)
    TELLURIUM = SaltVersion('Tellurium', info=3042)
    IODINE = SaltVersion('Iodine', info=3043)
    XENON = SaltVersion('Xenon', info=3044)
    CESIUM = SaltVersion('Cesium', info=3045)
    BARIUM = SaltVersion('Barium', info=3046)
    LANTHANUM = SaltVersion('Lanthanum', info=3047)
    CERIUM = SaltVersion('Cerium', info=3048)
    PRASEODYMIUM = SaltVersion('Praseodymium', info=3049)
    NEODYMIUM = SaltVersion('Neodymium', info=3050)
    PROMETHIUM = SaltVersion('Promethium', info=3051)
    SAMARIUM = SaltVersion('Samarium', info=3052)
    EUROPIUM = SaltVersion('Europium', info=3053)
    GADOLINIUM = SaltVersion('Gadolinium', info=3054)
    TERBIUM = SaltVersion('Terbium', info=3055)
    DYSPROSIUM = SaltVersion('Dysprosium', info=3056)
    HOLMIUM = SaltVersion('Holmium', info=3057)
    ERBIUM = SaltVersion('Erbium', info=3058)
    THULIUM = SaltVersion('Thulium', info=3059)
    YTTERBIUM = SaltVersion('Ytterbium', info=3060)
    LUTETIUM = SaltVersion('Lutetium', info=3061)
    HAFNIUM = SaltVersion('Hafnium', info=3062)
    TANTALUM = SaltVersion('Tantalum', info=3063)
    TUNGSTEN = SaltVersion('Tungsten', info=3064)
    RHENIUM = SaltVersion('Rhenium', info=3065)
    OSMIUM = SaltVersion('Osmium', info=3066)
    IRIDIUM = SaltVersion('Iridium', info=3067)
    PLATINUM = SaltVersion('Platinum', info=3068)
    GOLD = SaltVersion('Gold', info=3069)
    MERCURY = SaltVersion('Mercury', info=3070)
    THALLIUM = SaltVersion('Thallium', info=3071)
    LEAD = SaltVersion('Lead', info=3072)
    BISMUTH = SaltVersion('Bismuth', info=3073)
    POLONIUM = SaltVersion('Polonium', info=3074)
    ASTATINE = SaltVersion('Astatine', info=3075)
    RADON = SaltVersion('Radon', info=3076)
    FRANCIUM = SaltVersion('Francium', info=3077)
    RADIUM = SaltVersion('Radium', info=3078)
    ACTINIUM = SaltVersion('Actinium', info=3079)
    THORIUM = SaltVersion('Thorium', info=3080)
    PROTACTINIUM = SaltVersion('Protactinium', info=3081)
    URANIUM = SaltVersion('Uranium', info=3082)
    NEPTUNIUM = SaltVersion('Neptunium', info=3083)
    PLUTONIUM = SaltVersion('Plutonium', info=3084)
    AMERICIUM = SaltVersion('Americium', info=3085)
    CURIUM = SaltVersion('Curium', info=3086)
    BERKELIUM = SaltVersion('Berkelium', info=3087)
    CALIFORNIUM = SaltVersion('Californium', info=3088)
    EINSTEINIUM = SaltVersion('Einsteinium', info=3089)
    FERMIUM = SaltVersion('Fermium', info=3090)
    MENDELEVIUM = SaltVersion('Mendelevium', info=3091)
    NOBELIUM = SaltVersion('Nobelium', info=3092)
    LAWRENCIUM = SaltVersion('Lawrencium', info=3093)
    RUTHERFORDIUM = SaltVersion('Rutherfordium', info=3094)
    DUBNIUM = SaltVersion('Dubnium', info=3095)
    SEABORGIUM = SaltVersion('Seaborgium', info=3096)
    BOHRIUM = SaltVersion('Bohrium', info=3097)
    HASSIUM = SaltVersion('Hassium', info=3098)
    MEITNERIUM = SaltVersion('Meitnerium', info=3099)
    DARMSTADTIUM = SaltVersion('Darmstadtium', info=3100)
    ROENTGENIUM = SaltVersion('Roentgenium', info=3101)
    COPERNICIUM = SaltVersion('Copernicium', info=3102)
    NIHONIUM = SaltVersion('Nihonium', info=3103)
    FLEROVIUM = SaltVersion('Flerovium', info=3104)
    MOSCOVIUM = SaltVersion('Moscovium', info=3105)
    LIVERMORIUM = SaltVersion('Livermorium', info=3106)
    TENNESSINE = SaltVersion('Tennessine', info=3107)
    OGANESSON = SaltVersion('Oganesson', info=3108)

    @classmethod
    def versions(cls):
        if not cls._sorted_versions:
            cls._sorted_versions = sorted((getattr(cls, name) for name in dir(cls) if name.isupper()), key=operator.attrgetter('info'))
        return cls._sorted_versions

    @classmethod
    def current_release(cls):
        if cls._current_release is None:
            for version in cls.versions():
                if version.released is False:
                    cls._current_release = version
                    break
        return cls._current_release

    @classmethod
    def next_release(cls):
        if cls._next_release is None:
            next_release_ahead = False
            for version in cls.versions():
                if next_release_ahead:
                    cls._next_release = version
                    break
                if version == cls.current_release():
                    next_release_ahead = True
        return cls._next_release

    @classmethod
    def previous_release(cls):
        if cls._previous_release is None:
            previous = None
            for version in cls.versions():
                if version == cls.current_release():
                    break
                previous = version
            cls._previous_release = previous
        return cls._previous_release

class SaltStackVersion:
    """
    Handle SaltStack versions class.

    Knows how to parse ``git describe`` output, knows about release candidates
    and also supports version comparison.
    """
    __slots__ = ('name', 'major', 'minor', 'bugfix', 'mbugfix', 'pre_type', 'pre_num', 'noc', 'sha')
    git_sha_regex = '(?P<sha>g?[a-f0-9]{7,40})'
    git_describe_regex = re.compile('(?:[^\\d]+)?(?P<major>[\\d]{1,4})(?:\\.(?P<minor>[\\d]{1,2}))?(?:\\.(?P<bugfix>[\\d]{0,2}))?(?:\\.(?P<mbugfix>[\\d]{0,2}))?(?:(?P<pre_type>rc|a|b|alpha|beta|nb)(?P<pre_num>[\\d]+))?(?:(?:.*)(?:\\+|-)(?P<noc>(?:0na|[\\d]+|n/a))(?:-|\\.)' + git_sha_regex + ')?')
    git_sha_regex = '^' + git_sha_regex
    git_sha_regex = re.compile(git_sha_regex)
    NAMES = {v.name: v.info for v in SaltVersionsInfo.versions()}
    LNAMES = {k.lower(): v for (k, v) in iter(NAMES.items())}
    VNAMES = {v: k for (k, v) in iter(NAMES.items())}
    RMATCH = {v[:2]: k for (k, v) in iter(NAMES.items())}

    def __init__(self, major, minor=None, bugfix=None, mbugfix=0, pre_type=None, pre_num=None, noc=0, sha=None):
        if isinstance(major, str):
            major = int(major)
        if isinstance(minor, str):
            if not minor:
                minor = None
            else:
                minor = int(minor)
        if bugfix is None and (not self.new_version(major=major)):
            bugfix = 0
        elif isinstance(bugfix, str):
            if not bugfix:
                bugfix = None
            else:
                bugfix = int(bugfix)
        if mbugfix is None:
            mbugfix = 0
        elif isinstance(mbugfix, str):
            mbugfix = int(mbugfix)
        if pre_type is None:
            pre_type = ''
        if pre_num is None:
            pre_num = 0
        elif isinstance(pre_num, str):
            pre_num = int(pre_num)
        if noc is None:
            noc = 0
        elif isinstance(noc, str) and noc in ('0na', 'n/a'):
            noc = -1
        elif isinstance(noc, str):
            noc = int(noc)
        self.major = major
        self.minor = minor
        self.bugfix = bugfix
        self.mbugfix = mbugfix
        self.pre_type = pre_type
        self.pre_num = pre_num
        if self.new_version(major):
            vnames_key = (major,)
        else:
            vnames_key = (major, minor)
        self.name = self.VNAMES.get(vnames_key)
        self.noc = noc
        self.sha = sha

    def new_version(self, major):
        """
        determine if using new versioning scheme
        """
        return bool(int(major) >= 3000 and int(major) < VERSION_LIMIT)

    @classmethod
    def parse(cls, version_string):
        if version_string.lower() in cls.LNAMES:
            return cls.from_name(version_string)
        vstr = version_string.decode() if isinstance(version_string, bytes) else version_string
        match = cls.git_describe_regex.match(vstr)
        if not match:
            raise ValueError("Unable to parse version string: '{}'".format(version_string))
        return cls(*match.groups())

    @classmethod
    def from_name(cls, name):
        if name.lower() not in cls.LNAMES:
            raise ValueError("Named version '{}' is not known".format(name))
        return cls(*cls.LNAMES[name.lower()])

    @classmethod
    def from_last_named_version(cls):
        import salt.utils.versions
        salt.utils.versions.warn_until(SaltVersionsInfo.SULFUR, 'The use of SaltStackVersion.from_last_named_version() is deprecated and set to be removed in {version}. Please use SaltStackVersion.current_release() instead.')
        return cls.current_release()

    @classmethod
    def current_release(cls):
        return cls(*SaltVersionsInfo.current_release().info)

    @classmethod
    def next_release(cls):
        return cls(*SaltVersionsInfo.next_release().info)

    @property
    def sse(self):
        return 0 < self.major < 2014

    def min_info(self):
        info = [self.major]
        if self.new_version(self.major):
            if self.minor:
                info.append(self.minor)
        else:
            info.extend([self.minor, self.bugfix, self.mbugfix])
        return info

    @property
    def info(self):
        return tuple(self.min_info())

    @property
    def pre_info(self):
        info = self.min_info()
        info.extend([self.pre_type, self.pre_num])
        return tuple(info)

    @property
    def noc_info(self):
        info = self.min_info()
        info.extend([self.pre_type, self.pre_num, self.noc])
        return tuple(info)

    @property
    def full_info(self):
        info = self.min_info()
        info.extend([self.pre_type, self.pre_num, self.noc, self.sha])
        return tuple(info)

    @property
    def full_info_all_versions(self):
        """
        Return the full info regardless
        of which versioning scheme we
        are using.
        """
        info = [self.major, self.minor, self.bugfix, self.mbugfix, self.pre_type, self.pre_num, self.noc, self.sha]
        return tuple(info)

    @property
    def string(self):
        if self.new_version(self.major):
            version_string = '{}'.format(self.major)
            if self.minor:
                version_string = '{}.{}'.format(self.major, self.minor)
        else:
            version_string = '{}.{}.{}'.format(self.major, self.minor, self.bugfix)
        if self.mbugfix:
            version_string += '.{}'.format(self.mbugfix)
        if self.pre_type:
            version_string += '{}{}'.format(self.pre_type, self.pre_num)
        if self.noc and self.sha:
            noc = self.noc
            if noc < 0:
                noc = '0na'
            version_string += '+{}.{}'.format(noc, self.sha)
        return version_string

    @property
    def formatted_version(self):
        if self.name and self.major > 10000:
            version_string = self.name
            if self.sse:
                version_string += ' Enterprise'
            version_string += ' (Unreleased)'
            return version_string
        version_string = self.string
        if self.sse:
            version_string += ' Enterprise'
        if (self.major, self.minor) in self.RMATCH:
            version_string += ' ({})'.format(self.RMATCH[self.major, self.minor])
        return version_string

    @property
    def pre_index(self):
        if self.new_version(self.major):
            pre_type = 2
            if not isinstance(self.minor, int):
                pre_type = 1
        else:
            pre_type = 4
        return pre_type

    def __str__(self):
        return self.string

    def __compare__(self, other, method):
        if not isinstance(other, SaltStackVersion):
            if isinstance(other, str):
                other = SaltStackVersion.parse(other)
            elif isinstance(other, (list, tuple)):
                other = SaltStackVersion(*other)
            else:
                raise ValueError("Cannot instantiate Version from type '{}'".format(type(other)))
        pre_type = self.pre_index
        other_pre_type = other.pre_index
        other_noc_info = list(other.noc_info)
        noc_info = list(self.noc_info)
        if self.new_version(self.major):
            if self.minor and (not other.minor):
                if self.minor > 0:
                    other_noc_info[1] = 0
            if not self.minor and other.minor:
                if other.minor > 0:
                    noc_info[1] = 0
        if self.pre_type and (not other.pre_type):
            other_noc_info[other_pre_type] = 'zzzzz'
        if not self.pre_type and other.pre_type:
            noc_info[pre_type] = 'zzzzz'
        return method(tuple(noc_info), tuple(other_noc_info))

    def __lt__(self, other):
        return self.__compare__(other, lambda _self, _other: _self < _other)

    def __le__(self, other):
        return self.__compare__(other, lambda _self, _other: _self <= _other)

    def __eq__(self, other):
        return self.__compare__(other, lambda _self, _other: _self == _other)

    def __ne__(self, other):
        return self.__compare__(other, lambda _self, _other: _self != _other)

    def __ge__(self, other):
        return self.__compare__(other, lambda _self, _other: _self >= _other)

    def __gt__(self, other):
        return self.__compare__(other, lambda _self, _other: _self > _other)

    def __repr__(self):
        parts = []
        if self.name:
            parts.append("name='{}'".format(self.name))
        parts.extend(['major={}'.format(self.major), 'minor={}'.format(self.minor)])
        if self.new_version(self.major):
            if not self.minor:
                parts.remove(''.join([x for x in parts if re.search('^minor*', x)]))
        else:
            parts.extend(['bugfix={}'.format(self.bugfix)])
        if self.mbugfix:
            parts.append('minor-bugfix={}'.format(self.mbugfix))
        if self.pre_type:
            parts.append('{}={}'.format(self.pre_type, self.pre_num))
        noc = self.noc
        if noc == -1:
            noc = '0na'
        if noc and self.sha:
            parts.extend(['noc={}'.format(noc), 'sha={}'.format(self.sha)])
        return '<{} {}>'.format(self.__class__.__name__, ' '.join(parts))
__saltstack_version__ = SaltStackVersion.current_release()

def __discover_version(saltstack_version):
    import os
    import subprocess
    if 'SETUP_DIRNAME' in globals():
        cwd = SETUP_DIRNAME
        if not os.path.exists(os.path.join(cwd, '.git')):
            return saltstack_version
    else:
        cwd = os.path.abspath(os.path.dirname(__file__))
        if not os.path.exists(os.path.join(os.path.dirname(cwd), '.git')):
            return saltstack_version
    try:
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        if not sys.platform.startswith('win'):
            kwargs['close_fds'] = True
        process = subprocess.Popen(['git', 'describe', '--tags', '--long', '--match', 'v[0-9]*', '--always'], **kwargs)
        (out, err) = process.communicate()
        out = out.decode().strip()
        err = err.decode().strip()
        if not out or err:
            return saltstack_version
        if SaltStackVersion.git_sha_regex.match(out):
            saltstack_version.sha = out.strip()
            saltstack_version.noc = -1
            return saltstack_version
        return SaltStackVersion.parse(out)
    except OSError as os_err:
        if os_err.errno != 2:
            raise
    return saltstack_version

def __get_version(saltstack_version):
    """
    If we can get a version provided at installation time or from Git, use
    that instead, otherwise we carry on.
    """
    try:
        from salt._version import __saltstack_version__
        return __saltstack_version__
    except ImportError:
        return __discover_version(saltstack_version)
__saltstack_version__ = __get_version(__saltstack_version__)
if __saltstack_version__.name:
    SaltVersionsInfo._current_release = getattr(SaltVersionsInfo, __saltstack_version__.name.upper())
del __get_version
__version_info__ = __saltstack_version__.info
__version__ = __saltstack_version__.string

def salt_information():
    """
    Report version of salt.
    """
    yield ('Salt', __version__)

def dependency_information(include_salt_cloud=False):
    """
    Report versions of library dependencies.
    """
    libs = [('Python', None, sys.version.rsplit('\n')[0].strip()), ('Jinja2', 'jinja2', '__version__'), ('M2Crypto', 'M2Crypto', 'version'), ('msgpack', 'msgpack', 'version'), ('msgpack-pure', 'msgpack_pure', 'version'), ('pycrypto', 'Crypto', '__version__'), ('pycryptodome', 'Cryptodome', 'version_info'), ('PyYAML', 'yaml', '__version__'), ('PyZMQ', 'zmq', '__version__'), ('ZMQ', 'zmq', 'zmq_version'), ('Mako', 'mako', '__version__'), ('Tornado', 'tornado', 'version'), ('timelib', 'timelib', 'version'), ('dateutil', 'dateutil', '__version__'), ('pygit2', 'pygit2', '__version__'), ('libgit2', 'pygit2', 'LIBGIT2_VERSION'), ('smmap', 'smmap', '__version__'), ('cffi', 'cffi', '__version__'), ('pycparser', 'pycparser', '__version__'), ('gitdb', 'gitdb', '__version__'), ('gitpython', 'git', '__version__'), ('python-gnupg', 'gnupg', '__version__'), ('mysql-python', 'MySQLdb', '__version__'), ('cherrypy', 'cherrypy', '__version__'), ('docker-py', 'docker', '__version__')]
    if include_salt_cloud:
        libs.append(('Apache Libcloud', 'libcloud', '__version__'))
    for (name, imp, attr) in libs:
        if imp is None:
            yield (name, attr)
            continue
        try:
            log.info('Trace')
            imp = __import__(imp)
            version = getattr(imp, attr)
            if callable(version):
                version = version()
            if isinstance(version, (tuple, list)):
                version = '.'.join(map(str, version))
            yield (name, version)
        except Exception:
            log.info('Trace')
            yield (name, None)

def system_information():
    """
    Report system versions.
    """
    from distro import linux_distribution

    def system_version():
        """
        Return host system version.
        """
        lin_ver = linux_distribution()
        mac_ver = platform.mac_ver()
        win_ver = platform.win32_ver()
        if mac_ver[0]:
            if isinstance(mac_ver[1], (tuple, list)) and ''.join(mac_ver[1]):
                return ' '.join([mac_ver[0], '.'.join(mac_ver[1]), mac_ver[2]])
            else:
                return ' '.join([mac_ver[0], mac_ver[2]])
        elif win_ver[0]:
            return ' '.join(win_ver)
        elif lin_ver[0]:
            return ' '.join(lin_ver)
        else:
            return ''
    if platform.win32_ver()[0]:
        import win32api
        import win32con
        hkey = win32con.HKEY_LOCAL_MACHINE
        key = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
        value_name = 'ProductName'
        reg_handle = win32api.RegOpenKey(hkey, key)
        (product_name, _) = win32api.RegQueryValueEx(reg_handle, value_name)
        version = 'Unknown'
        release = ''
        if 'Server' in product_name:
            for item in product_name.split(' '):
                if re.match('\\d+', item):
                    version = item
                if re.match('^R\\d+$', item):
                    release = item
            release = '{}Server{}'.format(version, release)
        else:
            for item in product_name.split(' '):
                if re.match('^(\\d+(\\.\\d+)?)|Thin|Vista$', item):
                    version = item
            release = version
        (_, ver, service_pack, extra) = platform.win32_ver()
        version = ' '.join([release, ver, service_pack, extra])
    else:
        version = system_version()
        release = platform.release()
    system = [('system', platform.system()), ('dist', ' '.join(linux_distribution(full_distribution_name=False))), ('release', release), ('machine', platform.machine()), ('version', version), ('locale', __salt_system_encoding__)]
    for (name, attr) in system:
        yield (name, attr)
        continue

def extensions_information():
    """
    Gather infomation about any installed salt extensions
    """
    import salt.utils.entrypoints
    extensions = {}
    for entry_point in salt.utils.entrypoints.iter_entry_points('salt.loader'):
        dist_nv = salt.utils.entrypoints.name_and_version_from_entry_point(entry_point)
        if not dist_nv:
            continue
        if dist_nv.name in extensions:
            continue
        extensions[dist_nv.name] = dist_nv.version
    return extensions

def versions_information(include_salt_cloud=False, include_extensions=True):
    """
    Report the versions of dependent software.
    """
    salt_info = list(salt_information())
    lib_info = list(dependency_information(include_salt_cloud))
    sys_info = list(system_information())
    info = {'Salt Version': dict(salt_info), 'Dependency Versions': dict(lib_info), 'System Versions': dict(sys_info)}
    if include_extensions:
        extensions_info = extensions_information()
        if extensions_info:
            info['Salt Extensions'] = extensions_info
    return info

def versions_report(include_salt_cloud=False, include_extensions=True):
    """
    Yield each version properly formatted for console output.
    """
    ver_info = versions_information(include_salt_cloud=include_salt_cloud, include_extensions=include_extensions)
    not_installed = 'Not Installed'
    ns_pad = len(not_installed)
    lib_pad = max((len(name) for name in ver_info['Dependency Versions']))
    sys_pad = max((len(name) for name in ver_info['System Versions']))
    if include_extensions and 'Salt Extensions' in ver_info:
        ext_pad = max((len(name) for name in ver_info['Salt Extensions']))
    else:
        ext_pad = 1
    padding = max(lib_pad, sys_pad, ns_pad, ext_pad) + 1
    fmt = '{0:>{pad}}: {1}'
    info = []
    for ver_type in ('Salt Version', 'Dependency Versions', 'Salt Extensions', 'System Versions'):
        if ver_type == 'Salt Extensions' and ver_type not in ver_info:
            continue
        info.append('{}:'.format(ver_type))
        for name in sorted(ver_info[ver_type], key=lambda x: x.lower()):
            ver = fmt.format(name, ver_info[ver_type][name] or not_installed, pad=padding)
            info.append(ver)
        info.append(' ')
    yield from info
if __name__ == '__main__':
    print(__version__)