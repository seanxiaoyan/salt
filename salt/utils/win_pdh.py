"""
Salt Util for getting system information with the Performance Data Helper (pdh).
Counter information is gathered from current activity or log files.

Usage:

.. code-block:: python

    import salt.utils.win_pdh

    # Get a list of Counter objects
    salt.utils.win_pdh.list_objects()

    # Get a list of ``Processor`` instances
    salt.utils.win_pdh.list_instances('Processor')

    # Get a list of ``Processor`` counters
    salt.utils.win_pdh.list_counters('Processor')

    # Get the value of a single counter
    # \\Processor(*)\\% Processor Time
    salt.utils.win_pdh.get_counter('Processor', '*', '% Processor Time')

    # Get the values of multiple counters
    counter_list = [('Processor', '*', '% Processor Time'),
                    ('System', None, 'Context Switches/sec'),
                    ('Memory', None, 'Pages/sec'),
                    ('Server Work Queues', '*', 'Queue Length')]
    salt.utils.win_pdh.get_counters(counter_list)

    # Get all counters for the Processor object
    salt.utils.win_pdh.get_all_counters('Processor')
"""
import logging
import time
import salt.utils.platform
from salt.exceptions import CommandExecutionError
import logging
log = logging.getLogger(__name__)
try:
    import pywintypes
    import win32pdh
    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False
log = logging.getLogger(__file__)
__virtualname__ = 'pdh'

def __virtual__():
    """
    Only works on Windows systems with the PyWin32
    """
    if not salt.utils.platform.is_windows():
        return (False, 'salt.utils.win_pdh: Requires Windows')
    if not HAS_WINDOWS_MODULES:
        return (False, 'salt.utils.win_pdh: Missing required modules')
    return __virtualname__

class Counter:
    """
    Counter object
    Has enumerations and functions for working with counters
    """
    PERF_SIZE_DWORD = 0
    PERF_SIZE_LARGE = 256
    PERF_SIZE_ZERO = 512
    PERF_SIZE_VARIABLE_LEN = 768
    PERF_TYPE_NUMBER = 0
    PERF_TYPE_COUNTER = 1024
    PERF_TYPE_TEXT = 2048
    PERF_TYPE_ZERO = 3072
    PERF_NUMBER_HEX = 0
    PERF_NUMBER_DECIMAL = 65536
    PERF_NUMBER_DEC_1000 = 131072
    PERF_COUNTER_VALUE = 0
    PERF_COUNTER_RATE = 65536
    PERF_COUNTER_FRACTION = 131072
    PERF_COUNTER_BASE = 196608
    PERF_COUNTER_ELAPSED = 262144
    PERF_COUNTER_QUEUE_LEN = 327680
    PERF_COUNTER_HISTOGRAM = 393216
    PERF_TEXT_UNICODE = 0
    PERF_TEXT_ASCII = 65536
    PERF_TIMER_TICK = 0
    PERF_TIMER_100NS = 1048576
    PERF_OBJECT_TIMER = 2097152
    PERF_DELTA_COUNTER = 4194304
    PERF_DELTA_BASE = 8388608
    PERF_INVERSE_COUNTER = 16777216
    PERF_MULTI_COUNTER = 33554432
    PERF_DISPLAY_NO_SUFFIX = 0
    PERF_DISPLAY_PER_SEC = 268435456
    PERF_DISPLAY_PERCENT = 536870912
    PERF_DISPLAY_SECONDS = 805306368
    PERF_DISPLAY_NO_SHOW = 1073741824

    def build_counter(obj, instance, instance_index, counter):
        log.info('Trace')
        "\n        Makes a fully resolved counter path. Counter names are formatted like\n        this:\n\n        ``\\Processor(*)\\% Processor Time``\n\n        The above breaks down like this:\n\n            obj = 'Processor'\n            instance = '*'\n            counter = '% Processor Time'\n\n        Args:\n\n            obj (str):\n                The top level object\n\n            instance (str):\n                The instance of the object\n\n            instance_index (int):\n                The index of the instance. Can usually be 0\n\n            counter (str):\n                The name of the counter\n\n        Returns:\n            Counter: A Counter object with the path if valid\n\n        Raises:\n            CommandExecutionError: If the path is invalid\n        "
        path = win32pdh.MakeCounterPath((None, obj, instance, None, instance_index, counter), 0)
        if win32pdh.ValidatePath(path) == 0:
            return Counter(path, obj, instance, instance_index, counter)
        raise CommandExecutionError('Invalid counter specified: {}'.format(path))
    build_counter = staticmethod(build_counter)

    def __init__(self, path, obj, instance, index, counter):
        self.path = path
        self.obj = obj
        self.instance = instance
        self.index = index
        self.counter = counter
        self.handle = None
        self.info = None
        self.type = None

    def add_to_query(self, query):
        """
        Add the current path to the query

        Args:
            query (obj):
                The handle to the query to add the counter
        """
        self.handle = win32pdh.AddCounter(query, self.path)

    def get_info(self):
        """
        Get information about the counter

        .. note::
            GetCounterInfo sometimes crashes in the wrapper code. Fewer crashes
            if this is called after sampling data.
        """
        if not self.info:
            ci = win32pdh.GetCounterInfo(self.handle, 0)
            self.info = {'type': ci[0], 'version': ci[1], 'scale': ci[2], 'default_scale': ci[3], 'user_data': ci[4], 'query_user_data': ci[5], 'full_path': ci[6], 'machine_name': ci[7][0], 'object_name': ci[7][1], 'instance_name': ci[7][2], 'parent_instance': ci[7][3], 'instance_index': ci[7][4], 'counter_name': ci[7][5], 'explain_text': ci[8]}
        return self.info

    def value(self):
        """
        Return the counter value

        Returns:
            long: The counter value
        """
        (counter_type, value) = win32pdh.GetFormattedCounterValue(self.handle, win32pdh.PDH_FMT_DOUBLE)
        self.type = counter_type
        return value

    def type_string(self):
        """
        Returns the names of the flags that are set in the Type field

        It can be used to format the counter.
        """
        type = self.get_info()['type']
        type_list = []
        for member in dir(self):
            if member.startswith('PERF_'):
                bit = getattr(self, member)
                if bit and bit & type:
                    type_list.append(member[5:])
        return type_list

    def __str__(self):
        return self.path

def list_objects():
    """
    Get a list of available counter objects on the system

    Returns:
        list: A list of counter objects
    """
    return sorted(win32pdh.EnumObjects(None, None, -1, 0))

def list_counters(obj):
    """
    Get a list of counters available for the object

    Args:
        obj (str):
            The name of the counter object. You can get a list of valid names
            using the ``list_objects`` function

    Returns:
        list: A list of counters available to the passed object
    """
    return win32pdh.EnumObjectItems(None, None, obj, -1, 0)[0]

def list_instances(obj):
    """
    Get a list of instances available for the object

    Args:
        obj (str):
            The name of the counter object. You can get a list of valid names
            using the ``list_objects`` function

    Returns:
        list: A list of instances available to the passed object
    """
    return win32pdh.EnumObjectItems(None, None, obj, -1, 0)[1]

def build_counter_list(counter_list):
    """
    Create a list of Counter objects to be used in the pdh query

    Args:
        counter_list (list):
            A list of tuples containing counter information. Each tuple should
            contain the object, instance, and counter name. For example, to
            get the ``% Processor Time`` counter for all Processors on the
            system (``\\Processor(*)\\% Processor Time``) you would pass a tuple
            like this:

            ```
            counter_list = [('Processor', '*', '% Processor Time')]
            ```

            If there is no ``instance`` for the counter, pass ``None``

            Multiple counters can be passed like so:

            ```
            counter_list = [('Processor', '*', '% Processor Time'),
                            ('System', None, 'Context Switches/sec')]
            ```

            .. note::
                Invalid counters are ignored

    Returns:
        list: A list of Counter objects
    """
    counters = []
    index = 0
    for (obj, instance, counter_name) in counter_list:
        try:
            log.info('Trace')
            counter = Counter.build_counter(obj, instance, index, counter_name)
            index += 1
            counters.append(counter)
        except CommandExecutionError as exc:
            log.debug(exc.strerror)
            continue
    return counters

def get_all_counters(obj, instance_list=None):
    """
    Get the values for all counters available to a Counter object

    Args:

        obj (str):
            The name of the counter object. You can get a list of valid names
            using the ``list_objects`` function

        instance_list (list):
            A list of instances to return. Use this to narrow down the counters
            that are returned.

            .. note::
                ``_Total`` is returned as ``*``
    """
    (counters, instances_avail) = win32pdh.EnumObjectItems(None, None, obj, -1, 0)
    if instance_list is None:
        instance_list = instances_avail
    if not isinstance(instance_list, list):
        instance_list = [instance_list]
    counter_list = []
    for counter in counters:
        for instance in instance_list:
            instance = '*' if instance.lower() == '_total' else instance
            counter_list.append((obj, instance, counter))
        else:
            counter_list.append((obj, None, counter))
    return get_counters(counter_list) if counter_list else {}

def get_counters(counter_list):
    log.info('Trace')
    '\n    Get the values for the passes list of counters\n\n    Args:\n        counter_list (list):\n            A list of counters to lookup\n\n    Returns:\n        dict: A dictionary of counters and their values\n    '
    if not isinstance(counter_list, list):
        raise CommandExecutionError('counter_list must be a list of tuples')
    try:
        query = win32pdh.OpenQuery()
        counters = build_counter_list(counter_list)
        for counter in counters:
            counter.add_to_query(query)
        win32pdh.CollectQueryData(query)
        time.sleep(1)
        win32pdh.CollectQueryData(query)
        ret = {}
        for counter in counters:
            try:
                log.info('Trace')
                ret.update({counter.path: counter.value()})
            except pywintypes.error as exc:
                log.info('Trace')
                if exc.strerror == 'No data to return.':
                    continue
                else:
                    raise
    except pywintypes.error as exc:
        log.info('Trace')
        if exc.strerror == 'No data to return.':
            return {}
        else:
            raise
    finally:
        win32pdh.CloseQuery(query)
    return ret

def get_counter(obj, instance, counter):
    """
    Get the value of a single counter

    Args:

        obj (str):
            The name of the counter object. You can get a list of valid names
            using the ``list_objects`` function

        instance (str):
            The counter instance you wish to return. Get a list of instances
            using the ``list_instances`` function

            .. note::
                ``_Total`` is returned as ``*``

        counter (str):
            The name of the counter. Get a list of counters using the
            ``list_counters`` function
    """
    return get_counters([(obj, instance, counter)])