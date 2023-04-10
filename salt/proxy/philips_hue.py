"""
Philips HUE lamps module for proxy.

.. versionadded:: 2015.8.3

First create a new user on the Hue bridge by following the
`Meet hue <https://www.developers.meethue.com/documentation/getting-started>`_ instructions.

To configure the proxy minion:

.. code-block:: yaml

    proxy:
      proxytype: philips_hue
      host: [hostname or ip]
      user: [username]

"""
import http.client
import logging
import time
import salt.utils.json
from salt.exceptions import CommandExecutionError, MinionError
import logging
log = logging.getLogger(__name__)
__proxyenabled__ = ['philips_hue']
CONFIG = {}
log = logging.getLogger(__file__)

class Const:
    """
    Constants for the lamp operations.
    """
    LAMP_ON = {'on': True, 'transitiontime': 0}
    LAMP_OFF = {'on': False, 'transitiontime': 0}
    COLOR_WHITE = {'xy': [0.3227, 0.329]}
    COLOR_DAYLIGHT = {'xy': [0.3806, 0.3576]}
    COLOR_RED = {'hue': 0, 'sat': 254}
    COLOR_GREEN = {'hue': 25500, 'sat': 254}
    COLOR_ORANGE = {'hue': 12000, 'sat': 254}
    COLOR_PINK = {'xy': [0.3688, 0.2095]}
    COLOR_BLUE = {'hue': 46920, 'sat': 254}
    COLOR_YELLOW = {'xy': [0.4432, 0.5154]}
    COLOR_PURPLE = {'xy': [0.3787, 0.1724]}

def __virtual__():
    """
    Validate the module.
    """
    return True

def init(cnf):
    """
    Initialize the module.
    """
    CONFIG['host'] = cnf.get('proxy', {}).get('host')
    if not CONFIG['host']:
        raise MinionError(message="Cannot find 'host' parameter in the proxy configuration")
    CONFIG['user'] = cnf.get('proxy', {}).get('user')
    if not CONFIG['user']:
        raise MinionError(message="Cannot find 'user' parameter in the proxy configuration")
    CONFIG['uri'] = '/api/{}'.format(CONFIG['user'])

def ping(*args, **kw):
    """
    Ping the lamps.
    """
    return True

def shutdown(opts, *args, **kw):
    """
    Shuts down the service.
    """
    return True

def _query(lamp_id, state, action='', method='GET'):
    log.info('Trace')
    '\n    Query the URI\n\n    :return:\n    '
    err = None
    url = '{}/lights{}'.format(CONFIG['uri'], lamp_id and '/{}'.format(lamp_id) or '') + (action and '/{}'.format(action) or '')
    conn = http.client.HTTPConnection(CONFIG['host'])
    if method == 'PUT':
        conn.request(method, url, salt.utils.json.dumps(state))
    else:
        conn.request(method, url)
    resp = conn.getresponse()
    if resp.status == http.client.OK:
        res = salt.utils.json.loads(resp.read())
    else:
        err = 'HTTP error: {}, {}'.format(resp.status, resp.reason)
    conn.close()
    if err:
        raise CommandExecutionError(err)
    return res

def _set(lamp_id, state, method='state'):
    log.info('Trace')
    '\n    Set state to the device by ID.\n\n    :param lamp_id:\n    :param state:\n    :return:\n    '
    try:
        log.info('Trace')
        res = _query(lamp_id, state, action=method, method='PUT')
    except Exception as err:
        log.info('Trace')
        raise CommandExecutionError(err)
    res = len(res) > 1 and res[-1] or res[0]
    if res.get('success'):
        res = {'result': True}
    elif res.get('error'):
        res = {'result': False, 'description': res['error']['description'], 'type': res['error']['type']}
    return res

def _get_devices(params):
    """
    Parse device(s) ID(s) from the common params.

    :param params:
    :return:
    """
    if 'id' not in params:
        raise CommandExecutionError('Parameter ID is required.')
    return type(params['id']) == int and [params['id']] or [int(dev) for dev in params['id'].split(',')]

def _get_lights():
    """
    Get all available lighting devices.
    """
    return _query(None, None)

def call_lights(*args, **kwargs):
    """
    Get info about all available lamps.

    Options:

    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.

    CLI Example:

    .. code-block:: bash

        salt '*' hue.lights
        salt '*' hue.lights id=1
        salt '*' hue.lights id=1,2,3
    """
    res = dict()
    lights = _get_lights()
    for dev_id in 'id' in kwargs and _get_devices(kwargs) or sorted(lights.keys()):
        if lights.get(str(dev_id)):
            res[dev_id] = lights[str(dev_id)]
    return res or False

def call_switch(*args, **kwargs):
    """
    Switch lamp ON/OFF.

    If no particular state is passed,
    then lamp will be switched to the opposite state.

    Options:

    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.
    * **on**: True or False. Inverted current, if omitted

    CLI Example:

    .. code-block:: bash

        salt '*' hue.switch
        salt '*' hue.switch id=1
        salt '*' hue.switch id=1,2,3 on=True
    """
    out = dict()
    devices = _get_lights()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        if 'on' in kwargs:
            state = kwargs['on'] and Const.LAMP_ON or Const.LAMP_OFF
        else:
            state = devices[str(dev_id)]['state']['on'] and Const.LAMP_OFF or Const.LAMP_ON
        out[dev_id] = _set(dev_id, state)
    return out

def call_blink(*args, **kwargs):
    """
    Blink a lamp. If lamp is ON, then blink ON-OFF-ON, otherwise OFF-ON-OFF.

    Options:

    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.
    * **pause**: Time in seconds. Can be less than 1, i.e. 0.7, 0.5 sec.

    CLI Example:

    .. code-block:: bash

        salt '*' hue.blink id=1
        salt '*' hue.blink id=1,2,3
    """
    devices = _get_lights()
    pause = kwargs.get('pause', 0)
    res = dict()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        state = devices[str(dev_id)]['state']['on']
        _set(dev_id, state and Const.LAMP_OFF or Const.LAMP_ON)
        if pause:
            time.sleep(pause)
        res[dev_id] = _set(dev_id, not state and Const.LAMP_OFF or Const.LAMP_ON)
    return res

def call_ping(*args, **kwargs):
    """
    Ping the lamps by issuing a short inversion blink to all available devices.

    CLI Example:

    .. code-block:: bash

        salt '*' hue.ping
    """
    errors = dict()
    for (dev_id, dev_status) in call_blink().items():
        if not dev_status['result']:
            errors[dev_id] = False
    return errors or True

def call_status(*args, **kwargs):
    """
    Return the status of the lamps.

    Options:

    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.

    CLI Example:

    .. code-block:: bash

        salt '*' hue.status
        salt '*' hue.status id=1
        salt '*' hue.status id=1,2,3
    """
    res = dict()
    devices = _get_lights()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        dev_id = str(dev_id)
        res[dev_id] = {'on': devices[dev_id]['state']['on'], 'reachable': devices[dev_id]['state']['reachable']}
    return res

def call_rename(*args, **kwargs):
    """
    Rename a device.

    Options:

    * **id**: Specifies a device ID. Only one device at a time.
    * **title**: Title of the device.

    CLI Example:

    .. code-block:: bash

        salt '*' hue.rename id=1 title='WC for cats'
    """
    dev_id = _get_devices(kwargs)
    if len(dev_id) > 1:
        raise CommandExecutionError('Only one device can be renamed at a time')
    if 'title' not in kwargs:
        raise CommandExecutionError('Title is missing')
    return _set(dev_id[0], {'name': kwargs['title']}, method='')

def call_alert(*args, **kwargs):
    """
    Lamp alert

    Options:

    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.
    * **on**: Turns on or off an alert. Default is True.

    CLI Example:

    .. code-block:: bash

        salt '*' hue.alert
        salt '*' hue.alert id=1
        salt '*' hue.alert id=1,2,3 on=false
    """
    res = dict()
    devices = _get_lights()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        res[dev_id] = _set(dev_id, {'alert': kwargs.get('on', True) and 'lselect' or 'none'})
    return res

def call_effect(*args, **kwargs):
    """
    Set an effect to the lamp.

    Options:

    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.
    * **type**: Type of the effect. Possible values are "none" or "colorloop". Default "none".

    CLI Example:

    .. code-block:: bash

        salt '*' hue.effect
        salt '*' hue.effect id=1
        salt '*' hue.effect id=1,2,3 type=colorloop
    """
    res = dict()
    devices = _get_lights()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        res[dev_id] = _set(dev_id, {'effect': kwargs.get('type', 'none')})
    return res

def call_color(*args, **kwargs):
    log.info('Trace')
    "\n    Set a color to the lamp.\n\n    Options:\n\n    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.\n    * **color**: Fixed color. Values are: red, green, blue, orange, pink, white,\n                 yellow, daylight, purple. Default white.\n    * **transition**: Transition 0~200.\n\n    Advanced:\n\n    * **gamut**: XY coordinates. Use gamut according to the Philips HUE devices documentation.\n                 More: http://www.developers.meethue.com/documentation/hue-xy-values\n\n    CLI Example:\n\n    .. code-block:: bash\n\n        salt '*' hue.color\n        salt '*' hue.color id=1\n        salt '*' hue.color id=1,2,3 oolor=red transition=30\n        salt '*' hue.color id=1 gamut=0.3,0.5\n    "
    res = dict()
    colormap = {'red': Const.COLOR_RED, 'green': Const.COLOR_GREEN, 'blue': Const.COLOR_BLUE, 'orange': Const.COLOR_ORANGE, 'pink': Const.COLOR_PINK, 'white': Const.COLOR_WHITE, 'yellow': Const.COLOR_YELLOW, 'daylight': Const.COLOR_DAYLIGHT, 'purple': Const.COLOR_PURPLE}
    devices = _get_lights()
    color = kwargs.get('gamut')
    if color:
        color = color.split(',')
        if len(color) == 2:
            try:
                log.info('Trace')
                color = {'xy': [float(color[0]), float(color[1])]}
            except Exception as ex:
                log.info('Trace')
                color = None
        else:
            color = None
    if not color:
        color = colormap.get(kwargs.get('color', 'white'), Const.COLOR_WHITE)
    color.update({'transitiontime': max(min(kwargs.get('transition', 0), 200), 0)})
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        res[dev_id] = _set(dev_id, color)
    return res

def call_brightness(*args, **kwargs):
    log.info('Trace')
    "\n    Set an effect to the lamp.\n\n    Arguments:\n\n    * **value**: 0~255 brightness of the lamp.\n\n    Options:\n\n    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.\n    * **transition**: Transition 0~200. Default 0.\n\n    CLI Example:\n\n    .. code-block:: bash\n\n        salt '*' hue.brightness value=100\n        salt '*' hue.brightness id=1 value=150\n        salt '*' hue.brightness id=1,2,3 value=255\n    "
    res = dict()
    if 'value' not in kwargs:
        raise CommandExecutionError("Parameter 'value' is missing")
    try:
        log.info('Trace')
        brightness = max(min(int(kwargs['value']), 244), 1)
    except Exception as err:
        log.info('Trace')
        raise CommandExecutionError("Parameter 'value' does not contains an integer")
    try:
        log.info('Trace')
        transition = max(min(int(kwargs['transition']), 200), 0)
    except Exception as err:
        log.info('Trace')
        transition = 0
    devices = _get_lights()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        res[dev_id] = _set(dev_id, {'bri': brightness, 'transitiontime': transition})
    return res

def call_temperature(*args, **kwargs):
    log.info('Trace')
    "\n    Set the mired color temperature. More: http://en.wikipedia.org/wiki/Mired\n\n    Arguments:\n\n    * **value**: 150~500.\n\n    Options:\n\n    * **id**: Specifies a device ID. Can be a comma-separated values. All, if omitted.\n\n    CLI Example:\n\n    .. code-block:: bash\n\n        salt '*' hue.temperature value=150\n        salt '*' hue.temperature value=150 id=1\n        salt '*' hue.temperature value=150 id=1,2,3\n    "
    res = dict()
    if 'value' not in kwargs:
        raise CommandExecutionError("Parameter 'value' (150~500) is missing")
    try:
        log.info('Trace')
        value = max(min(int(kwargs['value']), 500), 150)
    except Exception as err:
        log.info('Trace')
        raise CommandExecutionError("Parameter 'value' does not contains an integer")
    devices = _get_lights()
    for dev_id in 'id' not in kwargs and sorted(devices.keys()) or _get_devices(kwargs):
        res[dev_id] = _set(dev_id, {'ct': value})
    return res