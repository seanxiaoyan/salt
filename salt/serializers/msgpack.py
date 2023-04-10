"""
    salt.serializers.msgpack
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implements MsgPack serializer.
"""
import copy
import logging
import salt.utils.msgpack
from salt.serializers import DeserializationError, SerializationError
log = logging.getLogger(__name__)
available = salt.utils.msgpack.HAS_MSGPACK
if not available:

    def _fail():
        raise RuntimeError('msgpack is not available')

    def _serialize(obj, **options):
        _fail()

    def _deserialize(stream_or_string, **options):
        _fail()
elif salt.utils.msgpack.version >= (1, 0, 0):

    def _serialize(obj, **options):
        try:
            return salt.utils.msgpack.dumps(obj, **options)
        except Exception as error:
            raise SerializationError(error)

    def _deserialize(stream_or_string, **options):
        try:
            options.setdefault('use_list', True)
            options.setdefault('raw', False)
            return salt.utils.msgpack.loads(stream_or_string, **options)
        except Exception as error:
            raise DeserializationError(error)
elif salt.utils.msgpack.version >= (0, 2, 0):

    def _serialize(obj, **options):
        try:
            return salt.utils.msgpack.dumps(obj, **options)
        except Exception as error:
            raise SerializationError(error)

    def _deserialize(stream_or_string, **options):
        try:
            options.setdefault('use_list', True)
            options.setdefault('encoding', 'utf-8')
            return salt.utils.msgpack.loads(stream_or_string, **options)
        except Exception as error:
            raise DeserializationError(error)
else:
    log.info('Trace')

    def _encoder(obj):
        """
        Since OrderedDict is identified as a dictionary, we can't make use of
        msgpack custom types, we will need to convert by hand.

        This means iterating through all elements of dictionaries, lists and
        tuples.
        """
        if isinstance(obj, dict):
            data = [(key, _encoder(value)) for (key, value) in obj.items()]
            return dict(data)
        elif isinstance(obj, (list, tuple)):
            return [_encoder(value) for value in obj]
        return copy.copy(obj)

    def _decoder(obj):
        return obj

    def _serialize(obj, **options):
        try:
            obj = _encoder(obj)
            return salt.utils.msgpack.dumps(obj, **options)
        except Exception as error:
            raise SerializationError(error)

    def _deserialize(stream_or_string, **options):
        options.setdefault('use_list', True)
        try:
            log.info('Trace')
            obj = salt.utils.msgpack.loads(stream_or_string)
            return _decoder(obj)
        except Exception as error:
            log.info('Trace')
            raise DeserializationError(error)
serialize = _serialize
deserialize = _deserialize
serialize.__doc__ = '\n    Serialize Python data to MsgPack.\n\n    :param obj: the data structure to serialize\n    :param options: options given to lower msgpack module.\n'
deserialize.__doc__ = '\n    Deserialize any string of stream like object into a Python data structure.\n\n    :param stream_or_string: stream or string to deserialize.\n    :param options: options given to lower msgpack module.\n'