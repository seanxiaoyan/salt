# -*- coding: utf-8 -*-
'''
Boto Common Utils
=================

Note: This module depends on the dicts packed by the loader and,
therefore, must be accessed via the loader or from the __utils__ dict.

.. versionadded:: Beryllium
'''

# Import Python libs
from __future__ import absolute_import
import hashlib
import logging
from distutils.version import LooseVersion as _LooseVersion  # pylint: disable=import-error,no-name-in-module

# Import salt libs
from salt.exceptions import SaltInvocationError, CommandExecutionError
from salt._compat import ElementTree as ET

# Import third party libs
# pylint: disable=import-error
try:
    # pylint: disable=import-error
    import boto
    import boto.exception
    from boto.exception import BotoServerError
    # pylint: enable=import-error
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
# pylint: enable=import-error


log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if boto libraries exist and if boto libraries are greater than
    a given version.
    '''
    # TODO: Determine minimal version we want to support. VPC requires > 2.8.0.
    required_boto_version = '2.0.0'
    if not HAS_BOTO:
        return False
    elif _LooseVersion(boto.__version__) < _LooseVersion(required_boto_version):
        return False
    else:
        return True


def _option(value):
    '''
    Look up the value for an option.
    '''
    if value in __opts__:
        return __opts__[value]
    master_opts = __pillar__.get('master', {})
    if value in master_opts:
        return master_opts[value]
    if value in __pillar__:
        return __pillar__[value]


def _get_profile(service, region, key, keyid, profile):
    if profile:
        if isinstance(profile, six.string_types):
            _profile = _option(profile)
        elif isinstance(profile, dict):
            _profile = profile
        key = _profile.get('key', None)
        keyid = _profile.get('keyid', None)
        region = _profile.get('region', None)

    if not region and _option(service + '.region'):
        region = _option(service + '.region')

    if not region:
        region = 'us-east-1'

    if not key and _option(service + '.key'):
        key = _option(service + '.key')
    if not keyid and _option(service + '.keyid'):
        keyid = _option(service + '.keyid')

    label = 'boto_{0}:'.format(service)
    if keyid:
        cxkey = label + hashlib.md5(region + keyid + key).hexdigest()
    else:
        cxkey = label + region

    return (cxkey, region, key, keyid)


def cache_id(service, name, sub_resource=None, resource_id=None,
             invalidate=False, region=None, key=None, keyid=None,
             profile=None):
    '''
    Cache, invalidate, or retrieve an AWS resource id keyed by name.
    '''

    cxkey, _, _, _ = _get_profile(service, region, key,
                                  keyid, profile)
    if sub_resource:
        cxkey = '{0}:{1}:{2}:id'.format(cxkey, sub_resource, name)
    else:
        cxkey = '{0}:{1}:id'.format(cxkey, name)

    if invalidate:
        if cxkey in __context__:
            del __context__[cxkey]
            return True
        else:
            return False
    if resource_id:
        __context__[cxkey] = resource_id
        return True

    return __context__.get(cxkey)


def get_connection(service, module=None, region=None, key=None, keyid=None,
             profile=None):
    '''
    Return a boto connection for the service.

    .. code-block:: python

        conn = __utils__['boto.get_connection']('ec2', profile='custom_profile')
    '''

    module = module or service

    svc_mod = __import__('boto.' + module, fromlist=[module])

    cxkey, region, key, keyid = _get_profile(service, region, key,
                                             keyid, profile)
    cxkey = cxkey + ':conn'

    if cxkey in __context__:
        return __context__[cxkey]

    try:
        conn = svc_mod.connect_to_region(region, aws_access_key_id=keyid,
                                         aws_secret_access_key=key)
    except boto.exception.NoAuthHandlerFound:
        raise SaltInvocationError('No authentication credentials found when '
                                  'attempting to make boto {0} connection to '
                                  'region "{1}".'.format(service, region))
    except BotoServerError as exc:
        raise CommandExecutionError(exc.reason)
    __context__[cxkey] = conn
    return conn
