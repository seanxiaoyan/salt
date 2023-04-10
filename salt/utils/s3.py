"""
Connection library for Amazon S3

:depends: requests
"""
import logging
import urllib.parse
import xml.etree.ElementTree as ET
import salt.utils.aws
import salt.utils.files
import salt.utils.hashutils
import salt.utils.xmlutil as xml
from salt.exceptions import CommandExecutionError
log = logging.getLogger(__name__)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def query(key, keyid, method='GET', params=None, headers=None, requesturl=None, return_url=False, bucket=None, service_url=None, path='', return_bin=False, action=None, local_file=None, verify_ssl=True, full_headers=False, kms_keyid=None, location=None, role_arn=None, chunk_size=16384, path_style=False, https_enable=True):
    log.info('Trace')
    '\n    Perform a query against an S3-like API. This function requires that a\n    secret key and the id for that key are passed in. For instance:\n\n        s3.keyid: GKTADJGHEIQSXMKKRBJ08H\n        s3.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs\n\n    If keyid or key is not specified, an attempt to fetch them from EC2 IAM\n    metadata service will be made.\n\n    A service_url may also be specified in the configuration:\n\n        s3.service_url: s3.amazonaws.com\n\n    If a service_url is not specified, the default is s3.amazonaws.com. This\n    may appear in various documentation as an "endpoint". A comprehensive list\n    for Amazon S3 may be found at::\n\n        http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region\n\n    The service_url will form the basis for the final endpoint that is used to\n    query the service.\n\n    Path style can be enabled:\n\n        s3.path_style: True\n\n    This can be useful if you need to use salt with a proxy for an s3 compatible storage\n\n    You can use either https protocol or http protocol:\n\n        s3.https_enable: True\n\n    SSL verification may also be turned off in the configuration:\n\n        s3.verify_ssl: False\n\n    This is required if using S3 bucket names that contain a period, as\n    these will not match Amazon\'s S3 wildcard certificates. Certificate\n    verification is enabled by default.\n\n    A region may be specified:\n\n        s3.location: eu-central-1\n\n    If region is not specified, an attempt to fetch the region from EC2 IAM\n    metadata service will be made. Failing that, default is us-east-1\n    '
    if not HAS_REQUESTS:
        log.error('There was an error: requests is required for s3 access')
    if not headers:
        log.info('Trace')
        headers = {}
    if not params:
        log.info('Trace')
        params = {}
    if not service_url:
        log.info('Trace')
        service_url = 's3.amazonaws.com'
    if not bucket or path_style:
        log.info('Trace')
        endpoint = service_url
    else:
        log.info('Trace')
        endpoint = '{}.{}'.format(bucket, service_url)
    if path_style and bucket:
        log.info('Trace')
        path = '{}/{}'.format(bucket, path)
    if not key:
        log.info('Trace')
        key = salt.utils.aws.IROLE_CODE
    if not keyid:
        log.info('Trace')
        keyid = salt.utils.aws.IROLE_CODE
    if kms_keyid is not None and method in ('PUT', 'POST'):
        log.info('Trace')
        headers['x-amz-server-side-encryption'] = 'aws:kms'
        headers['x-amz-server-side-encryption-aws-kms-key-id'] = kms_keyid
    if not location:
        log.info('Trace')
        location = salt.utils.aws.get_location()
    data = ''
    fh = None
    payload_hash = None
    if method == 'PUT':
        log.info('Trace')
        if local_file:
            payload_hash = salt.utils.hashutils.get_hash(local_file, form='sha256')
    if path is None:
        log.info('Trace')
        path = ''
    path = urllib.parse.quote(path)
    if not requesturl:
        log.info('Trace')
        requesturl = '{}://{}/{}'.format('https' if https_enable else 'http', endpoint, path)
        (headers, requesturl) = salt.utils.aws.sig4(method, endpoint, params, data=data, uri='/{}'.format(path), prov_dict={'id': keyid, 'key': key}, role_arn=role_arn, location=location, product='s3', requesturl=requesturl, headers=headers, payload_hash=payload_hash)
    log.debug('S3 Request: %s', requesturl)
    log.debug('S3 Headers::')
    log.debug('    Authorization: %s', headers['Authorization'])
    if not data:
        log.info('Trace')
        data = None
    try:
        log.info('Trace')
        if method == 'PUT':
            if local_file:
                fh = salt.utils.files.fopen(local_file, 'rb')
                data = fh.read()
            result = requests.request(method, requesturl, headers=headers, data=data, verify=verify_ssl, stream=True, timeout=300)
        elif method == 'GET' and local_file and (not return_bin):
            result = requests.request(method, requesturl, headers=headers, data=data, verify=verify_ssl, stream=True, timeout=300)
        else:
            result = requests.request(method, requesturl, headers=headers, data=data, verify=verify_ssl, timeout=300)
    finally:
        if fh is not None:
            log.info('Trace')
            fh.close()
    err_code = None
    err_msg = None
    if result.status_code >= 400:
        err_text = result.content or 'Unknown error'
        log.debug('    Response content: %s', err_text)
        try:
            log.info('Trace')
            err_data = xml.to_dict(ET.fromstring(err_text))
            err_code = err_data['Code']
            err_msg = err_data['Message']
        except (KeyError, ET.ParseError) as err:
            log.debug('Failed to parse s3 err response. %s: %s', type(err).__name__, err)
            err_code = 'http-{}'.format(result.status_code)
            err_msg = err_text
    log.debug('S3 Response Status Code: %s', result.status_code)
    if method == 'PUT':
        if result.status_code != 200:
            if local_file:
                raise CommandExecutionError('Failed to upload from {} to {}. {}: {}'.format(local_file, path, err_code, err_msg))
            raise CommandExecutionError('Failed to create bucket {}. {}: {}'.format(bucket, err_code, err_msg))
        if local_file:
            log.debug('Uploaded from %s to %s', local_file, path)
        else:
            log.debug('Created bucket %s', bucket)
        return
    if method == 'DELETE':
        if not str(result.status_code).startswith('2'):
            if path:
                raise CommandExecutionError('Failed to delete {} from bucket {}. {}: {}'.format(path, bucket, err_code, err_msg))
            raise CommandExecutionError('Failed to delete bucket {}. {}: {}'.format(bucket, err_code, err_msg))
        if path:
            log.debug('Deleted %s from bucket %s', path, bucket)
        else:
            log.debug('Deleted bucket %s', bucket)
        return
    if local_file and method == 'GET':
        if result.status_code < 200 or result.status_code >= 300:
            raise CommandExecutionError('Failed to get file. {}: {}'.format(err_code, err_msg))
        log.debug('Saving to local file: %s', local_file)
        with salt.utils.files.fopen(local_file, 'wb') as out:
            for chunk in result.iter_content(chunk_size=chunk_size):
                out.write(chunk)
        return 'Saved to local file: {}'.format(local_file)
    if result.status_code < 200 or result.status_code >= 300:
        log.info('Trace')
        raise CommandExecutionError('Failed s3 operation. {}: {}'.format(err_code, err_msg))
    if return_bin:
        log.info('Trace')
        return result.content
    if result.content:
        log.info('Trace')
        items = ET.fromstring(result.content)
        ret = []
        for item in items:
            ret.append(xml.to_dict(item))
        if return_url is True:
            return (ret, requesturl)
    else:
        if result.status_code != requests.codes.ok:
            return
        ret = {'headers': []}
        if full_headers:
            ret['headers'] = dict(result.headers)
        else:
            for header in result.headers:
                ret['headers'].append(header.strip())
    return ret