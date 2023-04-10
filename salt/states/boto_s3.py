"""
Manage S3 Resources
===================

.. versionadded:: 2018.3.0

Manage S3 resources. Be aware that this interacts with Amazon's services,
and so may incur charges.

This module uses ``boto3``, which can be installed via package, or pip.

This module accepts explicit AWS credentials but can also utilize
IAM roles assigned to the instance through Instance Profiles. Dynamic
credentials are then automatically obtained from AWS API and no further
configuration is necessary. More information available `here
<http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html>`_.

If IAM roles are not used you need to specify them either in a pillar file or
in the minion's config file:

.. code-block:: yaml

    s3.keyid: GKTADJGHEIQSXMKKRBJ08H
    s3.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

It's also possible to specify ``key``, ``keyid`` and ``region`` via a profile,
either passed in as a dict, or as a string to pull from pillars or minion
config:

.. code-block:: yaml

    myprofile:
        keyid: GKTADJGHEIQSXMKKRBJ08H
        key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            region: us-east-1

.. code-block:: yaml

    Ensure s3 object exists:
        boto_s3.object_present:
            - name: s3-bucket/s3-key
            - source: /path/to/local/file
            - region: us-east-1
            - keyid: GKTADJGHEIQSXMKKRBJ08H
            - key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            - profile: my-profile

:depends: boto3
"""
import copy
import difflib
import logging
import salt.utils.hashutils
log = logging.getLogger(__name__)

def __virtual__():
    """
    Only load if boto is available.
    """
    if 'boto_s3.get_object_metadata' not in __salt__:
        return (False, 'boto_s3 module could not be loaded')
    return 'boto_s3'
STORED_EXTRA_ARGS = frozenset(['CacheControl', 'ContentDisposition', 'ContentEncoding', 'ContentLanguage', 'ContentType', 'Expires', 'Metadata', 'ServerSideEncryption', 'SSECustomerAlgorithm', 'SSECustomerKeyMD5', 'SSEKMSKeyId', 'StorageClass', 'WebsiteRedirectLocation'])
UPLOAD_ONLY_EXTRA_ARGS = frozenset(['SSECustomerKey', 'RequestPayer'])
GET_METADATA_EXTRA_ARGS = frozenset(['SSECustomerAlgorithm', 'SSECustomerKey', 'SSECustomerKeyMD5', 'RequestPayer'])

def object_present(name, source=None, hash_type=None, extra_args=None, extra_args_from_pillar='boto_s3_object_extra_args', region=None, key=None, keyid=None, profile=None):
    log.info('Trace')
    "\n    Ensure object exists in S3.\n\n    name\n        The name of the state definition.\n        This will be used to determine the location of the object in S3,\n        by splitting on the first slash and using the first part\n        as the bucket name and the remainder as the S3 key.\n\n    source\n        The source file to upload to S3,\n        currently this only supports files hosted on the minion's local\n        file system (starting with /).\n\n    hash_type\n        Hash algorithm to use to check that the object contents are correct.\n        Defaults to the value of the `hash_type` config option.\n\n    extra_args\n        A dictionary of extra arguments to use when uploading the file.\n        Note that these are only enforced if new objects are uploaded,\n        and not modified on existing objects.\n        The supported args are those in the ALLOWED_UPLOAD_ARGS list at\n        http://boto3.readthedocs.io/en/latest/reference/customizations/s3.html.\n        However, Note that the 'ACL', 'GrantFullControl', 'GrantRead',\n        'GrantReadACP',  and 'GrantWriteACL' keys are currently not supported.\n\n    extra_args_from_pillar\n        Name of pillar dict that contains extra arguments.\n        Extra arguments defined for this specific state will be\n        merged over those from the pillar.\n\n    region\n        Region to connect to.\n\n    key\n        Secret key to be used.\n\n    keyid\n        Access key to be used.\n\n    profile\n        A dict with region, key and keyid, or a pillar key (string) that\n        contains a dict with region, key and keyid.\n    "
    ret = {'name': name, 'comment': '', 'changes': {}}
    if extra_args is None:
        extra_args = {}
    combined_extra_args = copy.deepcopy(__salt__['config.option'](extra_args_from_pillar, {}))
    __utils__['dictupdate.update'](combined_extra_args, extra_args)
    if combined_extra_args:
        supported_args = STORED_EXTRA_ARGS | UPLOAD_ONLY_EXTRA_ARGS
        combined_extra_args_keys = frozenset(combined_extra_args.keys())
        extra_keys = combined_extra_args_keys - supported_args
        if extra_keys:
            msg = 'extra_args keys {} are not supported'.format(extra_keys)
            return {'error': msg}
    if not hash_type:
        hash_type = __opts__['hash_type']
    try:
        log.info('Trace')
        digest = salt.utils.hashutils.get_hash(source, form=hash_type)
    except OSError as e:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = 'Could not read local file {}: {}'.format(source, e)
        return ret
    except ValueError as e:
        log.info('Trace')
        ret['result'] = False
        ret['comment'] = 'Could not hash local file {}: {}'.format(source, e)
        return ret
    HASH_METADATA_KEY = 'salt_managed_content_hash'
    combined_extra_args.setdefault('Metadata', {})
    if HASH_METADATA_KEY in combined_extra_args['Metadata']:
        if combined_extra_args['Metadata'][HASH_METADATA_KEY] != digest:
            ret['result'] = False
            ret['comment'] = 'Salt uses the {} metadata key internally,do not pass it to the boto_s3.object_present state.'.format(HASH_METADATA_KEY)
            return ret
    combined_extra_args['Metadata'][HASH_METADATA_KEY] = digest
    desired_metadata = {k: v for (k, v) in combined_extra_args.items() if k not in UPLOAD_ONLY_EXTRA_ARGS}
    metadata_extra_args = {k: v for (k, v) in combined_extra_args.items() if k in GET_METADATA_EXTRA_ARGS}
    r = __salt__['boto_s3.get_object_metadata'](name, extra_args=metadata_extra_args, region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to check if S3 object exists: {}.'.format(r['error'])
        return ret
    if r['result']:
        s3_metadata = {k: r['result'][k] for k in STORED_EXTRA_ARGS if k in desired_metadata and k in r['result']}
        if s3_metadata == desired_metadata:
            ret['result'] = True
            ret['comment'] = 'S3 object {} is present.'.format(name)
            return ret
        action = 'update'
    else:
        s3_metadata = None
        action = 'create'

    def _yaml_safe_dump(attrs):
        """
        Safely dump YAML using a readable flow style
        """
        dumper_name = 'IndentedSafeOrderedDumper'
        dumper = __utils__['yaml.get_dumper'](dumper_name)
        return __utils__['yaml.dump'](attrs, default_flow_style=False, Dumper=dumper)
    changes_diff = ''.join(difflib.unified_diff(_yaml_safe_dump(s3_metadata).splitlines(True), _yaml_safe_dump(desired_metadata).splitlines(True)))
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'S3 object {} set to be {}d.'.format(name, action)
        ret['comment'] += '\nChanges:\n{}'.format(changes_diff)
        ret['changes'] = {'diff': changes_diff}
        return ret
    r = __salt__['boto_s3.upload_file'](source, name, extra_args=combined_extra_args, region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to {} S3 object: {}.'.format(action, r['error'])
        return ret
    ret['result'] = True
    ret['comment'] = 'S3 object {} {}d.'.format(name, action)
    ret['comment'] += '\nChanges:\n{}'.format(changes_diff)
    ret['changes'] = {'diff': changes_diff}
    return ret