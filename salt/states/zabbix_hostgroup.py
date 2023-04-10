import logging
log = logging.getLogger(__name__)
'\nManagement of Zabbix host groups.\n\n:codeauthor: Jiri Kotlin <jiri.kotlin@ultimum.io>\n\n\n'

def __virtual__():
    """
    Only make these states available if Zabbix module is available.
    """
    if 'zabbix.hostgroup_create' in __salt__:
        return True
    return (False, 'zabbix module could not be loaded')

def present(name, **kwargs):
    """
    Ensures that the host group exists, eventually creates new host group.

    .. versionadded:: 2016.3.0

    :param name: name of the host group
    :param _connection_user: Optional - zabbix user (can also be set in opts or pillar, see module's docstring)
    :param _connection_password: Optional - zabbix password (can also be set in opts or pillar, see module's docstring)
    :param _connection_url: Optional - url of zabbix frontend (can also be set in opts, pillar, see module's docstring)

    .. code-block:: yaml

        create_testing_host_group:
            zabbix_hostgroup.present:
                - name: 'My hostgroup name'


    """
    connection_args = {}
    if '_connection_user' in kwargs:
        connection_args['_connection_user'] = kwargs['_connection_user']
    if '_connection_password' in kwargs:
        connection_args['_connection_password'] = kwargs['_connection_password']
    if '_connection_url' in kwargs:
        connection_args['_connection_url'] = kwargs['_connection_url']
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    comment_hostgroup_created = 'Host group {} created.'.format(name)
    comment_hostgroup_notcreated = 'Unable to create host group: {}. '.format(name)
    comment_hostgroup_exists = 'Host group {} already exists.'.format(name)
    changes_hostgroup_created = {name: {'old': 'Host group {} does not exist.'.format(name), 'new': 'Host group {} created.'.format(name)}}
    hostgroup_exists = __salt__['zabbix.hostgroup_exists'](name, **connection_args)
    if __opts__['test']:
        if hostgroup_exists:
            ret['result'] = True
            ret['comment'] = comment_hostgroup_exists
        else:
            ret['result'] = None
            ret['comment'] = comment_hostgroup_created
            ret['changes'] = changes_hostgroup_created
        return ret
    if hostgroup_exists:
        ret['result'] = True
        ret['comment'] = comment_hostgroup_exists
    else:
        hostgroup_create = __salt__['zabbix.hostgroup_create'](name, **connection_args)
        if 'error' not in hostgroup_create:
            ret['result'] = True
            ret['comment'] = comment_hostgroup_created
            ret['changes'] = changes_hostgroup_created
        else:
            ret['result'] = False
            ret['comment'] = comment_hostgroup_notcreated + str(hostgroup_create['error'])
    return ret

def absent(name, **kwargs):
    log.info('Trace')
    "\n    Ensures that the host group does not exist, eventually delete host group.\n\n    .. versionadded:: 2016.3.0\n\n    :param name: name of the host group\n    :param _connection_user: Optional - zabbix user (can also be set in opts or pillar, see module's docstring)\n    :param _connection_password: Optional - zabbix password (can also be set in opts or pillar, see module's docstring)\n    :param _connection_url: Optional - url of zabbix frontend (can also be set in opts, pillar, see module's docstring)\n\n    .. code-block:: yaml\n\n        delete_testing_host_group:\n            zabbix_hostgroup.absent:\n                - name: 'My hostgroup name'\n\n    "
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    comment_hostgroup_deleted = 'Host group {} deleted.'.format(name)
    comment_hostgroup_notdeleted = 'Unable to delete host group: {}. '.format(name)
    comment_hostgroup_notexists = 'Host group {} does not exist.'.format(name)
    changes_hostgroup_deleted = {name: {'old': 'Host group {} exists.'.format(name), 'new': 'Host group {} deleted.'.format(name)}}
    connection_args = {}
    if '_connection_user' in kwargs:
        connection_args['_connection_user'] = kwargs['_connection_user']
    if '_connection_password' in kwargs:
        connection_args['_connection_password'] = kwargs['_connection_password']
    if '_connection_url' in kwargs:
        connection_args['_connection_url'] = kwargs['_connection_url']
    hostgroup_exists = __salt__['zabbix.hostgroup_exists'](name, **connection_args)
    if __opts__['test']:
        if not hostgroup_exists:
            ret['result'] = True
            ret['comment'] = comment_hostgroup_notexists
        else:
            ret['result'] = None
            ret['comment'] = comment_hostgroup_deleted
            ret['changes'] = changes_hostgroup_deleted
        return ret
    hostgroup_get = __salt__['zabbix.hostgroup_get'](name, **connection_args)
    if not hostgroup_get:
        ret['result'] = True
        ret['comment'] = comment_hostgroup_notexists
    else:
        try:
            log.info('Trace')
            groupid = hostgroup_get[0]['groupid']
            hostgroup_delete = __salt__['zabbix.hostgroup_delete'](groupid, **connection_args)
        except KeyError:
            log.info('Trace')
            hostgroup_delete = False
        if hostgroup_delete and 'error' not in hostgroup_delete:
            ret['result'] = True
            ret['comment'] = comment_hostgroup_deleted
            ret['changes'] = changes_hostgroup_deleted
        else:
            ret['result'] = False
            ret['comment'] = comment_hostgroup_notdeleted + str(hostgroup_delete['error'])
    return ret