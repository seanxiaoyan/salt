"""
All salt configuration loading and defaults should be in this module
"""
import codecs
import glob
import logging
import os
import re
import sys
import time
import types
import urllib.parse
from copy import deepcopy
import salt.defaults.exitcodes
import salt.exceptions
import salt.syspaths
import salt.utils.data
import salt.utils.dictupdate
import salt.utils.files
import salt.utils.immutabletypes as immutabletypes
import salt.utils.network
import salt.utils.path
import salt.utils.platform
import salt.utils.stringutils
import salt.utils.user
import salt.utils.validate.path
import salt.utils.xdg
import salt.utils.yaml
import salt.utils.zeromq
from salt._logging import DFLT_LOG_DATEFMT, DFLT_LOG_DATEFMT_LOGFILE, DFLT_LOG_FMT_CONSOLE, DFLT_LOG_FMT_JID, DFLT_LOG_FMT_LOGFILE
log = logging.getLogger(__name__)
try:
    import psutil
    if not hasattr(psutil, 'virtual_memory'):
        raise ImportError('Version of psutil too old.')
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
_DFLT_REFSPECS = ['+refs/heads/*:refs/remotes/origin/*', '+refs/tags/*:refs/tags/*']
DEFAULT_INTERVAL = 60
if salt.utils.platform.is_windows():
    _DFLT_IPC_MODE = 'tcp'
    _DFLT_FQDNS_GRAINS = False
    _MASTER_TRIES = -1
    _MASTER_USER = 'SYSTEM'
elif salt.utils.platform.is_proxy():
    _DFLT_IPC_MODE = 'ipc'
    _DFLT_FQDNS_GRAINS = False
    _MASTER_TRIES = 1
    _MASTER_USER = salt.utils.user.get_user()
else:
    _DFLT_IPC_MODE = 'ipc'
    _DFLT_FQDNS_GRAINS = True
    _MASTER_TRIES = 1
    _MASTER_USER = salt.utils.user.get_user()

def _gather_buffer_space():
    """
    Gather some system data and then calculate
    buffer space.

    Result is in bytes.
    """
    if HAS_PSUTIL and psutil.version_info >= (0, 6, 0):
        total_mem = psutil.virtual_memory().total
    else:
        import platform
        import salt.grains.core
        os_data = {'kernel': platform.system()}
        grains = salt.grains.core._memdata(os_data)
        total_mem = grains['mem_total']
    return max([total_mem * 0.05, 10 << 20])
_DFLT_IPC_WBUFFER = _gather_buffer_space() * 0.5
_DFLT_IPC_RBUFFER = _gather_buffer_space() * 0.5
VALID_OPTS = immutabletypes.freeze({'master': (str, list), 'master_port': (str, int), 'master_type': str, 'master_uri_format': str, 'source_interface_name': str, 'source_address': str, 'source_ret_port': (str, int), 'source_publish_port': (str, int), 'master_finger': str, 'master_shuffle': bool, 'master_alive_interval': int, 'master_failback': bool, 'master_failback_interval': int, 'master_sign_key_name': str, 'master_sign_pubkey': bool, 'verify_master_pubkey_sign': bool, 'always_verify_signature': bool, 'master_pubkey_signature': str, 'master_use_pubkey_signature': bool, 'master_stats': bool, 'master_stats_event_iter': int, 'syndic_finger': str, 'key_cache': str, 'user': str, 'root_dir': str, 'pki_dir': str, 'id': str, 'id_function': (dict, str), 'cachedir': str, 'append_minionid_config_dirs': list, 'cache_jobs': bool, 'conf_file': str, 'sock_dir': str, 'sock_pool_size': int, 'backup_mode': str, 'renderer': str, 'renderer_whitelist': list, 'renderer_blacklist': list, 'failhard': bool, 'autoload_dynamic_modules': bool, 'saltenv': (type(None), str), 'lock_saltenv': bool, 'pillarenv': (type(None), str), 'pillarenv_from_saltenv': bool, 'state_top': str, 'state_top_saltenv': (type(None), str), 'startup_states': str, 'sls_list': list, 'snapper_states': bool, 'snapper_states_config': str, 'top_file': str, 'file_client': str, 'local': bool, 'use_master_when_local': bool, 'file_roots': dict, 'pillar_roots': dict, 'on_demand_ext_pillar': list, 'decrypt_pillar': list, 'decrypt_pillar_delimiter': str, 'decrypt_pillar_default': str, 'decrypt_pillar_renderers': list, 'gpg_decrypt_must_succeed': bool, 'hash_type': str, 'optimization_order': list, 'disable_modules': list, 'disable_returners': list, 'whitelist_modules': list, 'module_dirs': list, 'returner_dirs': list, 'states_dirs': list, 'grains_dirs': list, 'render_dirs': list, 'outputter_dirs': list, 'utils_dirs': list, 'providers': dict, 'clean_dynamic_modules': bool, 'open_mode': bool, 'multiprocessing': bool, 'process_count_max': int, 'mine_enabled': bool, 'mine_return_job': bool, 'mine_interval': int, 'ipc_mode': str, 'ipv6': (type(None), bool), 'file_buffer_size': int, 'tcp_pub_port': int, 'tcp_pull_port': int, 'tcp_master_pub_port': int, 'tcp_master_pull_port': int, 'tcp_master_publish_pull': int, 'tcp_master_workers': int, 'log_file': str, 'log_level': str, 'log_level_logfile': (type(None), str), 'log_datefmt': str, 'log_datefmt_logfile': str, 'log_fmt_console': str, 'log_fmt_logfile': (tuple, str), 'log_granular_levels': dict, 'log_rotate_max_bytes': int, 'log_rotate_backup_count': int, 'max_event_size': int, 'enable_legacy_startup_events': bool, 'test': bool, 'cython_enable': bool, 'enable_fqdns_grains': bool, 'enable_gpu_grains': bool, 'enable_zip_modules': bool, 'show_timeout': bool, 'show_jid': bool, 'unique_jid': bool, 'state_verbose': bool, 'state_output': str, 'state_output_diff': bool, 'state_output_profile': bool, 'state_output_pct': bool, 'state_compress_ids': bool, 'state_auto_order': bool, 'state_events': bool, 'acceptance_wait_time': float, 'acceptance_wait_time_max': float, 'rejected_retry': bool, 'loop_interval': float, 'verify_env': bool, 'grains': dict, 'permissive_pki_access': bool, 'key_pass': (type(None), str), 'signing_key_pass': (type(None), str), 'default_include': str, 'update_url': (bool, str), 'update_restart_services': list, 'retry_dns': float, 'retry_dns_count': (type(None), int), 'resolve_dns_fallback': bool, 'recon_max': float, 'recon_default': float, 'recon_randomize': bool, 'return_retry_timer': int, 'return_retry_timer_max': int, 'return_retry_tries': int, 'event_return': (list, str), 'event_return_queue': int, 'event_return_queue_max_seconds': int, 'event_return_whitelist': list, 'event_return_blacklist': list, 'event_match_type': str, 'pidfile': str, 'range_server': str, 'tcp_keepalive': bool, 'tcp_keepalive_idle': float, 'tcp_keepalive_cnt': float, 'tcp_keepalive_intvl': float, 'interface': str, 'publish_port': int, 'auth_mode': int, 'zmq_backlog': int, 'pub_hwm': int, 'ipc_write_buffer': int, 'req_server_niceness': (type(None), int), 'pub_server_niceness': (type(None), int), 'fileserver_update_niceness': (type(None), int), 'maintenance_niceness': (type(None), int), 'mworker_niceness': (type(None), int), 'mworker_queue_niceness': (type(None), int), 'event_return_niceness': (type(None), int), 'event_publisher_niceness': (type(None), int), 'reactor_niceness': (type(None), int), 'worker_threads': int, 'ret_port': int, 'keep_jobs': int, 'archive_jobs': bool, 'master_roots': dict, 'add_proxymodule_to_opts': bool, 'proxy_merge_pillar_in_opts': bool, 'proxy_deep_merge_pillar_in_opts': bool, 'proxy_merge_pillar_in_opts_strategy': str, 'proxy_mines_pillar': bool, 'proxy_always_alive': bool, 'proxy_keep_alive': bool, 'proxy_keep_alive_interval': int, 'roots_update_interval': int, 'azurefs_update_interval': int, 'gitfs_update_interval': int, 'git_pillar_update_interval': int, 'hgfs_update_interval': int, 'minionfs_update_interval': int, 's3fs_update_interval': int, 'svnfs_update_interval': int, 'git_pillar_ssl_verify': bool, 'git_pillar_global_lock': bool, 'git_pillar_user': str, 'git_pillar_password': str, 'git_pillar_insecure_auth': bool, 'git_pillar_privkey': str, 'git_pillar_pubkey': str, 'git_pillar_passphrase': str, 'git_pillar_refspecs': list, 'git_pillar_includes': bool, 'git_pillar_verify_config': bool, 'gitfs_remotes': list, 'gitfs_insecure_auth': bool, 'gitfs_privkey': str, 'gitfs_pubkey': str, 'gitfs_passphrase': str, 'gitfs_saltenv_whitelist': list, 'gitfs_saltenv_blacklist': list, 'gitfs_ssl_verify': bool, 'gitfs_global_lock': bool, 'gitfs_saltenv': list, 'gitfs_ref_types': list, 'gitfs_refspecs': list, 'gitfs_disable_saltenv_mapping': bool, 'hgfs_remotes': list, 'hgfs_mountpoint': str, 'hgfs_root': str, 'hgfs_base': str, 'hgfs_branch_method': str, 'hgfs_saltenv_whitelist': list, 'hgfs_saltenv_blacklist': list, 'svnfs_remotes': list, 'svnfs_mountpoint': str, 'svnfs_root': str, 'svnfs_trunk': str, 'svnfs_branches': str, 'svnfs_tags': str, 'svnfs_saltenv_whitelist': list, 'svnfs_saltenv_blacklist': list, 'minionfs_env': str, 'minionfs_mountpoint': str, 'minionfs_whitelist': list, 'minionfs_blacklist': list, 'ext_pillar': list, 'pillar_version': int, 'pillar_opts': bool, 'pillar_cache': bool, 'pillar_cache_ttl': int, 'pillar_cache_backend': str, 'gpg_cache': bool, 'gpg_cache_ttl': int, 'gpg_cache_backend': str, 'pillar_safe_render_error': bool, 'pillar_source_merging_strategy': str, 'pillar_merge_lists': bool, 'pillar_includes_override_sls': bool, 'top_file_merging_strategy': str, 'env_order': list, 'default_top': str, 'ping_on_rotate': bool, 'peer': dict, 'preserve_minion_cache': bool, 'syndic_master': (str, list), 'syndic_failover': str, 'syndic_forward_all_events': bool, 'runner_dirs': list, 'client_acl_verify': bool, 'publisher_acl': dict, 'publisher_acl_blacklist': dict, 'sudo_acl': bool, 'external_auth': dict, 'token_expire': int, 'token_expire_user_override': (bool, dict), 'file_recv': bool, 'file_recv_max_size': int, 'file_ignore_regex': (list, str), 'file_ignore_glob': (list, str), 'fileserver_backend': list, 'fileserver_followsymlinks': bool, 'fileserver_ignoresymlinks': bool, 'fileserver_verify_config': bool, 'permissive_acl': bool, 'keep_acl_in_token': bool, 'eauth_acl_module': str, 'eauth_tokens': str, 'max_open_files': int, 'auto_accept': bool, 'autosign_timeout': int, 'master_tops': dict, 'master_tops_first': bool, 'order_masters': bool, 'job_cache': bool, 'ext_job_cache': str, 'master_job_cache': str, 'job_cache_store_endtime': bool, 'minion_data_cache': bool, 'publish_session': int, 'reactor': list, 'reactor_refresh_interval': int, 'reactor_worker_threads': int, 'reactor_worker_hwm': int, 'engines': list, 'runner_returns': bool, 'serial': str, 'search': str, 'nodegroups': (dict, list), 'ssh_list_nodegroups': dict, 'ssh_use_home_key': bool, 'key_logfile': str, 'random_startup_delay': int, 'winrepo_source_dir': str, 'winrepo_dir': str, 'winrepo_dir_ng': str, 'winrepo_cachefile': str, 'winrepo_cache_expire_max': int, 'winrepo_cache_expire_min': int, 'winrepo_remotes': list, 'winrepo_remotes_ng': list, 'winrepo_ssl_verify': bool, 'winrepo_user': str, 'winrepo_password': str, 'winrepo_insecure_auth': bool, 'winrepo_privkey': str, 'winrepo_pubkey': str, 'winrepo_passphrase': str, 'winrepo_refspecs': list, 'modules_max_memory': int, 'grains_blacklist': list, 'grains_refresh_every': int, 'grains_refresh_pre_exec': bool, 'enable_lspci': bool, 'syndic_wait': int, 'jinja_env': dict, 'jinja_sls_env': dict, 'jinja_lstrip_blocks': bool, 'jinja_trim_blocks': bool, 'minion_id_caching': bool, 'minion_id_lowercase': bool, 'minion_id_remove_domain': (str, bool), 'sign_pub_messages': bool, 'keysize': int, 'transport': str, 'gather_job_timeout': int, 'auth_timeout': int, 'auth_tries': int, 'master_tries': int, 'auth_safemode': bool, 'random_master': bool, 'random_reauth_delay': int, 'syndic_event_forward_timeout': float, 'syndic_jid_forward_cache_hwm': int, 'ssh_passwd': str, 'ssh_port': str, 'ssh_sudo': bool, 'ssh_sudo_user': str, 'ssh_timeout': float, 'ssh_user': str, 'ssh_scan_ports': str, 'ssh_scan_timeout': float, 'ssh_identities_only': bool, 'ssh_log_file': str, 'ssh_config_file': str, 'ssh_merge_pillar': bool, 'ssh_run_pre_flight': bool, 'cluster_mode': bool, 'sqlite_queue_dir': str, 'queue_dirs': list, 'ping_interval': int, 'cli_summary': bool, 'max_minions': int, 'username': (type(None), str), 'password': (type(None), str), 'zmq_filtering': bool, 'con_cache': bool, 'rotate_aes_key': bool, 'cache_sreqs': bool, 'cmd_safe': bool, 'rest_timeout': int, 'sudo_user': str, 'http_connect_timeout': float, 'http_request_timeout': float, 'http_max_body': int, 'bootstrap_delay': int, 'proxy_merge_grains_in_module': bool, 'minion_restart_command': list, 'pub_ret': bool, 'proxy_host': str, 'proxy_username': str, 'proxy_password': str, 'proxy_port': int, 'no_proxy': list, 'minion_jid_queue_hwm': int, 'cache': str, 'memcache_expire_seconds': int, 'memcache_max_items': int, 'memcache_full_cleanup': bool, 'memcache_debug': bool, 'thin_extra_mods': str, 'min_extra_mods': str, 'return': (str, list), 'ssl': (dict, bool, type(None)), 'multifunc_ordered': bool, 'beacons_before_connect': bool, 'scheduler_before_connect': bool, 'extmod_whitelist': dict, 'extmod_blacklist': dict, 'django_auth_path': str, 'django_auth_settings': str, 'tcp_authentication_retries': int, 'tcp_reconnect_backoff': float, 'allow_minion_key_revoke': bool, 'salt_cp_chunk_size': int, 'minion_sign_messages': bool, 'drop_messages_signature_fail': bool, 'require_minion_sign_messages': bool, 'pass_to_ext_pillars': (str, list), 'discovery': (dict, bool), 'schedule': dict, 'auth_events': bool, 'minion_data_cache_events': bool, 'enable_ssh_minions': bool, 'thoriumenv': (type(None), str), 'thorium_top': str, 'netapi_allow_raw_shell': bool, 'disabled_requisites': (str, list), 'features': dict, 'fips_mode': bool, 'detect_remote_minions': bool, 'remote_minions_port': int})
DEFAULT_MINION_OPTS = immutabletypes.freeze({'interface': '0.0.0.0', 'master': 'salt', 'master_type': 'str', 'master_uri_format': 'default', 'source_interface_name': '', 'source_address': '', 'source_ret_port': 0, 'source_publish_port': 0, 'master_port': 4506, 'master_finger': '', 'master_shuffle': False, 'master_alive_interval': 0, 'master_failback': False, 'master_failback_interval': 0, 'verify_master_pubkey_sign': False, 'sign_pub_messages': False, 'always_verify_signature': False, 'master_sign_key_name': 'master_sign', 'syndic_finger': '', 'user': salt.utils.user.get_user(), 'root_dir': salt.syspaths.ROOT_DIR, 'pki_dir': os.path.join(salt.syspaths.CONFIG_DIR, 'pki', 'minion'), 'id': '', 'id_function': {}, 'cachedir': os.path.join(salt.syspaths.CACHE_DIR, 'minion'), 'append_minionid_config_dirs': [], 'cache_jobs': False, 'grains_blacklist': [], 'grains_cache': False, 'grains_cache_expiration': 300, 'grains_deep_merge': False, 'conf_file': os.path.join(salt.syspaths.CONFIG_DIR, 'minion'), 'sock_dir': os.path.join(salt.syspaths.SOCK_DIR, 'minion'), 'sock_pool_size': 1, 'backup_mode': '', 'renderer': 'jinja|yaml', 'renderer_whitelist': [], 'renderer_blacklist': [], 'random_startup_delay': 0, 'failhard': False, 'autoload_dynamic_modules': True, 'saltenv': None, 'lock_saltenv': False, 'pillarenv': None, 'pillarenv_from_saltenv': False, 'pillar_opts': False, 'pillar_source_merging_strategy': 'smart', 'pillar_merge_lists': False, 'pillar_includes_override_sls': False, 'pillar_cache': False, 'pillar_cache_ttl': 3600, 'pillar_cache_backend': 'disk', 'gpg_cache': False, 'gpg_cache_ttl': 86400, 'gpg_cache_backend': 'disk', 'extension_modules': os.path.join(salt.syspaths.CACHE_DIR, 'minion', 'extmods'), 'state_top': 'top.sls', 'state_top_saltenv': None, 'startup_states': '', 'sls_list': [], 'start_event_grains': [], 'top_file': '', 'thoriumenv': None, 'thorium_top': 'top.sls', 'thorium_interval': 0.5, 'thorium_roots': {'base': [salt.syspaths.BASE_THORIUM_ROOTS_DIR]}, 'file_client': 'remote', 'local': False, 'use_master_when_local': False, 'file_roots': {'base': [salt.syspaths.BASE_FILE_ROOTS_DIR, salt.syspaths.SPM_FORMULA_PATH]}, 'top_file_merging_strategy': 'merge', 'env_order': [], 'default_top': 'base', 'file_recv': False, 'file_recv_max_size': 100, 'file_ignore_regex': [], 'file_ignore_glob': [], 'fileserver_backend': ['roots'], 'fileserver_followsymlinks': True, 'fileserver_ignoresymlinks': False, 'pillar_roots': {'base': [salt.syspaths.BASE_PILLAR_ROOTS_DIR, salt.syspaths.SPM_PILLAR_PATH]}, 'on_demand_ext_pillar': ['libvirt', 'virtkey'], 'decrypt_pillar': [], 'decrypt_pillar_delimiter': ':', 'decrypt_pillar_default': 'gpg', 'decrypt_pillar_renderers': ['gpg'], 'gpg_decrypt_must_succeed': False, 'roots_update_interval': DEFAULT_INTERVAL, 'azurefs_update_interval': DEFAULT_INTERVAL, 'gitfs_update_interval': DEFAULT_INTERVAL, 'git_pillar_update_interval': DEFAULT_INTERVAL, 'hgfs_update_interval': DEFAULT_INTERVAL, 'minionfs_update_interval': DEFAULT_INTERVAL, 's3fs_update_interval': DEFAULT_INTERVAL, 'svnfs_update_interval': DEFAULT_INTERVAL, 'git_pillar_base': 'master', 'git_pillar_branch': 'master', 'git_pillar_env': '', 'git_pillar_fallback': '', 'git_pillar_root': '', 'git_pillar_ssl_verify': True, 'git_pillar_global_lock': True, 'git_pillar_user': '', 'git_pillar_password': '', 'git_pillar_insecure_auth': False, 'git_pillar_privkey': '', 'git_pillar_pubkey': '', 'git_pillar_passphrase': '', 'git_pillar_refspecs': _DFLT_REFSPECS, 'git_pillar_includes': True, 'gitfs_remotes': [], 'gitfs_mountpoint': '', 'gitfs_root': '', 'gitfs_base': 'master', 'gitfs_fallback': '', 'gitfs_user': '', 'gitfs_password': '', 'gitfs_insecure_auth': False, 'gitfs_privkey': '', 'gitfs_pubkey': '', 'gitfs_passphrase': '', 'gitfs_saltenv_whitelist': [], 'gitfs_saltenv_blacklist': [], 'gitfs_global_lock': True, 'gitfs_ssl_verify': True, 'gitfs_saltenv': [], 'gitfs_ref_types': ['branch', 'tag', 'sha'], 'gitfs_refspecs': _DFLT_REFSPECS, 'gitfs_disable_saltenv_mapping': False, 'unique_jid': False, 'hash_type': 'sha256', 'optimization_order': [0, 1, 2], 'disable_modules': [], 'disable_returners': [], 'whitelist_modules': [], 'module_dirs': [], 'returner_dirs': [], 'grains_dirs': [], 'states_dirs': [], 'render_dirs': [], 'outputter_dirs': [], 'utils_dirs': [], 'publisher_acl': {}, 'publisher_acl_blacklist': {}, 'providers': {}, 'clean_dynamic_modules': True, 'open_mode': False, 'auto_accept': True, 'autosign_timeout': 120, 'multiprocessing': True, 'process_count_max': -1, 'mine_enabled': True, 'mine_return_job': False, 'mine_interval': 60, 'ipc_mode': _DFLT_IPC_MODE, 'ipc_write_buffer': _DFLT_IPC_WBUFFER, 'ipv6': None, 'file_buffer_size': 262144, 'tcp_pub_port': 4510, 'tcp_pull_port': 4511, 'tcp_authentication_retries': 5, 'tcp_reconnect_backoff': 1, 'log_file': os.path.join(salt.syspaths.LOGS_DIR, 'minion'), 'log_level': 'warning', 'log_level_logfile': None, 'log_datefmt': DFLT_LOG_DATEFMT, 'log_datefmt_logfile': DFLT_LOG_DATEFMT_LOGFILE, 'log_fmt_console': DFLT_LOG_FMT_CONSOLE, 'log_fmt_logfile': DFLT_LOG_FMT_LOGFILE, 'log_fmt_jid': DFLT_LOG_FMT_JID, 'log_granular_levels': {}, 'log_rotate_max_bytes': 0, 'log_rotate_backup_count': 0, 'max_event_size': 1048576, 'enable_legacy_startup_events': True, 'test': False, 'ext_job_cache': '', 'cython_enable': False, 'enable_fqdns_grains': _DFLT_FQDNS_GRAINS, 'enable_gpu_grains': True, 'enable_zip_modules': False, 'state_verbose': True, 'state_output': 'full', 'state_output_diff': False, 'state_output_profile': True, 'state_auto_order': True, 'state_events': False, 'state_aggregate': False, 'snapper_states': False, 'snapper_states_config': 'root', 'acceptance_wait_time': 10, 'acceptance_wait_time_max': 0, 'rejected_retry': False, 'loop_interval': 1, 'verify_env': True, 'grains': {}, 'permissive_pki_access': False, 'default_include': 'minion.d/*.conf', 'update_url': False, 'update_restart_services': [], 'retry_dns': 30, 'retry_dns_count': None, 'resolve_dns_fallback': True, 'recon_max': 10000, 'recon_default': 1000, 'recon_randomize': True, 'return_retry_timer': 5, 'return_retry_timer_max': 10, 'return_retry_tries': 3, 'random_reauth_delay': 10, 'winrepo_source_dir': 'salt://win/repo-ng/', 'winrepo_dir': os.path.join(salt.syspaths.BASE_FILE_ROOTS_DIR, 'win', 'repo'), 'winrepo_dir_ng': os.path.join(salt.syspaths.BASE_FILE_ROOTS_DIR, 'win', 'repo-ng'), 'winrepo_cachefile': 'winrepo.p', 'winrepo_cache_expire_max': 604800, 'winrepo_cache_expire_min': 1800, 'winrepo_remotes': ['https://github.com/saltstack/salt-winrepo.git'], 'winrepo_remotes_ng': ['https://github.com/saltstack/salt-winrepo-ng.git'], 'winrepo_branch': 'master', 'winrepo_fallback': '', 'winrepo_ssl_verify': True, 'winrepo_user': '', 'winrepo_password': '', 'winrepo_insecure_auth': False, 'winrepo_privkey': '', 'winrepo_pubkey': '', 'winrepo_passphrase': '', 'winrepo_refspecs': _DFLT_REFSPECS, 'pidfile': os.path.join(salt.syspaths.PIDFILE_DIR, 'salt-minion.pid'), 'range_server': 'range:80', 'reactor_refresh_interval': 60, 'reactor_worker_threads': 10, 'reactor_worker_hwm': 10000, 'engines': [], 'tcp_keepalive': True, 'tcp_keepalive_idle': 300, 'tcp_keepalive_cnt': -1, 'tcp_keepalive_intvl': -1, 'modules_max_memory': -1, 'grains_refresh_every': 0, 'minion_id_caching': True, 'minion_id_lowercase': False, 'minion_id_remove_domain': False, 'keysize': 2048, 'transport': 'zeromq', 'auth_timeout': 5, 'auth_tries': 7, 'master_tries': _MASTER_TRIES, 'master_tops_first': False, 'auth_safemode': False, 'random_master': False, 'cluster_mode': False, 'restart_on_error': False, 'ping_interval': 0, 'username': None, 'password': None, 'zmq_filtering': False, 'zmq_monitor': False, 'cache_sreqs': True, 'cmd_safe': True, 'sudo_user': '', 'http_connect_timeout': 20.0, 'http_request_timeout': 1 * 60 * 60.0, 'http_max_body': 100 * 1024 * 1024 * 1024, 'event_match_type': 'startswith', 'minion_restart_command': [], 'pub_ret': True, 'proxy_host': '', 'proxy_username': '', 'proxy_password': '', 'proxy_port': 0, 'minion_jid_queue_hwm': 100, 'ssl': None, 'multifunc_ordered': False, 'beacons_before_connect': False, 'scheduler_before_connect': False, 'cache': 'localfs', 'salt_cp_chunk_size': 65536, 'extmod_whitelist': {}, 'extmod_blacklist': {}, 'minion_sign_messages': False, 'discovery': False, 'schedule': {}, 'ssh_merge_pillar': True, 'disabled_requisites': [], 'reactor_niceness': None, 'fips_mode': False})
DEFAULT_MASTER_OPTS = immutabletypes.freeze({'interface': '0.0.0.0', 'publish_port': 4505, 'zmq_backlog': 1000, 'pub_hwm': 1000, 'auth_mode': 1, 'user': _MASTER_USER, 'worker_threads': 5, 'sock_dir': os.path.join(salt.syspaths.SOCK_DIR, 'master'), 'sock_pool_size': 1, 'ret_port': 4506, 'timeout': 5, 'keep_jobs': 24, 'archive_jobs': False, 'root_dir': salt.syspaths.ROOT_DIR, 'pki_dir': os.path.join(salt.syspaths.CONFIG_DIR, 'pki', 'master'), 'key_cache': '', 'cachedir': os.path.join(salt.syspaths.CACHE_DIR, 'master'), 'file_roots': {'base': [salt.syspaths.BASE_FILE_ROOTS_DIR, salt.syspaths.SPM_FORMULA_PATH]}, 'master_roots': {'base': [salt.syspaths.BASE_MASTER_ROOTS_DIR]}, 'pillar_roots': {'base': [salt.syspaths.BASE_PILLAR_ROOTS_DIR, salt.syspaths.SPM_PILLAR_PATH]}, 'on_demand_ext_pillar': ['libvirt', 'virtkey'], 'decrypt_pillar': [], 'decrypt_pillar_delimiter': ':', 'decrypt_pillar_default': 'gpg', 'decrypt_pillar_renderers': ['gpg'], 'gpg_decrypt_must_succeed': False, 'thoriumenv': None, 'thorium_top': 'top.sls', 'thorium_interval': 0.5, 'thorium_roots': {'base': [salt.syspaths.BASE_THORIUM_ROOTS_DIR]}, 'top_file_merging_strategy': 'merge', 'env_order': [], 'saltenv': None, 'lock_saltenv': False, 'pillarenv': None, 'default_top': 'base', 'file_client': 'local', 'local': True, 'roots_update_interval': DEFAULT_INTERVAL, 'azurefs_update_interval': DEFAULT_INTERVAL, 'gitfs_update_interval': DEFAULT_INTERVAL, 'git_pillar_update_interval': DEFAULT_INTERVAL, 'hgfs_update_interval': DEFAULT_INTERVAL, 'minionfs_update_interval': DEFAULT_INTERVAL, 's3fs_update_interval': DEFAULT_INTERVAL, 'svnfs_update_interval': DEFAULT_INTERVAL, 'git_pillar_base': 'master', 'git_pillar_branch': 'master', 'git_pillar_env': '', 'git_pillar_fallback': '', 'git_pillar_root': '', 'git_pillar_ssl_verify': True, 'git_pillar_global_lock': True, 'git_pillar_user': '', 'git_pillar_password': '', 'git_pillar_insecure_auth': False, 'git_pillar_privkey': '', 'git_pillar_pubkey': '', 'git_pillar_passphrase': '', 'git_pillar_refspecs': _DFLT_REFSPECS, 'git_pillar_includes': True, 'git_pillar_verify_config': True, 'gitfs_remotes': [], 'gitfs_mountpoint': '', 'gitfs_root': '', 'gitfs_base': 'master', 'gitfs_fallback': '', 'gitfs_user': '', 'gitfs_password': '', 'gitfs_insecure_auth': False, 'gitfs_privkey': '', 'gitfs_pubkey': '', 'gitfs_passphrase': '', 'gitfs_saltenv_whitelist': [], 'gitfs_saltenv_blacklist': [], 'gitfs_global_lock': True, 'gitfs_ssl_verify': True, 'gitfs_saltenv': [], 'gitfs_ref_types': ['branch', 'tag', 'sha'], 'gitfs_refspecs': _DFLT_REFSPECS, 'gitfs_disable_saltenv_mapping': False, 'hgfs_remotes': [], 'hgfs_mountpoint': '', 'hgfs_root': '', 'hgfs_base': 'default', 'hgfs_branch_method': 'branches', 'hgfs_saltenv_whitelist': [], 'hgfs_saltenv_blacklist': [], 'show_timeout': True, 'show_jid': False, 'unique_jid': False, 'svnfs_remotes': [], 'svnfs_mountpoint': '', 'svnfs_root': '', 'svnfs_trunk': 'trunk', 'svnfs_branches': 'branches', 'svnfs_tags': 'tags', 'svnfs_saltenv_whitelist': [], 'svnfs_saltenv_blacklist': [], 'max_event_size': 1048576, 'master_stats': False, 'master_stats_event_iter': 60, 'minionfs_env': 'base', 'minionfs_mountpoint': '', 'minionfs_whitelist': [], 'minionfs_blacklist': [], 'ext_pillar': [], 'pillar_version': 2, 'pillar_opts': False, 'pillar_safe_render_error': True, 'pillar_source_merging_strategy': 'smart', 'pillar_merge_lists': False, 'pillar_includes_override_sls': False, 'pillar_cache': False, 'pillar_cache_ttl': 3600, 'pillar_cache_backend': 'disk', 'gpg_cache': False, 'gpg_cache_ttl': 86400, 'gpg_cache_backend': 'disk', 'ping_on_rotate': False, 'peer': {}, 'preserve_minion_cache': False, 'syndic_master': 'masterofmasters', 'syndic_failover': 'random', 'syndic_forward_all_events': False, 'syndic_log_file': os.path.join(salt.syspaths.LOGS_DIR, 'syndic'), 'syndic_pidfile': os.path.join(salt.syspaths.PIDFILE_DIR, 'salt-syndic.pid'), 'outputter_dirs': [], 'runner_dirs': [], 'utils_dirs': [], 'client_acl_verify': True, 'publisher_acl': {}, 'publisher_acl_blacklist': {}, 'sudo_acl': False, 'external_auth': {}, 'token_expire': 43200, 'token_expire_user_override': False, 'permissive_acl': False, 'keep_acl_in_token': False, 'eauth_acl_module': '', 'eauth_tokens': 'localfs', 'extension_modules': os.path.join(salt.syspaths.CACHE_DIR, 'master', 'extmods'), 'module_dirs': [], 'file_recv': False, 'file_recv_max_size': 100, 'file_buffer_size': 1048576, 'file_ignore_regex': [], 'file_ignore_glob': [], 'fileserver_backend': ['roots'], 'fileserver_followsymlinks': True, 'fileserver_ignoresymlinks': False, 'fileserver_verify_config': True, 'max_open_files': 100000, 'hash_type': 'sha256', 'optimization_order': [0, 1, 2], 'conf_file': os.path.join(salt.syspaths.CONFIG_DIR, 'master'), 'open_mode': False, 'auto_accept': False, 'renderer': 'jinja|yaml', 'renderer_whitelist': [], 'renderer_blacklist': [], 'failhard': False, 'state_top': 'top.sls', 'state_top_saltenv': None, 'master_tops': {}, 'master_tops_first': False, 'order_masters': False, 'job_cache': True, 'ext_job_cache': '', 'master_job_cache': 'local_cache', 'job_cache_store_endtime': False, 'minion_data_cache': True, 'enforce_mine_cache': False, 'ipc_mode': _DFLT_IPC_MODE, 'ipc_write_buffer': _DFLT_IPC_WBUFFER, 'req_server_niceness': None, 'pub_server_niceness': None, 'fileserver_update_niceness': None, 'mworker_niceness': None, 'mworker_queue_niceness': None, 'maintenance_niceness': None, 'event_return_niceness': None, 'event_publisher_niceness': None, 'reactor_niceness': None, 'ipv6': None, 'tcp_master_pub_port': 4512, 'tcp_master_pull_port': 4513, 'tcp_master_publish_pull': 4514, 'tcp_master_workers': 4515, 'log_file': os.path.join(salt.syspaths.LOGS_DIR, 'master'), 'log_level': 'warning', 'log_level_logfile': None, 'log_datefmt': DFLT_LOG_DATEFMT, 'log_datefmt_logfile': DFLT_LOG_DATEFMT_LOGFILE, 'log_fmt_console': DFLT_LOG_FMT_CONSOLE, 'log_fmt_logfile': DFLT_LOG_FMT_LOGFILE, 'log_fmt_jid': DFLT_LOG_FMT_JID, 'log_granular_levels': {}, 'log_rotate_max_bytes': 0, 'log_rotate_backup_count': 0, 'pidfile': os.path.join(salt.syspaths.PIDFILE_DIR, 'salt-master.pid'), 'publish_session': 86400, 'range_server': 'range:80', 'reactor': [], 'reactor_refresh_interval': 60, 'reactor_worker_threads': 10, 'reactor_worker_hwm': 10000, 'engines': [], 'event_return': '', 'event_return_queue': 0, 'event_return_whitelist': [], 'event_return_blacklist': [], 'event_match_type': 'startswith', 'runner_returns': True, 'serial': 'msgpack', 'test': False, 'state_verbose': True, 'state_output': 'full', 'state_output_diff': False, 'state_output_profile': True, 'state_auto_order': True, 'state_events': False, 'state_aggregate': False, 'search': '', 'loop_interval': 60, 'nodegroups': {}, 'ssh_list_nodegroups': {}, 'ssh_use_home_key': False, 'cython_enable': False, 'enable_gpu_grains': False, 'key_logfile': os.path.join(salt.syspaths.LOGS_DIR, 'key'), 'verify_env': True, 'permissive_pki_access': False, 'key_pass': None, 'signing_key_pass': None, 'default_include': 'master.d/*.conf', 'winrepo_dir': os.path.join(salt.syspaths.BASE_FILE_ROOTS_DIR, 'win', 'repo'), 'winrepo_dir_ng': os.path.join(salt.syspaths.BASE_FILE_ROOTS_DIR, 'win', 'repo-ng'), 'winrepo_cachefile': 'winrepo.p', 'winrepo_remotes': ['https://github.com/saltstack/salt-winrepo.git'], 'winrepo_remotes_ng': ['https://github.com/saltstack/salt-winrepo-ng.git'], 'winrepo_branch': 'master', 'winrepo_fallback': '', 'winrepo_ssl_verify': True, 'winrepo_user': '', 'winrepo_password': '', 'winrepo_insecure_auth': False, 'winrepo_privkey': '', 'winrepo_pubkey': '', 'winrepo_passphrase': '', 'winrepo_refspecs': _DFLT_REFSPECS, 'syndic_wait': 5, 'jinja_env': {}, 'jinja_sls_env': {}, 'jinja_lstrip_blocks': False, 'jinja_trim_blocks': False, 'tcp_keepalive': True, 'tcp_keepalive_idle': 300, 'tcp_keepalive_cnt': -1, 'tcp_keepalive_intvl': -1, 'sign_pub_messages': True, 'keysize': 2048, 'transport': 'zeromq', 'gather_job_timeout': 10, 'syndic_event_forward_timeout': 0.5, 'syndic_jid_forward_cache_hwm': 100, 'regen_thin': False, 'ssh_passwd': '', 'ssh_priv_passwd': '', 'ssh_port': '22', 'ssh_sudo': False, 'ssh_sudo_user': '', 'ssh_timeout': 60, 'ssh_user': 'root', 'ssh_scan_ports': '22', 'ssh_scan_timeout': 0.01, 'ssh_identities_only': False, 'ssh_log_file': os.path.join(salt.syspaths.LOGS_DIR, 'ssh'), 'ssh_config_file': os.path.join(salt.syspaths.HOME_DIR, '.ssh', 'config'), 'cluster_mode': False, 'sqlite_queue_dir': os.path.join(salt.syspaths.CACHE_DIR, 'master', 'queues'), 'queue_dirs': [], 'cli_summary': False, 'max_minions': 0, 'master_sign_key_name': 'master_sign', 'master_sign_pubkey': False, 'master_pubkey_signature': 'master_pubkey_signature', 'master_use_pubkey_signature': False, 'zmq_filtering': False, 'zmq_monitor': False, 'con_cache': False, 'rotate_aes_key': True, 'cache_sreqs': True, 'dummy_pub': False, 'http_connect_timeout': 20.0, 'http_request_timeout': 1 * 60 * 60.0, 'http_max_body': 100 * 1024 * 1024 * 1024, 'cache': 'localfs', 'memcache_expire_seconds': 0, 'memcache_max_items': 1024, 'memcache_full_cleanup': False, 'memcache_debug': False, 'thin_extra_mods': '', 'min_extra_mods': '', 'ssl': None, 'extmod_whitelist': {}, 'extmod_blacklist': {}, 'clean_dynamic_modules': True, 'django_auth_path': '', 'django_auth_settings': '', 'allow_minion_key_revoke': True, 'salt_cp_chunk_size': 98304, 'require_minion_sign_messages': False, 'drop_messages_signature_fail': False, 'discovery': False, 'schedule': {}, 'auth_events': True, 'minion_data_cache_events': True, 'enable_ssh_minions': False, 'netapi_allow_raw_shell': False, 'fips_mode': False, 'detect_remote_minions': False, 'remote_minions_port': 22})
DEFAULT_PROXY_MINION_OPTS = immutabletypes.freeze({'conf_file': os.path.join(salt.syspaths.CONFIG_DIR, 'proxy'), 'log_file': os.path.join(salt.syspaths.LOGS_DIR, 'proxy'), 'add_proxymodule_to_opts': False, 'proxy_merge_grains_in_module': True, 'extension_modules': os.path.join(salt.syspaths.CACHE_DIR, 'proxy', 'extmods'), 'append_minionid_config_dirs': ['cachedir', 'pidfile', 'default_include', 'extension_modules'], 'default_include': 'proxy.d/*.conf', 'proxy_merge_pillar_in_opts': False, 'proxy_deep_merge_pillar_in_opts': False, 'proxy_merge_pillar_in_opts_strategy': 'smart', 'proxy_mines_pillar': True, 'proxy_always_alive': True, 'proxy_keep_alive': True, 'proxy_keep_alive_interval': 1, 'pki_dir': os.path.join(salt.syspaths.CONFIG_DIR, 'pki', 'proxy'), 'cachedir': os.path.join(salt.syspaths.CACHE_DIR, 'proxy'), 'sock_dir': os.path.join(salt.syspaths.SOCK_DIR, 'proxy')})
DEFAULT_CLOUD_OPTS = immutabletypes.freeze({'verify_env': True, 'default_include': 'cloud.conf.d/*.conf', 'ssh_auth': '', 'cachedir': os.path.join(salt.syspaths.CACHE_DIR, 'cloud'), 'keysize': 4096, 'os': '', 'script': 'bootstrap-salt', 'start_action': None, 'enable_hard_maps': False, 'delete_sshkeys': False, 'deploy_scripts_search_path': 'cloud.deploy.d', 'log_file': os.path.join(salt.syspaths.LOGS_DIR, 'cloud'), 'log_level': 'warning', 'log_level_logfile': None, 'log_datefmt': DFLT_LOG_DATEFMT, 'log_datefmt_logfile': DFLT_LOG_DATEFMT_LOGFILE, 'log_fmt_console': DFLT_LOG_FMT_CONSOLE, 'log_fmt_logfile': DFLT_LOG_FMT_LOGFILE, 'log_fmt_jid': DFLT_LOG_FMT_JID, 'log_granular_levels': {}, 'log_rotate_max_bytes': 0, 'log_rotate_backup_count': 0, 'bootstrap_delay': 0, 'cache': 'localfs'})
DEFAULT_API_OPTS = immutabletypes.freeze({'api_pidfile': os.path.join(salt.syspaths.PIDFILE_DIR, 'salt-api.pid'), 'api_logfile': os.path.join(salt.syspaths.LOGS_DIR, 'api'), 'rest_timeout': 300})
DEFAULT_SPM_OPTS = immutabletypes.freeze({'spm_conf_file': os.path.join(salt.syspaths.CONFIG_DIR, 'spm'), 'formula_path': salt.syspaths.SPM_FORMULA_PATH, 'pillar_path': salt.syspaths.SPM_PILLAR_PATH, 'reactor_path': salt.syspaths.SPM_REACTOR_PATH, 'spm_logfile': os.path.join(salt.syspaths.LOGS_DIR, 'spm'), 'spm_default_include': 'spm.d/*.conf', 'spm_repos_config': '/etc/salt/spm.repos', 'spm_cache_dir': os.path.join(salt.syspaths.CACHE_DIR, 'spm'), 'spm_build_dir': os.path.join(salt.syspaths.SRV_ROOT_DIR, 'spm_build'), 'spm_build_exclude': ['CVS', '.hg', '.git', '.svn'], 'spm_db': os.path.join(salt.syspaths.CACHE_DIR, 'spm', 'packages.db'), 'cache': 'localfs', 'spm_repo_dups': 'ignore', 'spm_node_type': '', 'spm_share_dir': os.path.join(salt.syspaths.SHARE_DIR, 'spm')})
VM_CONFIG_DEFAULTS = immutabletypes.freeze({'default_include': 'cloud.profiles.d/*.conf'})
PROVIDER_CONFIG_DEFAULTS = immutabletypes.freeze({'default_include': 'cloud.providers.d/*.conf'})

def _normalize_roots(file_roots):
    """
    Normalize file or pillar roots.
    """
    for (saltenv, dirs) in file_roots.items():
        normalized_saltenv = str(saltenv)
        if normalized_saltenv != saltenv:
            file_roots[normalized_saltenv] = file_roots.pop(saltenv)
        if not isinstance(dirs, (list, tuple)):
            file_roots[normalized_saltenv] = []
        file_roots[normalized_saltenv] = _expand_glob_path(file_roots[normalized_saltenv])
    return file_roots

def _validate_pillar_roots(pillar_roots):
    """
    If the pillar_roots option has a key that is None then we will error out,
    just replace it with an empty list
    """
    if not isinstance(pillar_roots, dict):
        log.warning('The pillar_roots parameter is not properly formatted, using defaults')
        return {'base': _expand_glob_path([salt.syspaths.BASE_PILLAR_ROOTS_DIR])}
    return _normalize_roots(pillar_roots)

def _validate_file_roots(file_roots):
    """
    If the file_roots option has a key that is None then we will error out,
    just replace it with an empty list
    """
    if not isinstance(file_roots, dict):
        log.warning('The file_roots parameter is not properly formatted, using defaults')
        return {'base': _expand_glob_path([salt.syspaths.BASE_FILE_ROOTS_DIR])}
    return _normalize_roots(file_roots)

def _expand_glob_path(file_roots):
    log.info('Trace')
    '\n    Applies shell globbing to a set of directories and returns\n    the expanded paths\n    '
    unglobbed_path = []
    for path in file_roots:
        try:
            log.info('Trace')
            if glob.has_magic(path):
                unglobbed_path.extend(glob.glob(path))
            else:
                unglobbed_path.append(path)
        except Exception:
            log.info('Trace')
            unglobbed_path.append(path)
    return unglobbed_path

def _validate_opts(opts):
    log.info('Trace')
    '\n    Check that all of the types of values passed into the config are\n    of the right types\n    '

    def format_multi_opt(valid_type):
        try:
            log.info('Trace')
            num_types = len(valid_type)
        except TypeError:
            log.info('Trace')
            return valid_type.__name__
        else:

            def get_types(types, type_tuple):
                for item in type_tuple:
                    if isinstance(item, tuple):
                        get_types(types, item)
                    else:
                        try:
                            types.append(item.__name__)
                        except AttributeError:
                            log.warning('Unable to interpret type %s while validating configuration', item)
            types = []
            get_types(types, valid_type)
            ret = ', '.join(types[:-1])
            ret += ' or ' + types[-1]
            return ret
    errors = []
    err = "Config option '{}' with value {} has an invalid type of {}, a {} is required for this option"
    for (key, val) in opts.items():
        if key in VALID_OPTS:
            if val is None:
                if VALID_OPTS[key] is None:
                    continue
                else:
                    try:
                        if None in VALID_OPTS[key]:
                            continue
                    except TypeError:
                        pass
            if val is True or val is False:
                if VALID_OPTS[key] is bool:
                    continue
            elif isinstance(val, VALID_OPTS[key]):
                continue
            if isinstance(val, str) and val.startswith('sdb://'):
                continue
            nf_types = {str: [list, tuple, dict], list: [dict, str], tuple: [dict, str], bool: [list, tuple, str, int, float, dict, type(None)], int: [bool, float], float: [bool]}
            if hasattr(VALID_OPTS[key], '__call__'):
                try:
                    VALID_OPTS[key](val)
                    for nf_type in nf_types:
                        if VALID_OPTS[key] is nf_type:
                            if isinstance(val, tuple(nf_types[nf_type])):
                                errors.append(err.format(key, val, type(val).__name__, VALID_OPTS[key].__name__))
                except (TypeError, ValueError):
                    errors.append(err.format(key, val, type(val).__name__, VALID_OPTS[key].__name__))
            else:
                if type(val) in VALID_OPTS[key]:
                    continue
                valid = []
                for nf_type in nf_types:
                    try:
                        nf_type(val)
                        if nf_type in VALID_OPTS[key]:
                            nf = nf_types[nf_type]
                            for item in VALID_OPTS[key]:
                                if item in nf:
                                    nf.remove(item)
                            if isinstance(val, tuple(nf)):
                                valid.append(False)
                            else:
                                valid.append(True)
                    except (TypeError, ValueError):
                        valid.append(False)
                if True not in valid:
                    errors.append(err.format(key, val, type(val).__name__, format_multi_opt(VALID_OPTS[key])))
    if isinstance(opts.get('return'), list):
        opts['return'] = ','.join(opts['return'])
    for error in errors:
        log.warning(error)
    if errors:
        return False
    return True

def _validate_ssh_minion_opts(opts):
    """
    Ensure we're not using any invalid ssh_minion_opts. We want to make sure
    that the ssh_minion_opts does not override any pillar or fileserver options
    inherited from the master config. To add other items, modify the if
    statement in the for loop below.
    """
    ssh_minion_opts = opts.get('ssh_minion_opts', {})
    if not isinstance(ssh_minion_opts, dict):
        log.error('Invalidly-formatted ssh_minion_opts')
        opts.pop('ssh_minion_opts')
    for opt_name in list(ssh_minion_opts):
        if re.match('^[a-z0-9]+fs_', opt_name, flags=re.IGNORECASE) or ('pillar' in opt_name and (not 'ssh_merge_pillar' == opt_name)) or opt_name in ('fileserver_backend',):
            log.warning("'%s' is not a valid ssh_minion_opts parameter, ignoring", opt_name)
            ssh_minion_opts.pop(opt_name)

def _append_domain(opts):
    """
    Append a domain to the existing id if it doesn't already exist
    """
    if opts['id'].endswith(opts['append_domain']):
        return opts['id']
    if opts['id'].endswith('.'):
        return opts['id']
    return '{0[id]}.{0[append_domain]}'.format(opts)

def _read_conf_file(path):
    """
    Read in a config file from a given path and process it into a dictionary
    """
    log.debug('Reading configuration from %s', path)
    append_file_suffix_YAMLError = False
    with salt.utils.files.fopen(path, 'r') as conf_file:
        try:
            conf_opts = salt.utils.yaml.safe_load(conf_file) or {}
        except salt.utils.yaml.YAMLError as err:
            message = 'Error parsing configuration file: {} - {}'.format(path, err)
            log.error(message)
            if path.endswith('_schedule.conf'):
                conf_opts = {}
                append_file_suffix_YAMLError = True
            else:
                raise salt.exceptions.SaltConfigurationError(message)
    if append_file_suffix_YAMLError:
        message = 'Renaming to {}'.format(path + 'YAMLError')
        log.error(message)
        os.replace(path, path + 'YAMLError')
    if not isinstance(conf_opts, dict):
        message = 'Error parsing configuration file: {} - conf should be a document, not {}.'.format(path, type(conf_opts))
        log.error(message)
        raise salt.exceptions.SaltConfigurationError(message)
    if 'id' in conf_opts:
        if not isinstance(conf_opts['id'], str):
            conf_opts['id'] = str(conf_opts['id'])
        else:
            conf_opts['id'] = salt.utils.data.decode(conf_opts['id'])
    return conf_opts

def _absolute_path(path, relative_to=None):
    """
    Return an absolute path. In case ``relative_to`` is passed and ``path`` is
    not an absolute path, we try to prepend ``relative_to`` to ``path``and if
    that path exists, return that one
    """
    if path and os.path.isabs(path):
        return path
    if path and relative_to is not None:
        _abspath = os.path.join(relative_to, path)
        if os.path.isfile(_abspath):
            log.debug("Relative path '%s' converted to existing absolute path '%s'", path, _abspath)
            return _abspath
    return path

def load_config(path, env_var, default_path=None, exit_on_config_errors=True):
    """
    Returns configuration dict from parsing either the file described by
    ``path`` or the environment variable described by ``env_var`` as YAML.
    """
    if path is None:
        return {}
    if default_path is None:
        import inspect
        previous_frame = inspect.getframeinfo(inspect.currentframe().f_back)
        log.warning("The function '%s()' defined in '%s' is not yet using the new 'default_path' argument to `salt.config.load_config()`. As such, the '%s' environment variable will be ignored", previous_frame.function, previous_frame.filename, env_var)
        default_path = DEFAULT_MASTER_OPTS['conf_file']
    env_path = os.environ.get(env_var, path)
    if not env_path or not os.path.isfile(env_path):
        env_path = path
    if path != default_path:
        env_path = path
    path = env_path
    if not os.path.isfile(path):
        template = '{}.template'.format(path)
        if os.path.isfile(template):
            log.debug('Writing %s based on %s', path, template)
            with salt.utils.files.fopen(path, 'w') as out:
                with salt.utils.files.fopen(template, 'r') as ifile:
                    ifile.readline()
                    out.write(ifile.read())
    opts = {}
    if salt.utils.validate.path.is_readable(path):
        try:
            opts = _read_conf_file(path)
            opts['conf_file'] = path
        except salt.exceptions.SaltConfigurationError as error:
            log.error(error)
            if exit_on_config_errors:
                sys.exit(salt.defaults.exitcodes.EX_GENERIC)
    else:
        log.debug('Missing configuration file: %s', path)
    return opts

def include_config(include, orig_path, verbose, exit_on_config_errors=False):
    """
    Parses extra configuration file(s) specified in an include list in the
    main config file.
    """
    if not include:
        return {}
    if orig_path is None:
        return {}
    if isinstance(include, str):
        include = [include]
    configuration = {}
    for path in include:
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(orig_path), path)
        glob_matches = glob.glob(path)
        if not glob_matches:
            if verbose:
                log.warning('Warning parsing configuration file: "include" path/glob \'%s\' matches no files', path)
        for fn_ in sorted(glob_matches):
            log.debug("Including configuration from '%s'", fn_)
            try:
                opts = _read_conf_file(fn_)
            except salt.exceptions.SaltConfigurationError as error:
                log.error(error)
                if exit_on_config_errors:
                    sys.exit(salt.defaults.exitcodes.EX_GENERIC)
                else:
                    opts = {}
            schedule = opts.get('schedule', {})
            if schedule and 'schedule' in configuration:
                configuration['schedule'].update(schedule)
            include = opts.get('include', [])
            if include:
                opts.update(include_config(include, fn_, verbose))
            salt.utils.dictupdate.update(configuration, opts, True, True)
    return configuration

def prepend_root_dir(opts, path_options):
    """
    Prepends the options that represent filesystem paths with value of the
    'root_dir' option.
    """
    root_dir = os.path.abspath(opts['root_dir'])
    def_root_dir = salt.syspaths.ROOT_DIR.rstrip(os.sep)
    for path_option in path_options:
        if path_option in opts:
            path = opts[path_option]
            tmp_path_def_root_dir = None
            tmp_path_root_dir = None
            if path == def_root_dir or path.startswith(def_root_dir + os.sep):
                tmp_path_def_root_dir = path[len(def_root_dir):]
            if root_dir and (path == root_dir or path.startswith(root_dir + os.sep)):
                tmp_path_root_dir = path[len(root_dir):]
            if tmp_path_def_root_dir and (not tmp_path_root_dir):
                path = tmp_path_def_root_dir
            elif tmp_path_root_dir and (not tmp_path_def_root_dir):
                path = tmp_path_root_dir
            elif tmp_path_def_root_dir and tmp_path_root_dir:
                if def_root_dir in root_dir:
                    path = tmp_path_root_dir
                else:
                    path = tmp_path_def_root_dir
            elif salt.utils.platform.is_windows() and (not os.path.splitdrive(path)[0]):
                pass
            elif os.path.isabs(path):
                continue
            opts[path_option] = salt.utils.path.join(root_dir, path)

def insert_system_path(opts, paths):
    """
    Inserts path into python path taking into consideration 'root_dir' option.
    """
    if isinstance(paths, str):
        paths = [paths]
    for path in paths:
        path_options = {'path': path, 'root_dir': opts['root_dir']}
        prepend_root_dir(path_options, path_options)
        if os.path.isdir(path_options['path']) and path_options['path'] not in sys.path:
            sys.path.insert(0, path_options['path'])

def minion_config(path, env_var='SALT_MINION_CONFIG', defaults=None, cache_minion_id=False, ignore_config_errors=True, minion_id=None, role='minion'):
    """
    Reads in the minion configuration file and sets up special options

    This is useful for Minion-side operations, such as the
    :py:class:`~salt.client.Caller` class, and manually running the loader
    interface.

    .. code-block:: python

        import salt.config
        minion_opts = salt.config.minion_config('/etc/salt/minion')
    """
    if defaults is None:
        defaults = DEFAULT_MINION_OPTS.copy()
    if not os.environ.get(env_var, None):
        salt_config_dir = os.environ.get('SALT_CONFIG_DIR', None)
        if salt_config_dir:
            env_config_file_path = os.path.join(salt_config_dir, 'minion')
            if salt_config_dir and os.path.isfile(env_config_file_path):
                os.environ[env_var] = env_config_file_path
    overrides = load_config(path, env_var, DEFAULT_MINION_OPTS['conf_file'])
    default_include = overrides.get('default_include', defaults['default_include'])
    include = overrides.get('include', [])
    overrides.update(include_config(default_include, path, verbose=False, exit_on_config_errors=not ignore_config_errors))
    overrides.update(include_config(include, path, verbose=True, exit_on_config_errors=not ignore_config_errors))
    opts = apply_minion_config(overrides, defaults, cache_minion_id=cache_minion_id, minion_id=minion_id)
    opts['__role'] = role
    if role != 'master':
        apply_sdb(opts)
        _validate_opts(opts)
    return opts

def mminion_config(path, overrides, ignore_config_errors=True):
    opts = minion_config(path, ignore_config_errors=ignore_config_errors, role='master')
    opts.update(overrides)
    apply_sdb(opts)
    _validate_opts(opts)
    opts['grains'] = salt.loader.grains(opts)
    opts['pillar'] = {}
    return opts

def proxy_config(path, env_var='SALT_PROXY_CONFIG', defaults=None, cache_minion_id=False, ignore_config_errors=True, minion_id=None):
    """
    Reads in the proxy minion configuration file and sets up special options

    This is useful for Minion-side operations, such as the
    :py:class:`~salt.client.Caller` class, and manually running the loader
    interface.

    .. code-block:: python

        import salt.config
        proxy_opts = salt.config.proxy_config('/etc/salt/proxy')
    """
    if defaults is None:
        defaults = DEFAULT_MINION_OPTS.copy()
    defaults.update(DEFAULT_PROXY_MINION_OPTS)
    if not os.environ.get(env_var, None):
        salt_config_dir = os.environ.get('SALT_CONFIG_DIR', None)
        if salt_config_dir:
            env_config_file_path = os.path.join(salt_config_dir, 'proxy')
            if salt_config_dir and os.path.isfile(env_config_file_path):
                os.environ[env_var] = env_config_file_path
    overrides = load_config(path, env_var, DEFAULT_PROXY_MINION_OPTS['conf_file'])
    default_include = overrides.get('default_include', defaults['default_include'])
    include = overrides.get('include', [])
    overrides.update(include_config(default_include, path, verbose=False, exit_on_config_errors=not ignore_config_errors))
    overrides.update(include_config(include, path, verbose=True, exit_on_config_errors=not ignore_config_errors))
    opts = apply_minion_config(overrides, defaults, cache_minion_id=cache_minion_id, minion_id=minion_id)
    default_include = opts.get('default_include', defaults['default_include'])
    include = opts.get('include', [])
    overrides.update(include_config(default_include, path, verbose=False, exit_on_config_errors=not ignore_config_errors))
    overrides.update(include_config(include, path, verbose=True, exit_on_config_errors=not ignore_config_errors))
    opts = apply_minion_config(overrides, defaults, cache_minion_id=cache_minion_id, minion_id=minion_id)
    apply_sdb(opts)
    _validate_opts(opts)
    return opts

def syndic_config(master_config_path, minion_config_path, master_env_var='SALT_MASTER_CONFIG', minion_env_var='SALT_MINION_CONFIG', minion_defaults=None, master_defaults=None):
    if minion_defaults is None:
        minion_defaults = DEFAULT_MINION_OPTS.copy()
    if master_defaults is None:
        master_defaults = DEFAULT_MASTER_OPTS.copy()
    opts = {}
    master_opts = master_config(master_config_path, master_env_var, master_defaults)
    minion_opts = minion_config(minion_config_path, minion_env_var, minion_defaults)
    opts['_minion_conf_file'] = master_opts['conf_file']
    opts['_master_conf_file'] = minion_opts['conf_file']
    opts.update(master_opts)
    opts.update(minion_opts)
    syndic_opts = {'__role': 'syndic', 'root_dir': opts.get('root_dir', salt.syspaths.ROOT_DIR), 'pidfile': opts.get('syndic_pidfile', 'salt-syndic.pid'), 'log_file': opts.get('syndic_log_file', 'salt-syndic.log'), 'log_level': master_opts['log_level'], 'id': minion_opts['id'], 'pki_dir': minion_opts['pki_dir'], 'master': opts['syndic_master'], 'interface': master_opts['interface'], 'master_port': int(opts.get('syndic_master_port', opts.get('master_port', minion_defaults.get('master_port', DEFAULT_MINION_OPTS['master_port'])))), 'user': opts.get('syndic_user', opts['user']), 'sock_dir': os.path.join(opts['cachedir'], opts.get('syndic_sock_dir', opts['sock_dir'])), 'sock_pool_size': master_opts['sock_pool_size'], 'cachedir': master_opts['cachedir']}
    opts.update(syndic_opts)
    prepend_root_dirs = ['pki_dir', 'cachedir', 'pidfile', 'sock_dir', 'extension_modules', 'autosign_file', 'autoreject_file', 'token_dir', 'autosign_grains_dir']
    for config_key in ('log_file', 'key_logfile', 'syndic_log_file'):
        if urllib.parse.urlparse(opts.get(config_key, '')).scheme == '':
            prepend_root_dirs.append(config_key)
    prepend_root_dir(opts, prepend_root_dirs)
    return opts

def apply_sdb(opts, sdb_opts=None):
    """
    Recurse for sdb:// links for opts
    """
    import salt.utils.sdb
    if sdb_opts is None:
        sdb_opts = opts
    if isinstance(sdb_opts, str) and sdb_opts.startswith('sdb://'):
        return salt.utils.sdb.sdb_get(sdb_opts, opts)
    elif isinstance(sdb_opts, dict):
        for (key, value) in sdb_opts.items():
            if value is None:
                continue
            sdb_opts[key] = apply_sdb(opts, value)
    elif isinstance(sdb_opts, list):
        for (key, value) in enumerate(sdb_opts):
            if value is None:
                continue
            sdb_opts[key] = apply_sdb(opts, value)
    return sdb_opts

def cloud_config(path, env_var='SALT_CLOUD_CONFIG', defaults=None, master_config_path=None, master_config=None, providers_config_path=None, providers_config=None, profiles_config_path=None, profiles_config=None):
    log.info('Trace')
    '\n    Read in the Salt Cloud config and return the dict\n    '
    if path:
        config_dir = os.path.dirname(path)
    else:
        config_dir = salt.syspaths.CONFIG_DIR
    overrides = load_config(path, env_var, os.path.join(config_dir, 'cloud'))
    if defaults is None:
        defaults = DEFAULT_CLOUD_OPTS.copy()
    defaults.update(overrides)
    overrides = defaults
    overrides.update(salt.config.include_config(overrides['default_include'], path, verbose=False))
    include = overrides.get('include', [])
    overrides.update(salt.config.include_config(include, path, verbose=True))
    if 'master_config' in overrides and master_config_path is None:
        master_config_path = overrides['master_config']
    elif 'master_config' not in overrides and (not master_config) and (not master_config_path):
        master_config_path = os.path.join(config_dir, 'master')
    master_config_path = _absolute_path(master_config_path, config_dir)
    if 'providers_config' in overrides and providers_config_path is None:
        providers_config_path = overrides['providers_config']
    elif 'providers_config' not in overrides and (not providers_config) and (not providers_config_path):
        providers_config_path = os.path.join(config_dir, 'cloud.providers')
    providers_config_path = _absolute_path(providers_config_path, config_dir)
    if 'profiles_config' in overrides and profiles_config_path is None:
        profiles_config_path = overrides['profiles_config']
    elif 'profiles_config' not in overrides and (not profiles_config) and (not profiles_config_path):
        profiles_config_path = os.path.join(config_dir, 'cloud.profiles')
    profiles_config_path = _absolute_path(profiles_config_path, config_dir)
    deploy_scripts_search_path = overrides.get('deploy_scripts_search_path', defaults.get('deploy_scripts_search_path', 'cloud.deploy.d'))
    if isinstance(deploy_scripts_search_path, str):
        deploy_scripts_search_path = [deploy_scripts_search_path]
    for (idx, entry) in enumerate(deploy_scripts_search_path[:]):
        if not os.path.isabs(entry):
            entry = os.path.join(os.path.dirname(path), entry)
        if os.path.isdir(entry):
            deploy_scripts_search_path[idx] = entry
            continue
        deploy_scripts_search_path.pop(idx)
    deploy_scripts_search_path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cloud', 'deploy')))
    overrides.update(deploy_scripts_search_path=tuple(deploy_scripts_search_path))
    if master_config_path is not None and master_config is not None:
        raise salt.exceptions.SaltCloudConfigError('Only pass `master_config` or `master_config_path`, not both.')
    elif master_config_path is None and master_config is None:
        master_config = salt.config.master_config(overrides.get('master_config', os.path.join(salt.syspaths.CONFIG_DIR, 'master')))
    elif master_config_path is not None and master_config is None:
        master_config = salt.config.master_config(master_config_path)
    del master_config['cachedir']
    master_config.update(overrides)
    overrides = master_config
    if providers_config_path is not None and providers_config is not None:
        raise salt.exceptions.SaltCloudConfigError('Only pass `providers_config` or `providers_config_path`, not both.')
    elif providers_config_path is None and providers_config is None:
        providers_config_path = overrides.get('providers_config', os.path.join(salt.syspaths.CONFIG_DIR, 'cloud.providers'))
    if profiles_config_path is not None and profiles_config is not None:
        raise salt.exceptions.SaltCloudConfigError('Only pass `profiles_config` or `profiles_config_path`, not both.')
    elif profiles_config_path is None and profiles_config is None:
        profiles_config_path = overrides.get('profiles_config', os.path.join(salt.syspaths.CONFIG_DIR, 'cloud.profiles'))
    opts = apply_cloud_config(overrides, defaults)
    if 'providers' in opts:
        if providers_config is not None:
            raise salt.exceptions.SaltCloudConfigError('Do not mix the old cloud providers configuration with the passing a pre-configured providers configuration dictionary.')
        if providers_config_path is not None:
            providers_confd = os.path.join(os.path.dirname(providers_config_path), 'cloud.providers.d', '*')
            if os.path.isfile(providers_config_path) or glob.glob(providers_confd):
                raise salt.exceptions.SaltCloudConfigError('Do not mix the old cloud providers configuration with the new one. The providers configuration should now go in the file `{0}` or a separate `*.conf` file within `cloud.providers.d/` which is relative to `{0}`.'.format(os.path.join(salt.syspaths.CONFIG_DIR, 'cloud.providers')))
        providers_config = opts['providers']
    elif providers_config_path is not None:
        providers_config = cloud_providers_config(providers_config_path)
    opts['providers'] = providers_config
    if profiles_config is None:
        profiles_config = vm_profiles_config(profiles_config_path, providers_config)
    opts['profiles'] = profiles_config
    apply_sdb(opts)
    prepend_root_dirs = ['cachedir']
    if 'log_file' in opts and urllib.parse.urlparse(opts['log_file']).scheme == '':
        prepend_root_dirs.append(opts['log_file'])
    prepend_root_dir(opts, prepend_root_dirs)
    return opts

def apply_cloud_config(overrides, defaults=None):
    """
    Return a cloud config
    """
    if defaults is None:
        defaults = DEFAULT_CLOUD_OPTS.copy()
    config = defaults.copy()
    if overrides:
        config.update(overrides)
    if 'providers' in config:
        providers = config['providers'].copy()
        config['providers'] = {}
        for (alias, details) in providers.items():
            if isinstance(details, list):
                for detail in details:
                    if 'driver' not in detail:
                        raise salt.exceptions.SaltCloudConfigError("The cloud provider alias '{}' has an entry missing the required setting of 'driver'.".format(alias))
                    driver = detail['driver']
                    if ':' in driver:
                        (alias, driver) = driver.split(':')
                    if alias not in config['providers']:
                        config['providers'][alias] = {}
                    detail['provider'] = '{}:{}'.format(alias, driver)
                    config['providers'][alias][driver] = detail
            elif isinstance(details, dict):
                if 'driver' not in details:
                    raise salt.exceptions.SaltCloudConfigError("The cloud provider alias '{}' has an entry missing the required setting of 'driver'".format(alias))
                driver = details['driver']
                if ':' in driver:
                    (alias, driver) = driver.split(':')
                if alias not in config['providers']:
                    config['providers'][alias] = {}
                details['provider'] = '{}:{}'.format(alias, driver)
                config['providers'][alias][driver] = details
    config = old_to_new(config)
    return config

def old_to_new(opts):
    providers = ('AWS', 'CLOUDSTACK', 'DIGITALOCEAN', 'EC2', 'GOGRID', 'IBMSCE', 'JOYENT', 'LINODE', 'OPENSTACK', 'PARALLELS', 'RACKSPACE', 'SALTIFY')
    for provider in providers:
        provider_config = {}
        for (opt, val) in opts.items():
            if provider in opt:
                value = val
                name = opt.split('.', 1)[1]
                provider_config[name] = value
        lprovider = provider.lower()
        if provider_config:
            provider_config['provider'] = lprovider
            opts.setdefault('providers', {})
            opts['providers'][lprovider] = {}
            opts['providers'][lprovider][lprovider] = provider_config
    return opts

def vm_profiles_config(path, providers, env_var='SALT_CLOUDVM_CONFIG', defaults=None):
    """
    Read in the salt cloud VM config file
    """
    if defaults is None:
        defaults = VM_CONFIG_DEFAULTS
    overrides = salt.config.load_config(path, env_var, os.path.join(salt.syspaths.CONFIG_DIR, 'cloud.profiles'))
    default_include = overrides.get('default_include', defaults['default_include'])
    include = overrides.get('include', [])
    overrides.update(salt.config.include_config(default_include, path, verbose=False))
    overrides.update(salt.config.include_config(include, path, verbose=True))
    return apply_vm_profiles_config(providers, overrides, defaults)

def apply_vm_profiles_config(providers, overrides, defaults=None):
    if defaults is None:
        defaults = VM_CONFIG_DEFAULTS
    config = defaults.copy()
    if overrides:
        config.update(overrides)
    vms = {}
    for (key, val) in config.items():
        if key in ('conf_file', 'include', 'default_include', 'user'):
            continue
        if not isinstance(val, dict):
            raise salt.exceptions.SaltCloudConfigError("The VM profiles configuration found in '{0[conf_file]}' is not in the proper format".format(config))
        val['profile'] = key
        vms[key] = val
    for (profile, details) in vms.copy().items():
        if 'extends' not in details:
            if ':' in details['provider']:
                (alias, driver) = details['provider'].split(':')
                if alias not in providers or driver not in providers[alias]:
                    log.trace("The profile '%s' is defining '%s' as the provider. Since there is no valid configuration for that provider, the profile will be removed from the available listing", profile, details['provider'])
                    vms.pop(profile)
                    continue
                if 'profiles' not in providers[alias][driver]:
                    providers[alias][driver]['profiles'] = {}
                providers[alias][driver]['profiles'][profile] = details
            if details['provider'] not in providers:
                log.trace("The profile '%s' is defining '%s' as the provider. Since there is no valid configuration for that provider, the profile will be removed from the available listing", profile, details['provider'])
                vms.pop(profile)
                continue
            driver = next(iter(list(providers[details['provider']].keys())))
            providers[details['provider']][driver].setdefault('profiles', {}).update({profile: details})
            details['provider'] = '{0[provider]}:{1}'.format(details, driver)
            vms[profile] = details
            continue
        extends = details.pop('extends')
        if extends not in vms:
            log.error("The '%s' profile is trying to extend data from '%s' though '%s' is not defined in the salt profiles loaded data. Not extending and removing from listing!", profile, extends, extends)
            vms.pop(profile)
            continue
        extended = deepcopy(vms.get(extends))
        extended.pop('profile')
        extended = salt.utils.dictupdate.update(extended, details)
        if ':' not in extended['provider']:
            if extended['provider'] not in providers:
                log.trace("The profile '%s' is defining '%s' as the provider. Since there is no valid configuration for that provider, the profile will be removed from the available listing", profile, extended['provider'])
                vms.pop(profile)
                continue
            driver = next(iter(list(providers[extended['provider']].keys())))
            providers[extended['provider']][driver].setdefault('profiles', {}).update({profile: extended})
            extended['provider'] = '{0[provider]}:{1}'.format(extended, driver)
        else:
            (alias, driver) = extended['provider'].split(':')
            if alias not in providers or driver not in providers[alias]:
                log.trace("The profile '%s' is defining '%s' as the provider. Since there is no valid configuration for that provider, the profile will be removed from the available listing", profile, extended['provider'])
                vms.pop(profile)
                continue
            providers[alias][driver].setdefault('profiles', {}).update({profile: extended})
        vms[profile] = extended
    return vms

def cloud_providers_config(path, env_var='SALT_CLOUD_PROVIDERS_CONFIG', defaults=None):
    """
    Read in the salt cloud providers configuration file
    """
    if defaults is None:
        defaults = PROVIDER_CONFIG_DEFAULTS
    overrides = salt.config.load_config(path, env_var, os.path.join(salt.syspaths.CONFIG_DIR, 'cloud.providers'))
    default_include = overrides.get('default_include', defaults['default_include'])
    include = overrides.get('include', [])
    overrides.update(salt.config.include_config(default_include, path, verbose=False))
    overrides.update(salt.config.include_config(include, path, verbose=True))
    return apply_cloud_providers_config(overrides, defaults)

def apply_cloud_providers_config(overrides, defaults=None):
    """
    Apply the loaded cloud providers configuration.
    """
    if defaults is None:
        defaults = PROVIDER_CONFIG_DEFAULTS
    config = defaults.copy()
    if overrides:
        config.update(overrides)
    for (name, settings) in config.copy().items():
        if '.' in name:
            log.warning('Please switch to the new providers configuration syntax')
            config = old_to_new(config)
            for (prov_name, prov_settings) in config.pop('providers').items():
                config[prov_name] = prov_settings
            break
    providers = {}
    ext_count = 0
    for (key, val) in config.items():
        if key in ('conf_file', 'include', 'default_include', 'user'):
            continue
        if not isinstance(val, (list, tuple)):
            val = [val]
        else:
            handled_providers = set()
            for details in val:
                if 'driver' not in details:
                    if 'extends' not in details:
                        log.error("Please check your cloud providers configuration. There's no 'driver' nor 'extends' definition referenced.")
                    continue
                if details['driver'] in handled_providers:
                    log.error("You can only have one entry per cloud provider. For example, if you have a cloud provider configuration section named, 'production', you can only have a single entry for EC2, Joyent, Openstack, and so forth.")
                    raise salt.exceptions.SaltCloudConfigError("The cloud provider alias '{0}' has multiple entries for the '{1[driver]}' driver.".format(key, details))
                handled_providers.add(details['driver'])
        for entry in val:
            if 'driver' not in entry:
                entry['driver'] = '-only-extendable-{}'.format(ext_count)
                ext_count += 1
            if key not in providers:
                providers[key] = {}
            provider = entry['driver']
            if provider not in providers[key]:
                providers[key][provider] = entry
    while True:
        keep_looping = False
        for (provider_alias, entries) in providers.copy().items():
            for (driver, details) in entries.items():
                providers[provider_alias][driver]['profiles'] = {}
                if 'extends' not in details:
                    continue
                extends = details.pop('extends')
                if ':' in extends:
                    (alias, provider) = extends.split(':')
                    if alias not in providers:
                        raise salt.exceptions.SaltCloudConfigError("The '{0}' cloud provider entry in '{1}' is trying to extend data from '{2}' though '{2}' is not defined in the salt cloud providers loaded data.".format(details['driver'], provider_alias, alias))
                    if provider not in providers.get(alias):
                        raise salt.exceptions.SaltCloudConfigError("The '{0}' cloud provider entry in '{1}' is trying to extend data from '{2}:{3}' though '{3}' is not defined in '{1}'".format(details['driver'], provider_alias, alias, provider))
                    details['extends'] = '{}:{}'.format(alias, provider)
                    details['driver'] = provider
                elif providers.get(extends):
                    raise salt.exceptions.SaltCloudConfigError("The '{}' cloud provider entry in '{}' is trying to extend from '{}' and no provider was specified. Not extending!".format(details['driver'], provider_alias, extends))
                elif extends not in providers:
                    raise salt.exceptions.SaltCloudConfigError("The '{0}' cloud provider entry in '{1}' is trying to extend data from '{2}' though '{2}' is not defined in the salt cloud providers loaded data.".format(details['driver'], provider_alias, extends))
                elif driver in providers.get(extends):
                    details['extends'] = '{}:{}'.format(extends, driver)
                elif '-only-extendable-' in providers.get(extends):
                    details['extends'] = '{}:{}'.format(extends, '-only-extendable-{}'.format(ext_count))
                else:
                    details['extends'] = extends
                    keep_looping = True
        if not keep_looping:
            break
    while True:
        keep_looping = False
        for (alias, entries) in providers.copy().items():
            for driver in list(entries.keys()):
                details = entries[driver]
                if 'extends' not in details:
                    continue
                if 'extends' in details['extends']:
                    keep_looping = True
                    continue
                extends = details.pop('extends')
                (ext_alias, ext_driver) = extends.split(':')
                extended = providers.get(ext_alias).get(ext_driver).copy()
                extended = salt.utils.dictupdate.update(extended, details)
                providers[alias][driver] = extended
                if driver.startswith('-only-extendable-'):
                    providers[alias][ext_driver] = providers[alias][driver]
                    del providers[alias][driver]
        if not keep_looping:
            break
    for (provider_alias, entries) in providers.copy().items():
        for (driver, details) in entries.copy().items():
            if not driver.startswith('-only-extendable-'):
                continue
            log.info("There's at least one cloud driver under the '%s' cloud provider alias which does not have the required 'driver' setting. Removing it from the available providers listing.", provider_alias)
            providers[provider_alias].pop(driver)
        if not providers[provider_alias]:
            providers.pop(provider_alias)
    return providers

def get_cloud_config_value(name, vm_, opts, default=None, search_global=True):
    """
    Search and return a setting in a known order:

        1. In the virtual machine's configuration
        2. In the virtual machine's profile configuration
        3. In the virtual machine's provider configuration
        4. In the salt cloud configuration if global searching is enabled
        5. Return the provided default
    """
    value = default
    if search_global is True and opts.get(name, None) is not None:
        value = deepcopy(opts[name])
    if vm_ and name:
        if 'profile' in vm_ and vm_['profile'] is not None:
            if name in opts['profiles'][vm_['profile']]:
                if isinstance(value, dict):
                    value.update(opts['profiles'][vm_['profile']][name].copy())
                else:
                    value = deepcopy(opts['profiles'][vm_['profile']][name])
        if ':' in vm_['driver']:
            (alias, driver) = vm_['driver'].split(':')
            if alias in opts['providers'] and driver in opts['providers'][alias]:
                details = opts['providers'][alias][driver]
                if name in details:
                    if isinstance(value, dict):
                        value.update(details[name].copy())
                    else:
                        value = deepcopy(details[name])
        elif len(opts['providers'].get(vm_['driver'], ())) > 1:
            log.error("The '%s' cloud provider definition has more than one entry. Your VM configuration should be specifying the provider as 'driver: %s:<driver-engine>'. Since it's not, we're returning the first definition which might not be what you intended.", vm_['driver'], vm_['driver'])
        if vm_['driver'] in opts['providers']:
            alias_defs = opts['providers'].get(vm_['driver'])
            provider_driver_defs = alias_defs[next(iter(list(alias_defs.keys())))]
            if name in provider_driver_defs:
                if isinstance(value, dict):
                    value.update(provider_driver_defs[name].copy())
                else:
                    value = deepcopy(provider_driver_defs[name])
    if name and vm_ and (name in vm_):
        if isinstance(vm_[name], types.GeneratorType):
            value = next(vm_[name], '')
        elif isinstance(value, dict) and isinstance(vm_[name], dict):
            value.update(vm_[name].copy())
        else:
            value = deepcopy(vm_[name])
    return value

def is_provider_configured(opts, provider, required_keys=(), log_message=True, aliases=()):
    """
    Check and return the first matching and fully configured cloud provider
    configuration.
    """
    if ':' in provider:
        (alias, driver) = provider.split(':')
        if alias not in opts['providers']:
            return False
        if driver not in opts['providers'][alias]:
            return False
        for key in required_keys:
            if opts['providers'][alias][driver].get(key, None) is None:
                if log_message is True:
                    log.warning("The required '%s' configuration setting is missing from the '%s' driver, which is configured under the '%s' alias.", key, provider, alias)
                return False
        return opts['providers'][alias][driver]
    for (alias, drivers) in opts['providers'].items():
        for (driver, provider_details) in drivers.items():
            if driver != provider and driver not in aliases:
                continue
            skip_provider = False
            for key in required_keys:
                if provider_details.get(key, None) is None:
                    if log_message is True:
                        log.warning("The required '%s' configuration setting is missing from the '%s' driver, which is configured under the '%s' alias.", key, provider, alias)
                    skip_provider = True
                    break
            if skip_provider:
                continue
            return provider_details
    return False

def is_profile_configured(opts, provider, profile_name, vm_=None):
    """
    Check if the requested profile contains the minimum required parameters for
    a profile.

    Required parameters include image and provider for all drivers, while some
    drivers also require size keys.

    .. versionadded:: 2015.8.0
    """
    required_keys = ['provider']
    (alias, driver) = provider.split(':')
    non_image_drivers = ['nova', 'virtualbox', 'libvirt', 'softlayer', 'oneandone', 'profitbricks']
    non_size_drivers = ['opennebula', 'parallels', 'proxmox', 'scaleway', 'softlayer', 'softlayer_hw', 'vmware', 'vsphere', 'virtualbox', 'libvirt', 'oneandone', 'profitbricks']
    provider_key = opts['providers'][alias][driver]
    profile_key = opts['providers'][alias][driver]['profiles'][profile_name]
    if driver == 'linode' and profile_key.get('clonefrom', False):
        non_image_drivers.append('linode')
        non_size_drivers.append('linode')
    elif driver == 'gce' and 'sourceImage' in str(vm_.get('ex_disks_gce_struct')):
        non_image_drivers.append('gce')
    if driver == 'vmware' and 'image' not in list(profile_key.keys()):
        non_image_drivers.append('vmware')
    if driver not in non_image_drivers:
        required_keys.append('image')
        if driver == 'vmware':
            required_keys.append('datastore')
    elif driver in ['linode', 'virtualbox']:
        required_keys.append('clonefrom')
    elif driver == 'nova':
        nova_image_keys = ['image', 'block_device_mapping', 'block_device', 'boot_volume']
        if not any([key in provider_key for key in nova_image_keys]) and (not any([key in profile_key for key in nova_image_keys])):
            required_keys.extend(nova_image_keys)
    if driver not in non_size_drivers:
        required_keys.append('size')
    for item in list(required_keys):
        if item in provider_key:
            required_keys.remove(item)
    if vm_:
        for item in list(required_keys):
            if item in vm_:
                required_keys.remove(item)
    for item in required_keys:
        if profile_key.get(item, None) is None:
            log.error("The required '%s' configuration setting is missing from the '%s' profile, which is configured under the '%s' alias.", item, profile_name, alias)
            return False
    return True

def check_driver_dependencies(driver, dependencies):
    """
    Check if the driver's dependencies are available.

    .. versionadded:: 2015.8.0

    driver
        The name of the driver.

    dependencies
        The dictionary of dependencies to check.
    """
    ret = True
    for (key, value) in dependencies.items():
        if value is False:
            log.warning("Missing dependency: '%s'. The %s driver requires '%s' to be installed.", key, driver, key)
            ret = False
    return ret

def _cache_id(minion_id, cache_file):
    """
    Helper function, writes minion id to a cache file.
    """
    path = os.path.dirname(cache_file)
    try:
        if not os.path.isdir(path):
            os.makedirs(path)
    except OSError as exc:
        if os.path.isdir(path):
            pass
        else:
            log.error('Failed to create dirs to minion_id file: %s', exc)
    try:
        with salt.utils.files.fopen(cache_file, 'w') as idf:
            idf.write(minion_id)
    except OSError as exc:
        log.error('Could not cache minion ID: %s', exc)

def call_id_function(opts):
    """
    Evaluate the function that determines the ID if the 'id_function'
    option is set and return the result
    """
    if opts.get('id'):
        return opts['id']
    import salt.loader as loader
    if isinstance(opts['id_function'], str):
        mod_fun = opts['id_function']
        fun_kwargs = {}
    elif isinstance(opts['id_function'], dict):
        (mod_fun, fun_kwargs) = next(iter(opts['id_function'].items()))
        if fun_kwargs is None:
            fun_kwargs = {}
    else:
        log.error("'id_function' option is neither a string nor a dictionary")
        sys.exit(salt.defaults.exitcodes.EX_GENERIC)
    (mod, fun) = mod_fun.split('.')
    if not opts.get('grains'):
        opts['grains'] = loader.grains(opts)
    try:
        id_mod = loader.raw_mod(opts, mod, fun)
        if not id_mod:
            raise KeyError
        newid = id_mod[mod_fun](**fun_kwargs)
        if not isinstance(newid, str) or not newid:
            log.error('Function %s returned value "%s" of type %s instead of string', mod_fun, newid, type(newid))
            sys.exit(salt.defaults.exitcodes.EX_GENERIC)
        log.info('Evaluated minion ID from module: %s %s', mod_fun, newid)
        return newid
    except TypeError:
        log.error('Function arguments %s are incorrect for function %s', fun_kwargs, mod_fun)
        sys.exit(salt.defaults.exitcodes.EX_GENERIC)
    except KeyError:
        log.error('Failed to load module %s', mod_fun)
        sys.exit(salt.defaults.exitcodes.EX_GENERIC)

def remove_domain_from_fqdn(opts, newid):
    """
    Depending on the values of `minion_id_remove_domain`,
    remove all domains or a single domain from a FQDN, effectivly generating a hostname.
    """
    opt_domain = opts.get('minion_id_remove_domain')
    if opt_domain is True:
        if '.' in newid:
            (newid, xdomain) = newid.split('.', 1)
            log.debug('Removed any domain (%s) from minion id.', xdomain)
    elif newid.upper().endswith('.' + opt_domain.upper()):
        newid = newid[:-len('.' + opt_domain)]
        log.debug('Removed single domain %s from minion id.', opt_domain)
    return newid

def get_id(opts, cache_minion_id=False):
    """
    Guess the id of the minion.

    If CONFIG_DIR/minion_id exists, use the cached minion ID from that file.
    If no minion id is configured, use multiple sources to find a FQDN.
    If no FQDN is found you may get an ip address.

    Returns two values: the detected ID, and a boolean value noting whether or
    not an IP address is being used for the ID.
    """
    if opts['root_dir'] is None:
        root_dir = salt.syspaths.ROOT_DIR
    else:
        root_dir = opts['root_dir']
    config_dir = salt.syspaths.CONFIG_DIR
    if config_dir.startswith(salt.syspaths.ROOT_DIR):
        config_dir = config_dir.split(salt.syspaths.ROOT_DIR, 1)[-1]
    id_cache = os.path.join(root_dir, config_dir.lstrip(os.path.sep), 'minion_id')
    if opts.get('minion_id_caching', True):
        try:
            with salt.utils.files.fopen(id_cache) as idf:
                name = salt.utils.stringutils.to_unicode(idf.readline().strip())
                bname = salt.utils.stringutils.to_bytes(name)
                if bname.startswith(codecs.BOM):
                    name = salt.utils.stringutils.to_str(bname.replace(codecs.BOM, '', 1))
            if name and name != 'localhost':
                log.debug('Using cached minion ID from %s: %s', id_cache, name)
                return (name, False)
        except OSError:
            pass
    if '__role' in opts and opts.get('__role') == 'minion':
        log.debug('Guessing ID. The id can be explicitly set in %s', os.path.join(salt.syspaths.CONFIG_DIR, 'minion'))
    if opts.get('id_function'):
        newid = call_id_function(opts)
    else:
        newid = salt.utils.network.generate_minion_id()
    if opts.get('minion_id_lowercase'):
        newid = newid.lower()
        log.debug('Changed minion id %s to lowercase.', newid)
    if opts.get('minion_id_remove_domain'):
        newid = remove_domain_from_fqdn(opts, newid)
    if '__role' in opts and opts.get('__role') == 'minion':
        if opts.get('id_function'):
            log.debug('Found minion id from external function %s: %s', opts['id_function'], newid)
        else:
            log.debug('Found minion id from generate_minion_id(): %s', newid)
    if cache_minion_id and opts.get('minion_id_caching', True):
        _cache_id(newid, id_cache)
    is_ipv4 = salt.utils.network.is_ipv4(newid)
    return (newid, is_ipv4)

def _update_ssl_config(opts):
    """
    Resolves string names to integer constant in ssl configuration.
    """
    if opts['ssl'] in (None, False):
        opts['ssl'] = None
        return
    if opts['ssl'] is True:
        opts['ssl'] = {}
        return
    import ssl
    for (key, prefix) in (('cert_reqs', 'CERT_'), ('ssl_version', 'PROTOCOL_')):
        val = opts['ssl'].get(key)
        if val is None:
            continue
        if not isinstance(val, str) or not val.startswith(prefix) or (not hasattr(ssl, val)):
            message = "SSL option '{}' must be set to one of the following values: '{}'.".format(key, "', '".join([val for val in dir(ssl) if val.startswith(prefix)]))
            log.error(message)
            raise salt.exceptions.SaltConfigurationError(message)
        opts['ssl'][key] = getattr(ssl, val)

def _adjust_log_file_override(overrides, default_log_file):
    """
    Adjusts the log_file based on the log_dir override
    """
    if overrides.get('log_dir'):
        if overrides.get('log_file'):
            if not os.path.isabs(overrides['log_file']):
                overrides['log_file'] = os.path.join(overrides['log_dir'], overrides['log_file'])
        else:
            overrides['log_file'] = os.path.join(overrides['log_dir'], os.path.basename(default_log_file))

def apply_minion_config(overrides=None, defaults=None, cache_minion_id=False, minion_id=None):
    """
    Returns minion configurations dict.
    """
    if defaults is None:
        defaults = DEFAULT_MINION_OPTS.copy()
    if overrides is None:
        overrides = {}
    opts = defaults.copy()
    opts['__role'] = 'minion'
    _adjust_log_file_override(overrides, defaults['log_file'])
    if overrides:
        opts.update(overrides)
    if 'environment' in opts:
        if opts['saltenv'] is not None:
            log.warning("The 'saltenv' and 'environment' minion config options cannot both be used. Ignoring 'environment' in favor of 'saltenv'.")
            opts['environment'] = opts['saltenv']
        else:
            log.warning("The 'environment' minion config option has been renamed to 'saltenv'. Using %s as the 'saltenv' config value.", opts['environment'])
            opts['saltenv'] = opts['environment']
    for (idx, val) in enumerate(opts['fileserver_backend']):
        if val in ('git', 'hg', 'svn', 'minion'):
            new_val = val + 'fs'
            log.debug("Changed %s to %s in minion opts' fileserver_backend list", val, new_val)
            opts['fileserver_backend'][idx] = new_val
    opts['__cli'] = salt.utils.stringutils.to_unicode(os.path.basename(sys.argv[0]))
    using_ip_for_id = False
    if not opts.get('id'):
        if minion_id:
            opts['id'] = minion_id
        else:
            (opts['id'], using_ip_for_id) = get_id(opts, cache_minion_id=cache_minion_id)
    if not using_ip_for_id and 'append_domain' in opts:
        opts['id'] = _append_domain(opts)
    for directory in opts.get('append_minionid_config_dirs', []):
        if directory in ('pki_dir', 'cachedir', 'extension_modules'):
            newdirectory = os.path.join(opts[directory], opts['id'])
            opts[directory] = newdirectory
        elif directory == 'default_include' and directory in opts:
            include_dir = os.path.dirname(opts[directory])
            new_include_dir = os.path.join(include_dir, opts['id'], os.path.basename(opts[directory]))
            opts[directory] = new_include_dir
    if 'pidfile' in opts.get('append_minionid_config_dirs', []):
        newpath_list = os.path.split(opts['pidfile'])
        opts['pidfile'] = os.path.join(newpath_list[0], 'salt', opts['id'], newpath_list[1])
    if len(opts['sock_dir']) > len(opts['cachedir']) + 10:
        opts['sock_dir'] = os.path.join(opts['cachedir'], '.salt-unix')
    opts['open_mode'] = opts['open_mode'] is True
    opts['file_roots'] = _validate_file_roots(opts['file_roots'])
    opts['pillar_roots'] = _validate_pillar_roots(opts['pillar_roots'])
    opts['extension_modules'] = opts.get('extension_modules') or os.path.join(opts['cachedir'], 'extmods')
    opts['utils_dirs'] = opts.get('utils_dirs') or [os.path.join(opts['extension_modules'], 'utils')]
    insert_system_path(opts, opts['utils_dirs'])
    prepend_root_dirs = ['pki_dir', 'cachedir', 'sock_dir', 'extension_modules', 'pidfile']
    for config_key in ('log_file', 'key_logfile'):
        if urllib.parse.urlparse(opts.get(config_key, '')).scheme == '':
            prepend_root_dirs.append(config_key)
    prepend_root_dir(opts, prepend_root_dirs)
    if 'beacons' not in opts:
        opts['beacons'] = {}
    if overrides.get('ipc_write_buffer', '') == 'dynamic':
        opts['ipc_write_buffer'] = _DFLT_IPC_WBUFFER
    if 'ipc_write_buffer' not in overrides:
        opts['ipc_write_buffer'] = 0
    opts['hash_type'] = opts['hash_type'].lower()
    _update_ssl_config(opts)
    _update_discovery_config(opts)
    return opts

def _update_discovery_config(opts):
    """
    Update discovery config for all instances.

    :param opts:
    :return:
    """
    if opts.get('discovery') not in (None, False):
        if opts['discovery'] is True:
            opts['discovery'] = {}
        discovery_config = {'attempts': 3, 'pause': 5, 'port': 4520, 'match': 'any', 'mapping': {}}
        for key in opts['discovery']:
            if key not in discovery_config:
                raise salt.exceptions.SaltConfigurationError('Unknown discovery option: {}'.format(key))
        if opts.get('__role') != 'minion':
            for key in ['attempts', 'pause', 'match']:
                del discovery_config[key]
        opts['discovery'] = salt.utils.dictupdate.update(discovery_config, opts['discovery'], True, True)

def master_config(path, env_var='SALT_MASTER_CONFIG', defaults=None, exit_on_config_errors=False):
    """
    Reads in the master configuration file and sets up default options

    This is useful for running the actual master daemon. For running
    Master-side client interfaces that need the master opts see
    :py:func:`salt.client.client_config`.
    """
    if defaults is None:
        defaults = DEFAULT_MASTER_OPTS.copy()
    if not os.environ.get(env_var, None):
        salt_config_dir = os.environ.get('SALT_CONFIG_DIR', None)
        if salt_config_dir:
            env_config_file_path = os.path.join(salt_config_dir, 'master')
            if salt_config_dir and os.path.isfile(env_config_file_path):
                os.environ[env_var] = env_config_file_path
    overrides = load_config(path, env_var, DEFAULT_MASTER_OPTS['conf_file'])
    default_include = overrides.get('default_include', defaults['default_include'])
    include = overrides.get('include', [])
    overrides.update(include_config(default_include, path, verbose=False, exit_on_config_errors=exit_on_config_errors))
    overrides.update(include_config(include, path, verbose=True, exit_on_config_errors=exit_on_config_errors))
    opts = apply_master_config(overrides, defaults)
    _validate_ssh_minion_opts(opts)
    _validate_opts(opts)
    if opts.get('nodegroups') is None:
        opts['nodegroups'] = DEFAULT_MASTER_OPTS.get('nodegroups', {})
    if salt.utils.data.is_dictlist(opts['nodegroups']):
        opts['nodegroups'] = salt.utils.data.repack_dictlist(opts['nodegroups'])
    apply_sdb(opts)
    return opts

def apply_master_config(overrides=None, defaults=None):
    """
    Returns master configurations dict.
    """
    if defaults is None:
        defaults = DEFAULT_MASTER_OPTS.copy()
    if overrides is None:
        overrides = {}
    opts = defaults.copy()
    opts['__role'] = 'master'
    _adjust_log_file_override(overrides, defaults['log_file'])
    if overrides:
        opts.update(overrides)
    opts['__cli'] = salt.utils.stringutils.to_unicode(os.path.basename(sys.argv[0]))
    if 'environment' in opts:
        if opts['saltenv'] is not None:
            log.warning("The 'saltenv' and 'environment' master config options cannot both be used. Ignoring 'environment' in favor of 'saltenv'.")
            opts['environment'] = opts['saltenv']
        else:
            log.warning("The 'environment' master config option has been renamed to 'saltenv'. Using %s as the 'saltenv' config value.", opts['environment'])
            opts['saltenv'] = opts['environment']
    for (idx, val) in enumerate(opts['fileserver_backend']):
        if val in ('git', 'hg', 'svn', 'minion'):
            new_val = val + 'fs'
            log.debug("Changed %s to %s in master opts' fileserver_backend list", val, new_val)
            opts['fileserver_backend'][idx] = new_val
    if len(opts['sock_dir']) > len(opts['cachedir']) + 10:
        opts['sock_dir'] = os.path.join(opts['cachedir'], '.salt-unix')
    opts['token_dir'] = os.path.join(opts['cachedir'], 'tokens')
    opts['syndic_dir'] = os.path.join(opts['cachedir'], 'syndics')
    opts['extension_modules'] = opts.get('extension_modules') or os.path.join(opts['cachedir'], 'extmods')
    opts['utils_dirs'] = opts.get('utils_dirs') or [os.path.join(opts['extension_modules'], 'utils')]
    insert_system_path(opts, opts['utils_dirs'])
    if overrides.get('ipc_write_buffer', '') == 'dynamic':
        opts['ipc_write_buffer'] = _DFLT_IPC_WBUFFER
    if 'ipc_write_buffer' not in overrides:
        opts['ipc_write_buffer'] = 0
    using_ip_for_id = False
    append_master = False
    if not opts.get('id'):
        (opts['id'], using_ip_for_id) = get_id(opts, cache_minion_id=None)
        append_master = True
    if not using_ip_for_id and 'append_domain' in opts:
        opts['id'] = _append_domain(opts)
    if append_master:
        opts['id'] += '_master'
    prepend_root_dirs = ['pki_dir', 'cachedir', 'pidfile', 'sock_dir', 'extension_modules', 'autosign_file', 'autoreject_file', 'token_dir', 'syndic_dir', 'sqlite_queue_dir', 'autosign_grains_dir']
    for config_key in ('log_file', 'key_logfile', 'ssh_log_file'):
        log_setting = opts.get(config_key, '')
        if log_setting is None:
            continue
        if urllib.parse.urlparse(log_setting).scheme == '':
            prepend_root_dirs.append(config_key)
    prepend_root_dir(opts, prepend_root_dirs)
    opts['open_mode'] = opts['open_mode'] is True
    opts['auto_accept'] = opts['auto_accept'] is True
    opts['file_roots'] = _validate_file_roots(opts['file_roots'])
    opts['pillar_roots'] = _validate_file_roots(opts['pillar_roots'])
    if opts['file_ignore_regex']:
        if isinstance(opts['file_ignore_regex'], str):
            ignore_regex = [opts['file_ignore_regex']]
        elif isinstance(opts['file_ignore_regex'], list):
            ignore_regex = opts['file_ignore_regex']
        opts['file_ignore_regex'] = []
        for regex in ignore_regex:
            try:
                re.compile(regex)
                opts['file_ignore_regex'].append(regex)
            except Exception:
                log.warning('Unable to parse file_ignore_regex. Skipping: %s', regex)
    if opts['file_ignore_glob']:
        if isinstance(opts['file_ignore_glob'], str):
            opts['file_ignore_glob'] = [opts['file_ignore_glob']]
    if opts['worker_threads'] < 3 and opts.get('peer', None):
        log.warning("The 'worker_threads' setting in '%s' cannot be lower than 3. Resetting it to the default value of 3.", opts['conf_file'])
        opts['worker_threads'] = 3
    opts.setdefault('pillar_source_merging_strategy', 'smart')
    opts['hash_type'] = opts['hash_type'].lower()
    _update_ssl_config(opts)
    _update_discovery_config(opts)
    return opts

def client_config(path, env_var='SALT_CLIENT_CONFIG', defaults=None):
    """
    Load Master configuration data

    Usage:

    .. code-block:: python

        import salt.config
        master_opts = salt.config.client_config('/etc/salt/master')

    Returns a dictionary of the Salt Master configuration file with necessary
    options needed to communicate with a locally-running Salt Master daemon.
    This function searches for client specific configurations and adds them to
    the data from the master configuration.

    This is useful for master-side operations like
    :py:class:`~salt.client.LocalClient`.
    """
    if defaults is None:
        defaults = DEFAULT_MASTER_OPTS.copy()
    xdg_dir = salt.utils.xdg.xdg_config_dir()
    if os.path.isdir(xdg_dir):
        client_config_dir = xdg_dir
        saltrc_config_file = 'saltrc'
    else:
        client_config_dir = os.path.expanduser('~')
        saltrc_config_file = '.saltrc'
    opts = {'token_file': defaults.get('token_file', os.path.join(client_config_dir, 'salt_token'))}
    opts.update(master_config(path, defaults=defaults))
    saltrc_config = os.path.join(client_config_dir, saltrc_config_file)
    opts.update(load_config(saltrc_config, env_var, saltrc_config))
    if 'token_file' in opts:
        opts['token_file'] = os.path.abspath(os.path.expanduser(opts['token_file']))
    if os.path.isfile(opts['token_file']):
        expire = opts.get('token_expire', 43200)
        if os.stat(opts['token_file']).st_mtime + expire > time.mktime(time.localtime()):
            with salt.utils.files.fopen(opts['token_file']) as fp_:
                opts['token'] = fp_.read().strip()
    if opts['interface'] == '0.0.0.0':
        opts['interface'] = '127.0.0.1'
    if 'master_uri' not in opts:
        opts['master_uri'] = 'tcp://{ip}:{port}'.format(ip=salt.utils.zeromq.ip_bracket(opts['interface']), port=opts['ret_port'])
    _validate_opts(opts)
    return opts

def api_config(path):
    """
    Read in the Salt Master config file and add additional configs that
    need to be stubbed out for salt-api
    """
    opts = DEFAULT_API_OPTS.copy()
    opts.update(client_config(path, defaults=DEFAULT_MASTER_OPTS.copy()))
    opts.update({'pidfile': opts.get('api_pidfile', DEFAULT_API_OPTS['api_pidfile']), 'log_file': opts.get('api_logfile', DEFAULT_API_OPTS['api_logfile'])})
    prepend_root_dir(opts, ['api_pidfile', 'api_logfile', 'log_file', 'pidfile'])
    return opts

def spm_config(path):
    """
    Read in the salt master config file and add additional configs that
    need to be stubbed out for spm

    .. versionadded:: 2015.8.0
    """
    defaults = DEFAULT_MASTER_OPTS.copy()
    defaults.update(DEFAULT_SPM_OPTS)
    overrides = load_config(path, 'SPM_CONFIG', DEFAULT_SPM_OPTS['spm_conf_file'])
    default_include = overrides.get('spm_default_include', defaults['spm_default_include'])
    include = overrides.get('include', [])
    overrides.update(include_config(default_include, path, verbose=False))
    overrides.update(include_config(include, path, verbose=True))
    defaults = apply_master_config(overrides, defaults)
    defaults = apply_spm_config(overrides, defaults)
    return client_config(path, env_var='SPM_CONFIG', defaults=defaults)

def apply_spm_config(overrides, defaults):
    """
    Returns the spm configurations dict.

    .. versionadded:: 2015.8.1
    """
    opts = defaults.copy()
    _adjust_log_file_override(overrides, defaults['log_file'])
    if overrides:
        opts.update(overrides)
    prepend_root_dirs = ['formula_path', 'pillar_path', 'reactor_path', 'spm_cache_dir', 'spm_build_dir']
    for config_key in ('spm_logfile',):
        log_setting = opts.get(config_key, '')
        if log_setting is None:
            continue
        if urllib.parse.urlparse(log_setting).scheme == '':
            prepend_root_dirs.append(config_key)
    prepend_root_dir(opts, prepend_root_dirs)
    return opts