import platformdirs, os

config_dir = platformdirs.user_config_dir('AutoRecon')
data_dir = platformdirs.user_data_dir('AutoRecon')

configurable_keys = [
	'ports',
	'max_scans',
	'max_port_scans',
	'tags',
	'exclude_tags',
	'port_scans',
	'service_scans',
	'reports',
	'plugins_dir',
	'add_plugins-dir',
	'output',
	'single_target',
	'only_scans_dir',
	'no_port_dirs',
	'heartbeat',
	'timeout',
	'target_timeout',
	'nmap',
	'nmap_append',
	'proxychains',
	'disable_sanity_checks',
	'disable_keyboard_control',
	'ignore_plugin_checks',
	'force_services',
	'max_plugin_target_instances',
	'max_plugin_global_instances',
	'accessible',
	'verbose'
]

configurable_boolean_keys = [
	'single_target',
	'only_scans_dir',
	'no_port_dirs',
	'proxychains',
	'disable_sanity_checks',
	'ignore_plugin_checks',
	'accessible'
]

config = {
	'protected_classes': ['autorecon', 'target', 'service', 'commandstreamreader', 'plugin', 'portscan', 'report', 'servicescan', 'global', 'pattern'],
	'service_exceptions': ['infocrypt', 'mc-nmf', 'ncacn_http', 'smux', 'status', 'tcpwrapped', 'unknown'],
	'config_dir': config_dir,
	'data_dir': data_dir,
	'global_file': None,
	'ports': None,
	'max_scans': 50,
	'max_port_scans': None,
	'tags': 'default',
	'exclude_tags': None,
	'port_scans': None,
	'service_scans': None,
	'reports': None,
	'plugins_dir': None,
	'add_plugins_dir': None,
	'output': 'results',
	'single_target': False,
	'only_scans_dir': False,
	'no_port_dirs': False,
	'heartbeat': 60,
	'timeout': None,
	'target_timeout': None,
	'nmap': '-vv --reason -Pn -T4',
	'nmap_append': '',
	'proxychains': False,
	'disable_sanity_checks': False,
	'disable_keyboard_control': False,
	'ignore_plugin_checks': False,
	'force_services': None,
	'max_plugin_target_instances': None,
	'max_plugin_global_instances': None,
	'accessible': False,
	'verbose': 0,
	'imported_nmap_services': None
}
