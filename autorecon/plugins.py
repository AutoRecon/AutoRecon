import asyncio, inspect, os, re, sys
from typing import final
from autorecon.config import config
from autorecon.io import slugify, info, warn, error, fail, CommandStreamReader
from autorecon.targets import Service

class Pattern:

	def __init__(self, pattern, description=None):
		self.pattern = pattern
		self.description = description

class Plugin(object):

	def __init__(self):
		self.name = None
		self.slug = None
		self.description = None
		self.tags = ['default']
		self.priority = 1
		self.patterns = []
		self.autorecon = None
		self.disabled = False

	@final
	def add_option(self, name, default=None, help=None):
		self.autorecon.add_argument(self, name, metavar='VALUE', default=default, help=help)

	@final
	def add_constant_option(self, name, const, default=None, help=None):
		self.autorecon.add_argument(self, name, action='store_const', const=const, default=default, help=help)

	@final
	def add_true_option(self, name, help=None):
		self.autorecon.add_argument(self, name, action='store_true', help=help)

	@final
	def add_false_option(self, name, help=None):
		self.autorecon.add_argument(self, name, action='store_false', help=help)

	@final
	def add_list_option(self, name, default=None, help=None):
		self.autorecon.add_argument(self, name, nargs='+', metavar='VALUE', default=default, help=help)

	@final
	def add_choice_option(self, name, choices, default=None, help=None):
		if not isinstance(choices, list):
			fail('The choices argument for ' + self.name + '\'s ' + name + ' choice option should be a list.')
		self.autorecon.add_argument(self, name, choices=choices, default=default, help=help)

	@final
	def get_option(self, name, default=None):
		# TODO: make sure name is simple.
		name = self.slug.replace('-', '_') + '.' + slugify(name).replace('-', '_')

		if name in vars(self.autorecon.args):
			if vars(self.autorecon.args)[name] is None:
				if default:
					return default
				else:
					return list()
			else:
				return vars(self.autorecon.args)[name]
		else:
			if default:
				return default
			return list()

	@final
	def get_global_option(self, name, default=None):
		name = 'global.' + slugify(name).replace('-', '_')

		if name in vars(self.autorecon.args):
			if vars(self.autorecon.args)[name] is None:
				if default:
					return default
				else:
					return None
			else:
				return vars(self.autorecon.args)[name]
		else:
			if default:
				return default
			return None

	@final
	def get_global(self, name, default=None):
		return self.get_global_option(name, default)

	@final
	def add_pattern(self, pattern, description=None):
		try:
			compiled = re.compile(pattern)
			if description:
				self.patterns.append(Pattern(compiled, description=description))
			else:
				self.patterns.append(Pattern(compiled))
		except re.error:
			fail('Error: The pattern "' + pattern + '" in the plugin "' + self.name + '" is invalid regex.')

	@final
	def info(self, msg, verbosity=0):
		info('{bright}[{bgreen}' + self.slug + '{crst}]{rst} ' + msg)

	@final
	def warn(self, msg, verbosity=0):
		warn('{bright}[{bgreen}' + self.slug + '{crst}]{rst} ' + msg)

	@final
	def error(self, msg, verbosity=0):
		error('{bright}[{bgreen}' + self.slug + '{crst}]{rst} ' + msg)

class PortScan(Plugin):

	def __init__(self):
		super().__init__()
		self.type = None
		self.specific_ports = False

	async def run(self, target):
		raise NotImplementedError

class ServiceScan(Plugin):

	def __init__(self):
		super().__init__()
		self.ports = {'tcp':[], 'udp':[]}
		self.ignore_ports = {'tcp':[], 'udp':[]}
		self.services = []
		self.service_names = []
		self.ignore_service_names = []
		self.run_once_boolean = False
		self.require_ssl_boolean = False
		self.max_target_instances = 0
		self.max_global_instances = 0

	@final
	def match_service(self, protocol, port, name, negative_match=False):
		protocol = protocol.lower()
		if protocol not in ['tcp', 'udp']:
			print('Invalid protocol.')
			sys.exit(1)

		if not isinstance(port, list):
			port = [port]

		port = list(map(int, port))

		if not isinstance(name, list):
			name = [name]

		valid_regex = True
		for r in name:
			try:
				re.compile(r)
			except re.error:
				print('Invalid regex: ' + r)
				valid_regex = False

		if not valid_regex:
			sys.exit(1)

		service = {'protocol': protocol, 'port': port, 'name': name, 'negative_match': negative_match}
		self.services.append(service)

	@final
	def match_port(self, protocol, port, negative_match=False):
		protocol = protocol.lower()
		if protocol not in ['tcp', 'udp']:
			print('Invalid protocol.')
			sys.exit(1)
		else:
			if not isinstance(port, list):
				port = [port]

			port = list(map(int, port))

			if negative_match:
				self.ignore_ports[protocol] = list(set(self.ignore_ports[protocol] + port))
			else:
				self.ports[protocol] = list(set(self.ports[protocol] + port))

	@final
	def match_service_name(self, name, negative_match=False):
		if not isinstance(name, list):
			name = [name]

		valid_regex = True
		for r in name:
			try:
				re.compile(r)
			except re.error:
				print('Invalid regex: ' + r)
				valid_regex = False

		if valid_regex:
			if negative_match:
				self.ignore_service_names = list(set(self.ignore_service_names + name))
			else:
				self.service_names = list(set(self.service_names + name))
		else:
			sys.exit(1)

	@final
	def require_ssl(self, boolean):
		self.require_ssl_boolean = boolean

	@final
	def run_once(self, boolean):
		self.run_once_boolean = boolean

	@final
	def match_all_service_names(self, boolean):
		if boolean:
			# Add a "match all" service name.
			self.match_service_name('.*')

class Report(Plugin):

	def __init__(self):
		super().__init__()

class AutoRecon(object):

	def __init__(self):
		self.pending_targets = []
		self.scanning_targets = []
		self.completed_targets = []
		self.plugins = {}
		self.__slug_regex = re.compile(r'^[a-z0-9\-]+$')
		self.plugin_types = {'port':[], 'service':[], 'report':[]}
		self.port_scan_semaphore = None
		self.service_scan_semaphore = None
		self.argparse = None
		self.argparse_group = None
		self.args = None
		self.missing_services = []
		self.taglist = []
		self.tags = []
		self.excluded_tags = []
		self.patterns = []
		self.errors = False
		self.lock = asyncio.Lock()
		self.load_slug = None
		self.load_module = None

	def add_argument(self, plugin, name, **kwargs):
		# TODO: make sure name is simple.
		name = '--' + plugin.slug + '.' + slugify(name)

		if self.argparse_group is None:
			self.argparse_group = self.argparse.add_argument_group('plugin arguments', description='These are optional arguments for certain plugins.')
		self.argparse_group.add_argument(name, **kwargs)

	def extract_service(self, line, regex):
		if regex is None:
			regex = r'^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
		match = re.search(regex, line)
		if match:
			protocol = match.group('protocol').lower()
			port = int(match.group('port'))
			service = match.group('service')
			secure = True if 'ssl' in service or 'tls' in service else False

			if service.startswith('ssl/') or service.startswith('tls/'):
				service = service[4:]

			return Service(protocol, port, service, secure)
		else:
			return None

	async def extract_services(self, stream, regex):
		if not isinstance(stream, CommandStreamReader):
			print('Error: extract_services must be passed an instance of a CommandStreamReader.')
			sys.exit(1)

		services = []
		while True:
			line = await stream.readline()
			if line is not None:
				service = self.extract_service(line, regex)
				if service:
					services.append(service)
			else:
				break
		return services

	def register(self, plugin, filename):
		if plugin.disabled:
			return

		if plugin.name is None:
			fail('Error: Plugin with class name "' + plugin.__class__.__name__ + '" in ' + filename + ' does not have a name.')

		for _, loaded_plugin in self.plugins.items():
			if plugin.name == loaded_plugin.name:
				fail('Error: Duplicate plugin name "' + plugin.name + '" detected in ' + filename + '.', file=sys.stderr)

		if plugin.slug is None:
			plugin.slug = slugify(plugin.name)
		elif not self.__slug_regex.match(plugin.slug):
			fail('Error: provided slug "' + plugin.slug + '" in ' + filename + ' is not valid (must only contain lowercase letters, numbers, and hyphens).', file=sys.stderr)

		if plugin.slug in config['protected_classes']:
			fail('Error: plugin slug "' + plugin.slug + '" in ' + filename + ' is a protected string. Please change.')

		if plugin.slug not in self.plugins:

			for _, loaded_plugin in self.plugins.items():
				if plugin is loaded_plugin:
					fail('Error: plugin "' + plugin.name + '" in ' + filename + ' already loaded as "' + loaded_plugin.name + '" (' + str(loaded_plugin) + ')', file=sys.stderr)

			configure_function_found = False
			run_coroutine_found = False
			manual_function_found = False

			for member_name, member_value in inspect.getmembers(plugin, predicate=inspect.ismethod):
				if member_name == 'configure':
					configure_function_found = True
				elif member_name == 'run' and inspect.iscoroutinefunction(member_value):
					if len(inspect.getfullargspec(member_value).args) != 2:
						fail('Error: the "run" coroutine in the plugin "' + plugin.name + '" in ' + filename + ' should have two arguments.', file=sys.stderr)
					run_coroutine_found = True
				elif member_name == 'manual':
					if len(inspect.getfullargspec(member_value).args) != 3:
						fail('Error: the "manual" function in the plugin "' + plugin.name + '" in ' + filename + ' should have three arguments.', file=sys.stderr)
					manual_function_found = True

			if not run_coroutine_found and not manual_function_found:
				fail('Error: the plugin "' + plugin.name + '" in ' + filename + ' needs either a "manual" function, a "run" coroutine, or both.', file=sys.stderr)

			if issubclass(plugin.__class__, PortScan):
				if plugin.type is None:
					fail('Error: the PortScan plugin "' + plugin.name + '" in ' + filename + ' requires a type (either tcp or udp).')
				else:
					plugin.type = plugin.type.lower()
					if plugin.type not in ['tcp', 'udp']:
						fail('Error: the PortScan plugin "' + plugin.name + '" in ' + filename + ' has an invalid type (should be tcp or udp).')
				self.plugin_types["port"].append(plugin)
			elif issubclass(plugin.__class__, ServiceScan):
				self.plugin_types["service"].append(plugin)
			elif issubclass(plugin.__class__, Report):
				self.plugin_types["report"].append(plugin)
			else:
				fail('Plugin "' + plugin.name + '" in ' + filename + ' is neither a PortScan, ServiceScan, nor a Report.', file=sys.stderr)

			plugin.tags = [tag.lower() for tag in plugin.tags]

			# Add plugin tags to tag list.
			[self.taglist.append(t) for t in plugin.tags if t not in self.tags]

			plugin.autorecon = self
			if configure_function_found:
				plugin.configure()
			self.plugins[plugin.slug] = plugin
		else:
			fail('Error: plugin slug "' + plugin.slug + '" in ' + filename + ' is already assigned.', file=sys.stderr)

	async def execute(self, cmd, target, tag, patterns=None, outfile=None, errfile=None):
		if patterns:
			combined_patterns = self.patterns + patterns
		else:
			combined_patterns = self.patterns

		process = await asyncio.create_subprocess_shell(
			cmd,
			stdin=open('/dev/null'),
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE)

		cout = CommandStreamReader(process.stdout, target, tag, patterns=combined_patterns, outfile=outfile)
		cerr = CommandStreamReader(process.stderr, target, tag, patterns=combined_patterns, outfile=errfile)

		asyncio.create_task(cout._read())
		asyncio.create_task(cerr._read())

		return process, cout, cerr
