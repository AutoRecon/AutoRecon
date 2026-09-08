from autorecon.plugins import ServiceScan
from shutil import which

class Enum4Linux(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Enum4Linux"
		self.tags = ['default', 'safe', 'active-directory']

	def configure(self):
		self.add_choice_option('tool', default=('enum4linux-ng' if which('enum4linux-ng') else 'enum4linux'), choices=['enum4linux-ng', 'enum4linux'], help='The tool to use for doing Windows and Samba enumeration. Default: %(default)s')
		self.match_service_name(['^ldap', '^smb', '^microsoft\\-ds', '^netbios'])
		self.match_port('tcp', [139, 389, 445])
		self.match_port('udp', 137)
		self.run_once(True)

	def check(self):
		tool = self.get_option('tool')
		if tool == 'enum4linux' and which('enum4linux') is None:
			self.error('The enum4linux program could not be found. Make sure it is installed. (On Kali, run: sudo apt install enum4linux)')
			return False
		elif tool == 'enum4linux-ng' and which('enum4linux-ng') is None:
			self.error('The enum4linux-ng program could not be found. Make sure it is installed. (https://github.com/cddmp/enum4linux-ng)')
			return False

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			tool = self.get_option('tool')
			if tool is not None:
				if tool == 'enum4linux':
					await service.execute('enum4linux -a -M -l -d {address} 2>&1', outfile='enum4linux.txt')
				elif tool == 'enum4linux-ng':
					await service.execute('enum4linux-ng -A -d -v {address} 2>&1', outfile='enum4linux-ng.txt')
