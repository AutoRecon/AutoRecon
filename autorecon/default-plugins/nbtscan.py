from autorecon.plugins import ServiceScan

class NBTScan(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'nbtscan'
		self.tags = ['default', 'safe', 'netbios', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\\-ds', '^netbios'])
		self.match_port('udp', 137)
		self.run_once(True)

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('nbtscan -rvh {ipaddress} 2>&1', outfile='nbtscan.txt')
