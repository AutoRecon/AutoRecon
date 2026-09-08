from autorecon.plugins import ServiceScan

class SMBMap(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SMBMap"
		self.tags = ['default', 'safe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\\-ds', '^netbios'])

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('smbmap -H {address} -P {port} 2>&1', outfile='smbmap-share-permissions.txt')
			await service.execute('smbmap -u null -p "" -H {address} -P {port} 2>&1', outfile='smbmap-share-permissions.txt')
			await service.execute('smbmap -H {address} -P {port} -r 2>&1', outfile='smbmap-list-contents.txt')
			await service.execute('smbmap -u null -p "" -H {address} -P {port} -r 2>&1', outfile='smbmap-list-contents.txt')
			await service.execute('smbmap -H {address} -P {port} -x "ipconfig /all" 2>&1', outfile='smbmap-execute-command.txt')
			await service.execute('smbmap -u null -p "" -H {address} -P {port} -x "ipconfig /all" 2>&1', outfile='smbmap-execute-command.txt')
