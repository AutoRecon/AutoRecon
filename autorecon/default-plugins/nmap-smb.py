from autorecon.plugins import ServiceScan

class NmapSMB(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SMB"
		self.tags = ['default', 'safe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\\-ds', '^netbios'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_smb_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_nmap.xml" {address}')
