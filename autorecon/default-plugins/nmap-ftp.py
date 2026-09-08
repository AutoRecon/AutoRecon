from autorecon.plugins import ServiceScan

class NmapFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap FTP'
		self.tags = ['default', 'safe', 'ftp']

	def configure(self):
		self.match_service_name(['^ftp', '^ftp\\-data'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ftp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ftp_nmap.xml" {address}')
