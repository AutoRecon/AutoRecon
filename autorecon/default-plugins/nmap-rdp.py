from autorecon.plugins import ServiceScan

class NmapRDP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap RDP"
		self.tags = ['default', 'safe', 'rdp']

	def configure(self):
		self.match_service_name(['^rdp', '^ms\\-wbt\\-server', '^ms\\-term\\-serv'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(rdp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_rdp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rdp_nmap.xml" {address}')
