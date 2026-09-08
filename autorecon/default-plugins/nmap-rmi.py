from autorecon.plugins import ServiceScan

class NmapRMI(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap RMI"
		self.tags = ['default', 'safe', 'rmi']

	def configure(self):
		self.match_service_name(['^java\\-rmi', '^rmiregistry'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,rmi-vuln-classloader,rmi-dumpregistry" -oN "{scandir}/{protocol}_{port}_rmi_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rmi_nmap.xml" {address}')
