from autorecon.plugins import ServiceScan

class SMBVuln(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SMB Vulnerabilities"
		self.tags = ['unsafe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\\-ds', '^netbios'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="smb-vuln-*" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_vulnerabilities.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_vulnerabilities.xml" {address}')

	def manual(self, service, plugin_was_run):
		if not plugin_was_run: # Only suggest these if they weren't run.
			service.add_manual_commands('Nmap scans for SMB vulnerabilities that could potentially cause a DoS if scanned (according to Nmap). Be careful:', 'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-* and dos" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_vulnerabilities.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_vulnerabilities.xml" {address}')
