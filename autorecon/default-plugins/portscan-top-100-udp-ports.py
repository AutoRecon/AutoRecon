from autorecon.plugins import PortScan
from autorecon.config import config
import os, re

class Top100UDPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = 'Top 100 UDP Ports'
		self.description = 'Performs an Nmap scan of the top 100 UDP ports.'
		self.type = 'udp'
		self.specific_ports = True
		self.tags = ['default', 'default-port-scan', 'long']

	async def run(self, target):
		# Only run UDP scan if user is root.
		if os.getuid() == 0 or config['disable_sanity_checks']:
			if target.ports:
				if target.ports['udp']:
					process, stdout, stderr = await target.execute('nmap {nmap_extra} -sU -A --osscan-guess -p ' + target.ports['udp'] + ' -oN "{scandir}/' + str(target.address) + '_custom_ports_udp_nmap.txt" -oX "{scandir}/xml/' + str(target.address) + '_custom_ports_udp_nmap.xml" {address}', blocking=False)
				else:
					return []
			else:
				process, stdout, stderr = await target.execute('nmap {nmap_extra} -sU -A --top-ports 100 -oN "{scandir}/' + str(target.address) + '_top_100_udp_nmap.txt" -oX "{scandir}/xml/' + str(target.address) + '_top_100_udp_nmap.xml" {address}', blocking=False)
			services = []
			while True:
				line = await stdout.readline()
				if line is not None:
					match = re.search('^Discovered open port ([0-9]+)/udp', line)
					if match:
						target.info('Discovered open port {bmagenta}udp/' + match.group(1) + '{rst} on {byellow}' + target.address + '{rst}', verbosity=1)
					service = target.extract_service(line)
					if service:
						services.append(service)
				else:
					break
			await process.wait()
			return services
		else:
			target.error('UDP scan requires AutoRecon be run with root privileges.')
