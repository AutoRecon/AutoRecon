from autorecon.plugins import PortScan
from autorecon.targets import Service
import re

class GuessPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = 'Guess TCP Ports'
		self.type = 'tcp'
		self.description = 'Performs an Nmap scan of the all TCP ports but guesses services based off the port found. Can be quicker. Proper service matching is performed at the end of the scan.'
		self.tags = ['guess-port-scan', 'long']
		self.priority = 0

	async def run(self, target):
		if target.ports:
			if target.ports['tcp']:
				process, stdout, stderr = await target.execute('nmap {nmap_extra} -A --osscan-guess --version-all -p ' + target.ports['tcp'] + ' -oN "{scandir}/' + str(target.address) + '_custom_ports_tcp_nmap.txt" -oX "{scandir}/xml/' + str(target.address) + '_custom_ports_tcp_nmap.xml" {address}', blocking=False)
			else:
				return []
		else:
			process, stdout, stderr = await target.execute('nmap {nmap_extra} -A --osscan-guess --version-all -p- -oN "{scandir}/' + str(target.address) + '_quick_tcp_nmap.txt" -oX "{scandir}/xml/' + str(target.address) + '_quick_tcp_nmap.xml" {address}', blocking=False)

		insecure_ports = {
			'20':'ftp', '21':'ftp', '22':'ssh', '23':'telnet', '25':'smtp', '53':'domain', '69':'tftp', '79':'finger', '80':'http', '88':'kerberos', '109':'pop3', '110':'pop3', '111':'rpcbind', '119':'nntp', '135':'msrpc', '139':'netbios-ssn', '143':'imap', '161':'snmp', '220':'imap', '389':'ldap', '433':'nntp', '445':'smb', '587':'smtp', '631':'ipp', '873':'rsync', '1098':'java-rmi', '1099':'java-rmi', '1433':'mssql', '1521':'oracle', '2049':'nfs', '2483':'oracle', '3020':'smb', '3306':'mysql', '3389':'rdp', '3632':'distccd', '5060':'asterisk', '5500':'vnc', '5900':'vnc', '5985':'wsman', '6379':'redis', '8080':'http-proxy', '27017':'mongod', '27018':'mongod', '27019':'mongod'
		}
		secure_ports = {
			'443':'https', '465':'smtp', '563':'nntp', '585':'imaps', '593':'msrpc', '636':'ldap', '989':'ftp', '990':'ftp', '992':'telnet', '993':'imaps', '995':'pop3s', '2484':'oracle', '5061':'asterisk', '5986':'wsman'
		}

		services = []
		while True:
			line = await stdout.readline()
			if line is not None:
				match = re.match('^Discovered open port ([0-9]+)/tcp', line)
				if match:
					if match.group(1) in insecure_ports.keys():
						await target.add_service(Service('tcp', match.group(1), insecure_ports[match.group(1)]))
					elif match.group(1) in secure_ports.keys():
						await target.add_service(Service('tcp', match.group(1), secure_ports[match.group(1)], True))
				service = target.extract_service(line)
				if service is not None:
					services.append(service)
			else:
				break

		await process.wait()
		return services
