from autorecon.plugins import ServiceScan

class SNMPWalk(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SNMPWalk"
		self.tags = ['default', 'safe', 'snmp']

	def configure(self):
		self.match_service_name('^snmp')
		self.match_port('udp', 161)
		self.run_once(True)

	async def run(self, service):
		await service.execute('snmpbulkwalk -c public -v2c {address} 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} NET-SNMP-EXTEND-MIB::nsExtendObjects 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_extend_objects.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.2.1.25.1.6.0 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_system_processes.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.2.1.25.4.2.1.2 2>&1', outfile='{scandir}/{protocol}_{port}_snmp_snmpwalk_running_processes.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.2.1.25.4.2.1.4 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_process_paths.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.2.1.25.2.3.1.4 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_storage_units.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.2.1.25.2.3.1.4 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_software_names.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.4.1.77.1.2.25 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_user_accounts.txt')
		await service.execute('snmpbulkwalk -c public -v2c {address} 1.3.6.1.2.1.6.13.1.3 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_tcp_ports.txt')
