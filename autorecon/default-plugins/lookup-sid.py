from autorecon.plugins import ServiceScan

class LookupSID(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'lookupsid'
		self.tags = ['default', 'safe', 'active-directory']

	def configure(self):
		self.match_service('tcp', 445, '^microsoft\\-ds')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Lookup SIDs', [
			'impacket-lookupsid \'[username]:[password]@{address}\''
		])
