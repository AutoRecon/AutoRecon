from autorecon.plugins import ServiceScan

class BruteforceSMB(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Bruteforce SMB'
		self.tags = ['default', 'safe', 'active-directory']

	def configure(self):
		self.match_service('tcp', 445, '^microsoft\-ds')
		self.match_service('tcp', 139, '^netbios')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Bruteforce SMB', [
			'netexec smb {address} --port={port} -u "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -p "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '"'
		])
