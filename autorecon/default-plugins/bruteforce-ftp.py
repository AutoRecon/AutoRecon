from autorecon.plugins import ServiceScan

class BruteforceFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Bruteforce FTP"
		self.tags = ['default', 'ftp']

	def configure(self):
		self.match_service_name(['^ftp', '^ftp\\-data'])

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Bruteforce logins:', [
			'hydra -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_ftp_hydra.txt" ftp://{addressv6}',
			'medusa -U "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_ftp_medusa.txt" -M ftp -h {addressv6}'
		])
