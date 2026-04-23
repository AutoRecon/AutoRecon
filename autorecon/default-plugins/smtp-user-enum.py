from autorecon.plugins import ServiceScan

class SMTPUserEnum(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'SMTP-User-Enum'
		self.tags = ['default', 'safe', 'smtp', 'email']

	def configure(self):
		self.match_service_name('^smtp')

	async def run(self, service):
		await service.execute('hydra smtp-enum://{addressv6}:{port}/vrfy -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" 2>&1', outfile='{protocol}_{port}_smtp_user-enum_hydra_vrfy.txt')
		await service.execute('hydra smtp-enum://{addressv6}:{port}/expn -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" 2>&1', outfile='{protocol}_{port}_smtp_user-enum_hydra_expn.txt')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Try User Enumeration using "RCPT TO". Replace <TARGET-DOMAIN> with the target domain name:', [
			'hydra smtp-enum://{addressv6}:{port}/rcpt -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -o "{scandir}/{protocol}_{port}_smtp_user-enum_hydra_rcpt.txt" -p <TARGET-DOMAIN>'
		])
