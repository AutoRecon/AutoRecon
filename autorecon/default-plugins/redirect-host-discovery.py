from autorecon.plugins import ServiceScan
from urllib.parse import urlparse
import requests
import urllib3
import os
import ipaddress

urllib3.disable_warnings()

class RedirectHostnameDiscovery(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Redirect Hostname Discovery'
		self.slug = 'redirect-host-discovery'
		self.tags = ['default', 'http', 'quick']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
		self.add_true_option(
			'update-hosts',
			help='If set, discovered redirect hostnames will be added to /etc/hosts with the target IP'
		)

	async def run(self, service):
		url = f"{'https' if service.secure else 'http'}://{service.target.address}:{service.port}/"

		try:
			resp = requests.get(url, verify=False, allow_redirects=False)

			if 'Location' in resp.headers:
				location = resp.headers['Location']
				parsed = urlparse(location)
				redirect_host = parsed.hostname

				if redirect_host and redirect_host != service.target.address:
					service.info(f"Redirect detected: {url} → {location}")
					service.info(f"Hostname found in redirect: {redirect_host}")

					if self.get_option('update-hosts'):
						if os.geteuid() != 0:
							service.error("[!] --redirect-host-discovery.update-hosts requires root to modify /etc/hosts.")
							return

						ip = service.target.address
						with open("/etc/hosts", "r") as hosts_file:
							for line in hosts_file:
								parts = line.strip().split()
								if len(parts) >= 2 and parts[0] == ip and redirect_host in parts[1:]:
									return

						with open("/etc/hosts", "a") as hosts_file:
							hosts_file.write(f"{ip} {redirect_host}\n")
						service.info(f"Hostname {redirect_host} added to /etc/hosts with IP {ip}")
				else:
					service.info(f"Redirect detected, but no new hostname found in: {location}")
			else:
				service.info(f"No redirect detected at {url}")

		except Exception as e:
			service.error(f"[!] Error during redirect check on {url} — {e}")
