from autorecon.plugins import ServiceScan
import asyncio
import requests
import urllib3
import os, random, string

urllib3.disable_warnings()

class SubdomainEnumeration(ServiceScan):
    def __init__(self):
        super().__init__()
        self.name = "Subdomain Enumeration"
        self.slug = "subdomain-enum"
        self.tags = ['default', 'safe', 'long', 'dns']

    def configure(self):
        self.add_option('domain', help='The domain to use as the base domain (e.g. example.com) for subdomain enumeration. Default: %(default)s')
        self.add_list_option('wordlist', default=['/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'], help='The wordlist(s) to use when enumerating subdomains. Separate multiple wordlists with spaces. Default: %(default)s')
        self.add_option('threads', default=10, help='The number of threads to use when enumerating subdomains. Default: %(default)s')
        self.match_service_name('^domain')

    async def run(self, service):
        domains = []
        if self.get_option('domain'):
            domains.append(self.get_option('domain'))
        if service.target.type == 'hostname' and service.target.address not in domains:
            domains.append(service.target.address)
        if self.get_global('domain') and self.get_global('domain') not in domains:
            domains.append(self.get_global('domain'))

        if not domains:
            service.info('The target was not a domain, nor was a domain provided as an option. Skipping subdomain enumeration.')
            return

        scheme   = 'https' if service.secure else 'http'
        ip_url   = f"{scheme}://{service.target.address}:{service.port}/"
        scandir  = os.path.join(service.target.scandir, f"{service.protocol}{service.port}")
        protocol = service.protocol
        port     = service.port

        for wordlist in self.get_option('wordlist'):
            name = os.path.splitext(os.path.basename(wordlist))[0]

            for domain in domains:
                # Wildcard probe — get baseline status and size
                wildcard_status = None
                wildcard_sizes  = []

                for i in range(3):
                    fuzz_host = ''.join(random.choice(string.ascii_letters) for _ in range(20)) + '.' + domain
                    try:
                        resp = await asyncio.to_thread(
                            requests.get,
                            ip_url,
                            headers={'Host': fuzz_host, 'User-Agent': 'Vhost Finder'},
                            verify=False,
                            allow_redirects=False,
                            timeout=10,
                        )
                        wildcard_status = resp.status_code
                        wildcard_sizes.append(len(resp.content))
                    except requests.exceptions.RequestException:
                        pass

                filter_sizes = list(set(wildcard_sizes))
                filter_codes = [str(wildcard_status)] if wildcard_status else []

                if not filter_codes and not filter_sizes:
                    service.info(f'Could not establish wildcard baseline for {domain}. Skipping.')
                    continue

                outfile = os.path.join(scandir, f"{protocol}_{port}_{domain}_subdomains_{name}.txt")

                cmd = [
                    'ffuf',
                    '-u', ip_url,
                    '-H', f'Host: FUZZ.{domain}',
                    '-H', 'User-Agent: Vhost Finder',
                    '-w', wordlist,
                    '-t', str(self.get_option('threads')),
                    '-mc', 'all',
                    '-noninteractive',
                    '-s',
                ]

                if filter_codes:
                    cmd += ['-fc', ','.join(filter_codes)]
                if filter_sizes:
                    cmd += ['-fs', ','.join(str(s) for s in filter_sizes)]

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )

                with open(outfile, 'w') as f:
                    async for line in proc.stdout:
                        hit = line.decode(errors='replace').strip()
                        if hit and '#' not in hit:
                            f.write(hit + '\n')
                            f.flush()

                await proc.wait()