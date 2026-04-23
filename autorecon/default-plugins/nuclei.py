from autorecon.plugins import ServiceScan
from shutil import which


class Nuclei(ServiceScan):
    def __init__(self):
        super().__init__()
        self.name = "nuclei"
        self.tags = ["default", "safe", "long"]

        self.cmd = 'nuclei -disable-update-check -no-color -target {address}:{port} -scan-all-ips -o "{scandir}/{protocol}_{port}_nuclei.txt"'

    def configure(self):
        self.match_all_service_names(True)
        self.add_pattern(
            r"(.*\[(critical|high)\].*)",
            description="Nuclei {match2} finding: {match1}",
        )

    def check(self):
        if which("nuclei") is None:
            self.error(
                "The program nuclei could not be found. Make sure it is installed. (On Kali, run: sudo apt install nuclei)"
            )
            return False

    async def run(self, service):
        if service.target.ipversion == "IPv4":
            await service.execute(self.cmd)

    def manual(self, service, plugin_was_run):
        if service.target.ipversion == "IPv4" and not plugin_was_run:
            service.add_manual_command(
                f"({self.name}) Fast and customizable vulnerability scanner based on simple YAML based DSL:",
                self.cmd,
            )