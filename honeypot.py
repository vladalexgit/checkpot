import nmap
import sys
import platform


class Honeypot:

    def __init__(self, address, scan_os=False):

        # load the nmap scanner
        self.address = address
        self.scan_os = scan_os
        self.host = None

        self._nm = nmap.PortScanner()  # TODO maybe override exception descriptions
        self.scan()

    def scan(self):

        if self.scan_os:
            if platform.system() == 'Windows':
                # No sudo on Windows systems
                self._nm.scan(hosts=self.address, arguments='-sV -O', sudo=False)
            else:
                self._nm.scan(hosts=self.address, arguments='-sV -O', sudo=True)
        else:
            self._nm.scan(hosts=self.address, arguments='-sV')

        hosts = self._nm.all_hosts()
        if hosts:
            self.host = hosts[0]
        else:
            # FIXME -> the scan failed, do something about it before user calls any other methods
            self.host = None

    @property
    def os(self):
        if self.scan_os and self.host and 'osmatch' in self._nm[self.host]:
            if self._nm[self.host]['osmatch'] and self._nm[self.host]['osmatch'][0]['osclass']:
                return "OS: " + self._nm[self.host]['osmatch'][0]['osclass'][0]['osfamily']

    def has_tcp(self, port_number):
        return self._nm[self.host].has_tcp(port_number)

    def get_service_port(self, service_name, protocol):

        if protocol not in self._nm[self.host]:
            return None

        for port, attributes in self._nm[self.host][protocol].items():
            if attributes['name'] == service_name:
                return port
