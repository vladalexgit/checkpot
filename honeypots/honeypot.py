import nmap
import platform


class Honeypot:

    def __init__(self, address, scan_os=False):

        self.address = address
        self.scan_os = scan_os
        self.host = None

        self._nm = nmap.PortScanner()
        self.scan()

    def scan(self):

        if self.scan_os:
            if platform.system() == 'Windows':
                # No sudo on Windows systems, let UAC handle this
                # FIXME workaround for the subnet python-nmap-bug.log also?
                self._nm.scan(hosts=self.address, arguments='-sV -O', sudo=False)
            else:
                try:
                    # FIXME this is just a workaround for the bug shown in python-nmap-bug.log
                    self._nm.scan(hosts=self.address, arguments='-sV -O', sudo=True)
                except Exception as e:
                    print(e.__class__, "occured trying again with get_last_output")
                    self._nm.get_nmap_last_output()
                    self._nm.scan(hosts=self.address, arguments='-sV -O', sudo=True)
        else:
            try:
                # FIXME this is just a workaround for the bug shown in python-nmap-bug.log
                self._nm.scan(hosts=self.address, arguments='-sV', sudo=False)
            except Exception as e:
                print(e.__class__, "occured trying again with get_last_output")
                self._nm.get_nmap_last_output()
                self._nm.scan(hosts=self.address, arguments='-sV', sudo=False)

        hosts = self._nm.all_hosts()
        if hosts:
            self.host = hosts[0]
        else:
            self.host = None
            raise ScanFailure("Requested host not available")

        # TODO error on connection refused, check if self._nm[self.host]['status']['reason'] = conn_refused
        # TODO also add -Pn option?

    @property
    def os(self):
        if self.scan_os and self.host and 'osmatch' in self._nm[self.host]:
            if self._nm[self.host]['osmatch'] and self._nm[self.host]['osmatch'][0]['osclass']:
                return "OS: " + self._nm[self.host]['osmatch'][0]['osclass'][0]['osfamily']

    @property
    def ip(self):
        return self._nm[self.host]['addresses']['ipv4']

    def has_tcp(self, port_number):
        return self._nm[self.host].has_tcp(port_number)

    def get_service_port(self, service_name, protocol):

        if protocol not in self._nm[self.host]:
            return None

        for port, attributes in self._nm[self.host][protocol].items():
            if attributes['name'] == service_name:
                return port


class ScanFailure(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'ScanFailure exception ' + self.value
