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

        # if int(self._nm.scanstats()['uphosts']) is 0:
        #     print("No destination host reachable")
        #     # TODO also add -Pn option?
        #     sys.exit(0)

        # TODO error on connection refused, check if nm[self.host]['status'][reason] = conn_refused

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
