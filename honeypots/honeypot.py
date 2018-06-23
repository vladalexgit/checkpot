import nmap
import platform


class Honeypot:
    """
    Holds all data known about one Honeypot.
    Used for decoupling the acquisition of the data from its usages.
    """

    def __init__(self, address, scan_os=False):
        """
        :param address: ip address of the target
        :param scan_os: scan for Operating System information (requires elevated privileges)
        """
        self.address = address
        self.scan_os = scan_os
        self.host = None
        self._nm = nmap.PortScanner()

    def scan(self, port_range=None):
        """
        Runs a scan on this Honeypot for data acquisition.
        """
        args = '-sV'

        if port_range:
            args += ' -p '+port_range

        if self.scan_os:

            args += ' -O'

            if platform.system() == 'Windows':
                # No sudo on Windows systems, let UAC handle this
                # FIXME workaround for the subnet python-nmap-bug.log also?
                self._nm.scan(hosts=self.address, arguments=args, sudo=False)
            else:
                try:
                    # FIXME this is just a workaround for the bug shown in python-nmap-bug.log
                    self._nm.scan(hosts=self.address, arguments=args, sudo=True)
                except Exception as e:
                    print(e.__class__, "occured trying again with get_last_output")
                    self._nm.get_nmap_last_output()
                    self._nm.scan(hosts=self.address, arguments=args, sudo=True)
        else:
            try:
                # FIXME this is just a workaround for the bug shown in python-nmap-bug.log
                self._nm.scan(hosts=self.address, arguments=args, sudo=False)
            except Exception as e:
                print(e.__class__, "occured trying again with get_last_output")
                self._nm.get_nmap_last_output()
                self._nm.scan(hosts=self.address, arguments=args, sudo=False)

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
                return self._nm[self.host]['osmatch'][0]['osclass'][0]['osfamily']

    @property
    def ip(self):
        return self._nm[self.host]['addresses']['ipv4']

    def has_tcp(self, port_number):
        """
        Checks if the Honeypot has a certain port open.
        :param port_number: port number
        :return: port status boolean
        """
        return self._nm[self.host].has_tcp(port_number)

    def get_service_ports(self, service_name, protocol):
        """
        Checks if the Honeypot has a certain service available.
        :param service_name: name of the service to search for
        :param protocol: 'tcp' or 'udp'
        :return: list of port numbers
        """
        results = []

        # TODO a certain service can run on multiple ports, convert the output to a list
        if protocol not in self._nm[self.host]:
            return results

        for port, attributes in self._nm[self.host][protocol].items():
            if attributes['name'] == service_name:
                results.append(port)

        return results

    def get_service_name(self, port, protocol):
        """
        Get name of service running on requested port
        :param port: target port
        :param protocol: 'tcp' or 'udp'
        :return: service name
        """
        if protocol not in self._nm[self.host]:
            return None

        return self._nm[self.host][protocol][port]["name"]

    def get_all_ports(self, protocol):
        """
        Returns all open ports on the honeypot
        :param protocol: 'tcp' / 'udp'
        :return: list of ports
        """
        if protocol not in self._nm[self.host]:
            return None
        else:
            return list((self._nm[self.host][protocol]).keys())

    def get_service_product(self, protocol, port):
        """
        Get the product description for a certain port
        :param protocol: 'tcp' / 'udp'
        :param port: port number
        :return: description string
        """
        # TODO cache requests for all parsers
        if protocol not in self._nm[self.host]:
            return None
        else:
            return self._nm[self.host][protocol][port]['product']

    def run_nmap_script(self, script, port, protocol='tcp'):

        tmp = nmap.PortScanner()
        tmp.scan(hosts=self.address, arguments="--script " + script + " -p " + str(port))

        port_info = tmp[self.address][protocol][int(port)]

        if 'script' in port_info:
            return port_info['script'][script.split('.')[0]]
        else:
            raise ScanFailure("Script execution failed")


class ScanFailure(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'ScanFailure exception ' + self.value
