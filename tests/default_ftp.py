from .test import *
import socket


class DefaultFTPBannerTest(Test):
    """Test unchanged banner for common services"""

    # FIXME FTP coming right up

    name = "Default Banner Test"

    def run(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        ports = self.target_honeypot.get_service_ports('ftp', 'tcp')

        for port in ports:

            try:
                s.connect((self.target_honeypot.ip, port))
            except socket.error as exception:
                self.set_result(TestResult.WARNING, "failed to connect to FTP server: ", exception.strerror)
                return

            recv = s.recv(1024)

            if b'220 BearTrap-ftpd Service ready' in recv:
                self.set_result(TestResult.WARNING, "Default Beartrap banner used")
                return
            else:
                self.set_result(TestResult.OK, "All banners OK")
                return