import socket

from tests.test import Test
from tests.test import TestResult


class SMTPTest(Test):

    def describe(self):
        return "Tests SMTP service implementation"

    def run(self):

        if self.target_honeypot.has_tcp(25):
            self.check_smtp_implemented(self.target_honeypot.ip)
        else:
            custom_port = self.target_honeypot.get_service_port('smtp', 'tcp')

            if custom_port:
                self.check_smtp_implemented(self.target_honeypot.ip, custom_port)

    def check_smtp_implemented(self, server_address, port=25):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        try:
            s.connect((server_address, port))
        except socket.error as exception:
            self.report = "failed to connect to smtp server: " + exception.strerror
            self.result = TestResult.WARNING
            return

        recv = s.recv(1024)

        if recv[:3] != b'220':
            self.report = "220 response not received from smtp server"
            self.result = TestResult.WARNING
            return
        else:
            self.report = "SMTP server ok"
            self.result = TestResult.OK
            return
