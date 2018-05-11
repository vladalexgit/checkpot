import socket

from .test import *


class SMTPTest(Test):

    name = "SMTP Test"
    description = "Tests SMTP service implementation"

    def run(self):

        if self.target_honeypot.has_tcp(25):
            self.check_smtp_implemented(self.target_honeypot.ip)
        else:
            custom_port = self.target_honeypot.get_service_port('smtp', 'tcp')

            if custom_port:
                self.check_smtp_implemented(self.target_honeypot.ip, custom_port)
            else:
                self.set_result(TestResult.NOT_APPLICABLE, "Service not present")

    def check_smtp_implemented(self, server_address, port=25):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        try:
            s.connect((server_address, port))
        except socket.error as exception:
            self.set_result(TestResult.WARNING, "failed to connect to smtp server: ", exception.strerror)
            return

        recv = s.recv(1024)

        if recv[:3] != b'220':
            self.set_result(TestResult.WARNING, "220 response not received from smtp server")
            return
        else:
            self.set_result(TestResult.OK, "SMTP server OK")
            return


class HTTPTest(Test):

    name = "HTTP Test"
    description = "Tests HTTP service implementation"

    def run(self):

        if self.target_honeypot.has_tcp(80):
            self.check_http_implemented(self.target_honeypot.ip)
        else:
            custom_port = self.target_honeypot.get_service_port('http', 'tcp')

            if custom_port:
                self.check_http_implemented(self.target_honeypot.ip, custom_port)
            else:
                self.set_result(TestResult.NOT_APPLICABLE, "Service not present")

    def check_http_implemented(self, server_address, port=80):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        try:
            s.connect((server_address, port))
        except socket.error as exception:
            self.set_result(TestResult.WARNING, "failed to connect to http server: ", exception.strerror)
            return

        try:
            s.sendall(b'GET / HTTP/1.1\r\n\r\n')  # s.sendall(b'HEAD / HTTP/1.1\r\n\r\n')
        except socket.error as exception:
            self.set_result(TestResult.WARNING, "sending GET request to http server failed: ", exception.strerror)
            return

        recv = s.recv(4096)

        if recv[:15] == b'HTTP/1.1 200 OK':
            self.set_result(TestResult.OK, "http service responded with 200/OK")
            return
        else:
            self.set_result(TestResult.WARNING, "http service responded with unknown sequence: ", recv[:15])
            return
