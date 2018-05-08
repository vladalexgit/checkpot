import socket

from .test import *


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

    def check_http_implemented(self, server_address, port=80):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        try:
            s.connect((server_address, port))
        except socket.error as exception:
            self.report = "failed to connect to http server: " + exception.strerror
            self.result = TestResult.WARNING
            return

        try:
            s.sendall(b'GET / HTTP/1.1\r\n\r\n')  # s.sendall(b'HEAD / HTTP/1.1\r\n\r\n')
        except socket.error as exception:
            self.report = "sending GET request to http server failed: " + exception.strerror
            self.result = TestResult.WARNING
            return

        recv = s.recv(4096)
        # print(recv)

        if recv[:15] == b'HTTP/1.1 200 OK':
            self.report = "http service responded with 200/OK"
            self.result = TestResult.OK
            return
        else:
            self.report = "http service responded with unknown sequence: " + recv[:15]
            self.result = TestResult.WARNING
            return
