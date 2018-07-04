from .test import *
from honeypots.honeypot import ScanFailure


class DefaultTemplateFileTest(Test):

    name = "Default Template File Test"
    description = "Tests usage of default running templates"

    def run(self):
        """Check if content matches any known content"""

        target_ports = self.target_honeypot.get_service_ports('iso-tsap', 'tcp')
        target_ports += self.target_honeypot.get_service_ports('s7-comm', 'tcp')

        if not target_ports:
            self.set_result(TestResult.NOT_APPLICABLE, "iso-tsap / s7-comm service not present in scan results")

        for port in target_ports:

            try:
                info = self.target_honeypot.run_nmap_script('s7-info.nse', port)
            except ScanFailure:
                self.set_result(TestResult.UNKNOWN, "Failed to run s7-info.nse script")
                return

            parsed = info.split('\n  ')[1:]

            default1 = ['Version: 0.0', 'System Name: Technodrome',
                        'Module Type: Siemens, SIMATIC, S7-200',
                        'Serial Number: 88111222',
                        'Plant Identification: Mouser Factory',
                        'Copyright: Original Siemens Equipment']

            matched = 0

            for a, b in zip(parsed, default1):
                if a == b:
                    matched += 1

            if matched > 0:
                self.set_result(TestResult.WARNING, "Template used for s7-comm service matches default ",
                                matched/len(default1)*100, "percent")
                return

            self.set_result(TestResult.OK, "s7-comm service does not match any default configurations")


class DefaultServiceBannerTest(Test):
    name = "Default Service Banner Test"
    description = "Tests usage of default service banners"

    def run(self):
        """Check if content matches any known content"""

        # TODO split in multiple atomic tests

        known_banners = {
            b'220 DiskStation FTP server ready.\r\n': "dionaea",
            b'220 Welcome to my FTP Server\r\n': "amun",
            b'\xff\xfb\x03\xff\xfb\x01\xff\xfd\x1f\xff\xfd\x18\r\nlogin: ': "telnetlogger",
            b'\xff\xfd\x1flogin: ': "cowrie",
            b'\xff\xfb\x01\xff\xfb\x03\xff\xfc\'\xff\xfe\x01\xff\xfd\x03\xff\xfe"\xff\xfd\'\xff\xfd\x18\xff\xfe\x1f': "mtpot",
            b'\xff\xfb\x01': "mtpot",
            b'Debian GNU/Linux 7\r\nLogin: ': "honeypy",
            b'220 mail.example.com SMTP Mailserver\r\n': "amun"
        }

        target_ports = self.target_honeypot.get_service_ports('telnet', 'tcp')
        target_ports += self.target_honeypot.get_service_ports('ftp', 'tcp')
        target_ports += self.target_honeypot.get_service_ports('smtp', 'tcp')

        if not target_ports:
            self.set_result(TestResult.NOT_APPLICABLE, "No open ports found!")
            return

        for port in target_ports:

            try:
                banner = self.target_honeypot.get_banner(port, protocol='tcp')
            except ScanFailure as e:
                self.set_result(TestResult.UNKNOWN, e)
                continue

            print(banner)
            print(port)

            if banner in known_banners:
                self.set_result(TestResult.WARNING, "Default", known_banners[banner], "banner used")
                return
            else:
                self.set_result(TestResult.OK, "No default banners")
