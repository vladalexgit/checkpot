from .test import *


class DirectFingerprintTest(Test):
    """Check if the nmap scan directly fingerprints any service as a honeypot"""

    name = "Direct Fingerprint Test"
    description = "Check if the nmap scan directly fingerprints any service as a honeypot"

    def run(self):
        """Check if the nmap scan directly fingerprints any service as a honeypot"""

        ports = self.target_honeypot.get_all_ports('tcp')

        for port in ports:
            product_description = self.target_honeypot.get_service_product('tcp', port)

            if 'honeypot' in product_description:
                self.set_result(TestResult.WARNING, "Service on port", port, "reported as honeypot directly by nmap")
                return

        self.set_result(TestResult.OK, "No service was fingerprinted directly as a honeypot by nmap")
