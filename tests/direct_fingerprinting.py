from .test import *


class DirectFingerprintTest(Test):
    """Check if the nmap scan directly fingerprints any service as a honeypot"""

    name = "Direct Fingerprint Test"
    description = "Check if the nmap scan directly fingerprints any service as a honeypot"

    def run(self):
        """Check if the nmap scan directly fingerprints any service as a honeypot"""

        ports = self.target_honeypot.get_all_ports('tcp')

        if ports is None:
            self.set_result(TestResult.UNKNOWN, "Port request returned None")
            return

        for port in ports:
            product_description = self.target_honeypot.get_service_product('tcp', port)

            if 'honeypot' in product_description.lower():
                self.set_result(TestResult.WARNING, "Service on port", port, "reported as honeypot directly by nmap")
                return

        self.set_result(TestResult.OK, "No service was fingerprinted directly as a honeypot by nmap")


class OSServiceCombinationTest(Test):
    """Check if the OS and running services combination makes sense"""
    # TODO make a high interaction version of this test in level 2?

    name = "OS Service combination test"
    description = "Check if the OS and running services combination makes sense"

    windows_exclusive = ['ms-sql', 'iis', 'windows', 'microsoft']
    linux_exclusive = []

    def run(self):
        """Check if the OS and running services combination makes sense"""

        os = self.target_honeypot.os

        ports = self.target_honeypot.get_all_ports('tcp')

        if ports is None:
            self.set_result(TestResult.UNKNOWN, "Port request returned None")
            return

        if os is None:
            self.set_result(TestResult.UNKNOWN, "Failed to retrieve OS")
            return

        if os.lower() == 'linux':
            for port in ports:
                product_description = self.target_honeypot.get_service_product('tcp', port)

                for s in self.windows_exclusive:
                    if s in product_description.lower():
                        self.set_result(TestResult.WARNING, "Linux machine is running", product_description)
                        return

        elif os.lower() == 'windows':
            for port in ports:
                product_description = self.target_honeypot.get_service_product('tcp', port)

                for s in self.linux_exclusive:
                    if s in product_description.lower():
                        self.set_result(TestResult.WARNING, "Windows machine is running", product_description)
                        return

        self.set_result(TestResult.OK, "Combination OK")


class DefaultServiceCombinationTest(Test):
    """Check if the running services combination is the default configuration for popular Honeypots"""

    name = "Default Service Combination Test"
    description = "Check if the running services combination is the default configuration for popular Honeypots"

    # currently known honeypot configurations
    # this only makes sense for honeypots with many open ports

    # TODO update this ASAP
    default_ports = {"artillery": [21, 22, 25, 53, 110, 1433, 1723, 5800, 5900, 8080, 10000, 16993, 44443],
                     "dionaea": [21, 42, 80, 135, 443, 445, 1433, 1723, 3306, 5060, 5061]
                     }

    # Any percent above this threshold will be shown as a warning
    threshold = 70

    def run(self):
        """Check if the running services combination is the default configuration for popular Honeypots"""

        results = {}

        target_ports = self.target_honeypot.get_all_ports('tcp')
        target_ports += self.target_honeypot.get_all_ports('udp')
        print(target_ports)  # TODO
        # return

        if not target_ports:
            self.set_result(TestResult.NOT_APPLICABLE, "No open ports found")

        for honeypot_name in self.default_ports:
            # go through all known configurations and compare with current configuration

            found = 0

            for p in target_ports:
                if p in self.default_ports[honeypot_name]:
                    found += 1

            # compute similarity percent with known configuration
            percent_similar = found / len(self.default_ports[honeypot_name]) * 100

            if percent_similar > self.threshold:
                results[honeypot_name] = percent_similar

        if results:  # if results dict is not empty
            self.set_result(TestResult.WARNING, "Target port configuration is similar to:", results)
        else:
            self.set_result(TestResult.OK, "Target port configuration is below",
                            self.threshold, "percent similar to all known popular honeypots")


class DuplicateServicesCheck(Test):
    """Check if the machine is running duplicate services"""

    name = "Duplicate Services Check"
    description = "Check if the machine is running duplicate services"

    def run(self):
        """Check if the machine is running duplicate services"""

        ports = self.target_honeypot.get_all_ports('tcp')

        service_names = {}

        for port in ports:

            name = self.target_honeypot.get_service_name(port, 'tcp')

            if name in service_names:
                service_names[name].append(port)
            else:
                service_names[name] = [port]

        report = ""

        for service, assigned_ports in service_names.items():
            if len(assigned_ports) > 1:
                report += service + "->" + str(assigned_ports) + " "

        if report:
            self.set_result(TestResult.WARNING, "The following services run on multiple ports:", report)
        else:
            self.set_result(TestResult.OK, "No duplicate services found")
