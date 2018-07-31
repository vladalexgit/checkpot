import sys

import argv_parser
from honeypots.honeypot import Honeypot, ScanFailure
from tests.test_platform import TestPlatform

from tests import *


def main(argv):
    """Entry point for the main application"""

    options = argv_parser.parse(argv)

    if options is None:
        sys.exit(2)

    # run scan

    print("Running scan on " + options["target"])

    hp = Honeypot(options["target"], options["scan_os"])

    test_list = []

    print("Scanning ports ...\n")

    # collect data

    try:
        if options["port_range"]:
            hp.scan(port_range=options["port_range"], fast=options["fast"])  # TODO restrict access to this?
        else:
            hp.scan()
    except ScanFailure as e:
        print("Scan failed: " + str(e))
        sys.exit(1)

    # run tests

    if options["scan_level"] > 0:

        test_list.append(direct_fingerprinting.DirectFingerprintTest())

        if options["scan_os"]:
            test_list.append(direct_fingerprinting.OSServiceCombinationTest())

        test_list.append(direct_fingerprinting.DefaultServiceCombinationTest())
        test_list.append(direct_fingerprinting.DuplicateServicesCheck())

    if options["scan_level"] > 1:
        test_list.append(default_ftp.DefaultFTPBannerTest())

        test_list.append(service_implementation.HTTPTest())
        test_list.append(default_http.DefaultWebsiteTest())
        test_list.append(default_http.DefaultGlastopfWebsiteTest())
        test_list.append(default_http.DefaultStylesheetTest())
        test_list.append(default_http.CertificateValidationTest())

        test_list.append(default_imap.DefaultIMAPBannerTest())

        test_list.append(default_smtp.DefaultSMTPBannerTest())
        test_list.append(service_implementation.SMTPTest())

        test_list.append(default_telnet.DefaultTelnetBannerTest())
        test_list.append(old_version_bugs.KippoErrorMessageBugTest())

        test_list.append(default_templates.DefaultTemplateFileTest())

    if options["scan_level"] > 2:
        pass
    if options["scan_level"] > 3:
        pass
    if options["scan_level"] > 4:
        pass

    tp = TestPlatform(test_list, hp)

    tp.run_tests(verbose=True)


if __name__ == '__main__':
    main(sys.argv)
