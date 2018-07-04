import sys

import argv_parser

from honeypots.honeypot import Honeypot


# TODO refine import structure
from tests.test_platform import TestPlatform
from tests.service_implementation import HTTPTest, SMTPTest
from tests.direct_fingerprinting import DirectFingerprintTest, OSServiceCombinationTest, DefaultServiceCombinationTest,\
    DuplicateServicesCheck
from tests.default_http import DefaultGlastopfWebsiteTest, DefaultGlastopfStylesheetTest
from tests.default_ftp import DefaultFTPBannerTest
from tests.default_configuration import DefaultTemplateFileTest, DefaultServiceBannerTest


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

    if options["port_range"]:
        hp.scan(port_range=options["port_range"])  # TODO restrict access to this
    else:
        hp.scan()

    # run tests

    if options["scan_level"] > 0:
        test_list.append(DirectFingerprintTest())
        if options["scan_os"]:
            test_list.append(OSServiceCombinationTest())
        test_list.append(DefaultServiceCombinationTest())
        test_list.append(DuplicateServicesCheck())
    if options["scan_level"] > 1:
        test_list.append(DefaultServiceBannerTest())
        test_list.append(DefaultGlastopfWebsiteTest())
        test_list.append(DefaultGlastopfStylesheetTest())
        test_list.append(SMTPTest())
        test_list.append(HTTPTest())
        test_list.append(DefaultFTPBannerTest())
        test_list.append(DefaultTemplateFileTest())
    if options["scan_level"] > 2:
        pass
    if options["scan_level"] > 3:
        pass
    if options["scan_level"] > 4:
        pass

    tp = TestPlatform(test_list, hp)

    tp.run_tests(verbose=True)

    ok, warnings, unknown = tp.get_stats()

    print("\nStats: OK -> ", ok, ", WARNING -> ", warnings, ", UNKNOWN -> ", unknown)


if __name__ == '__main__':
    main(sys.argv)
