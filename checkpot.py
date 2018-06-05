import sys
import getopt

from honeypots.honeypot import Honeypot

from tests.test_platform import TestPlatform
from tests.service_implementation import HTTPTest, SMTPTest
from tests.direct_fingerprinting import DirectFingerprintTest, OSServiceCombinationTest, DefaultServiceCombinationTest, DuplicateServicesCheck


def print_usage():
    """Prints correct command line usage of the app"""

    print("Usage: checkpot -t <target IP> <options>")
    print("Options: ")
    print("\t-O / --os-scan -> fingerprint OS (requires sudo)")
    print("\t-l <level> / -level= <level> -> maximum scanning level (1/2/3)")
    print("\t-cp / --common-ports -> restrict the scan only to the most common ports")


def main(argv):
    """Entry point for the main application"""

    # get command line arguments and options

    target = None
    scan_os = False
    scan_level = 5
    common_ports = False

    short_options = 't:l:O:cp'
    long_options = ['target=', 'level=', 'os-scan', 'common-ports']

    try:
        options, values = getopt.getopt(argv[1:], short_options, long_options)
    except getopt.GetoptError as opt_error:
        print(opt_error)
        print_usage()
        sys.exit(2)

    for option, value in options:

        if option in ('-t', '--target'):
            target = value
        elif option in ('-O', '--osscan'):
            scan_os = True
        elif option in ('-l', '--level'):
            scan_level = int(value)
        elif option in ('-cp', '--common-ports'):
            common_ports = True

    if target is None:
        print_usage()
        sys.exit(2)

    # run scan

    print("Running scan on " + target + " ...")

    hp = Honeypot(target, scan_os)

    test_list = []

    print("Fingerprinting ...\n")

    # collect data

    if not common_ports:
        hp.scan()  # TODO restrict access to this
    else:
        hp.scan(port_range="20-25,53,80,443")

    # run tests

    if scan_level > 0:
        test_list.append(DirectFingerprintTest())
        if scan_os:
            test_list.append(OSServiceCombinationTest())
        test_list.append(DefaultServiceCombinationTest())
        test_list.append(DuplicateServicesCheck())
    if scan_level > 1:
        test_list.append(SMTPTest())
        test_list.append(HTTPTest())
    if scan_level > 2:
        pass

    tp = TestPlatform(test_list, hp)

    tp.run_tests(verbose=True)

    ok, warnings, unknown = tp.get_stats()

    print("\nStats: OK -> ", ok, ", WARNING -> ", warnings, ", UNKNOWN -> ", unknown)


if __name__ == '__main__':
    main(sys.argv)
