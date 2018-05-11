import sys
import getopt

from honeypots.honeypot import Honeypot

from tests.test_platform import TestPlatform
from tests.service_implementation import HTTPTest, SMTPTest


def print_usage():
    """Prints correct command line usage of the app"""

    print("Example usage: honeydetect -t <IP> -O -l 3")


def main(argv):
    """Entry point for the main application"""

    # get command line arguments and options

    target = '127.0.0.1'
    scan_os = False
    scan_level = 5

    short_options = 't:l:O'
    long_options = ['target=', 'level=', 'osscan']

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

    # run scan

    print("Running scan on " + target + " ...")

    hp = Honeypot(target, scan_os)

    test_list = []

    print("Fingerprinting ...\n")

    if scan_level > 2:
        test_list.append(SMTPTest())
        test_list.append(HTTPTest())

    tp = TestPlatform(test_list, hp)

    tp.run_tests(verbose=True)

    ok, warnings, unknown = tp.get_stats()

    print("\nStats: OK -> ", ok, ", WARNING -> ", warnings, ", UNKNOWN -> ", unknown)


if __name__ == '__main__':
    main(sys.argv)
