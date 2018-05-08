import sys
import getopt

from honeypots.honeypot import Honeypot
from tests.test import TestResult
from test_platform import TestPlatform

from tests.smtp_test import SMTPTest
from tests.http_test import HTTPTest


def print_usage():
    # TODO elaborate this
    print("Example usage: honeydetect -t <IP> -O -l 3")


def main(argv):

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
            scan_level = value

    # run nmap scan

    print("Running scan on " + target + " ...")

    hp = Honeypot(target, scan_os)

    test_list = []

    print("Fingerprinting ...\n")

    if scan_level > 2:
        test_list.append(SMTPTest(hp))
        test_list.append(HTTPTest(hp))

    tp = TestPlatform(test_list)

    tp.run_tests()

    results = tp.get_results()

    for tname, treport, tresult in results:
        print(tname, " ---> ", tresult)
        print("\t", treport)

    print(tp.get_stats())


if __name__ == '__main__':
    main(sys.argv)
