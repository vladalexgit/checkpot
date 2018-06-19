import time
import sys

from containers.manager import Manager
from honeypots.honeypot import Honeypot
from tests.test import TestResult
from tests.test_platform import TestPlatform

from tests.service_implementation import HTTPTest, SMTPTest
from tests.direct_fingerprinting import DirectFingerprintTest, OSServiceCombinationTest, DefaultServiceCombinationTest,\
    DuplicateServicesCheck
from tests.default_content import DefaultWebsiteContentTest

import argv_parser


manager = Manager()


def honeypot_test(container_name, test_list, expected_results):
    """
    Starts a container and runs a list of tests against it.
    Compares results with the expected results.
    Stops the container.
    :param container_name: target container
    :param test_list: list of Test objects
    :param expected_results: correct results to compare with
    :return: boolean representing test pass/failure
    """
    assert all(isinstance(r, TestResult) for r in expected_results)

    manager.start_honeypot(container_name)

    time.sleep(10)  # TODO wait for container to start, catch some sort of signal

    hp = Honeypot(manager.get_honeypot_ip(container_name), False)

    print("Collecting data ...")
    hp.scan()

    print("Running tests ...")
    tp = TestPlatform(test_list, hp)

    tp.run_tests()

    manager.stop_honeypot(container_name)

    for i, result in enumerate(tp.results):

        tname, treport, tresult = result

        if expected_results[i] != tresult:
            print("Test ", container_name, " -> FAILED:")
            print("\ttest:", tname, " -> expected ", expected_results[i], " got ", tresult, " instead!")
            sys.exit(1)  # exit failure

    print("Test ", container_name, " -> PASSED")


def interface_test():

    parsed = argv_parser.parse(['checkpot.py', '-t', '172.17.0.2', '-O', '-p', '20-100,102'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 5, 'port_range': '20-100,102'}

    if parsed != expected:
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-t', '172.17.0.2', '-p', '20-1000'])
    expected = {'target': '172.17.0.2', 'scan_os': False, 'scan_level': 5, 'port_range': '20-1000'}

    if parsed != expected:
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-t', '172.17.0.2', '-O', '-l', '3'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 3, 'port_range': None}

    if parsed != expected:
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-O', '-t', '172.17.0.2', '-l', '3'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 3, 'port_range': None}

    if parsed != expected:
        sys.exit(1)


def main():
    """
    Entry point for the Continuous Integration tools.
    Write all tests here.
    """

    # test artillery
    honeypot_test('artillery', [DirectFingerprintTest(), DefaultServiceCombinationTest(), SMTPTest(), HTTPTest(), DuplicateServicesCheck()],
                  [TestResult.OK, TestResult.WARNING, TestResult.WARNING, TestResult.NOT_APPLICABLE, TestResult.OK])

    # test glastopf
    honeypot_test('glastopf', [DirectFingerprintTest(), SMTPTest(), HTTPTest(), DuplicateServicesCheck(), DefaultWebsiteContentTest()],
                  [TestResult.OK, TestResult.NOT_APPLICABLE, TestResult.OK, TestResult.OK, TestResult.WARNING])

    # test dionaea
    honeypot_test('dionaea', [DirectFingerprintTest(), DefaultServiceCombinationTest(), SMTPTest(), HTTPTest(), DuplicateServicesCheck()],
                  [TestResult.WARNING, TestResult.WARNING, TestResult.NOT_APPLICABLE, TestResult.OK, TestResult.WARNING])

    # test the interface
    interface_test()


if __name__ == '__main__':
    main()
