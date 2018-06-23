import time
import sys

from containers.manager import Manager
from honeypots.honeypot import Honeypot
from tests.test import Test
from tests.test import TestResult
from tests.test_platform import TestPlatform

from tests.service_implementation import HTTPTest, SMTPTest
from tests.direct_fingerprinting import DirectFingerprintTest, OSServiceCombinationTest, DefaultServiceCombinationTest, \
    DuplicateServicesCheck
from tests.default_content import DefaultWebsiteContentTest, DefaultBannerTest
from tests.default_configuration import DefaultTemplateFileTest

import argv_parser

manager = Manager()


def honeypot_test(container_name, tests, port_range=None):
    """
    Starts a container and runs a list of tests against it.
    Compares results with the expected results.
    Stops the container.
    :param container_name: target container
    :param tests: dict of Test objects and expected TestResult pairs
    :param port_range: specify a custom port range for scan (e.g '20-100')
    :return: boolean representing test pass/failure
    """

    test_list = [key for key in tests]
    expected_results = [tests[key] for key in tests]

    assert all(isinstance(test, Test) for test in test_list)
    assert all(isinstance(result, TestResult) for result in expected_results)

    manager.start_honeypot(container_name)

    time.sleep(10)  # TODO wait for container to start, catch some sort of signal

    hp = Honeypot(manager.get_honeypot_ip(container_name), False)

    print("Collecting data ...")
    if port_range:
        hp.scan(port_range)
    else:
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
    honeypot_test('artillery', {DirectFingerprintTest(): TestResult.OK,
                                DefaultServiceCombinationTest(): TestResult.WARNING,
                                SMTPTest(): TestResult.WARNING,
                                HTTPTest(): TestResult.NOT_APPLICABLE,
                                DuplicateServicesCheck(): TestResult.OK})

    # test glastopf
    honeypot_test('glastopf', {DirectFingerprintTest(): TestResult.OK,
                               DefaultServiceCombinationTest(): TestResult.OK,
                               SMTPTest(): TestResult.NOT_APPLICABLE,
                               HTTPTest(): TestResult.OK,
                               DuplicateServicesCheck(): TestResult.OK,
                               DefaultWebsiteContentTest(): TestResult.WARNING})

    # test dionaea
    honeypot_test('dionaea', {DirectFingerprintTest(): TestResult.WARNING,
                              DefaultServiceCombinationTest(): TestResult.WARNING,
                              SMTPTest(): TestResult.NOT_APPLICABLE,
                              HTTPTest(): TestResult.OK,
                              DuplicateServicesCheck(): TestResult.WARNING})

    # test beartrap
    honeypot_test('beartrap', {DirectFingerprintTest(): TestResult.OK,
                               DefaultServiceCombinationTest(): TestResult.OK,
                               DuplicateServicesCheck(): TestResult.OK,
                               DefaultWebsiteContentTest(): TestResult.UNKNOWN,
                               SMTPTest(): TestResult.NOT_APPLICABLE,
                               HTTPTest(): TestResult.NOT_APPLICABLE,
                               DefaultBannerTest(): TestResult.WARNING,
                               DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE})

    # test conpot
    honeypot_test('conpot',
                  {DirectFingerprintTest(): TestResult.OK,
                   DefaultServiceCombinationTest(): TestResult.OK,
                   DuplicateServicesCheck(): TestResult.OK,
                   DefaultWebsiteContentTest(): TestResult.UNKNOWN,
                   SMTPTest(): TestResult.NOT_APPLICABLE,
                   HTTPTest(): TestResult.WARNING,
                   DefaultBannerTest(): TestResult.UNKNOWN,
                   DefaultTemplateFileTest(): TestResult.WARNING},
                  port_range='0-1000')

    # test the interface
    interface_test()


if __name__ == '__main__':
    main()
