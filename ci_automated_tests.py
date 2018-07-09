import time
import sys

from containers.manager import Manager
from honeypots.honeypot import Honeypot
from tests.test import Test
from tests.test import TestResult
from tests.test_platform import TestPlatform

import argv_parser

from tests import *


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
    print("Testing argument parser ...")

    # TODO add tests for long options too

    parsed = argv_parser.parse(['checkpot.py', '-t', '172.17.0.2', '-O', '-p', '20-100,102'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 5, 'port_range': '20-100,102', 'fast': False}

    if parsed != expected:
        print("ERROR: parsed != expected")
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-t', '172.17.0.2', '-p', '20-1000'])
    expected = {'target': '172.17.0.2', 'scan_os': False, 'scan_level': 5, 'port_range': '20-1000', 'fast': False}

    if parsed != expected:
        print("ERROR: parsed != expected")
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-t', '172.17.0.2', '-O', '-l', '3'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 3, 'port_range': None, 'fast': False}

    if parsed != expected:
        print("ERROR: parsed != expected")
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-O', '-t', '172.17.0.2', '-l', '3', '-f'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 3, 'port_range': None, 'fast': True}

    if parsed != expected:
        print("ERROR: parsed != expected")
        sys.exit(1)

    parsed = argv_parser.parse(['checkpot.py', '-O', '-t', '172.17.0.2', '-l', '3'])
    expected = {'target': '172.17.0.2', 'scan_os': True, 'scan_level': 3, 'port_range': None, 'fast': False}

    if parsed != expected:
        print("ERROR: parsed != expected")
        sys.exit(1)

    print("OK")


def main():
    """
    Entry point for the Continuous Integration tools.
    Write all tests here.
    """

    # test amun
    honeypot_test('amun',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.WARNING,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.WARNING,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.WARNING,
                      default_ftp.DefaultFTPBannerTest(): TestResult.WARNING,
                      service_implementation.HTTPTest(): TestResult.OK,
                      default_http.DefaultWebsiteTest(): TestResult.WARNING,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.OK,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.WARNING,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.WARNING,
                      service_implementation.SMTPTest(): TestResult.OK,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.UNKNOWN,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test artillery
    honeypot_test('artillery',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.WARNING,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.OK,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.OK,
                      service_implementation.SMTPTest(): TestResult.WARNING,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.WARNING,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test beartrap
    honeypot_test('beartrap',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.WARNING,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  })

    # test conpot
    honeypot_test('conpot',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.OK,
                      default_http.DefaultWebsiteTest(): TestResult.OK,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.OK,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.WARNING
                  },
                  port_range='0-501,503-1000')

    # test cowrie
    honeypot_test('cowrie',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.WARNING,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.OK,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test dionaea
    honeypot_test('dionaea',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.WARNING,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.WARNING,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.WARNING,
                      default_ftp.DefaultFTPBannerTest(): TestResult.WARNING,
                      service_implementation.HTTPTest(): TestResult.OK,
                      default_http.DefaultWebsiteTest(): TestResult.WARNING,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.OK,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test glastopf
    honeypot_test('glastopf',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.OK,
                      default_http.DefaultWebsiteTest(): TestResult.OK,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.WARNING,
                      default_http.DefaultStylesheetTest(): TestResult.WARNING,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  })

    # test dionaea
    honeypot_test('honeypy',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.WARNING,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.WARNING,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.WARNING,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test dionaea
    honeypot_test('honeything',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.OK,
                      default_http.DefaultWebsiteTest(): TestResult.WARNING,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.OK,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  })

    # test honeytrap
    honeypot_test('honeytrap',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.WARNING,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.UNKNOWN,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test kippo
    honeypot_test('kippo',
                  {
                    direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                    direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                    direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                    default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                    service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                    default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                    default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                    default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                    default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                    default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                    service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                    default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                    old_version_bugs.KippoErrorMessageBugTest(): TestResult.OK,
                    default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test mtpot
    honeypot_test('mtpot',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.WARNING,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  })

    # test shockpot
    honeypot_test('shockpot',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.OK,
                      default_http.DefaultWebsiteTest(): TestResult.WARNING,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.OK,
                      default_http.DefaultStylesheetTest(): TestResult.OK,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.NOT_APPLICABLE,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  },
                  port_range='-')

    # test telnetlogger
    honeypot_test('telnetlogger',
                  {
                      direct_fingerprinting.DirectFingerprintTest(): TestResult.OK,
                      direct_fingerprinting.DefaultServiceCombinationTest(): TestResult.OK,
                      direct_fingerprinting.DuplicateServicesCheck(): TestResult.OK,
                      default_ftp.DefaultFTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.HTTPTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultGlastopfWebsiteTest(): TestResult.NOT_APPLICABLE,
                      default_http.DefaultStylesheetTest(): TestResult.NOT_APPLICABLE,
                      default_imap.DefaultIMAPBannerTest(): TestResult.NOT_APPLICABLE,
                      default_smtp.DefaultSMTPBannerTest(): TestResult.NOT_APPLICABLE,
                      service_implementation.SMTPTest(): TestResult.NOT_APPLICABLE,
                      default_telnet.DefaultTelnetBannerTest(): TestResult.WARNING,
                      old_version_bugs.KippoErrorMessageBugTest(): TestResult.NOT_APPLICABLE,
                      default_templates.DefaultTemplateFileTest(): TestResult.NOT_APPLICABLE
                  })

    # test the interface
    interface_test()


if __name__ == '__main__':
    main()
