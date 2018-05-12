import time
import sys

from containers.manager import Manager
from honeypots.honeypot import Honeypot
from tests.test import TestResult
from tests.test_platform import TestPlatform

from tests.service_implementation import HTTPTest, SMTPTest


manager = Manager()


def run_test(container_name, test_list, expected_results):
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

    time.sleep(5)  # TODO wait for container to start, catch some sort of signal

    hp = Honeypot(manager.get_honeypot_ip(container_name), False)

    tp = TestPlatform(test_list, hp)

    tp.run_tests()

    manager.stop_honeypot(container_name)

    for i, result in enumerate(tp.results):

        tname, treport, tresult = result

        if expected_results[i] != tresult:
            print("Test ", container_name, " -> FAILED:")
            print("\t expected ", expected_results[i], " got ", tresult, " instead!")
            sys.exit(1)  # exit failure

    print("Test ", container_name, " -> PASSED")


def main():
    """
    Entry point for the Continuous Integration tools.
    Write all tests here.
    """

    # test artillery
    run_test('artillery', [SMTPTest(), HTTPTest()], [TestResult.WARNING, TestResult.NOT_APPLICABLE])

    # test glastopf
    run_test('glastopf', [SMTPTest(), HTTPTest()], [TestResult.NOT_APPLICABLE, TestResult.UNKNOWN])


if __name__ == '__main__':
    main()
