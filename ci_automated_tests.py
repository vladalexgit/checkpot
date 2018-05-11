import time

from containers.manager import Manager
from honeypots.honeypot import Honeypot
from tests.test import TestResult
from tests.test_platform import TestPlatform

from tests.service_implementation import HTTPTest, SMTPTest


manager = Manager()


def run_test(container_name, test_list, expected_results):

    assert all(isinstance(r, TestResult) for r in expected_results)

    manager.start_honeypot(container_name)

    time.sleep(5)  # TODO wait for container to start, catch some sort of signal

    hp = Honeypot(manager.get_honeypot_ip(container_name), False)

    tp = TestPlatform(test_list, hp)

    tp.run_tests()

    results = tp.get_results()

    manager.stop_honeypot(container_name)

    for i, result in enumerate(results):

        tname, treport, tresult = result

        if expected_results[i] != tresult:
            print("Test ", container_name, " -> FAILED:")
            print("\t expected ", expected_results[i], " got ", tresult, " instead!")
            return False

    print("Test ", container_name, " -> PASSED")
    return True


def main():

    # test artillery
    run_test('artillery', [SMTPTest(), HTTPTest()], [TestResult.WARNING, TestResult.NOT_APPLICABLE])

    # test glastopf
    run_test('glastopf', [SMTPTest(), HTTPTest()], [TestResult.NOT_APPLICABLE, TestResult.OK])


if __name__ == '__main__':
    main()
