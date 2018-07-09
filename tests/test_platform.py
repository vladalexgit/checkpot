from .test import Test, TestResult
from honeypots.honeypot import Honeypot


class TestPlatform:
    """
    Holds a list of Tests and a reference to a Honeypot
    Runs the list of tests on the Honeypot and generates statistics based on the results
    """
    def __init__(self, test_list, target_honeypot):
        """
        :param test_list: list of Test objects
        :param target_honeypot: Honeypot object to run Tests against
        """
        assert isinstance(target_honeypot, Honeypot)  # for safety and autocomplete
        assert all(isinstance(t, Test) for t in test_list)

        self.test_list = test_list
        self.__results = []
        self.target_honeypot = target_honeypot

    def run_tests(self, verbose=False):
        """
        Runs the list of tests on the target Honeypot
        :param verbose: print results of each test
        """
        for test in self.test_list:

            test.target_honeypot = self.target_honeypot

            test.run()

            if verbose:
                print(test.name, " ---> ", test.result)
                print("\t", test.report)

        self.__results = [(test.name, test.report, test.result) for test in self.test_list]

    @property
    def results(self):
        """
        Returns the results of each test
        :return: list of tuples like (Test Name, Test Report, Test Result)
        """
        return self.__results

    def get_stats(self):
        """
        Calculates statistics based on the last scan
        :return: tuple containing number of ok, warnings, unknown
        """
        ok = 0
        warnings = 0
        unknown = 0

        for tname, treport, tresult in self.__results:
            if tresult == TestResult.WARNING:
                warnings += 1
            elif tresult == TestResult.OK:
                ok += 1
            elif tresult == TestResult.UNKNOWN:
                unknown += 1

        return ok, warnings, unknown
