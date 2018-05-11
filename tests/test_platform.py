from .test import Test, TestResult
from honeypots.honeypot import Honeypot


class TestPlatform:

    def __init__(self, test_list, target_honeypot):

        assert isinstance(target_honeypot, Honeypot)  # for safety and autocomplete
        assert all(isinstance(t, Test) for t in test_list)

        self.test_list = test_list
        self.__results = []
        self.target_honeypot = target_honeypot

    def run_tests(self, verbose=False):

        for test in self.test_list:

            test.target_honeypot = self.target_honeypot

            test.run()

            if verbose:
                print(test.name, " ---> ", test.result)
                print("\t", test.report)

        self.__results = [(test.name, test.report, test.result) for test in self.test_list]

    @property
    def results(self):
        return self.__results

    def get_stats(self):

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
