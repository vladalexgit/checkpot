from tests.test import Test, TestResult


class TestPlatform:

    def __init__(self, test_list):
        assert all(isinstance(t, Test) for t in test_list)
        self.test_list = test_list
        self.results = []

    def run_tests(self):

        for test in self.test_list:
            test.run()

        self.results = [(test.name, test.report, test.result) for test in self.test_list]

    def get_results(self):
        return self.results

    def get_stats(self):

        warnings = 0

        for tname, treport, tresult in self.results:
            if tresult == TestResult.WARNING:
                warnings += 1

        return warnings
