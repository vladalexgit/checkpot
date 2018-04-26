from honeypot import Honeypot
from tests.test_results import TestResult


class Test:

    result = TestResult.UNKNOWN
    report = "This test did not provide a report of it's findings"

    def __init__(self, target_honeypot):
        assert isinstance(target_honeypot, Honeypot)  # for safety and autocomplete
        self.target_honeypot = target_honeypot

    def describe(self):
        return "No description defined for this test"

    def run(self):
        pass

    def get_results(self):
        return self.result, self.report
