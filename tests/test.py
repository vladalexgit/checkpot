from honeypots.honeypot import Honeypot

from enum import Enum


class TestResult(Enum):
    OK = 0
    WARNING = 1
    UNKNOWN = 2


class Test:

    result = TestResult.UNKNOWN

    default_report = "This test did not provide a report of it's findings"
    default_description = "No description defined for this test"
    default_name = "UnknownName"

    description = default_description
    name = default_name

    def __init__(self, target_honeypot):
        assert isinstance(target_honeypot, Honeypot)  # for safety and autocomplete
        self.result = TestResult.UNKNOWN
        self.report = self.default_report
        self.target_honeypot = target_honeypot

    def run(self):
        pass

    def get_results(self):
        return self.result, self.report

    def reset(self):
        self.result = TestResult.UNKNOWN
        self.report = self.default_report
