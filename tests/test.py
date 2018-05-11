from enum import Enum
import string

from honeypots.honeypot import Honeypot


class TestResult(Enum):
    OK = 0
    WARNING = 1
    UNKNOWN = 2
    NOT_APPLICABLE = 3


class Test:

    default_report = "This test did not provide a report of its findings"
    default_description = "No description defined for this test"
    default_name = "UnknownName"

    description = default_description
    name = default_name
    __report = default_report
    __result = TestResult.UNKNOWN

    def __init__(self, target_honeypot=None):
        self.__target_honeypot = target_honeypot
        self.reset()

    def run(self):
        pass

    @property
    def target_honeypot(self):
        return self.__target_honeypot

    @target_honeypot.setter
    def target_honeypot(self, target_honeypot):
        assert isinstance(target_honeypot, Honeypot)
        self.reset()
        self.__target_honeypot = target_honeypot

    @property
    def result(self):
        return self.__result

    @property
    def report(self):
        return self.__report

    def set_result(self, result=TestResult.UNKNOWN, *report):

        self.__result = result
        self.__report = " ".join(str(r) for r in report)

    def get_results(self):
        return self.__result, self.__report

    def reset(self):
        self.__result = TestResult.UNKNOWN
        self.__report = self.default_report
