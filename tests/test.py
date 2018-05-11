from enum import Enum

from honeypots.honeypot import Honeypot


class TestResult(Enum):
    """Lists all possible results for a test"""

    OK = 0
    WARNING = 1
    UNKNOWN = 2
    NOT_APPLICABLE = 3


class Test:
    """
    Interface all Tests must extend from
    Please inspect this interface and other Tests before you write your own
    """
    default_report = "This test did not provide a report of its findings"
    default_description = "No description defined for this test"
    default_name = "UnknownName"

    description = default_description
    name = default_name
    __report = default_report
    __result = TestResult.UNKNOWN

    def __init__(self, target_honeypot=None):
        """
        Instantiate a new Test
        :param target_honeypot: optional target Honeypot (can also be set later)
        """
        self.__target_honeypot = target_honeypot
        self.reset()

    def run(self):
        """
        All tests must implement their own run() method and write docstrings for it.
        run() should never be called directly, the TestPlatform takes care of all initialisations.
        :return: this method returns nothing, however, before return set_result() should be called
        """
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
        """
        Stores the result and report of this test
        :param result: result of the test
        :param report: accurate report of findings the test has made
        """
        self.__result = result
        self.__report = " ".join(str(r) for r in report)

    def reset(self):
        """
        Resets the result and report of the test to defaults so it can be run again
        """
        self.__result = TestResult.UNKNOWN
        self.__report = self.default_report
