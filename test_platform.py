from honeypots.honeypot import Honeypot
from tests.test import Test, TestResult


class TestPlatform:

    def __init__(self, test_list):
        assert all(isinstance(t, Test) for t in test_list)
        self.test_list = test_list

    @@property
    def test_list(self):
        return self.test_list

    @test_list.setter
    def test_list(self, test_list):
        self.test_list = test_list

    def run_tests(self):

        for test in self.test_list:
            test.run()

