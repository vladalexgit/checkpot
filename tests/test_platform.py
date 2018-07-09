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

        print("direct_fingerprinting.DirectFingerprintTest():", self.test_list[0].result)
        print("direct_fingerprinting.DefaultServiceCombinationTest():", self.test_list[1].result)
        print("direct_fingerprinting.DuplicateServicesCheck():", self.test_list[2].result)
        print("default_ftp.DefaultFTPBannerTest():", self.test_list[3].result)
        print("service_implementation.HTTPTest():", self.test_list[4].result)
        print("default_http.DefaultWebsiteTest():", self.test_list[5].result)
        print("default_http.DefaultGlastopfWebsiteTest():", self.test_list[6].result)
        print("default_http.DefaultStylesheetTest():", self.test_list[7].result)
        print("default_imap.DefaultIMAPBannerTest():", self.test_list[8].result)
        print("default_smtp.DefaultSMTPBannerTest():", self.test_list[9].result)
        print("service_implementation.SMTPTest():", self.test_list[10].result)
        print("default_telnet.DefaultTelnetBannerTest():", self.test_list[11].result)
        print("old_version_bugs.KippoErrorMessageBugTest():", self.test_list[12].result)
        print("default_templates.DefaultTemplateFileTest():", self.test_list[13].result)

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
        :return: TODO
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
