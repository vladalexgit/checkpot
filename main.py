from honeypot import Honeypot
from tests.smtp_test import SMTPTest
from tests.test_results import TestResult

hp = Honeypot('192.168.100.117', False)

tst = SMTPTest(hp)

print(tst.describe())

tst.run()

print(tst.report)
if tst.result == TestResult.WARNING:
    print("PANIC!!!")
else:
    print("ALL OK!")

