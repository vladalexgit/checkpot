from honeypots.honeypot import Honeypot
from tests.smtp_test import SMTPTest
from tests.test import TestResult

from test_platform import TestPlatform


hp = Honeypot('192.168.100.117', True)

tst = SMTPTest(hp)

print(tst.describe())

tst.run()

print(tst.report)
if tst.result == TestResult.WARNING:
    print("PANIC!!!")
else:
    print("ALL OK!")

