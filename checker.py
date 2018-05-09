import time

from containers import manager

from honeypots.honeypot import Honeypot
from tests.test import TestResult
from test_platform import TestPlatform

from tests.http_test import HTTPTest
from tests.smtp_test import SMTPTest

# test artillery

manager.start_honeypot('artillery')

time.sleep(10)

hp = Honeypot(manager.get_honeypot_ip('artillery'), False)

tp = TestPlatform([SMTPTest(hp), HTTPTest(hp)])

tp.run_tests()

results = tp.get_results()

for tname, treport, tresult in results:
    print(tname, " ---> ", tresult)
    print("\t", treport)

print(tp.get_stats())
