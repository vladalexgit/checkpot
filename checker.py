import time

from containers import manager

from honeypots.honeypot import Honeypot
from tests.test import TestResult
from test_platform import TestPlatform

from tests.http_test import HTTPTest
from tests.smtp_test import SMTPTest


# test artillery

manager.start_honeypot('artillery')

time.sleep(5)  # TODO wait for container to start, catch some sort of signal

hp = Honeypot(manager.get_honeypot_ip('artillery'), False)

tp = TestPlatform([SMTPTest(hp)])

tp.run_tests()

results = tp.get_results()

for tname, treport, tresult in results:
    if tname == "SMTP Test":
        if tresult == TestResult.WARNING:
            print("artillery -> OK")
        else:
            print("artillery -> FAIL")

            print(tname, " ---> ", tresult)
            print("\t", treport)

manager.stop_honeypot('artillery')

# test glastopf

manager.start_honeypot('glastopf')

time.sleep(5)  # TODO wait for container to start, catch some sort of signal

hp = Honeypot(manager.get_honeypot_ip('glastopf'), False)

tp = TestPlatform([HTTPTest(hp)])

tp.run_tests()

results = tp.get_results()

for tname, treport, tresult in results:
    if tname == "HTTP Test":
        if tresult == TestResult.OK:
            print("glastopf -> OK")
        else:
            print("glastopf -> FAIL")

            print(tname, " ---> ", tresult)
            print("\t", treport)

manager.stop_honeypot('glastopf')
