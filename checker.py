import docker

from honeypots.honeypot import Honeypot
from tests.test import TestResult
from test_platform import TestPlatform
from tests.smtp_test import SMTPTest
from tests.http_test import HTTPTest

client = docker.from_env()

# TODO make sure the user is enrolled in the docker group

# build the images

# TODO check if image already exists first and reuse it
output = client.build(path='continuous_integration/containers/artillery', tag='artillery')

# create containers based on images

container = client.create_container(image='artillery', detach=True)

# start the containers

client.start(container)

# run the tests

container_details = client.inspect_container(container)
target_ip = container_details['NetworkSettings']['IPAddress']

print(target_ip)

# run the scan

hp = Honeypot(target_ip, False)

test_list = []

print("Fingerprinting ...\n")

test_list.append(SMTPTest(hp))
test_list.append(HTTPTest(hp))

tp = TestPlatform(test_list)

tp.run_tests()

results = tp.get_results()

for tname, treport, tresult in results:
    print(tname, " ---> ", tresult)
    print("\t", treport)

print(tp.get_stats())


client.stop(container)
