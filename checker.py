import os
import sys
import docker

from honeypots.honeypot import Honeypot
from tests.test import TestResult
from test_platform import TestPlatform

from tests.http_test import HTTPTest
from tests.smtp_test import SMTPTest


def start_container(name, client):

    # TODO make sure the user is enrolled in the docker group

    # build the image
    # TODO check if image already exists first and reuse it

    output = client.build(path=os.path.join('containers', name), tag='artillery')

    for response in output:
        print(response)
        # if 'error' in response:
        #    raise Exception("Error building docker image: {}".format(response['error']))

    # create container based on image

    container = client.create_container(image='artillery', detach=True)

    # start the container

    client.start(container)

    # return the container

    return container


def get_container_ip(container, client):

    container_details = client.inspect_container(container)
    target_ip = container_details['NetworkSettings']['IPAddress']

    return target_ip


def cleanup_honeypot(name, container, client):

    client.stop(container)
    client.remove_container(container, force=True)
    client.remove_image(name, force=True)


def main():

    client = docker.from_env()

    # test artillery

    container = start_container('artillery', client)

    hp = Honeypot(get_container_ip(container, client), False)

    tp = TestPlatform([SMTPTest(hp), HTTPTest(hp)])

    tp.run_tests()

    results = tp.get_results()

    for tname, treport, tresult in results:
        print(tname, " ---> ", tresult)
        print("\t", treport)

    print(tp.get_stats())

    cleanup_honeypot('artillery', container, client)


if __name__ == '__main__':
    main()
