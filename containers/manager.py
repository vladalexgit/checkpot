import os
import docker
import docker.errors


client = docker.from_env()


def start_honeypot(name):

    # TODO make sure the user is enrolled in the docker group in the modules init

    # check if the container exists

    try:
        client.inspect_container(name)
    except docker.errors.NotFound:

        print("Container ", name, " not found, creating new container from image ...")

        try:
            client.create_container(image=name, detach=True, name=name)
        except docker.errors.NotFound:

            print("Image not found, building image for ", name, " ...")

            output = client.build(path=os.path.join(os.path.dirname(__file__), name), tag=name)

            for line in output:
                print(line)

            client.create_container(image=name, detach=True, name=name)

    else:
        print("Container ", name, " found")

    # start the container

    client.start(name)


def get_honeypot_ip(name):

    container_details = client.inspect_container(name)
    target_ip = container_details['NetworkSettings']['IPAddress']

    return target_ip


def stop_honeypot(name):
    client.stop(name)


def stop_all_honeypots():
    pass


def cleanup_honeypot(name):

    client.stop(name)
    client.remove_container(name, force=True)
    client.remove_image(name, force=True)


def cleanup_all_honeypots():
    pass
