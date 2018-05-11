import os
import docker
import docker.errors


class Manager:

    def __init__(self, verbose=True, logfile=None, custom_client=None):

        if custom_client:
            assert isinstance(custom_client, docker.Client)
            self._client = custom_client
        else:
            self._client = docker.from_env()

        self._verbose = verbose
        self._logfile = logfile
        self._tag = "MANAGER"

        # TODO download required images?

    def log(self, *args):
            if self._verbose:
                print(self._tag, " : ", *args)

    def start_honeypot(self, name):

        # check if the container exists

        try:
            self._client.inspect_container(name)
        except docker.errors.NotFound:

            self.log("Container ", name, " not found, creating new container from image ...")

            try:
                self._client.create_container(image=name, detach=True, name=name)
            except docker.errors.NotFound:

                self.log("Image not found, building image for ", name, " ...")

                output = self._client.build(path=os.path.join(os.path.dirname(__file__), name), tag=name)

                for line in output:
                    self.log(line)

                self._client.create_container(image=name, detach=True, name=name)

        else:
            self.log("Container ", name, " found")

        self.log("Starting container")

        self._client.start(name)

    def get_honeypot_ip(self, name):

        container_details = self._client.inspect_container(name)
        target_ip = container_details['NetworkSettings']['IPAddress']

        return target_ip

    def stop_honeypot(self, name):
        self.log("Stopping container ", name)
        self._client.stop(name)

    def stop_all_honeypots(self):
        pass

    def cleanup_honeypot(self, name):
        self.log("Cleaning container ", name)
        self._client.stop(name)
        self._client.remove_container(name, force=True)
        self._client.remove_image(name, force=True)

    def cleanup_all_honeypots(self):
        pass
