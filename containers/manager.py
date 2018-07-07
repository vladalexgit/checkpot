import os
import docker
import docker.errors


class Manager:
    """Facilitates working with honeypot containers"""

    def __init__(self, verbose=True, logfile=None, custom_client=None):
        """
        :param verbose: generate logs related to container operations
        :param logfile: write logs to a file
        :param custom_client: specify a custom Docker Client
        """

        if custom_client:
            assert isinstance(custom_client, docker.DockerClient)
            self._client = custom_client
        else:
            self._client = docker.APIClient()

        self._verbose = verbose
        self._logfile = logfile
        self._tag = "MANAGER"

    def _log(self, *args):
        """
        Creates a new line in the log with given description
        :param args: log description
        """
        if self._verbose:
            print(self._tag, " : ", *args)

    def build_honeypot(self, name):
        """
        Builds the required image (if it doesn't exist) and then creates a container from it
        :param name: container name
        """
        try:
            self._client.create_container(image=name, detach=True, name=name)
        except docker.errors.NotFound:

            self._log("Image not found, building image for ", name, " ...")

            container_path = os.path.join(os.path.dirname(__file__), name)

            if not os.path.exists(os.path.join(container_path, 'Dockerfile')):
                raise BuildError("Dockerfile for container ", name, "not found")

            output = self._client.build(path=os.path.join(os.path.dirname(__file__), name), tag=name)

            for line in output:
                self._log(line)

            if name != "honeypy":
                self._client.create_container(image=name, detach=True, name=name)

    def start_honeypot(self, name):
        """
        Starts the chosen container
        :param name: container name
        """

        # check if the container exists
        try:
            self._client.inspect_container(name)
        except docker.errors.NotFound:
            self._log("Container ", name, " not found, creating new container from image ...")
            try:
                self.build_honeypot(name)
            except BuildError as e:
                self._log("Build failed:", e)
                return
        else:
            self._log("Container ", name, " found")

        self._log("Starting container")

        if name == "honeypy":
            docker.from_env().containers.run(name, cap_add='NET_ADMIN', detach=True, name=name)
        else:
            self._client.start(name)

    def get_honeypot_ip(self, name):
        """
        Gets the IP address of a running container
        :param name: container name
        :return: container ip address
        """
        container_details = self._client.inspect_container(name)
        target_ip = container_details['NetworkSettings']['IPAddress']

        return target_ip

    def stop_honeypot(self, name):
        """
        Stops the chosen container
        :param name: container name
        """
        self._log("Stopping container ", name)
        self._client.stop(name)

    def stop_all_honeypots(self):
        """Stops all active containers"""
        available_honeypots = self.get_available_honeypots()

        for hp in available_honeypots:
            try:
                self.stop_honeypot(hp)
            except docker.errors.NotFound:
                print("Container", hp, "not found")
                continue

    @staticmethod
    def get_available_honeypots():
        """Returns a list with the names of all available honeypots"""
        containers_folder = os.path.dirname(os.path.abspath(__file__))
        # folders contained in this module represent the available honeypots
        # folders starting with underscore are considered hidden
        return [f.name for f in os.scandir(containers_folder) if f.is_dir() and f.name[0] != '_']

    def clean_honeypot(self, name):
        """
        Removes container and underlying image for chosen container
        :param name: container name
        """
        self._log("Cleaning container ", name)
        self._client.stop(name)
        self._client.remove_container(name, force=True)
        self._client.remove_image(name, force=True)

    def clean_all_honeypots(self):
        """
        Removes all containers and underlying images
        :return:
        """
        available_honeypots = self.get_available_honeypots()

        for hp in available_honeypots:
            try:
                self.clean_honeypot(hp)
            except docker.errors.NotFound:
                print("Container", hp, "not found")
                continue


class BuildError(Exception):
    """Raised when build fails"""

    def __init__(self, *report):
        """
        :param report: description of the error
        """
        self.value = " ".join(str(r) for r in report)

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'BuildError exception ' + self.value
