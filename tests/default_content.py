from .test import *

from bs4 import BeautifulSoup
import urllib.request
import re
import difflib
import socket


class DefaultWebsiteContentTest(Test):
    """Test unchanged source for website content"""

    name = "Default Website Content Test"
    description = "Test unchanged source for website content"

    def run(self):
        """Check if content matches any known content"""

        target_ports = self.target_honeypot.get_service_ports('http', 'tcp')
        target_ports += self.target_honeypot.get_service_ports('https', 'tcp')

        if target_ports:
            for port in target_ports:
                # TODO create subtest classes?

                self.check_default_glastopf_content(port)
                if self.result == TestResult.WARNING:
                    return

                self.check_default_glastopf_stylesheet(port)
                if self.result == TestResult.WARNING:
                    return

    def check_default_glastopf_content(self, port):

        try:
            request = urllib.request.urlopen('http://' + self.target_honeypot.ip + ':' + str(port) + '/', timeout=10)
            content = request.read().decode(request.headers.get_content_charset())

            soup = BeautifulSoup(content, 'html.parser')

            article = soup.find('p')

            article = str(article)

            article = re.sub('</*p>', '', article)
            article = re.sub('<a.*?/a>', '---search---', article)

            items = article.split('---search---')
        except:
            print('Failed to fetch homepage for site', self.target_honeypot.ip, str(port))
            return

        try:
            request = urllib.request.urlopen('http://www.gutenberg.org/files/42671/42671.txt', timeout=10)
            book = request.read().decode(request.headers.get_content_charset())
        except:
            print('failed to download project guttenberg book content')
            return

        total_items = len(items)
        matched_items = 0

        for item in items:
            if item.strip(' ') in book:
                matched_items += 1

        # if more than 20 percent of the content is found
        if matched_items > 0.2 * total_items:
            self.set_result(TestResult.WARNING, "Default Glastopf webpage content was used")

    def check_default_glastopf_stylesheet(self, port):
        try:
            request = urllib.request.urlopen('http://' + self.target_honeypot.ip + ':' + str(port) + '/style.css',
                                             timeout=10)
            server_stylesheet = request.read().decode(request.headers.get_content_charset())
        except:
            print('Failed to fetch stylesheet for', self.target_honeypot.ip, str(port))
            return

        try:
            request = urllib.request.urlopen('https://raw.githubusercontent.com/mushorg/glastopf/master/glastopf/modules/handlers/emulators/data/style/style.css', 10)
            specimen_stylesheet = request.read().decode(request.headers.get_content_charset())

        except:
            print("Failed to fetch specimen stylesheet")
            return

        similarity = difflib.SequenceMatcher(None, server_stylesheet, specimen_stylesheet)
        percent_similar = similarity.ratio()

        if percent_similar > 0.8:
            self.set_result(TestResult.WARNING, "Page stylesheet matches Glastopf ",
                            str(percent_similar * 100), " percent")


class DefaultBannerTest(Test):
    """Test unchanged banner for common services"""

    name = "Default Banner Test"

    def run(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        ports = self.target_honeypot.get_service_ports('ftp', 'tcp')

        for port in ports:

            try:
                s.connect((self.target_honeypot.ip, port))
            except socket.error as exception:
                self.set_result(TestResult.WARNING, "failed to connect to FTP server: ", exception.strerror)
                return

            recv = s.recv(1024)

            if b'220 BearTrap-ftpd Service ready' in recv:
                self.set_result(TestResult.WARNING, "Default Beartrap banner used")
                return
            else:
                self.set_result(TestResult.OK, "All banners OK")
                return
