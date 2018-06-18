from .test import *
from bs4 import BeautifulSoup
import urllib.request
import re
import difflib


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
            request = urllib.request.urlopen('http://' + self.target_honeypot.ip + ':' + str(port) + '/')
            content = request.read().decode(request.headers.get_content_charset())

            soup = BeautifulSoup(content, 'html.parser')

            article = soup.find('p')

            article = str(article)

            article = re.sub('</*p>', '', article)
            article = re.sub('<a.*?/a>', '---search---', article)

            items = article.split('---search---')
        except urllib.request.HTTPError:
            print('Failed to fetch homepage for site', self.target_honeypot.ip, str(port))
            return False

        try:
            request = urllib.request.urlopen('http://www.gutenberg.org/cache/epub/42671/pg42671.txt')
            book = request.read().decode(request.headers.get_content_charset())
        except urllib.request.HTTPError:
            print('failed to download project guttenberg book content')
            return False

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
            request = urllib.request.urlopen('http://' + self.target_honeypot.ip + ':' + str(port) + '/style.css')
            server_stylesheet = request.read().decode(request.headers.get_content_charset())
        except urllib.request.HTTPError:
            print('Failed to fetch stylesheet for', self.target_honeypot.ip, str(port))
            return False

        try:
            request = urllib.request.urlopen('https://raw.githubusercontent.com/mushorg/glastopf/master/glastopf/modules/handlers/emulators/data/style/style.css')
            specimen_stylesheet = request.read().decode(request.headers.get_content_charset())

        except urllib.request.HTTPError:
            print("Failed to fetch specimen stylesheet")
            return False

        similarity = difflib.SequenceMatcher(None, server_stylesheet, specimen_stylesheet)
        percent_similar = similarity.ratio()

        if percent_similar > 0.8:
            self.set_result(TestResult.WARNING, "Page stylesheet matches Glastopf " + str(percent_similar * 100) + " percent")
