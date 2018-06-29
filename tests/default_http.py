from .test import *

from bs4 import BeautifulSoup
import urllib.request
import urllib.error
import re
import difflib


class DefaultGlastopfWebsiteTest(Test):
    name = "Default Glastopf Website Content Test"
    description = "Test unchanged source for website content"

    def run(self):
        """Check if content matches known content"""

        try:
            request = urllib.request.urlopen('http://www.gutenberg.org/files/42671/42671.txt', timeout=10)
            book = request.read().decode(request.headers.get_content_charset())
        except urllib.error.URLError:
            self.set_result(TestResult.UNKNOWN, 'failed to download gutenberg.org book content')
            return

        sites = self.target_honeypot.get_websites()

        for content in sites:

            soup = BeautifulSoup(content, 'html.parser')

            article = soup.find('p')

            article = str(article)

            article = re.sub('</*p>', '', article)
            article = re.sub('<a.*?/a>', '---search---', article)

            items = article.split('---search---')

            total_items = len(items)
            matched_items = 0

            for item in items:
                if len(item) > 15 and item.strip(' ') in book:
                    matched_items += 1

            # if more than 20 percent of the content is found
            if matched_items > 0.2 * total_items:
                self.set_result(TestResult.WARNING, "Default Glastopf content source was used")
            else:
                self.set_result(TestResult.OK, "No default content found")


class DefaultGlastopfStylesheetTest(Test):
    name = "Default Glastopf Website Stylesheet Test"
    description = "Test unchanged website stylesheet"

    def run(self):
        """Check if content matches known content"""

        try:
            request = urllib.request.urlopen('https://raw.githubusercontent.com/mushorg/glastopf/master/glastopf/modules/handlers/emulators/data/style/style.css', timeout=10)
            specimen_stylesheet = request.read().decode(request.headers.get_content_charset())

        except urllib.error.URLError:
            self.set_result(TestResult.UNKNOWN, "Failed to fetch specimen stylesheet")
            return

        css = self.target_honeypot.get_websites_css()

        for style in css:

            similarity = difflib.SequenceMatcher(None, style, specimen_stylesheet)
            percent_similar = similarity.ratio()

            if percent_similar > 0.8:
                self.set_result(TestResult.WARNING, "Page stylesheet matches Glastopf ",
                                str(percent_similar * 100), " percent")
            else:
                self.set_result(TestResult.OK, "No default content found")

