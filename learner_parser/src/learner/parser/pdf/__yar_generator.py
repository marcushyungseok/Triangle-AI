# -*- coding: utf-8 -*-
import re
import os
from html.parser import HTMLParser
import bintrees

root_dir = "/home/learner/workspace/"
api_dir = "mlframework/js/"
mlframework_dir = "mlframework/pdftool/"

default = '''rule %s : js {
    strings:
        $ = "%s"
    condition:
        all of them
}
'''


class MyHTMLParser(HTMLParser):
    text = ''

    def handle_starttag(self, tag, attrs):
        if tag in ['br', 'p', 'tr']:
            self.text += '\r\n'

    def handle_data(self, data):
        self.text += data


# Parse html docs
distinct_result = bintrees.RBTree()

for file in os.listdir(root_dir + api_dir):
    if file.startswith("JavaScript"):
        print(file)
        with open(root_dir + api_dir + file) as doc:
            regex = r'(\w+\(\))\<\/'
            re_result = re.findall(regex, doc.read())
            print(re_result)

            for name in re_result:
                distinct_result.update({name[:-2]: 0})

# print(distinct_result)
# Generate a file for yara

with open(root_dir + mlframework_dir + 'flash.yar', 'w') as outfile:
    for apiname, _ in distinct_result.items():
        outfile.write(default % (apiname + '_', apiname))
