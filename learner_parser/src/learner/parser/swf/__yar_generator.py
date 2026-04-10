# -*- coding: utf-8 -*-
import re
import os
from html.parser import HTMLParser
import bintrees

root_dir = "/home/learner/workspace/"
flash_api_dir = "flash_api/"
mlframework_dir = "mlframework/"

default = '''rule %s : ac3 %s {
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

for file in os.listdir(root_dir + flash_api_dir):
    if file.startswith("all-index-"):
        with open(root_dir + flash_api_dir + file) as doc:
            parser = MyHTMLParser(convert_charrefs=True)
            parser.feed(doc.read())
            regex = r'\n(\w{3,}).*? — (class|Static Method|method|Event)'
            re_result = re.findall(regex, parser.text)

            for name, apitype in re_result:
                apitype = apitype.lower().replace(" ", "_")
                apitypes = distinct_result.get(name)
                if apitypes is None:
                    apitypes = [apitype]
                elif apitype not in apitypes:
                    apitypes.append(apitype)
                distinct_result.update({name: apitypes})

# print(distinct_result)
# Generate a file for yara

with open(root_dir + mlframework_dir + 'flash.yar', 'w') as outfile:
    for apiname, apitypes in distinct_result.items():
        outfile.write(default % (apiname + '_', ' '.join(apitypes), apiname))
