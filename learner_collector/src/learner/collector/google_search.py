# -*- coding: utf-8 -*-
'''**Python3 wrapper of Google Custom Search Engine**

How to use:
    1. Create Custom Search Engine and check Engine ID at\
        "https://cse.google.com/cse/all"
    2. Generate API key at "https://console.cloud.google.com/home/dashboard"
    3. Create an instance of GoogleCustomSearchEngine() with Engine ID and API\
        key
    4. Search contents by search() method

.. note:: The following bugs can be reproduced in Google Advanced Search.

    1. The 'lr' and 'date Restrict' parameters must be set in order to get\
        the desired file type without a search string.
    2. Search results are not displayed according to the specified file type.\
        You must check additional MIME type. (For example, when you search\
        with "filetype: pdf", you can see also search results with pdfs\
        as well as html pages)
'''
# Default packages
import re
import time
import json
import logging
import requests
import urllib.parse

logger = logging.getLogger(__name__)

GOOGLE_CSE_GET_URL = 'https://www.googleapis.com/customsearch/v1?'


def download(url):
    response = requests.get(url, timeout=3)
    try:
        response.raise_for_status()
    except Exception as e:
        logger.warn(str(e))
    try:
        file_name = re.findall('filename=(?=\w+\.\w{3,4}$).+',
                               response.headers['content-disposition'])[0]
    except:
        # 다운받는 파일이 웹페이지일 경우 content-disposition 헤더가 존재하지 않음
        matched = re.findall('(?=\w+\.\w{3,4}$).+', response.url)
        if len(matched) > 0:
            file_name = matched[0]
        else:
            file_name = response.url

    return response.url, file_name, response.content


class GoogleCustomSearchEngine:
    '''**Provides the ability to search via "Google Custom Search Engine".**

    :param str api_key: API key received from
            "https://console.cloud.google.com/home/dashboard"
    :param int custom_search_engine_id: Engine ID received from
            "https://cse.google.co.kr/cse/all"
    '''
    def __init__(self, cse_id, api_keys):
        self.cse_id = cse_id
        self.api_keys = api_keys
        self.key_idx = 0
        self.allowed_mime_type = None

    def mime_filter(self, allowed_mime_type):
        self.allowed_mime_type = allowed_mime_type

    def search(self, keyword, **params):
        '''Search for keywords. Also, you can use "Advanced search"
        with given params.

        :param str keyword:
        :param dict params:
            dataRestrict (str): e.g. Search range restriction within one year
            ("d[365]", "w[52]", "m[12]", "y[1]")

            fileType (str): Restriction of file type ("doc", "ppt", "swf" etc.)
            gl (str): Two letter contry code ("KR", "CN", "JP" etc.)

            filter (str): Duplicate content prevention mode ("1", "0")
            safe (str): Level of safe browsing ("high", "medium", "off")

            Refer to `<https://developers.google.com/custom-search/json-api/v1/
            reference/cse/list>`_ for details.

        :return: A generator of dict {url(str), cur_idx(int), total_idx(int)}
        :raises HTTPError: HTTP Status code
        '''
        prev_urls = [None] * 10  # An array for checking duplicate previous URL
        build_params = {'key': self.api_keys[self.key_idx],
                        'cx': self.cse_id,
                        'q': keyword, 'filter': '1', 'safe': 'high',
                        'lr': 'lang_en', 'num': 10}
        build_params.update(params)

        # Request a page and loop until the end of the search result is reached
        total_idx, cur_idx = 0, 1
        while 0 < cur_idx <= 91:

            build_params.update({'start': cur_idx})
            encoded_params = urllib.parse.urlencode(build_params)
            logger.debug(' [CSE REQUEST] ' +
                         GOOGLE_CSE_GET_URL + encoded_params)
            response = requests.get(GOOGLE_CSE_GET_URL + encoded_params)
            try:
                response.raise_for_status()
            except Exception as e:
                time.sleep(5)
                self.key_idx = ((self.key_idx + 1) %
                                len(self.api_keys))
                logger.warn(' [API KEY CHANGED]\n' +
                            '\tError Message: %s\n' % str(e) +
                            '\tResponse: %s' % response.content)
                print(e)
                build_params.update(
                    {'key': self.api_keys[self.key_idx],
                     'cx': self.cse_id})
                continue
            json_content = response.content.decode(errors='backslashreplace')
            content = json.loads(json_content)
            logger.debug(' [CSE RESPONSE] ' + str(content))
            # Total number of results
            if 'searchInformation' in content:
                if 'totalResults' in content['searchInformation']:
                    total_idx = content['searchInformation']['totalResults']

            # Return result after checking link redundancy
            if 'items' in content:
                for item in content['items']:
                    # If it is not a previously searched URL
                    if not (item['link'] in prev_urls):
                        if self.allowed_mime_type is not None:
                            if 'mime' not in item:
                                logger.info(
                                    ' [CSE] Mime type is empty.(link:%s)'
                                    % item['link'])
                                continue
                            if item['mime'] != self.allowed_mime_type:
                                logger.info(
                                    ' [CSE] %s mime is not allowed.(link:%s)'
                                    % (item['mime'], item['link']))
                                continue
                        # TODO: mime type is correct, but file is type of html.
                        # but, the file contains link of mime type format file
                        yield {'url': item['link'],
                               'cur_idx': cur_idx, 'total_idx': total_idx}

                        prev_urls[cur_idx % len(prev_urls)] = item['link']

                    cur_idx += 1

            # Get the starting point index of the next search results page
            if 'queries' in content:
                if 'nextPage' in content['queries']:
                    nextpageinfo = content['queries']['nextPage']
                    if len(nextpageinfo) > 0:
                        if 'startIndex' in nextpageinfo[0]:
                            cur_idx = nextpageinfo[0]['startIndex']
                            continue
            return


# #### DEMO CODE #### #
if __name__ == '__main__':
    import sys
    import string
    from random import shuffle
    import learner.util as util

    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    CSE_ID = '018040515958341447856:uxuuw7frxgw'
    API_KEYS = ['AIzaSyCQjKxaV0DgU341B7PFAISOqS0fvjqtQ94',
                ]
    cse = GoogleCustomSearchEngine(CSE_ID, API_KEYS)
    cse.mime_filter('application/pdf')

    letters = list(string.ascii_lowercase + string.digits + ' ')
    shuffle(letters)
    for letter in letters:
        for result in cse.search(letter, fileType='pdf', gl='US', lr='lang_en',
                                 dateRestrict='', safe='high',
                                 sort='date:r:20100601:20160923'):
            try:
                redirected_url, file_name, mem_file = download(result['url'])

                # Tempo code for downloading PDF
                if not mem_file.startswith(b'%PDF'):
                    continue
                #####

                hashes = util.essential.cal_hashes(mem_file)

                util.essential.save_file_on_local(
                    mem_file, '/home/learner/pdfs/benign_tmp/'+hashes['md5'])
            except:
                pass
