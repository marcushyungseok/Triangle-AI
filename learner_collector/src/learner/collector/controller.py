# -*- coding: utf-8 -*-
'''
**A supervisor of file collector**

Since socket communication has many unstable factors, the child process
actually collects the files, and the parent process creates and monitors
the child processes. The parent process kills and regenerates when the child
process is slower or unresponsive.
'''
# Default packages
import time
import hashlib
import logging
import datetime
import multiprocessing as mp

# 3rd-party packages
import requests
from tzlocal import get_localzone

# Internal packages
import learner.collector.google_search as gs

logger = logging.getLogger(__name__)

# API_KEY = 'AIzaSyD2aGx1IiNbSt7ZDzjOz9Y2UBjyzudUCcE'
# SEARCH_ENGINE_ID = '018040515958341447856:uxuuw7frxgw'
API_KEY = 'AIzaSyBaZL_csvq1Zngg4rKxGxDt38OBrL7vmxg'
SEARCH_ENGINE_ID = '012805881847079181811:kfaqqgq0kgs'
DOWNLOAD_DIR = ''


def collector_proc(url_to_receive, cse_params, allowed_mime_type):
    '''After collecting normal files, save it in Network File System and RDB.
    It will be executed as a child process.

    :param dict cse_params: Arguments for Google Custom Search Engine
        (Ref.: :class:`collector.google_search.GoogleCustomSearchEngine`)
    '''
    while True:
        cse = gs.GoogleCustomSearchEngine(API_KEY, SEARCH_ENGINE_ID)
        cse.mime_filter(allowed_mime_type)
        for result in cse.search('', **cse_params):
            redirected_url, file_name, mem_file = gs.download(result['url'])

            send_data = {'file_name': file_name, 'label': 'benign',
                         'download_url': redirected_url,
                         'data_type': cse_params['fileType']}
            hashes = cal_hashes(mem_file)
            send_data.update(hashes)

            # TODO: Save file on NFS
            save_file_on_local(mem_file, '/files/', hashes['sha256'])
            del mem_file  # 메모리 낭비 방지

            # 로컬로 접속할때는 자동 설정된 프록시를 강제로 꺼야함.
            proxies = None
            if url_to_receive.startswith('http://127.0.0.1'):
                proxies = {'http': None}
            req = requests.post(url_to_receive, data=send_data,
                                proxies=proxies)
            req.raise_for_status()


def exec_collector_periodically(url_to_receive, cse_params, allowed_mime_type,
                                collection_time=datetime.time(),
                                collection_period=1):
    '''The collector is executed at designated "collection_time" per
    designated "collection_period" with "cse_params".

    :param dict cse_params: Arguments for Google Custom Search Engine
        (Ref.: :class:`collector.google_search.GoogleCustomSearchEngine`)
    :param datetime collection_time: The time at which the collector runs
    :param int collection_period: Period of days to execute collector
    '''
    while True:
        now = datetime.datetime.now(tz=get_localzone())
        exec_datetime = now.replace(
            day=now.day + collection_period, hour=collection_time.hour,
            minute=collection_time.minute, second=collection_time.second)

        delay = exec_datetime - now
        time.sleep(delay.total_seconds())

        cse_params.update({'dateRestrict': ('d%d' % collection_period)})
        proc_inst = mp.Process(target=collector_proc, args=(cse_params,))
        proc_inst.start()


def cal_hashes(mem_file, only_sha256=False):
    sha256 = hashlib.sha256(mem_file).hexdigest()
    if only_sha256:
        return {'sha256': sha256}
    md5 = hashlib.md5(mem_file).hexdigest()
    sha1 = hashlib.sha1(mem_file).hexdigest()
    return {'md5': md5, 'sha1': sha1, 'sha256': sha256}


def save_file_on_local(mem_file, file_name):
    with open(file_name, 'wb') as f:
        f.write(mem_file)


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

    # Parameters of Custom Search Engine
    url_to_receive = 'http://127.0.0.1:8000/upload_file_info'
    cse_params = {'fileType': 'pdf', 'lr': 'lang_ko', 'safe': 'high',
                  'dateRestrict': 'd1'}
    # exec_collector_periodically(url_to_receive, cse_params,allowed_mime_type)
    collector_proc(url_to_receive, cse_params, 'application/pdf')
