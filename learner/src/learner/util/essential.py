# -*- coding: utf-8 -*-
'''
**This is essential utilities for Learner.**
'''
# Default packages
import json
import os.path
import hashlib
import logging
import datetime
import configparser

logger = logging.getLogger(__name__)

CONF_FILE_PATH = os.path.dirname(__file__) + '/../../rdb.conf'


class Config:
    '''
    **This class helps you load the configuration file only once.**
    If there is a dict containing configurations that was previously loaded,
    it returns this. Here is the example code:

    .. code-block:: python

        >> conf_dict = Config()
    '''
    conf_dict = None
    updated = False

    def __new__(self):
        if self.conf_dict is None or self.updated is True:
            self.conf_dict = self.read_conf(CONF_FILE_PATH)
            self.updated = False
        return self.conf_dict

    @staticmethod
    def read_conf(conf_file_path):
        '''Read the specified configuration file and output it as dict type.

        :param str conf_file_path: configure file path
        :return: A nested dict of configuration. For example:
            {'SECTION': {'KEY': 'VALUE', ...}, ...}
        :rtype: dict
        '''
        confparser = configparser.ConfigParser(dict_type=dict)
        confparser.optionxform = str  # To return the value as dict type
        confparser.read(conf_file_path)
        return confparser._sections

    @staticmethod
    def update_cluster_spec(cluster_spec):
        pass


def cal_hashes(mem_file, only_sha256=False):
    sha256 = hashlib.sha256(mem_file).hexdigest()
    if only_sha256:
        return {'sha256': sha256}
    md5 = hashlib.md5(mem_file).hexdigest()
    sha1 = hashlib.sha1(mem_file).hexdigest()
    return {'md5': md5, 'sha1': sha1, 'sha256': sha256}


def cursor_to_data(cursor, max_num_rows=None, datetime_to_str=True):
    if cursor.rowcount < 1:
        return []

    column_names = [column_name[0] for column_name in cursor.description]
    if max_num_rows is not None:
        rows = cursor.fetchmany(max_num_rows)
    else:
        rows = cursor.fetchall()

    out = []
    for row in rows:  # For each row
        new_row = list(row)  # Convert to list type from tuple
        for i in range(len(row)):
            # If it is JSON form, convert it to Python type via json.loads()
            if type(row[i]) == str and '"' in row[i] and ',' in row[i]:
                try:
                    new_row[i] = json.loads(row[i])
                except:
                    pass

            # If it is datetime type, convert it to str.
            elif datetime_to_str is True and type(row[i]) == datetime.datetime:
                new_row[i] = str(row[i])

        out.append(dict(zip(column_names, new_row)))

    return out


def remove_if_value_is_empty(dict_obj):
    return dict((k, v) for k, v in dict_obj.items()
                if v is not None and v != '')
