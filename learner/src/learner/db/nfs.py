# -*- coding: utf-8 -*-
'''
**This is NFS client helper for Learner.**
When you install libnfs, refer this:
http://rickhau.github.io/blog/2015/05/08/install-libnfs-python-library/
'''
# Default packages
import os
import re
import sys
import logging

# 3rd-party packages
import libnfs

# Internal packages


logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)


class NFSManager:
    '''
    Sometimes a "segmentation fault" occurs,
    which make program terminated without any explain messages.
    Therefore, you should check here when "segmentation fault" occurs.
    '''
    ROOT_FILE_DIR = '/files'
    ROOT_TMP_FILE_DIR = '/files/tmp'
    ROOT_DOCKER_IMAGE_DIR = '/docker_images'
    ROOT_DATASET_DIR = '/datasets'

    def __init__(self, cluster_spec):
        # Changing a default port number doesn't support yet.
        self.nfs = libnfs.NFS('nfs://%s/learner_storage/nfs' %
                              (cluster_spec['nfs']['host']))
        self.delete_tmp_files()

    def get_tmp_file_path(self, name):
        return self.ROOT_TMP_FILE_DIR + '/' + name

    def get_file_path(self, sha256):
        return (self.ROOT_FILE_DIR + '/' + sha256[0:3] + '/' + sha256[3:6] +
                '/' + sha256[6:9] + '/' + sha256[9:12] + '/' + sha256)

    def get_image_path(self, image_id):
        return '%s/%s.tar' % (self.ROOT_DOCKER_IMAGE_DIR, image_id)

    def save_file(self, bytes_file, sha256):
        file_path = self.get_file_path(sha256)
        if self.__exists(file_path):
            raise FileExistsError
        else:
            self.__makedirs(os.path.dirname(file_path))
            self.__write(file_path, bytes_file)

    def read_file(self, sha256):
        if self.__exists(self.get_file_path(sha256)):
            return self.__read(self.get_file_path(sha256))
        else:
            raise FileNotFoundError

    def save_tmp_file(self, bytes_file, name):
        tmp_path = self.get_tmp_file_path(name)
        if self.__exists(tmp_path):
            raise FileExistsError
        else:
            self.__makedirs(os.path.dirname(tmp_path))
            self.__write(tmp_path, bytes_file)
            return tmp_path

    def delete_tmp_files(self):
        for file_path in self.nfs.listdir(self.ROOT_TMP_FILE_DIR):
            if file_path not in ['.', '..']:
                self.__delete(self.ROOT_TMP_FILE_DIR + '/' + file_path)

    def save_docker_image(self, bytes_file, image_id):
        img_path = self.get_image_path(image_id)
        self.nfs.mkdir(os.path.dirname(img_path))
        if self.__exists(img_path):
            raise FileExistsError
        else:
            self.__write(img_path, bytes_file)

    def read_docker_image(self, image_id):
        return self.__read(self.get_image_path(image_id))

    def save_dataset(self, bytes_file, dataset_name, data_type, label):
        dataset_path = self.get_dataset_path(dataset_name, data_type, label)
        self.nfs.mkdir(os.path.dirname(dataset_path))
        if self.__exists(dataset_path):
            raise FileExistsError
        else:
            self.__write(dataset_path, bytes_file)

    def read_dataset(self, dataset_name, data_type, label):
        dataset_path = self.get_dataset_path(dataset_name, data_type, label)
        return self.__read(dataset_path)

    def __makedirs(self, name):
        if self.__exists(name):
            return
        ptn = re.compile("/")
        start_idx = len(self.ROOT_FILE_DIR) + 1
        slash_idxs = [m.start() for m in ptn.finditer(name, start_idx)]
        for slash_idx in slash_idxs:
            self.nfs.mkdir(name[:slash_idx])
        self.nfs.mkdir(name)

    def __exists(self, path):
        try:
            self.nfs.stat(path)
            return True
        except FileNotFoundError:
            return False

    def __read(self, path):
        f = self.nfs.open(path, 'rb')
        bytes_file = f.read()
        f.close()
        return bytes_file

    def __write(self, path, bytes_file):
        f = self.nfs.open(path, 'wb')
        f.write(bytearray(bytes_file))
        f.close()

    def __delete(self, path):
        self.nfs.unlink(path)
