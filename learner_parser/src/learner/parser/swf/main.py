# -*- coding: utf-8 -*-
import os
import sys
import json
import zlib
import math
import inspect
import fnmatch
import multiprocessing
from functools import partial

import yara
import pylzma


class FeatureType:
    num_tag = 'num_tag'
    num_api = 'num_api'

    @staticmethod
    def all():
        attributes = inspect.getmembers(
            FeatureType, lambda a: not(inspect.isroutine(a)))
        return [a[0] for a in attributes
                if not(a[0].startswith('__') and a[0].endswith('__'))]


class TagType:
    id_to_name = {
        0: 'End', 1: 'ShowFrame', 2: 'DefineShape',
        # 3
        4: 'PlaceObject', 5: 'RemoveObject', 6: 'DefineBits',
        7: 'DefineButton', 8: 'JPEGTables', 9: 'SetBackgroundColor',
        10: 'DefineFont', 11: 'DefineText', 12: 'DoAction',
        13: 'DefineFontInfo', 14: 'DefineSound', 15: 'StartSound',
        # 16
        17: 'DefineButtonSound', 18: 'SoundStreamHead', 19: 'SoundStreamBlock',
        20: 'DefineBitsLossless', 21: 'DefineBitsJPEG2', 22: 'DefineShape2',
        # 23
        24: 'Protect',
        # 25
        26: 'PlaceObject2',
        # 27
        28: 'RemoveObject2',
        # 29 30 31
        32: 'DefineShape3', 33: 'DefineText2', 34: 'DefineButton2',
        35: 'DefineBitsJPEG3', 36: 'DefineBitsLossless2', 37: 'DefineEditText',
        # 38
        39: 'DefineSprite',
        # 40
        41: 'ProductInfo',
        # 42
        43: 'FrameLabel',
        # 44
        45: 'SoundStreamHead2', 46: 'DefineMorphShape',
        # 47
        48: 'DefineFont2',
        # 49 50 51 52 53 54 55
        56: 'ExportAssets',
        # 57
        58: 'EnableDebugger', 59: 'DoInitAction', 60: 'DefineVideoStream',
        61: 'VideoFrame',
        # 62
        63: 'DebugID', 64: 'EnableDebugger2', 65: 'ScriptLimits',
        # 66 67 68
        69: 'FileAttributes', 70: 'PlaceObject3',
        # 71 72
        73: 'DefineFontAlignZones', 74: 'CSMTextSettings', 75: 'DefineFont3',
        76: 'SymbolClass', 77: 'Metadata', 78: 'DefineScalingGrid',
        # 79 80 81
        82: 'DoABC', 83: 'DefineShape4', 84: 'DefineMorphShape2',
        # 85
        86: 'DefineSceneAndFrameLabelData', 87: 'DefineBinaryData',
        88: 'DefineFontName', 89: 'StartSound2',
    }

    @staticmethod
    def getid(tagname):
        tagname = tagname[0].upper() + tagname[1:].lower()
        for k, v in TagType.id_to_name.items():
            if v == tagname:
                return k

    def __init__(self, tagid, tagname=None):
        self.id = tagid
        self.name = self.id_to_name.get(tagid, 'Unknown(%s)' % tagid)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.id == other.id


class SWF:
    yara_api = yara.compile('swf_ac_apis.yar')

    def __init__(self):
        self.tags = []
        self.actionscripts = []
        self.swf_ver = -1
        self.errors = []

        self.features = {'orig_file_size': 0, 'decom_file_size': 0}

    def make_features(self, feature_types):
        features = {}

        if FeatureType.num_tag in feature_types:
            for key, val in self.features.items():
                if not key.startswith(FeatureType.num_tag):
                    continue

                if FeatureType.num_tag in features:
                    features[FeatureType.num_tag][key] = val
                else:
                    features[FeatureType.num_tag] = {key: val}

        if FeatureType.num_api in feature_types:
            merged_acs = b'\n\n'.join(self.actionscripts)
            match_objs = self.yara_api.match(data=merged_acs)
            for match_obj in match_objs:
                api_name = str(match_obj)[:-1]
                num_api = len(match_obj.strings)

                f_name = FeatureType.num_api + '_' + api_name
                if FeatureType.num_api in features:
                    features[FeatureType.num_api][f_name] = num_api
                else:
                    features[FeatureType.num_api] = {f_name: num_api}

        return features

    def parse(self, file_path):
        self.__init__()
        swf_data = self.open(file_path)
        self.features['decom_file_size'] = len(swf_data)

        def __read_uint(size):
            next_pos = pos + size
            return (int.from_bytes(swf_data[pos:next_pos], byteorder='little'),
                    next_pos)

        def __read_rect():
            nbits = int.from_bytes([swf_data[pos]], byteorder='little') >> 3
            # 총 필요한 bits: nbits(5bits) + (NBits값 * 4)
            # 여기서 바이트 단위로 파싱하므로 필요비트수에서 올림
            # 필요 바이트 계산 예시: 33bits->5bytes, 28bits->4bytes
            rect_size = math.ceil((5 + (nbits * 4)) / 8)
            next_pos = pos + rect_size
            return next_pos

        try:
            pos = 3
            self.swf_ver, pos = __read_uint(1)
            _, pos = __read_uint(4)  # File size
            pos = __read_rect()
            _, pos = __read_uint(2)  # Frame rate (8.8 fixed number)
            _, pos = __read_uint(2)  # Frame count
            while True:
                tag_id_len, pos = __read_uint(2)
                tagid = tag_id_len >> 6
                tag_len = tag_id_len & 0b111111
                if tag_len == 0b111111:
                    tag_len, pos = __read_uint(4)

                # if 태그이름 in ['DoAction', 'DoInitAction', 'DoABC']
                if tagid in [12, 59, 82]:
                    self.actionscripts.append(swf_data[pos:pos + tag_id_len])

                tag = TagType(tagid)
                self.tags.append(tag)

                f_name = '%s_%s' % (FeatureType.num_tag, str(tag))
                if f_name in self.features:
                    self.features[f_name] += 1
                else:
                    self.features[f_name] = 1

                if tag.name == 'End':
                    break
                else:
                    pos += tag_len
        except Exception as e:
            if len(self.tags) > 0:
                self.errors.append("A End tag doesn't exist.")
            else:
                self.errors.append('Parsing error:' + str(e))
                raise e

    def open(self, file_path):
        with open(file_path, 'rb') as f:
            swf_data = f.read()
            self.features['orig_file_size'] = len(swf_data)

        if swf_data.startswith(b'CWS'):
            header = swf_data[3:8]
            try:
                # [Bug fixed]: zlib.decompress()는 몇몇 파일에 대하여 압축해제가 실패
                # [Bug fixed]: 아래처럼 오브젝트를 생성하고 decompress()호출하는 방식으로 해결
                swf_data = zlib.decompressobj().decompress(swf_data[8:])
                swf_data = b'FWS' + header + swf_data
                return swf_data
            except Exception as e:
                raise Exception('(zlib) Decompression failed: %s' % str(e))
                return None

        elif swf_data.startswith(b'ZWS'):
            header = swf_data[3:8]
            try:
                swf_data = pylzma.decompress(swf_data[12:])
                swf_data = b'FWS' + header + swf_data
                return swf_data
            except Exception as e:
                raise Exception('(lzma) Decompression failed: %s' % str(e))
                return None

        elif swf_data.startswith(b'FWS'):
            return swf_data

        else:
            raise Exception('Invalid flash file.')
            return None

    def __list_files(self, dir_path):
        file_paths = []
        for root, dirnames, file_names in os.walk(dir_path):
            if len(dirnames) > 0:
                continue
            for file_name in fnmatch.filter(file_names, '*'):
                file_paths.append(os.path.join(root, file_name))

        return file_paths


def run(swf, dataset_types, raw_file_info):
    file_info = json.loads(raw_file_info)
    try:
        swf.parse(file_info.pop('file_path'))
        features = swf.make_features(dataset_types)
        file_info.update(features)
    except:
        pass
    return json.dumps(file_info)


if __name__ == '__main__':
    swf = SWF()
    dataset_types = [
                     FeatureType.num_api,
                     FeatureType.num_tag,
                     ]

    with multiprocessing.Pool() as pool:
        func = partial(run, swf, dataset_types)
        for out in pool.imap_unordered(func, sys.argv[1:]):
            print(out)
