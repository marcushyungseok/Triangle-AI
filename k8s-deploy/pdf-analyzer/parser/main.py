# -*- coding: utf-8 -*-
'''
Created on Aug 29, 2016

@author: learner
'''
import re
import os
import zlib
import html
import copy
import queue
import base64
import inspect
import binascii
import traceback

try:
    from .lzw import lzwdecode
    from .ccitt import ccittfaxdecode
except:
    from lzw import lzwdecode
    from ccitt import ccittfaxdecode

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

try:
    from entropy import shannon_entropy
    _HAS_ENTROPY = True
except ImportError:
    _HAS_ENTROPY = False
    import math
    def shannon_entropy(data):
        """Fallback Shannon entropy calculation."""
        if not data:
            return 0.0
        if isinstance(data, str):
            data = data.encode()
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


class PDFError(Exception):
    error_msgs = {
        'magic_number': '(Idx.%s) PDF 매직 넘버가 아님',
        'startxref': '(Idx.%s) startxref 주소가 바르지 않음',
        'cnt_xref': '(Idx.%s) 헤더의 xref 갯수와 실제 갯수 불일치',
        'filter_name': '(Idx.%s) 잘못된 필터 이름',
        'comment': '(Idx.%s) 손상된 Object (주석 포멧 손상)',
        'dict_key': '(Idx.%s) 손상된 Object (Dict 키의 값이 없음)',
        'root': '(Idx.%s) 손상된 Object (Root 구조 손상)',
        'dict': '(Idx.%s) 손상된 Object (Dictionary 구조 손상)',
        'arr': '(Idx.%s) 손상된 Object (Array 구조 손상)',
        'str': '(Idx.%s) 손상된 Object (String 구조 손상)',
    }

    def __init__(self, err_type, idx, err_info=None):
        self.err_type = err_type
        self.err_msg = self.error_msgs[err_type] % idx
        self.err_info = err_info


class FeatureType:
    num_name = 'num_name'  # Too many features...
    num_suspicious_name = 'num_suspicious_name'  # js, uri, swf, jbig2, etc.

    num_filter = 'num_filter'
    ratio_filter = 'ratio_filter'
    num_multi_filter = 'num_multi_filter'
    num_hex_in_filter_name = 'num_hex_in_filter_name'

    num_cmd = 'num_cmd'  # contain in the values
    num_file = 'num_file'

    js_max_line_length = 'js_max_line_length'
    js_ratio_in_size = 'js_ratio_in_size'
    js_num_api = 'js_num_api'

    object_entropy = 'object_entropy'  # TODO later
    format_error = 'format_error'
    appended_tail_len = 'appended_tail_len'
    appended_tail_entropy = 'appended_tail_entropy'
    file_size = 'file_size'
    ratio_hex_in_name = 'ratio_hex_in_name'

    @staticmethod
    def all():
        attributes = inspect.getmembers(
            FeatureType, lambda a: not(inspect.isroutine(a)))
        return [a[0] for a in attributes
                if not(a[0].startswith('__') and a[0].endswith('__'))]


class PDF:
    regex_ver = re.compile(br'%PDF-(?P<ver>\d+\.\d+)?\r?\n?')

    regex_fmt = re.compile(
        br'''
        ((?P<obj_id>\d+\s\d+\sobj)\s{1,2}
         (?P<content>.*?)\s{0,2}
         (stream\s{1,2}(?P<stream>.*?)endstream\s{1,2})?
         endob[jh])
        |
        (xref\s{0,2}(?P<xref_start_i>\d+)\s(?P<xref_conut>\d+)\s{0,2}
         (?P<xref_records>(\d{10}\s\d{5}\s[fn]\s*)*))
        |
        (trailer\s{0,2}(?P<trailer><<.*?>>)\s{0,2})
        |
        ((startxref\s{0,2}(?P<startxref>\d+))?\s{0,2}%%EOF\s*)
        ''', re.DOTALL | re.VERBOSE)

    regex_ref_obj = re.compile(br'(\d+\s\d+)\sR')

    regex_xfa_js = re.compile(
        r'''
        <(\w+:)?script.*?contentType\s*=\s*[\'"]application/x-javascript[\'"].*?>
        \s*(?P<js>.*?)\s*
        </(\w+:)?script>''', re.DOTALL | re.VERBOSE)

    regex_file = re.compile(
        br'''
        ((?P<pdf>%PDF)|
        (?P<swf>[FCZ]WS)|
        (?P<pe>MZ))''', re.VERBOSE)

    # Change to current directory and load a Yara rule file.
    _parser_dir = os.path.dirname(os.path.realpath(__file__))
    if _HAS_YARA:
        yara_js_apis = yara.compile(os.path.join(_parser_dir, 'pdf_js_apis.yar'))
    else:
        yara_js_apis = None

    # yara_js_apis = yara.compile('./dataset/pdf_js_apis.yar')
    suspicious_names = ['Page', 'Encrypt', 'ObjStm', 'JS', 'JavaScript',
                        'AA', 'OpenAction', 'AcroForm', 'JBIG2Decode',
                        'RichMedia', 'Launch', 'EmbeddedFile', 'XFA',
                        'Colors > 2^24', 'URI']

    def __init__(self):
        self.ver = ''
        self.objs = {}  # self.objs['id'] = (content, stream)
        self.obj_tree = {}
        self.startxref = []
        self.xrefs = []
        self.trailer = {}
        self.tail = None

        self.features = {'num_hex_in_name': 0, 'num_hex_in_filter_name': 0,
                         'num_character_in_name': 0, 'num_cmd': 0,
                         'num_correct_obj': 0, 'num_corrupted_obj': 0,
                         'num_stream': 0,
                         'num_succeeded_decoding': 0, 'num_failed_decoding': 0,
                         'file_size': 0, 'num_name': {}, 'num_filter': {},
                         'num_multi_filter': {}
                         }
        self.errors = []
        self.javascripts = []
        self.xfas = []
        # e.g. ['pe'][{'name', 'md5', 'size', 'mime', 'file'}, ...]
        self.embedded_files = {'pe': [], 'pdf': [], 'swf': []}
        self.file_objs = {}

        self.__idx = 0
        # TODO: null ref object
        # TODO: wrong /Length value

    def pretty_print(self):
        str_list = []

        str_list.append('== PDF Version ==\n')
        str_list.append('%s\n' % self.ver)
        str_list.append('\n\n')

        str_list.append('== Embedded Files ==\n')
        for file_type, file_info_list in self.embedded_files.items():
            str_list.append(' - %s\n' % file_type)
            for file_info in file_info_list:
                str_list.append('Filename: %s, MD5: %s, Size: %s\n' %
                                (file_info['name'], file_info['md5'],
                                 file_info['size']))
        str_list.append('\n\n')

        str_list.append('== XFAs ==\n')
        str_list.append(', '.join([str(s) for s in self.xfas]))
        str_list.append('\n\n')

        str_list.append('== Startxref ==\n')
        str_list.append(', '.join([str(e) for e in self.startxref]) + '\n')
        str_list.append('\n\n')

        str_list.append('== Xrefs ==\n')
        for xref in self.xrefs:
            for idx, info in xref.items():
                str_list.append('[%s]: Gen:%s, Offset:%s Use:%s\n' % (
                                idx, info['gen'], info['offset'], info['use']))
        str_list.append('\n\n')

        str_list.append('== Trailer ==\n')
        for k, v in self.trailer.items():
            str_list.append(' %s: %s\n' % (k, v))
        str_list.append('\n\n')

        str_list.append('== Tail ==\n')
        str_list.append(str(self.tail))
        str_list.append('\n\n')

        str_list.append('== Errors ==\n')
        str_list.append('(Error name, File position, Description)\n')
        str_list.append('\n'.join([str(e) for e in self.errors]) + '\n')
        str_list.append('\n\n')

        str_list.append('== Javascripts ==\n')
        str_list.append('## End of Javascript ##\n'.join(
                                [str(e) for e in self.javascripts]) + '\n')
        str_list.append('\n\n')

        str_list.append('== Objects ==\n')
        for obj_id, obj_info in self.objs.items():
            str_list.append('## %s ##\n' % obj_id)
            str_list.append(' ## contents:\n%s\n' % str(obj_info['content']))
            str_list.append(' ## stream:\n%s\n' % str(obj_info['stream']))
        str_list.append('\n\n')

        return ''.join(str_list)

    def make_features(self, feature_types):
        features = {}

        # Features containing single value #
        if FeatureType.file_size in feature_types:
            f_name = FeatureType.file_size
            if self.features['file_size'] > 0:
                features[f_name] = self.features['file_size']

        if FeatureType.ratio_hex_in_name in feature_types:
            f_name = FeatureType.ratio_hex_in_name
            features[f_name] = (self.features['num_hex_in_name'] /
                                max(self.features['num_character_in_name'], 1))

        if self.tail is not None:
            if FeatureType.appended_tail_len in feature_types:
                f_name = FeatureType.appended_tail_len
                if len(self.tail) > 0:
                    features[f_name] = len(self.tail)

            if FeatureType.appended_tail_entropy in feature_types:
                f_name = FeatureType.appended_tail_entropy
                features[f_name] = max(shannon_entropy(self.tail), 0.01)

        if FeatureType.js_max_line_length in feature_types:
            f_name = FeatureType.js_max_line_length
            lens_line = []
            for js in self.javascripts:
                for js_line in js.split():
                    lens_line.append(len(js_line))

            if len(lens_line) > 0:
                features[f_name] = max(lens_line)

        if FeatureType.js_ratio_in_size in feature_types:
            f_name = FeatureType.js_ratio_in_size
            js_size = 0
            for js in self.javascripts:
                js_size += len(js)
            ratio = js_size / max(self.features['file_size'], 1)
            features[f_name] = min(ratio, 1)

        if FeatureType.num_hex_in_filter_name in feature_types:
            features[FeatureType.num_hex_in_filter_name] = self.features[
                                                    'num_hex_in_filter_name']

        if FeatureType.num_cmd in feature_types:
            features[FeatureType.num_cmd] = self.features['num_cmd']  # OK

        # Features containing fixed multiple values #
        if FeatureType.num_filter in feature_types:
            features[FeatureType.num_filter] = self.features['num_filter']

        if FeatureType.ratio_filter in feature_types:
            features[FeatureType.ratio_filter] = {}
            for nested_key, nested_val in self.features['num_filter'].items():
                nested_key = 'ratio_' + nested_key[4:]
                ratio = nested_val/max(self.features['num_stream'], 1)
                features[FeatureType.ratio_filter][nested_key] = ratio

        # Features containing variable multiple values #
        if FeatureType.num_name in feature_types:
            features[FeatureType.num_name] = self.features['num_name']

        if FeatureType.num_suspicious_name in feature_types:
            features[FeatureType.num_suspicious_name] = {}
            for nested_key, nested_val in self.features['num_name'].items():
                if nested_key[9:] in self.suspicious_names:
                    features[FeatureType.num_suspicious_name][nested_key] = (
                                                                    nested_val)

        if FeatureType.js_num_api in feature_types:
            num_apis = {}
            f_name = FeatureType.js_num_api
            if self.yara_js_apis is not None:
                merged_js = '\n\n'.join(self.javascripts)
                match_objs = self.yara_js_apis.match(data=merged_js)
                for match_obj in match_objs:
                    api_name = str(match_obj)
                    nested_f_name = f_name + '_' + api_name[:-1]
                    if api_name in num_apis:
                        num_apis[nested_f_name] += 1
                    else:
                        num_apis[nested_f_name] = 1
            features[f_name] = num_apis

        if FeatureType.format_error in feature_types:
            err_features = {}
            f_name = FeatureType.format_error
            for error in self.errors:
                nested_f_name = f_name + '_' + error.err_type
                if nested_f_name in err_features:
                    err_features[nested_f_name] += 1
                else:
                    err_features[nested_f_name] = 1
            features[f_name] = err_features

        if FeatureType.num_file in feature_types:
            f_name = FeatureType.num_file
            num_file_features = {}
            for file_type, file_info_list in self.embedded_files.items():
                nested_f_name = f_name + '_' + file_type
                num_file_features[nested_f_name] = len(file_info_list)
            features[f_name] = num_file_features

        if FeatureType.num_multi_filter in feature_types:
            features[FeatureType.num_multi_filter] = self.features[
                                                    'num_multi_filter']

        return features

    def parse(self, file_path=None, bytes_pdf=None):
        self.__init__()  # Initialize arguments.

        if file_path is not None:
            self.file_path = file_path

            bytes_pdf = self.__read_and_check_pdf(file_path)
        elif bytes_pdf is not None:
            self.__check_pdf(bytes_pdf)
        else:
            raise Exception('Please input a file.')

        self.features['file_size'] = len(bytes_pdf)
        while self.__idx < self.features['file_size']:
            # obj, xref, trailer, startxref, eof 검사
            match_obj = self.regex_fmt.search(bytes_pdf[self.__idx:])
            if match_obj is None:
                self.tail = bytes_pdf[self.__idx:]
                break
            self.__idx = self.__idx + match_obj.end()
            groupdict = match_obj.groupdict()

            if groupdict['obj_id'] is not None:
                if len(groupdict['content']) == 0:
                    continue

                # 컨텐츠를 파이썬 타입으로 파싱
                obj_content_i = match_obj.start('content')
                obj_info = ObjectParser(
                    groupdict['content'], obj_content_i,
                    groupdict['stream']).parse()

                # self.features 업데이트
                for key, val in obj_info['features'].items():
                    if type(val) == dict:
                        for nested_key, nested_val in val.items():
                            if nested_key in self.features[key]:
                                self.features[key][nested_key] += nested_val
                            else:
                                self.features[key][nested_key] = nested_val
                    else:
                        if key in self.features:
                            self.features[key] += val
                        else:
                            self.features[key] = val

                # JavaScripts 저장 (하지만 레퍼런스[# # R] 형태도 포함)
                self.javascripts.extend(obj_info['javascripts_without_xfa'])
                self.xfas.extend(obj_info['xfas'])
                self.errors.extend(obj_info['errors'])

                # 파일 탐지 및 저장
                if obj_info['stream'] is not None:
                    match_obj = self.regex_file.match(obj_info['stream'])
                    if match_obj is not None:
                        match_dict = match_obj.groupdict()
                        for file_type, match_str in match_dict.items():
                            if match_str is not None:
                                file_info = {'file_type': file_type,
                                             'content': obj_info['content'],
                                             'stream': obj_info['stream']}
                                self.file_objs[groupdict['obj_id']] = file_info
                                break

                # object 데이터 및 정보 저장
                self.objs[groupdict['obj_id']] = {
                    'content': obj_info['content'],
                    'stream': obj_info['stream']
                }

            # xref이면 관련 주소들 파싱 및 [주소 레퍼런스, 카운트]가 올바른지 확인
            elif groupdict['xref_start_i'] is not None:
                xref_start_i = int(groupdict['xref_start_i'])
                self.startxref.append(self.__idx + match_obj.start())

                xref_conut = int(groupdict['xref_conut'])
                xref_records = groupdict['xref_records']
                xref_actual_conut = int(len(xref_records) / 20)
                if xref_conut != xref_actual_conut:
                    idx = self.__idx + match_obj.start()
                    msg = ('헤더의 xref_count는 %s 이지만, 실제 갯수는 %s' %
                           (xref_conut, xref_actual_conut))
                    self.errors.append(PDFError('cnt_xref', idx, msg))
                for i in range(xref_start_i, xref_start_i + xref_actual_conut):
                    offset = xref_records[i * 20:i * 20 + 10]
                    gen = xref_records[i * 20 + 11:i * 20 + 16]
                    use = xref_records[i * 20 + 17:i * 20 + 18]
                    self.xrefs.append(
                        {i: {'offset': offset, 'gen': gen, 'use': use}})

            elif groupdict['trailer'] is not None:
                trailer_idx = match_obj.start('trailer')
                info = ObjectParser(groupdict['trailer'], trailer_idx).parse()
                self.trailer = info['content']
                if info['features']['num_corrupted_obj'] == 1:
                    msg = ('Trailer 손상: %s' % groupdict['trailer'])
                    self.errors.append(PDFError('cnt_xref', trailer_idx, msg))

            elif groupdict['startxref'] is not None:
                startxref = int(groupdict['startxref'])
                if startxref not in self.startxref:
                    idx = self.__idx + match_obj.start()
                    msg = ('헤더의 startxref 리스트 %s 내에 실제 발견된 주소 %s 없음' %
                           (self.startxref, startxref))
                    self.errors.append(PDFError('startxref', idx, msg))

        # print(self.trailer)
        # self.obj_tree = self.__make_obj_tree(self.trailer)
        self.__collect_all_js()
        self.__collect_all_files()

    def __read_and_check_pdf(self, file_path):
        with open(file_path, 'rb') as f:
            bytes_pdf = f.read(12)
            self.__check_pdf(bytes_pdf)

            bytes_pdf += f.read()

        return bytes_pdf

    def __check_pdf(self, bytes_pdf):
        bytes_pdf = bytes_pdf[:12]
        match_obj = self.regex_ver.match(bytes_pdf)
        if match_obj is None:
            msg = '%s는 PDF 매직 넘버가 아님' % bytes_pdf
            self.errors.append(PDFError('magic_number', 0, msg))

        else:
            self.ver = match_obj.group('ver')
            if self.ver is None:
                msg = '%s는 잘못된 PDF 버전임' % bytes_pdf
                self.errors.append(PDFError('magic_number', 0, msg))

    def __make_obj_tree(self, content, visited_objs={}):
        out = copy.deepcopy(content)
        if type(content) is list:
            for i, item in enumerate(content):
                if type(item) is bytes:
                    out[i] = self.__find_ref_obj(item, visited_objs)
                else:
                    out[i] = self.__make_obj_tree(item, visited_objs)

        elif type(content) is dict:
            for k, v in self.__iter_nested_dict(content):
                if k == b'/Parent' or k == b'/Kids':
                    continue
                if type(v) is bytes:
                    out[k] = self.__find_ref_obj(v, visited_objs)
                else:
                    out[k] = self.__make_obj_tree(v, visited_objs)
        elif type(content) is bytes:
            out = self.__find_ref_obj(content, visited_objs)

        return out

    def __find_ref_obj(self, obj_bytes, visited_objs):
        match_obj = self.regex_ref_obj.match(obj_bytes)
        if match_obj is not None:
            obj_id = match_obj.group(1) + b' obj'
            if obj_id in self.objs:
                if visited_objs.get(obj_id) is False:
                    visited_objs.update({obj_id: True})
                    print(obj_id, self.objs[obj_id]['content'])
                    out = self.__make_obj_tree(self.objs[obj_id]['stream'],
                                               visited_objs)
                    visited_objs.pop(obj_id)
                    return out

        return obj_bytes

    def __iter_nested_dict(self, dictionary):
        for key, value in dictionary.items():
            if type(value) is dict:
                yield (key, value)
                yield from self.__iter_nested_dict(value)
            else:
                yield (key, value)

    def __collect_all_js(self):
        for i, js in enumerate(self.javascripts):
            if js[-1:] == b'R':
                js = js[:-1] + b'obj'
                if js in self.objs:
                    self.javascripts[i] = self.objs[js]['stream']

            if self.javascripts[i] is not None:
                self.javascripts[i] = self.javascripts[i].decode(
                                                            errors='replace')
            else:
                self.javascripts[i] = ''

        possible_js_obj_ids = []
        for xfa in self.xfas:
            if type(xfa) is list:
                for i, part_xfa in enumerate(xfa):
                    if i % 2 == 1 and part_xfa[-1:] == b'R':
                        possible_js_obj_ids.append(part_xfa[:-1] + b'obj')
            else:
                possible_js_obj_ids.append(xfa[:-1] + b'obj')

        for possible_js_obj_id in possible_js_obj_ids:
            if possible_js_obj_id in self.objs:
                obj = self.objs[possible_js_obj_id]
                if obj['stream'] is not None:
                    unescaped_xfa = html.unescape(
                        obj['stream'].decode(errors='replace'))
                    match_obj = self.regex_xfa_js.search(unescaped_xfa)
                    if match_obj is not None:
                        self.javascripts.append(match_obj.group('js'))

    def __collect_all_files(self):
        for file_obj_id, file_obj_info in self.file_objs.items():
            file_info = {'name': None, 'md5': None, 'size': None,
                         'mime': None, 'file': file_obj_info['stream']}
            content = file_obj_info['content']
            if type(content) is dict:
                if b'/Params' in content:
                    if b'/Checksum' in content[b'/Params']:
                        md5 = content[b'/Params'][b'/Checksum'][2:]
                        file_info['md5'] = md5
                    if b'/Size' in content[b'/Params']:
                        file_info['size'] = content[b'/Params'][b'/Size']
                if b'/Subtype' in content:
                    file_info['mime'] = content[b'/Subtype'][1:]

            for obj_id, obj_info in self.objs.items():
                if type(obj_info['content']) is dict:
                    for _, val in self.__iter_nested_dict(obj_info['content']):
                        ref_obj_id = file_obj_id[:-3] + b'R'
                        if val == ref_obj_id:
                            if b'/F' in self.objs[obj_id]['content']:
                                name = self.objs[obj_id]['content'][b'/F']
                                file_info['name'] = name

            self.embedded_files[file_obj_info['file_type']].append(file_info)


class ObjectParser:
    regex_primitive = re.compile(br'''
        (
            (?P<objref>\d+\s\d+\sR)|
            (?P<bool>true|false)|
            (?P<num>[-+]?(\d*\.\d*|\d+))|
            (?P<hex><[0-9a-fA-F\s]*>)|
            (?P<name>/([^\s\[\]<>\(\)/%]|//)+)|
            (?P<null>null)
        )(\s|\]|>>|/|<|\[|\(|\)|%|$)
        ''', re.DOTALL | re.VERBOSE)
    regex_name_hex = re.compile(br'#[0-9A-Fa-f]{2}')
    regex_string_hex = re.compile(br'\\([0-7]{1,3})')
    regex_newline = re.compile(br'[\n\r]')

    ascii_table = {('#%X' % i).encode(): chr(i).encode() for i in range(128)}
    filter_names = [b'/ASCIIHexDecode', b'/AHx', b'/ASCII85Decode', b'/A85',
                    b'/LZWDecode', b'/LZW', b'/FlateDecode', b'/Fl',
                    b'/RunLengthDecode', b'/RL', b'/CCITTFaxDecode', b'/CCF',
                    b'/JBIG2Decode', b'/DCTDecode', b'/DCT', b'/JPXDecode',
                    b'/Crypt']

    class Type:
        root = 0
        arr = 1
        dict = 2
        bool = 5
        num = 6
        str = 7
        name = 8
        obj = 9

    class ParseState:
            roo = 'root'
            arr = 'arr'
            dic = 'dict'

    class Decoder:
        regex_runlen = re.compile(br'(\d+)(\D)')

        @classmethod
        def ASCIIHexDecode(cls, stream):
            # 스트림 내 모든 공백을 제거
            stream = b''.join(stream.split())
            # 스트림 delimiter '>'를 삭제
            return binascii.unhexlify(stream.rstrip(b'>'))

        @classmethod
        def ASCII85Decode(cls, stream):
            return base64.a85decode(stream)

        @classmethod
        def LZWDecode(cls, stream, params={}):
            return cls.predictor(lzwdecode(stream), params)

        @classmethod
        def FlateDecode(cls, stream, params={}):
            return cls.predictor(
                zlib.decompressobj().decompress(stream), params)

        @classmethod
        def RunLengthDecode(cls, stream):
            return cls.regex_runlen.sub(lambda m: m.group(2) * int(m.group(1)),
                                        stream)

        @classmethod
        def CCITTFaxDecode(cls, stream, params):  # image
            return cls.predictor(ccittfaxdecode(stream, params), params)

        @classmethod
        def JBIG2Decode(cls, stream, params={}):  # image
            return stream

        @classmethod
        def DCTDecode(cls, stream, params={}):  # image
            return stream  # JPEG

        @classmethod
        def JPXDecode(cls, stream):  # image
            return stream  # JPEG2000

        @classmethod
        def Crypt(cls, stream, params={}):
            return stream

        @classmethod
        def predictor(cls, stream, params):
            try:
                # apply predictors
                if 'Predictor' in params:
                    pred = int(params['Predictor'])
                    if pred == 1:
                        # no predictor
                        pass
                    elif 10 <= pred:
                        # PNG predictor
                        colors = int(params.get(b'/Colors', 1))
                        columns = int(params.get(b'/Columns', 1))
                        bitspercomponent = int(params.get(b'/BitsPerComponent',
                                                          8))
                        stream = cls.apply_png_predictor(
                            pred, colors, columns, bitspercomponent, stream)
                    else:
                        # Unsupported
                        pass
            except Exception:
                        pass
            return stream

        @classmethod
        def apply_png_predictor(pred, colors, columns, bitspercomponent, data):
            if bitspercomponent != 8:
                # unsupported
                raise ValueError(bitspercomponent)
            nbytes = colors*columns*bitspercomponent//8
            i = 0
            buf = b''
            line0 = b'\x00' * columns
            for i in range(0, len(data), nbytes+1):
                ft = data[i]
                i += 1
                line1 = data[i:i+nbytes]
                line2 = b''
                if ft == b'\x00':
                    # PNG none
                    line2 += line1
                elif ft == b'\x01':
                    # PNG sub (UNTESTED)
                    c = 0
                    for b in line1:
                        c = (c+ord(b)) & 255
                        line2 += chr(c)
                elif ft == b'\x02':
                    # PNG up
                    for (a, b) in zip(line0, line1):
                        c = (ord(a)+ord(b)) & 255
                        line2 += chr(c)
                elif ft == b'\x03':
                    # PNG average (UNTESTED)
                    c = 0
                    for (a, b) in zip(line0, line1):
                        c = ((c+ord(a)+ord(b))//2) & 255
                        line2 += chr(c)
                else:
                    # unsupported
                    raise ValueError(ft)
                buf += line2
                line0 = line2
            return buf

    def __init__(self, bytes_obj, offset, stream=None):
        self.bytes_obj = bytes_obj
        self.offset = offset

        # Internal state
        self.__idx = 0
        self.state = self.ParseState.roo

        # Variables to return
        self.stream = stream
        self.errors = []
        self.javascripts_without_xfa = []
        self.xfas = []
        self.features = {'num_hex_in_name': 0, 'num_hex_in_filter_name': 0,
                         'num_character_in_name': 0, 'num_cmd': 0,
                         'num_filter': {
                            'num_filter_AHx': 0, 'num_filter_A85': 0,
                            'num_filter_LZW': 0, 'num_filter_Fl': 0,
                            'num_filter_RL': 0, 'num_filter_CCF': 0,
                            'num_filter_DCT': 0, 'num_filter_JBIG2': 0,
                            'num_filter_JPX': 0, 'num_filter_Crypt': 0},
                         'num_multi_filter': {}, 'num_name': {}
                         }

    def parse(self):
        try:
            content = self.__parse_obj()
            num_corrupted_obj = 0
        except Exception as e:
            if type(e) != PDFError:
                traceback.print_exc()
            self.errors.append(e)
            num_corrupted_obj = 1
            content = {}

        num_stream = 0
        num_failed_decoding = 0
        if self.stream is not None:
            num_stream = 1
            try:
                self.stream = self.__parse_stream(content)
            except:
                num_failed_decoding = 1

        self.features.update({'num_corrupted_obj': num_corrupted_obj,
                              'num_correct_obj': 1-num_corrupted_obj,
                              'num_failed_decoding': num_failed_decoding,
                              'num_succeeded_decoding': 1-num_failed_decoding,
                              'num_stream': num_stream})
        return {'content': content, 'stream': self.stream,
                'errors': self.errors,
                'javascripts_without_xfa': self.javascripts_without_xfa,
                'xfas': self.xfas, 'features': self.features}

    def __parse_obj(self):
        stat_stack = queue.LifoQueue()
        data_stack = queue.LifoQueue()

        while self.__idx < len(self.bytes_obj):
            cur_bytes = self.bytes_obj[self.__idx:]
            # print(self.state, self.__idx, cur_bytes[:100])
            if (cur_bytes[0:1] == b' ' or cur_bytes[0:1] == b'\n' or
                    cur_bytes[0:1] == b'\r' or cur_bytes[0:1] == b'\t' or
                    cur_bytes[0:1] == b'\0' or cur_bytes[0:1] == b'\f'):
                self.__set_stat_and_idx(None, 1)

            elif cur_bytes[0:1] == b'[':
                # Beginning of Array type
                data_stack.put(None)
                stat_stack.put(self.state)
                self.__set_stat_and_idx(self.ParseState.arr, 1)

            elif cur_bytes[0:2] == b'<<':
                # Beginning of Dictionary type
                data_stack.put(None)
                stat_stack.put(self.state)
                self.__set_stat_and_idx(self.ParseState.dic, 2)

            elif cur_bytes[0:1] == b'(':
                # String type
                parenthesis_count = 0
                cur_bytes_idx = 0
                while True:
                    cur_bytes_idx += 1
                    if cur_bytes_idx >= len(cur_bytes):
                        raise PDFError('str', self.offset + self.__idx,
                                       self.__msg_for_err())

                    if cur_bytes[cur_bytes_idx] == b'\\'[0]:
                        cur_bytes_idx += 1
                        continue
                    elif cur_bytes[cur_bytes_idx] == b')'[0]:
                        if parenthesis_count > 0:
                            parenthesis_count -= 1
                            continue
                        else:
                            # End position of literal string is reached.
                            val = cur_bytes[1:cur_bytes_idx]

                            # Replace all of octal values to characters.
                            bytes_list = []
                            prev_end_i = 0
                            while True:
                                match_obj = self.regex_string_hex.search(
                                    val, prev_end_i)
                                if match_obj is None:
                                    bytes_list.append(val[prev_end_i:])
                                    break
                                octal = match_obj.group(1)
                                literal = chr(int(octal, 8)).encode()

                                start_i = match_obj.start()
                                bytes_list.append(val[prev_end_i:start_i])
                                bytes_list.append(literal)
                                prev_end_i = match_obj.end()
                            val = b''.join(bytes_list)

                            data_stack.put(val)
                            self.__set_stat_and_idx(None, cur_bytes_idx+1)
                            break
                    elif cur_bytes[cur_bytes_idx] == b'('[0]:
                        parenthesis_count += 1
                        continue

                # cmd.exe 있는지 검사
                if val[:7].lower() == b'cmd.exe':
                    self.features['num_cmd'] += 1

            elif cur_bytes[0:1] == b'%':
                match_obj = self.regex_newline.search(cur_bytes)
                if match_obj is None:
                    raise PDFError('comment', self.offset + self.__idx,
                                   self.__msg_for_err())
                newline_idx = match_obj.end()
                self.__set_stat_and_idx(None, newline_idx)

            elif cur_bytes[0:1] == b']':
                # End of Array type
                vals = []
                while True:
                    data = data_stack.get(False)
                    if data is None:
                        break
                    else:
                        vals.append(data)
                vals.reverse()
                data_stack.put(vals)
                self.__set_stat_and_idx(stat_stack.get(False), 1)

            elif cur_bytes[0:2] == b'>>':
                # End of Dictionary type
                keys_and_vals = []
                while True:
                    try:
                        val = data_stack.get(False)
                        if val is None:
                            break
                        key = data_stack.get(False)
                    except:
                        raise PDFError('dict_key', self.offset + self.__idx,
                                       self.__msg_for_err())
                    keys_and_vals.append((key, val))

                keys_and_vals.reverse()
                keys_and_vals_dict = dict(keys_and_vals)
                data_stack.put(keys_and_vals_dict)
                self.__set_stat_and_idx(stat_stack.get(False), 2)

                for key, val in keys_and_vals_dict.items():
                    # Save all JavaScripts and XFAs
                    if type(val) == bytes:
                        if key == b'/JS':
                            self.javascripts_without_xfa.append(val)
                        if key == b'/XFA':
                            self.xfas.append(val)

                    if key == b'/Subtype' and type(val) == bytes:
                        lower_val = val.lower()
                        if lower_val.endswith(b'flash'):
                            pass
                        elif lower_val.endswith(b'pdf'):
                            pass

            else:
                # Parsing item
                match_obj = self.regex_primitive.match(cur_bytes)
                if match_obj is None:
                    raise PDFError(self.state, self.offset + self.__idx,
                                   self.__msg_for_err())
                val = match_obj.group(1)
                len_val = len(val)

                if match_obj.group('bool') is not None:
                    val = bool(val)

                elif match_obj.group('num') is not None:
                    val = float(val)

                elif match_obj.group('hex') is not None:
                    val = b'0x' + val.strip()[1:-1]

                # name 이면 모든 #XX값을 ascii_table을 보고 ascii 값으로 치환
                elif match_obj.group('name') is not None:
                    self.features['num_character_in_name'] += len(val)
                    # 모든 hex 인덱스를 찾아 그부분만 바꿔주는 방법
                    hex_idxs = [m.start() for m
                                in self.regex_name_hex.finditer(val)]
                    if len(hex_idxs) > 0:
                        self.features['num_hex_in_name'] += len(hex_idxs)
                        bytes_list = []
                        prev_hex_idx = 0

                        for hex_idx in hex_idxs:
                            # Hex 아닌값들
                            bytes_list.append(val[prev_hex_idx: hex_idx])
                            # Hex 값 치환
                            try:
                                c = chr(int(val[hex_idx+1:hex_idx+3], 16))
                                bytes_list.append(c.encode())
                            except:
                                print(val[hex_idx:hex_idx+3])
                                bytes_list.append(val[hex_idx:hex_idx+3])
                            # Hex 인덱스(3)만큼 이동
                            prev_hex_idx = hex_idx + 3
                        # Hex 아닌 끝부분 값들
                        bytes_list.append(val[prev_hex_idx:])

                        val = b''.join(bytes_list)
                        if val in self.filter_names:
                            self.features['num_hex_in_filter_name'] += len(
                                hex_idxs)

                    # 현재 Name 타입의 갯수 1 증가
                    feature_name = 'num_name_' + val[1:].decode(
                        errors='replace')
                    if feature_name in self.features['num_name']:
                        self.features['num_name'][feature_name] += 1
                    else:
                        self.features['num_name'][feature_name] = 1

                data_stack.put(val)
                self.__set_stat_and_idx(None, len_val)

        return data_stack.get(False)

    def __parse_stream(self, content):
        stream = self.stream
        if b'/Filter' in content:
            filters = content[b'/Filter']

            # Filter parameter to decode
            if b'/DecodeParms' in content:
                params = content[b'/DecodeParms']
                # for문을 쓰기 위해 리스트가 아니면 리스트로 만듬
                if type(params) != list:
                    params = [params]
            else:
                params = [{} for _ in range(len(filters))]

            # (for문을 쓰기 위해) 리스트가 아니면 리스트로 만듬
            if type(filters) != list:
                filters = [filters]

            num_filters = len(filters)
            key = 'num_multi_filter_%d' % num_filters
            if key in self.features['num_multi_filter']:
                self.features['num_multi_filter'][key] += 1
            else:
                self.features['num_multi_filter'][key] = 1

            for i, filter_ in enumerate(filters):
                param = params[i]
                if filter_ == b'/ASCIIHexDecode' or filter_ == b'/AHx':
                    stream = self.Decoder.ASCIIHexDecode(stream)
                    self.features['num_filter']['num_filter_AHx'] += 1
                elif filter_ == b'/ASCII85Decode' or filter_ == b'/A85':
                    stream = self.Decoder.ASCII85Decode(stream)
                    self.features['num_filter']['num_filter_A85'] += 1
                elif filter_ == b'/LZWDecode' or filter_ == b'/LZW':
                    stream = self.Decoder.LZWDecode(stream, param)
                    self.features['num_filter']['num_filter_LZW'] += 1
                elif filter_ == b'/FlateDecode' or filter_ == b'/Fl':
                    stream = self.Decoder.FlateDecode(stream, param)
                    self.features['num_filter']['num_filter_Fl'] += 1
                elif filter_ == b'/RunLengthDecode' or filter_ == b'/RL':
                    stream = self.Decoder.RunLengthDecode(stream)
                    self.features['num_filter']['num_filter_RL'] += 1
                elif filter_ == b'/CCITTFaxDecode' or filter_ == b'/CCF':
                    stream = self.Decoder.CCITTFaxDecode(stream, param)
                    self.features['num_filter']['num_filter_CCF'] += 1
                elif filter_ == b'/JBIG2Decode':
                    stream = self.Decoder.JBIG2Decode(stream, param)
                    self.features['num_filter']['num_filter_JBIG2'] += 1
                elif filter_ == b'/DCTDecode' or filter_ == b'/DCT':
                    stream = self.Decoder.DCTDecode(stream, param)
                    self.features['num_filter']['num_filter_DCT'] += 1
                elif filter_ == b'/JPXDecode':
                    stream = self.Decoder.JPXDecode(stream)
                    self.features['num_filter']['num_filter_JPX'] += 1
                elif filter_ == b'/Crypt':
                    stream = self.Decoder.Crypt(stream, param)
                    self.features['num_filter']['num_filter_Crypt'] += 1
                else:
                    stream_idx = self.offset + len(self.bytes_obj)
                    msg = '%s는 잘못된 필터 이름' % filter_
                    raise PDFError('filter_name', stream_idx, msg)

        return stream

    def __msg_for_err(self, byte_range=25):
        return ('\n(View) %s오류시작%s' %
                (self.bytes_obj[self.__idx-byte_range:self.__idx],
                 self.bytes_obj[self.__idx:self.__idx+byte_range]))

    def __set_stat_and_idx(self, stat, idx):
        self.__idx += idx
        if stat is not None:
            self.stat = stat


def run(pdf, dataset_types, raw_file_info):
    import json

    file_info = json.loads(raw_file_info)
    try:
        pdf.parse(file_info.pop('file_path'))
        features = pdf.make_features(dataset_types)
        file_info.update(features)
    except Exception as e:
        raise e
    return json.dumps(file_info)


if __name__ == '__main__':
    import sys
    import multiprocessing
    from functools import partial

    pdf = PDF()
    dataset_types = [
                     # FeatureType.num_name,
                     FeatureType.num_suspicious_name,

                     FeatureType.num_filter,
                     FeatureType.ratio_filter,
                     FeatureType.num_multi_filter,
                     FeatureType.num_hex_in_filter_name,

                     FeatureType.num_cmd,
                     FeatureType.num_file,

                     FeatureType.js_max_line_length,
                     FeatureType.js_ratio_in_size,
                     FeatureType.js_num_api,

                     # FeatureType.object_entropy,
                     FeatureType.format_error,
                     FeatureType.appended_tail_len,
                     FeatureType.appended_tail_entropy,
                     FeatureType.file_size,
                     FeatureType.ratio_hex_in_name,
                   ]

    with multiprocessing.Pool() as pool:
        func = partial(run, pdf, dataset_types)
        for out in pool.imap_unordered(func, sys.argv[1:]):
            print(out)
