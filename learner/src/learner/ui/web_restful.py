'''
**This describes definitions of restful web interfaces to control Learner.**
You can find Flask-RESTful documentation here:
http://flask-restful-cn.readthedocs.io/en/0.3.5/
'''
# Default packages
import json
from collections import OrderedDict

# 3rd-party packages
import flask
import flask_restful as rest
import flask_restful.reqparse as reqparse
import flask_restful.inputs as inputs


# Internal packages
from learner.util.essential import cursor_to_data, remove_if_value_is_empty

app = flask.Flask(__name__)
api = rest.Api(app)
cluster_master = None  # 이 값은 외부에서 세팅됨

debug = True


# #################### Miscellaneous #################### #
rgx_datetime_str = (r'^([0-9]{2,4})-([0-1][0-9])-([0-3][0-9])' +
                    '(?:( [0-2][0-9]):([0-5][0-9]):([0-5][0-9]))?$')
rgx_datetime = inputs.regex(rgx_datetime_str)

rgx_data_type_label = inputs.regex(r'^[A-Za-z][A-Za-z0-9]+$')


# #################### File Info and File Group Info #################### #

class Files(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('where_stmt', type=str, location='args')
        self.get_parser.add_argument('where_vals', type=str, location='args',
                                     action='append')
        self.get_parser.add_argument('group', type=str, location='args')
        self.get_parser.add_argument('data_type', type=str, location='args')
        self.get_parser.add_argument('label', type=str, location='args')
        self.get_parser.add_argument('sublabel', type=str, location='args')
        self.get_parser.add_argument('limit', type=int, location='args',
                                     ignore=True)
        self.get_parser.add_argument('show_count', type=int, location='args',
                                     ignore=True)

        self.post_parser = reqparse.RequestParser()
        # self.post_parser.add_argument('file_seq', type=int)
        # self.post_parser.add_argument('parent_file_seq', type=int)
        # self.post_parser.add_argument('root_file_seq', type=int)
        # self.post_parser.add_argument('num_dup_files', type=int)
        self.post_parser.add_argument('group', type=str)
        self.post_parser.add_argument('data_type', type=rgx_data_type_label)
        self.post_parser.add_argument('label', type=rgx_data_type_label)
        self.post_parser.add_argument('sublabel', type=str)
        # self.post_parser.add_argument('md5', type=str)
        # self.post_parser.add_argument('sha1', type=str)
        # self.post_parser.add_argument('sha256', type=str)
        # self.post_parser.add_argument('file_size', type=int)
        self.post_parser.add_argument('importance', type=float, ignore=True)
        self.post_parser.add_argument('download_url', type=str)
        self.post_parser.add_argument('tags', type=str)

        self.post_parser.add_argument('created_datetime', type=rgx_datetime)
        self.post_parser.add_argument('deleted_datetime', type=rgx_datetime)

    def get(self):
        args = remove_if_value_is_empty(dict(self.get_parser.parse_args()))
        limit = args.pop('limit', None)
        show_count = args.pop('show_count', 0)
        try:
            cursor = cluster_master.get_file_info(**args)
            rowcount = cursor.rowcount
            if rowcount > 100000 and show_count == 0:
                e = AssertionError('Too many records (%d > 100000)' % rowcount)
                # Request Entity Too Large
                return _exception_restful_msg(e), 413

            if show_count == 0:
                if limit is not None:
                    return cursor_to_data(cursor, limit), 200  # OK
                else:
                    return cursor_to_data(cursor), 200  # OK
            else:
                return cursor.rowcount, 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def post(self):
        args = remove_if_value_is_empty(dict(self.post_parser.parse_args()))
        if ('data_type' not in args or
                'label' not in args or 'sublabel' not in args):
            msg = 'You have to specify data_type, label and sublabel.'
            e = AssertionError(msg)
            return _exception_restful_msg(e), 409  # Conflict

        files = flask.request.files.getlist("files")
        out = []
        for file in files:
            bytes_file = file.stream.read()
            file_name = file.filename
            args.update({'file_name': file_name, 'bytes_file': bytes_file})
            try:
                out.append(cluster_master.upload_file(**args))
            except Exception as e:
                out.append(_exception_restful_msg(e))

        return out, 200  # OK


class File(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('group', type=str, location='args')
        self.get_parser.add_argument('data_type', type=str, location='args')
        self.get_parser.add_argument('label', type=str, location='args')
        self.get_parser.add_argument('sublabel', type=str, location='args')

    def get(self, sha256):
        args = remove_if_value_is_empty(dict(self.get_parser.parse_args()))
        args.update({'where_stmt': 'sha256=%s', 'where_vals': [sha256]})

        try:
            file_info_cursor = cluster_master.get_file_info(**args)
            if file_info_cursor.rowcount == 0:
                return None, 404  # Not Found

            row_dict = cursor_to_data(file_info_cursor)[0]
            return row_dict, 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def put(self, sha256):
        pass

    def delete(self, sha256):
        pass


class FileDownload(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('group', type=str, location='args')
        self.get_parser.add_argument('data_type', type=str, location='args')
        self.get_parser.add_argument('label', type=str, location='args')

    def get(self, sha256):
        args = remove_if_value_is_empty(dict(self.get_parser.parse_args()))
        args.update({'where_stmt': 'sha256=%s', 'where_vals': [sha256]})
        try:
            file_info_cursor = cluster_master.get_file_info(**args)
            if file_info_cursor.rowcount == 0:
                return None, 404  # Not Found

            row_dict = cursor_to_data(file_info_cursor)[0]
            bytes_file = cluster_master.download_file(row_dict['sha256'])
            response = flask.make_response(bytes_file)
            disposition = 'attachment; filename="%s"' % row_dict['file_name']
            response.headers['content-disposition'] = disposition
            response.headers['content-type'] = 'application/octet-stream'
            return response

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict


api.add_resource(Files, '/files')
api.add_resource(File, '/files/<sha256>')
api.add_resource(FileDownload, '/files/<sha256>/download')


# #################### Dataset Generator #################### #

class DatasetGenerators(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('where_stmt', type=str, location='args')
        self.get_parser.add_argument('where_vals', type=str, location='args',
                                     action='append', default=[])

        self.post_parser = reqparse.RequestParser()
        # self.post_parser.add_argument('generator_seq', type=int)
        self.post_parser.add_argument('generator_name', type=str)
        self.post_parser.add_argument('target_data_type', type=str)
        self.post_parser.add_argument('attrs', type=str)
        self.post_parser.add_argument('features', type=str)
        # self.post_parser.add_argument('docker_image_id', type=int)
        # self.post_parser.add_argument('created_datetime', type=int)
        self.post_parser.add_argument('tags', type=str)

    def get(self):
        args = dict(self.get_parser.parse_args())

        try:
            cursor = cluster_master.get_dataset_generator(**args)
            rowcount = cursor.rowcount
            if rowcount > 100000:
                e = AssertionError('Too many records (%d > 100000)' % rowcount)
                # Request Entity Too Large
                return _exception_restful_msg(e), 413

            return cursor_to_data(cursor), 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def post(self):
        args = remove_if_value_is_empty(dict(self.post_parser.parse_args()))

        try:
            file = flask.request.files['file']
            bytes_file = file.stream.read()
            args.update({'bytes_file': bytes_file})

            generator_info = cluster_master.upload_docker_image(**args)
            return generator_info, 201  # Created

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict


class DatasetGenerator(rest.Resource):
    def __init__(self):
        pass

    def get(self, name):
        try:
            dataset_gen_cursor = cluster_master.get_dataset_generator(
                'generator_name=%s', [name])
            if dataset_gen_cursor.rowcount == 0:
                return None, 404  # Not Found

            row_dict = cursor_to_data(dataset_gen_cursor)[0]
            return row_dict, 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def put(self, name):
        pass

    def delete(self, name):
        pass


class DatasetGeneratorDownload(rest.Resource):
    def get(self, name):
        try:
            file_info_cursor = cluster_master.get_dataset_generator(
                'generator_name=%s', [name])
            if file_info_cursor.rowcount == 0:
                return None, 404  # Not Found

            row_dict = cursor_to_data(file_info_cursor)[0]
            bytes_docker_image = cluster_master.download_docker_image(
                row_dict['docker_image_id'])

            response = flask.make_response(bytes_docker_image)
            disposition = ('attachment; filename="%s.tar"' %
                           row_dict['generator_name'])
            response.headers['content-disposition'] = disposition
            response.headers['content-type'] = 'application/octet-stream'
            return response

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict


api.add_resource(DatasetGenerators, '/dataset/generators')
api.add_resource(DatasetGenerator, '/dataset/generators/<name>')
api.add_resource(DatasetGeneratorDownload,
                 '/dataset/generators/<name>/download')


# #################### Dataset Info #################### #

class DatasetInfoList(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('where_stmt', type=str, location='args')
        self.get_parser.add_argument('where_vals', type=str, location='args',
                                     action='append', default=[])

        self.post_parser = reqparse.RequestParser()
        self.post_parser.add_argument('generator_name', type=str)

    def get(self):
        args = dict(self.get_parser.parse_args())

        try:
            cursor = cluster_master.get_dataset_info(**args)
            rowcount = cursor.rowcount
            if rowcount > 100000:
                e = AssertionError('Too many records (%d > 100000)' % rowcount)
                # Request Entity Too Large
                return _exception_restful_msg(e), 413

            return cursor_to_data(cursor), 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def post(self):
        args = remove_if_value_is_empty(dict(self.post_parser.parse_args()))
        dataset_info = cluster_master.create_datasets(**args)
        return dataset_info, 201  # Created

    def patch(self):
        'Start generating datasets (parsing files)'
        try:
            running_info_list = []
            cursor = cluster_master.get_dataset_info()
            dataset_info_list = cursor_to_data(cursor)
            for dataset_info in dataset_info_list:
                o = cluster_master.update_dataset(dataset_info['dataset_name'])
                if o is not None:
                    running_info_list.append(o)

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict
        return running_info_list, 200  # OK


class DatasetInfo(rest.Resource):
    def __init__(self):
        pass

    def get(self, name):
        try:
            dataset_info_cursor = cluster_master.get_dataset_info(
                'dataset_name=%s', [name])
            if dataset_info_cursor.rowcount == 0:
                return None, 404  # Not Found

            row_dict = cursor_to_data(dataset_info_cursor)[0]
            return row_dict, 200

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def patch(self, name):
        'Start generating dataset (parsing files)'
        try:
            running_info = cluster_master.update_dataset(name)
            if running_info is None:
                return None, 404  # Not Found
            else:
                return running_info, 200

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def delete(self, name):
        pass


class DatasetInfoDownload(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('beginning_created_datetime',
                                     type=rgx_datetime, location='args')
        self.get_parser.add_argument('end_created_datetime',
                                     type=rgx_datetime, location='args')

    def get(self, name):
        # args = dict(self.get_parser.parse_args())
        pass

api.add_resource(DatasetInfoList, '/dataset/info')
api.add_resource(DatasetInfo, '/dataset/info/<name>')
api.add_resource(DatasetInfoDownload, '/dataset/info/<name>/download')


# #################### Classification Algorithm #################### #

class ClassificationAlgorithms(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('where_stmt', type=str, location='args')
        self.get_parser.add_argument('where_vals', type=str, location='args',
                                     action='append', default=[])

        self.post_parser = reqparse.RequestParser()
    # self.post_parser.add_argument('classification_algorithm_seq', type=int)
        self.post_parser.add_argument('algorithm_name', type=str)
        self.post_parser.add_argument('init_params', type=str)
        self.post_parser.add_argument('variable_params', type=str)
        self.post_parser.add_argument('support_distribution', type=int)
        self.post_parser.add_argument('gen_dataset_dims', type=int)
        self.post_parser.add_argument('algorithm', type=str)
        self.post_parser.add_argument('tags', type=str)
        # self.post_parser.add_argument('created_datetime', type=str)

    def get(self):
        args = dict(self.get_parser.parse_args())

        try:
            algorithm_info_list = cluster_master.get_classification_algorithm(
                                                                        **args)
            return algorithm_info_list, 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def post(self):
        args = remove_if_value_is_empty(dict(self.post_parser.parse_args()))
        file = flask.request.files['file']
        bytes_file = file.stream.read()
        args.update({'algorithm': bytes_file})
        try:
            algorithm_info = cluster_master.upload_classification_algorithm(
                                                                        **args)
            return algorithm_info, 201  # Created

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict


class ClassificationAlgorithm(rest.Resource):
    def __init__(self):
        pass

    def get(self, name):
        try:
            algorithm_info_list = cluster_master.get_classification_algorithm(
                'algorithm_name=%s', [name])
            if len(algorithm_info_list) == 0:
                return None, 404
            else:
                return algorithm_info_list[0], 200

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def put(self, name):
        pass

    def delete(self, name):
        pass


class ClassificationAlgorithmDownload(rest.Resource):
    def get(self, name):
        try:
            algorithm = cluster_master.download_classification_algorithm(name)
            response = flask.make_response(algorithm)
            disposition = ('attachment; filename="%s"' % (name + '.py'))
            response.headers['content-disposition'] = disposition
            response.headers['content-type'] = 'application/octet-stream'
            return response

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

api.add_resource(ClassificationAlgorithms, '/classification/algorithms')
api.add_resource(ClassificationAlgorithm, '/classification/algorithms/<name>')
api.add_resource(ClassificationAlgorithmDownload,
                 '/classification/algorithms/<name>/download')


# #################### Classification Learner #################### #

class ClassificationLearners(rest.Resource):
    def __init__(self):
        self.get_parser = reqparse.RequestParser()
        self.get_parser.add_argument('where_stmt', type=str, location='args')
        self.get_parser.add_argument('where_vals', type=str, location='args',
                                     action='append', default=[])

        self.post_parser = reqparse.RequestParser()
        self.post_parser.add_argument('target_datasets', type=str)
        self.post_parser.add_argument('target_features', type=str)
        self.post_parser.add_argument('dataset_proportion', type=str)
        # self.post_parser.add_argument('classification_learner_seq', type=int)
        self.post_parser.add_argument('algorithm_name', type=str)
        self.post_parser.add_argument('learner_name', type=str)
        # self.post_parser.add_argument('target_data_type', type=str)
        # self.post_parser.add_argument('learner', type=str)
        self.post_parser.add_argument('params', type=str)
        # self.post_parser.add_argument('feature_idxs', type=str)
        # self.post_parser.add_argument('attr_cols', type=str)
        # self.post_parser.add_argument('created_datetime', type=str)
        # self.post_parser.add_argument('updated_datetime', type=str)
        self.post_parser.add_argument('tags', type=str)

    def get(self):
        args = dict(self.get_parser.parse_args())

        try:
            return cluster_master.get_classification_learner(**args), 200  # OK

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def post(self):
        args = remove_if_value_is_empty(dict(self.post_parser.parse_args()))
        if not ('target_datasets' in args and 'algorithm_name' in args and
                'params' in args):
            msg = 'You have to specify target_datasets, '
            e = AssertionError(msg + 'algorithm_name and params')
            return _exception_restful_msg(e), 409  # Conflict

        args['od_target_datasets'] = json.loads(
            args.pop('target_datasets'), object_pairs_hook=OrderedDict)
        args['params'] = json.loads(args['params'])
        if hasattr(args, 'target_features'):
            args['features'] = json.loads(args.pop('target_features'))

        try:
            learner_info = cluster_master.create_classificiation_learner(
                                                                        **args)
            return learner_info, 201  # Created

        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict


class ClassificationLearner(rest.Resource):
    def __init__(self):
        self.patch_parser = reqparse.RequestParser()
        self.patch_parser.add_argument('num_iter', type=int)
        self.patch_parser.add_argument('eval_period', type=int)
        self.patch_parser.add_argument('batch_size', type=int)
        self.patch_parser.add_argument('learning_rate', type=float)
        self.patch_parser.add_argument('need_num_gpus', type=int)
        self.patch_parser.add_argument('save_prediction_result', type=int)

    def get(self, name):
        pass

    def put(self, name):
        pass

    def patch(self, name):
        args = remove_if_value_is_empty(dict(self.patch_parser.parse_args()))
        try:
            out = cluster_master.full_training_for_classification_learner(
                name, **args)
            return out, 200
        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

    def delete(self, name):
        pass


class ClassificationLearnerLog(rest.Resource):
    def get(self, name):
        out = cluster_master.get_classification_learner_log(name)
        if out is None:
            return None, 404
        else:
            return out, 200


class ClassificationLearnerLogHtml(rest.Resource):
    def get(self, name):
        out = cluster_master.get_classification_learner_log(name)
        if out is None:
            return None, 404
        else:
            js = '''
            <script type="text/javascript">
            function moveWin() {
                window.scroll(0,document.body.scrollHeight);
            }
            setTimeout("moveWin();", 0);
            </script>
            '''
            html = ('<html><body>%s</body>%s<html>' %
                    (out['recent_training_log'].replace('\n', '<br>'), js))

            response = flask.make_response(html)
            response.headers['content-type'] = 'text/html'
            return response


class ClassificationLearnerDownload(rest.Resource):
    def get(self, name):
        pass


class ClassificationLearnerPredict(rest.Resource):
    def post(self, name):
        files = flask.request.files.getlist("files")
        file_with_info_list = []
        total_file_size = 0
        for file in files:
            file_with_info = {}
            bytes_file = file.stream.read()

            # If total size of files is over 1GB, refuse it.
            total_file_size += len(bytes_file)
            if total_file_size > 1073741824:
                msg = 'Total size of group files is over 1GB.'
                msg += 'Please, split it into small size of partial files.'
                return {'msg': msg}, 413
                break

            file_name = file.filename
            file_with_info.update(
                {'file_name': file_name, 'bytes_file': bytes_file})
            file_with_info_list.append(file_with_info)

        return cluster_master.predict_with_classification_learner(
                    name, file_with_info_list), 200


api.add_resource(ClassificationLearners, '/classification/learners')
api.add_resource(ClassificationLearner, '/classification/learners/<name>')
api.add_resource(
    ClassificationLearnerLog, '/classification/learners/<name>/log')
api.add_resource(
    ClassificationLearnerLogHtml, '/classification/learners/<name>/log.html')
api.add_resource(
    ClassificationLearnerDownload, '/classification/learners/<name>/download')
api.add_resource(
    ClassificationLearnerPredict, '/classification/learners/<name>/predict')


# ################### Classification Learner Result Info ################### #

class ClassificationLearnerResultInfo(rest.Resource):
    def __init__(self):
        pass

    def get(self):
        pass

    def put(self):
        pass

    def delete(self):
        pass


class ClassificationLearnerResultInfoList(rest.Resource):
    def __init__(self):
        pass

    def get(self):
        pass

    def post(self):
        pass

api.add_resource(ClassificationLearnerResultInfo,
                 '/classification/result/<data_type>/<seq>')
api.add_resource(ClassificationLearnerResultInfoList,
                 '/classification/result/<data_type>')


# #################### Helper Functions #################### #

def _exception_restful_msg(exception_obj):
    msg = ('%s: %s' % (type(exception_obj).__name__, str(exception_obj)))
    return {'message': msg}


# #################### Miscellaneous #################### #

class PDFAnalyzer(rest.Resource):
    def __init__(self):
        import os
        import sys
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        libpath = r'../../../../learner_parser/src/learner/parser'
        sys.path.insert(0, os.path.realpath(libpath))
        from pdf.main import PDF
        self.pdf = PDF()

    def post(self):
        try:
            file = flask.request.files['file']
            bytes_file = file.stream.read()
            self.pdf.parse(bytes_pdf=bytes_file)
            out = self.pdf.pretty_print()
            response = flask.make_response(out)
            if len(out) > 100000000:
                disposition = 'attachment; filename="%s.log"' % file.filename
                response.headers['content-disposition'] = disposition
                response.headers['content-type'] = 'application/octet-stream'
                return response
            else:
                response.headers['content-type'] = 'text'
                return response
        except Exception as e:
            if debug:
                raise e
            else:
                return _exception_restful_msg(e), 409  # Conflict

api.add_resource(PDFAnalyzer, '/pdf_analyzer')

if __name__ == '__main__':
    # app.run('127.0.0.1', 8000, debug=True)
    pass
