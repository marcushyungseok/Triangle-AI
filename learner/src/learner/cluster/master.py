# -*- coding: utf-8 -*-
'''
**This module defines the interfaces for controlling the cluster through
the master node.** When the master node receives a command through the
interface, it creates tasks and distributes it to the connected slave nodes
for distributed processing.

Some interfaces for DB queries or a small amount of file test could be
processed only on the master node, not on the slave node.

.. |data_type| replace:: Data type such as PDF, SWF, etc.
.. |label| replace:: Label such as benign, malicious, etc.
.. |sublabel| replace:: Sub-label such as cve-xxxx-xxxx, etc.
.. |where_stmt| replace:: A where SQL statement containing question mark
        that represents a value.
        (e.g. "file_size>? and created_datetime>?")
.. |where_vals| replace:: Sequential value list for "?" used in where_stmt.
        (e.g. [102400, "2016-12-24 20:40:31"])
.. |column_names| replace:: Comma-separated column names to print
        (e.g. "file_size, created_datetime")
'''
# Default packages
import io
import os
import sys
import json
import tarfile
import logging
import threading
from copy import deepcopy
from datetime import datetime
from collections import OrderedDict

# 3rd-party packages

# Internal packages
import learner.db as db
from learner.db.rdb_schemas import Tables
import learner.ui.web_restful as web_restful
from learner.cluster.master_controller import _ClusterMaster
from learner.cluster.slave import _ClusterSlave
from learner.util.essential import (cal_hashes, cursor_to_data,
                                    remove_if_value_is_empty)

logger = logging.getLogger(__name__)
os.environ['CUDA_VISIBLE_DEVICES'] = ''


def run(cluster_spec, web_interface_port):
    '''Run the Master of the cluster with restful web server.

    :param dict cluster_spec: e.g.
        {'mongodb': {'host': '127.0.0.1', 'port':27017}, 'nfs':...,
        'master':..., 'slaves':[{'host':...}, {...}, ...]}
    :param int web_interface_port: Port number of the restful web server
    '''
    global cluster_mgr, file_mgr, slave_lib

    file_mgr = db.nfs.NFSManager(cluster_spec)
    cluster_mgr = _ClusterMaster(cluster_spec)
    slave_lib = _ClusterSlave(cluster_spec)

    # Creating and starting the web interface
    class WebFlaskThread(threading.Thread):
        def run(self):
            web_restful.cluster_master = sys.modules[__name__]
            web_restful.app.run(port=web_interface_port, threaded=True,
                                debug=True, use_reloader=False,
                                )
    WebFlaskThread().start()

    cluster_mgr.run_forever()


# #################### File Info and File Group Info #################### #

def upload_file(bytes_file, file_name, data_type, label, sublabel,
                **file_info):
    '''Upload file and file information.

    :param bytes bytes_file: A file loaded in memory
    :param str file_name: File name
    :param str data_type: |data_type|
    :param str label: |label|
    :param str sublabel: |sublabel|
    :param str download_url: (Optional) URL where the file was downloaded
    :param int importance: (Optional) This value increases the learning
        intensity of the file
    :param str md5: (Optional) MD5 of the file
    :param str sha1: (Optional) SHA1 of the file
    :param str sha256: (Optional) SHA256 of the file
    :param int parent_file_seq: (Optional) The sequence number of a parent file
    :param int root_file_seq: (Optional) The sequence number of a root
        ancestor file
    :return: sha256
    :rtype: dict
    :raises FileExistsError: If given file exists in the disk
    '''
    data_type_label_sublabel = data_type + '_' + label + '_' + sublabel + '_'
    args = {'file_name': file_name, 'data_type': data_type, 'label': label,
            'sublabel': sublabel, 'file_size': len(bytes_file),
            'data_type_label_sublabel': data_type_label_sublabel}
    file_info.update(args)
    file_info = remove_if_value_is_empty(file_info)

    if len(set(['md5', 'sha1', 'sha256']) & set(file_info.keys())) != 3:
        hashes = cal_hashes(bytes_file)
        file_info.update(hashes)
    db.rdb.insert(Tables.FileInfo.name, file_info,
                  __gen_partition_names(data_type, label, sublabel))
    try:
        file_mgr.save_file(bytes_file, hashes['sha256'])
    except FileExistsError:
        logger.info('File already exist in NFS.')
    logger.info(' [File uploaded] sha256: %s' % hashes['sha256'])
    return {'sha256': hashes['sha256']}


def get_file_info(data_type=None, label=None, sublabel=None, where_stmt=None,
                  where_vals=None, column_names='*', order_by=None):
    '''Get file information.

    :param str data_type: |data_type|
    :param str label: |label|
    :param str sublabel: |sublabel|
    :param str where_stmt: |where_stmt|
    :param list where_vals: |where_vals|
    :param str column_names: |column_names|
    :param str order_by: Order-by statement for given column sorting
        (e.g. "created_datetime DESC")
    :return: A DB cursor for files.
    :rtype: pymysql.cursor
    '''
    partition_names = __gen_partition_names(data_type, label, sublabel)
    if partition_names is not None:
        logger.info(' [RDB PARTITION] %s is/are selected' %
                    ', '.join((partition_names)))
    if partition_names == []:
        return db.rdb.cursor()

    cursor = db.rdb.select(Tables.FileInfo.name, where_stmt,
                           where_vals, column_names, order_by, partition_names)
    return cursor


def download_file(sha256):
    '''Returns a file specified by sha256.

    :param str sha256: SHA256 of the file
    '''
    return file_mgr.read_file(sha256)


def __gen_partition_names(data_type, label=None, sublabel=None):
    '''Generates "data_type_label_sublabel" query to leverage the partition
    technique of MariaDB.
    '''
    partition_names = []
    if data_type is not None and label is not None and sublabel is not None:
        prefix_partition_name = data_type + '_' + label + '_' + sublabel + '_'
    elif data_type is not None and label is not None:
        prefix_partition_name = data_type + '_' + label + '_'
    elif data_type is not None:
        prefix_partition_name = data_type + '_'
    else:
        return None

    for partition_name in db.rdb.query_mgr.partition_names:
        if partition_name.startswith(prefix_partition_name):
            partition_names.append(partition_name)
    return partition_names


# #################### Dataset Generator #################### #

def get_dataset_generator(where_stmt=None, where_vals=None):
    '''Returns generator information.

    :param str where_stmt: |where_stmt|
    :param str where_vals: |where_vals|
    '''
    cursor = db.rdb.select(
        Tables.DatasetGenerator.name, where_stmt, where_vals)
    return cursor


def download_docker_image(image_id):
    '''Returns a docker image file specified by image_id.

    :param str image_id:
    '''
    return file_mgr.read_docker_image(image_id)


def upload_docker_image(bytes_file, target_data_type, features,
                        attrs=Tables.FileInfo.attrs, **generator_info):
    '''Upload a docker image file with its information.

    :param bytes bytes_file: Bytes of a docker image
    :param str target_data_type: (e.g. pdf)
    :param str features: JSON form of list of features
    :param str attrs: JSON form of list of attributes
    :param dict generator_info: Optional arguments
        (generator_name, docker_image_id, created_datetime and tags)
    '''
    with tarfile.open(fileobj=io.BytesIO(bytes_file)) as f:
        manifest = json.loads(f.extractfile('manifest.json').read().decode())
        generator_info['docker_image_id'] = manifest[0]['Config'][:12]

    if 'generator_name' not in generator_info:
        generator_info['generator_name'] = generator_info['docker_image_id']

    generator_info.update({'target_data_type': target_data_type,
                           'attrs': attrs, 'features': features})
    db.rdb.insert(Tables.DatasetGenerator.name, generator_info)

    create_datasets(generator_info['generator_name'])
    file_mgr.save_docker_image(bytes_file, generator_info['docker_image_id'])
    return {'generator_name': generator_info['generator_name']}


# #################### Dataset Info #################### #

def get_dataset_info(where_stmt=None, where_vals=None):
    '''Returns dataset information.

    :param str where_stmt: |where_stmt|
    :param str where_vals: |where_vals|
    '''
    cursor = db.rdb.select(
        Tables.DatasetInfo.name, where_stmt, where_vals)
    return cursor


def create_datasets(generator_name=None):
    '''Create empty datasets, if it doesn't exist.

    :param str generator_name:
    '''
    if generator_name is None:
        where_stmt, where_vals = None, None
    else:
        where_stmt, where_vals = 'generator_name=?', [generator_name]
    cursor = get_dataset_generator(where_stmt, where_vals)
    if cursor.rowcount == 0:
        return None
    row_dict = cursor_to_data(cursor)[0]

    out = []
    for label, sublabel in db.rdb.query_mgr.get_full_labels(
                                                row_dict['target_data_type']):
        dataset_name = '%s_%s_%s_%s' % (row_dict['target_data_type'], label,
                                        sublabel, generator_name)

        dataset_info = {'generator_seq': row_dict['generator_seq'],
                        'dataset_name': dataset_name, 'label': label,
                        'sublabel': sublabel,
                        'data_type': row_dict['target_data_type']}

        # Check whether duplicated dataset or not.
        cursor = db.rdb.select(
            Tables.DatasetInfo.name,
            'generator_seq=? and data_type=? and label=? and sublabel=?',
            [dataset_info['generator_seq'], dataset_info['data_type'],
             dataset_info['label'], dataset_info['sublabel']], '1')
        if cursor.rowcount == 0:
            db.rdb.insert(Tables.DatasetInfo.name, dataset_info)
            out.append({'dataset_name': dataset_name})

    return out


def download_dataset(dataset_name, dataset_format='csv', sha256s=None,
                     beginning_created_datetime=None,
                     end_created_datetime=None):
    '''Returns a specified format (such as CSV) of dataset.

    :param str dataset_name:
    :param str dataset_format: Available format: csv (Default: csv)
    :param str sha256s: JSON form of list of SHA256 of files
    :param beginning_created_datetime:
        Beginning value of file of created datetime.
    :type beginning_created_datetime: datetime or str
    :param end_created_datetime: End value of file of created datetime.
    :type end_created_datetime: datetime or str
    '''
    pass


def update_dataset(dataset_name, updated_datetime=None):
    '''Update dataset

    :param str dataset_name:
    :param updated_datetime:
        Only files created before created_datetime are updated.
    :type updated_datetime: datetime or str
    '''
    if updated_datetime is None:
        updated_datetime = datetime.now()

    # Get a record of dataset_info
    dataset_info_list = cursor_to_data(
                        get_dataset_info('dataset_name=?', [dataset_name]))
    if len(dataset_info_list) == 0:
        return None
    dataset_info = dataset_info_list[0]

    # Get a record of dataset_generator
    dataset_generator = cursor_to_data(get_dataset_generator(
        'generator_seq=?', [dataset_info['generator_seq']]))[0]

    # Define task_kwargs
    task_kwargs = {'dataset_name': dataset_name,
                   'docker_image_id': dataset_generator['docker_image_id'],
                   'updated_datetime': str(updated_datetime)}

    # Define task_info
    num_total_files = get_file_info(
        dataset_info['data_type'], dataset_info['label'],
        dataset_info['sublabel']).rowcount
    task_info = deepcopy(task_kwargs)
    task_info.update(
        {'generator_name': dataset_generator['generator_name'],
         'data_type': dataset_info['data_type'],
         'label': dataset_info['label'],
         'sublabel': dataset_info['sublabel'],
         'updated_datetime': str(dataset_info['updated_datetime']),
         'num_total_files': num_total_files})

    # Check it is already processing or not.
    running_states = {}
    num_target_files = None
    for task in cluster_mgr.tasks:
        if task['kwargs'].get('dataset_name') == dataset_name:
            if task['running_state'] in running_states:
                running_states[task['running_state']] += 1
            else:
                running_states[task['running_state']] = 1
                num_target_files = task['num_target_files']

    # If tasks already exist.
    if len(running_states) != 0:
        task_info.update({'running_state': running_states,
                          'num_target_files': num_target_files})
        return task_info

    # Get a cursor of file_info
    where_stmt = 'created_datetime>? AND created_datetime<?'
    where_stmt += ' AND deleted_datetime IS NULL'
    if dataset_info['updated_datetime'] is None:
        where_vals = [0, updated_datetime]
    else:
        where_vals = [dataset_info['updated_datetime'], updated_datetime]

    column_names = ','.join(dataset_generator['attrs'])
    file_info_cursor = get_file_info(
        dataset_info['data_type'], dataset_info['label'],
        dataset_info['sublabel'], where_stmt=where_stmt, where_vals=where_vals,
        column_names=column_names)

    # If there's no files to parse
    if file_info_cursor.rowcount == 0:
        task_info.update({'num_target_files': 0, 'running_state': 'Aborted'})
        return task_info

    # Send to the master of the cluster
    task_kwargs['file_info_cursor'] = file_info_cursor
    cluster_mgr.parsing_for_dataset(**task_kwargs)
    task_info.update({'running_state': 'Created',
                      'num_target_files': file_info_cursor.rowcount})
    return task_info


# #################### Classification Algorithm #################### #

def get_classification_algorithm(where_stmt=None, where_vals=None):
    '''Returns classification algorithm information.

    :param str where_stmt: |where_stmt|
    :param str where_vals: |where_vals|
    '''
    cols = ['classification_algorithm_seq', 'algorithm_name', 'init_params',
            'variable_params', 'support_distribution', 'gen_dataset_dims',
            'tags', 'created_datetime']
    return cursor_to_data(db.rdb.select(Tables.ClassificationAlgorithm.name,
                          where_stmt, where_vals, ','.join(cols)))


def download_classification_algorithm(algorithm_name):
    '''Returns a python script with Tensorflow library.

    :param str algorithm_name:
    '''
    cursor = db.rdb.select(Tables.ClassificationAlgorithm.name,
                           'algorithm_name=?', [algorithm_name], 'algorithm')
    if cursor.rowcount == 0:
        return None
    else:
        return cursor.fetchone()[0]


def upload_classification_algorithm(algorithm, algorithm_name,
                                    **algorithm_info):
    '''Upload a python script with Tensorflow library.

    :param str algorithm: A python script with Tensorflow library.
    :param str algorithm_name:
    :param dict algorithm_info: Optional arguments
        (which are init_params, variable_params, support_distribution,
        gen_dataset_dims and tags)
    '''
    algorithm_info.update({'algorithm': algorithm,
                           'algorithm_name': algorithm_name,
                           'sha256': cal_hashes(algorithm, True)['sha256']})
    db.rdb.insert(Tables.ClassificationAlgorithm.name, algorithm_info)
    return {'algorithm_name': algorithm_name}


# #################### Classification Learner #################### #

def get_classification_learner(where_stmt=None, where_vals=None,
                               for_training=False):
    '''Returns classification algorithm information.

    :param str where_stmt: |where_stmt|
    :param str where_vals: |where_vals|
    '''
    # Get learner information
    cols = ('classification_learner_seq, classification_algorithm_seq, ' +
            'learner_name, attrs, features, params, created_datetime, ' +
            'dataset_updated_datetime')
    if for_training:
        cols += ',learner, scaling_func, scaling_params, feature_idxs'
    cursor = db.rdb.select(Tables.ClassificationLearner.name,
                           where_stmt, where_vals, cols)

    # Get learner algorithm information
    learner_info_list = []
    for learner_info in cursor_to_data(cursor):
        cols = 'algorithm_name'
        if for_training:
            cols += ',algorithm'
        algorithm_info = cursor_to_data(db.rdb.select(
            Tables.ClassificationAlgorithm.name,
            'classification_algorithm_seq=?',
            [learner_info['classification_algorithm_seq']], cols))[0]
        learner_info.update(algorithm_info)

        # Get target datasets and dataset proportion
        relation_info_list = cursor_to_data(db.rdb.select(
            Tables.DatasetToClassificationLearner.name,
            'classification_learner_seq=?',
            [learner_info['classification_learner_seq']],
            order_by='learner_label_idx ASC'))

        # Translate dataset_seq to dataset_name to restore target datasets
        od_tgt_ds = OrderedDict()
        for relation_info in relation_info_list:
            label_name = relation_info['learner_label_name']
            dataset_name = cursor_to_data(db.rdb.select(
                Tables.DatasetInfo.name, 'dataset_seq=?',
                [relation_info['dataset_seq']],
                'dataset_name'))[0]['dataset_name']

            if label_name not in od_tgt_ds:
                od_tgt_ds[label_name] = [dataset_name]
            else:
                od_tgt_ds[label_name].append(dataset_name)

        learner_info.update({
            'target_datasets': od_tgt_ds,
            'dataset_proportion': relation_info['dataset_proportion']})
        learner_info_list.append(learner_info)

    return learner_info_list


def create_classificiation_learner(od_target_datasets,  algorithm_name,
                                   dataset_proportion=None, **learner_info):
    '''Create initial classification learner.

    :param str od_target_datasets: JSON form of ordered dict with target
        datasets
        (e.g. {"benign": ["dataset1"], "malicious": ["dataset2", "dataset3"]})
    :param str algorithm_name:
    :param str dataset_proportion: JSON form of dict with regular expression,
        which describes proportion of each dataset (train, valid and test)
        (e.g. {"train": "^[0-9a-d]", "valid": "^e", "test": "^f"})
    :param dict learner_info: Optional arguments
        (learner_name, attrs, features, scaling_func, scaling_params and tags)
    '''
    cols = 'classification_algorithm_seq, init_params, variable_params, '
    cols += 'algorithm_name'
    cursor = db.rdb.select(Tables.ClassificationAlgorithm.name,
                           'algorithm_name=?', [algorithm_name], cols)
    if cursor.rowcount == 0:
        raise Exception('algorithm_name (%s) is not found.' % algorithm_name)
    algorithm_info = cursor_to_data(cursor)[0]
    init_params = algorithm_info['init_params']
    variable_params = algorithm_info['variable_params']

    # Validates params
    if 'params' in learner_info:
        param_keys = learner_info['params'].keys()
        if not set(init_params + variable_params) > param_keys:
            msg = 'Some "param"s (%s) are not valid.' % param_keys
            raise AssertionError(msg)

    # Get all targeted dataset_info
    dataset_names = [dataset_name for sublist in od_target_datasets.values()
                     for dataset_name in sublist]
    where_stmt = ' or '.join(['dataset_name=?'] * len(dataset_names))
    cursor = db.rdb.select(
        Tables.DatasetInfo.name, where_stmt, dataset_names,
        'dataset_seq, generator_seq, dataset_name, data_type')
    if cursor.rowcount != len(dataset_names):
        raise AssertionError('Some "dataset_name"s (%s) are not valid.'
                             % str(dataset_names))
    dataset_info_list = cursor_to_data(cursor)

    # Validates whether "generator_seq" is identical.
    generator_seq = dataset_info_list[0]['generator_seq']
    for dataset_info in dataset_info_list[1:]:
        if generator_seq != dataset_info['generator_seq']:
            raise AssertionError('"data_type"s are not identical.')

    # Get generator_info.
    cursor = db.rdb.select(Tables.DatasetGenerator.name,
                           'generator_seq=%s', [generator_seq])
    generator_info = cursor_to_data(cursor)[0]

    # Insert learner_info.
    if 'features' not in learner_info:
        learner_info['features'] = generator_info['features']

    if 'learner_name' not in learner_info or not learner_info['learner_name']:
        learner_name = '%s_%s' % (generator_info['target_data_type'],
                                  algorithm_info['algorithm_name'])
        learner_info['learner_name'] = learner_name

    if 'scaling_func' not in learner_info:
        learner_info['scaling_func'] = '''import numpy as np

def scaling_params(data):
    return {'max': np.max(data, axis=0).tolist(),
            'std': np.std(data, ddof=1, axis=0).tolist()}


def scaling_func(data, params):
    if len(data) == 0:
        return data

    data = np.array(data, dtype=np.float)
    for j in range(len(data[0])):
        if params['max'][j] <= 1:
            continue
        elif params['std'][j] >= 1000:
            x = data[:, j] / params['std'][j]
        else:
            x = data[:, j]
        data[:, j] = np.log(1 + x)

    return data
'''

    learner_info.update({
        'classification_algorithm_seq':
        algorithm_info['classification_algorithm_seq'],
        'generator_seq': generator_info['generator_seq'],
        'target_data_type': generator_info['target_data_type'],
        'attrs': generator_info['attrs']})
    learner_seq = db.rdb.insert(
        Tables.ClassificationLearner.name, learner_info)

    # Insert relation information.
    if dataset_proportion is None:
        dataset_proportion = {
                            "train": "^[0-9a-d]", "valid": "^e", "test": "^f"}
    for idx, (name, dataset_names) in enumerate(od_target_datasets.items()):
        for dataset_name in dataset_names:
            for j, dataset_info in enumerate(dataset_info_list):
                if dataset_name == dataset_info['dataset_name']:
                    relation_info = {
                        'classification_learner_seq': learner_seq,
                        'dataset_seq': dataset_info['dataset_seq'],
                        'learner_label_idx': idx, 'learner_label_name': name,
                        'dataset_proportion': dataset_proportion}
                    db.rdb.insert(Tables.DatasetToClassificationLearner.name,
                                  relation_info)
                    break
            del dataset_info_list[j]

    return {'learner_name': learner_info['learner_name']}


def full_training_for_classification_learner(
        learner_name, num_iter=1, eval_period=10, batch_size=1,
        save_prediction_result=0, **params):
    '''Start training for classification learner with entire target datasets.

    :param str learner_name:
    :param int num_iter: Number of iteration for the target datasets.
    :param int eval_period: Evaluation period for the learner.
    :param int batch_size: Bundle size of records. The bigger batch_size is,
        the faster training speed is. However it doesn't reach high accuracy.
        For the initial learner, you can give large batch_size(20~100),
        and then you have to give small batch_size(2~10) for fine-tunning.
    :param int save_prediction_result: 0:Do not save,
        1:Save prediction results of dataset
    :param dict params: User defined parameters given to the Learner
    '''
    learner_info = get_classification_learner(
        'learner_name=?', [learner_name], for_training=True)[0]

    arg_names = ['learner_name', 'target_datasets', 'dataset_proportion',
                 'scaling_func', 'scaling_params', 'algorithm',
                 'learner', 'params', 'feature_idxs', 'attrs', 'features']
    kwargs = {k: v for k, v in learner_info.items() if k in arg_names}

    # Check target_datasets are not None
    none_dataset = []
    for _, dataset_names in kwargs['target_datasets'].items():
        for dataset_name in dataset_names:
            dt_info = cursor_to_data(get_dataset_info('dataset_name=?',
                                                      [dataset_name]))[0]
            if dt_info['updated_datetime'] is None:
                none_dataset.append(dataset_name)
    if len(none_dataset) > 0:
        raise Exception('Dataset %s is/are empty.' % str(none_dataset))

    # Start full training
    kwargs.update({
        'num_iter': num_iter, 'eval_period': eval_period,
        'batch_size': batch_size, 'params': params,
        'save_prediction_result': save_prediction_result,
        'target_datasets': list(kwargs.pop('target_datasets').items())})
    kwargs = remove_if_value_is_empty(kwargs)
    cluster_mgr.full_training_for_classification_learner(**kwargs)

    running_info = {'learner_name': learner_name}
    running_info.update(params)
    return running_info


def get_classification_learner_log(learner_name):
    '''Returns a recent training log of classification learner.

    :param str learner_name:
    '''
    cursor = db.rdb.select(Tables.ClassificationLearner.name,
                           'learner_name=%s', [learner_name],
                           'recent_training_log')
    if cursor.rowcount == 0:
        return None
    else:
        return cursor_to_data(cursor)[0]


def predict_with_classification_learner(learner_name, file_with_info_list):
    '''Processing and retures predictions for given files immediately.

    .. warning::

        SMALL GROUP OF FILES ONLY (PLEASE DO NOT ABUSE IT)

    Your files will be processed in Master. If you want to test a large number
    of files, upload files, create and update dataset, and then test your
    dataset using test function.

    :param str learner_name:
    :param list file_with_info_list:
        A list of dict of file with meta information
    '''
    # Get information of learner, dataset generator and learner algorithm
    learner_info = cursor_to_data(db.rdb.select(
        Tables.ClassificationLearner.name,
        'learner_name=?', [learner_name]))[0]
    generator_info = cursor_to_data(db.rdb.select(
        Tables.DatasetGenerator.name, 'generator_seq=?',
        [learner_info['generator_seq']]))[0]
    algorithm_info = cursor_to_data(db.rdb.select(
        Tables.ClassificationAlgorithm.name, 'classification_algorithm_seq=?',
        [learner_info['classification_algorithm_seq']]))[0]

    # Parse files in Master
    file_info_list = []
    for file_with_info in file_with_info_list:
        bytes_file = file_with_info['bytes_file']
        file_info = cal_hashes(bytes_file)
        file_name = file_with_info['file_name']
        file_path = file_mgr.save_tmp_file(bytes_file, file_name)
        file_info.update({'file_name': file_name, 'file_size': len(bytes_file),
                          'file_path': file_path})
        file_info_list.append(file_info)
    named_dataset = slave_lib.parsing_files(file_info_list,
                                            generator_info['docker_image_id'])
    file_mgr.delete_tmp_files()

    return slave_lib.predict_with_classification_learner(
        named_dataset, algorithm_info['algorithm'], learner_info['learner'],
        learner_info['params'], learner_info['scaling_func'],
        learner_info['scaling_params'], learner_info['feature_idxs'],
        learner_info['attrs'])


# ####################################################### #

def online_training_for_classification_learner(
        classification_learner_seq, beginning_created_datetime=None,
        end_created_datetime=None, need_num_gpus=0, priority=20):
    pass


def partial_training_for_classification_learner(
        classification_learner_seq, sha256s, need_num_gpus=0, priority=20):
    pass


def test_classification_learner(classification_learner_seq, mem_file=None,
                                condition_stmt=None, condition_vals=[],
                                need_num_gpus=0, priority=10):
    pass
