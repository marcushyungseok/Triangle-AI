# -*- coding: utf-8 -*-
'''
**This defines Slave logic of connection to Master.**
There are **a XMLRPC server** that allow Master to connect to send tasks
and **a XMLRPC client** that send running results to Master.
'''
# Default packages
import json
import time
import queue
import types
import logging
import threading
import statistics
import xmlrpc.server
import xmlrpc.client
from datetime import datetime

# 3rd-party packages
import docker
from collections import OrderedDict
from tensorflow.python.client import device_lib

# Internal packages
import learner.db as db

logger = logging.getLogger(__name__)

XMLRPC_PATH = '/LearNeR'

# TODO: Exception Handling for disconnection between the Master and Slaves.


class _ClusterSlave:
    def __init__(self, cluster_spec, slave_idx=None):
        self.cluster_spec = cluster_spec
        self.slave_idx = slave_idx
        self.master_server = None

        # Create nfs file manager.
        self.file_mgr = db.nfs.NFSManager(cluster_spec)
        # Create nosqldb manager.
        self.nosql_mgr = db.nosql.NosqlManager(cluster_spec)
        # Connect to docker
        self.dc = docker.Client(base_url='unix://var/run/docker.sock')
        # Mount the NFS server to docker
        if self.dc.volumes({'name': 'files'})['Volumes'] is None:
            nfs_host = self.cluster_spec['nfs']['host']
            self.dc.create_volume(
                name='files', driver='local', driver_opts={
                    'type': 'nfs', 'o': 'addr=%s,ro' % nfs_host,
                    'device': ':/learner_storage/nfs/files'}
            )

        self._tasks = queue.Queue()

    @property
    def docker_image_ids(self):
        return [x[7:19] for x in self.dc.images(quiet=True)]

    @property
    def gpus(self):
        return ['gpu0']
        # BUG: Below code hangs sometimes...
        local_device_protos = device_lib.list_local_devices()
        return [x.name for x in local_device_protos if x.device_type == 'GPU']

    def run_forever(self):
        for _ in range(3):
            threading.Thread(target=self.__worker).start()
        self.__connect_to_master()
        self.__run_rpc_server_forever()

    def parsing_files(self, file_info_list, docker_image_id):
        container_id = self.__get_running_container_id(docker_image_id)
        exec_str = self.__make_exec_str(file_info_list)
        exec_id = self.dc.exec_create(container_id, exec_str)
        del file_info_list, exec_str  # To deallocate LARGE lists or strings.

        console_out = b''.join(self.dc.exec_start(exec_id['Id'], stream=True))
        try:
            datasets = []
            for line in console_out.splitlines():
                datasets.append(json.loads(line.decode()))
            return datasets
        except ValueError:
            msg = '=====\n%s\n...\n%s\n...\n%s\n=====\n' % (
                    console_out[:100], line, console_out[-100:])
            msg += 'Wrong stdout format: Please fix the docker image ('
            msg += 'Image ID:%s)\n' % docker_image_id
            raise ValueError(msg)

    def predict_with_classification_learner(
            self, named_dataset, algorithm, learner, params, scaling_func,
            scaling_params, feature_idxs, attrs):
        # Load feature scaling and ML module.
        scaling_mod = self.__load_module('scailing_mod', scaling_func)
        learner_mod = self.__load_module('learner', algorithm)

        params['batch_size'] = len(named_dataset)
        logger.info(' [Testing] Parameters: %s' % str(params))
        learner_mod.init_learner(**params)

        if learner:
            learner_mod.load_learner(learner)

        # Predict the data.
        data, file_info_list = [], []
        for col in named_dataset:
            X, z = self.__make_dataset(feature_idxs, col, attrs)
            data.append(X)
            file_info_list.append(z)

        scaled_data = list(scaling_mod.scaling_func(data, scaling_params))
        out = learner_mod.predict(scaled_data)
        return self.__transpose_result(out, None, file_info_list)

    def __worker(self):
        while True:
            task = self._tasks.get()

            if task['task_name'] == 'parsing_for_dataset':
                self.__parsing_for_dataset(**task['kwargs'])
            elif (task['task_name'] ==
                  'full_training_for_classification_learner'):
                self.__full_training_for_classification_learner(
                                                            **task['kwargs'])

    def __make_exec_str(self, file_info_list):
        file_info_str_list = []
        for file_info in file_info_list:
            arg = '"' + json.dumps(file_info).replace('"', r'\"') + '"'
            file_info_str_list.append(arg)
        return 'python main.py %s' % ' '.join(file_info_str_list)

    def __parsing_for_dataset(self, task_id, dataset_name, file_info_list,
                              docker_image_id):
        kwargs = {'slave_idx': self.slave_idx, 'task_id': task_id,
                  'dataset_name': dataset_name}
        try:
            for file_info in file_info_list:
                file_path = self.file_mgr.get_file_path(file_info['sha256'])
                file_info.update({'file_path': file_path})

            datasets = self.parsing_files(file_info_list, docker_image_id)
            kwargs['msg'] = 'ok'
            self.master_server.update_dataset_info(kwargs)
            self.nosql_mgr.insert_dataset(dataset_name, datasets)
        except ValueError as e:
            kwargs['msg'] = str(e)
            self.master_server.update_dataset_info(kwargs)

    def __get_running_container_id(self, docker_image_id):
        if docker_image_id not in self.docker_image_ids:
            mem_file = self.file_mgr.read_docker_image(docker_image_id)
            self.dc.load_image(mem_file)
            logger.info('[Image loaded] %s' % docker_image_id)
        else:
            logger.info('[Image reused] %s' % docker_image_id)

        filters = {'ancestor': docker_image_id}
        containers_info = self.dc.containers(filters=filters, quiet=True)
        if len(containers_info) > 0:
            container_info = containers_info[-1]
            logger.info('[Container reused] %s' % container_info)

        else:
            bind = 'files:%s' % (self.file_mgr.ROOT_FILE_DIR)
            hc = self.dc.create_host_config(binds=[bind])
            container_info = self.dc.create_container(
                docker_image_id, '/bin/sh', stdin_open=True,
                volumes=['/files'], host_config=hc)
            self.dc.start(container_info['Id'])
            logger.info('[Container created] %s' % container_info)

        return container_info['Id']

    def __load_module(self, name, pyscript):
        code_object = compile(pyscript, '<string>', 'exec')
        module = types.ModuleType(name)
        exec(code_object, module.__dict__)
        return module

    def __full_training_for_classification_learner(
            self, task_id, learner_name, algorithm, target_datasets,
            dataset_proportion, scaling_func, scaling_params,
            attrs, features, learner, params, feature_idxs, batch_size,
            num_iter, eval_period, save_prediction_result,
            need_num_gpus, priority):
        recent_training_log = []

        # Load feature scaling and ML module.
        scaling_mod = self.__load_module('scailing_mod', scaling_func)
        learner_mod = self.__load_module('learner_mod', algorithm)

        # Create dataset cursors and unique_col_names.
        target_dataset_cursors = OrderedDict()
        dataset_updated_datetime = {}
        nosql = self.nosql_mgr
        proj = {feature: 1 for feature in (features + attrs)}
        for label_name, ds_nms in target_datasets:
            csrs = {'train': None, 'valid': None, 'test': None}
            kwargs = {'dataset_names': ds_nms}

            try:
                dataset_updated_datetime.update(
                    self.master_server.lock_datasets(kwargs))
                print(dataset_updated_datetime)

                rgx = {'md5': {'$regex': dataset_proportion['train']}}
                csrs['train'] = nosql.find_datasets(ds_nms, rgx, proj)
                rgx = {'md5': {'$regex': dataset_proportion['valid']}}
                csrs['valid'] = nosql.find_datasets(ds_nms, rgx, proj)
                rgx = {'md5': {'$regex': dataset_proportion['test']}}
                csrs['test'] = nosql.find_datasets(ds_nms, rgx, proj)
                csrs['sample'] = nosql.find_datasets(ds_nms, None, proj, 999)
            finally:
                self.master_server.release_dataset(kwargs)

            target_dataset_cursors[label_name] = csrs

        ds_nms = [item for _, vals in target_datasets for item in vals]
        proj = {feature: 1 for feature in features}
        unique_col_names = nosql.find_unique_column_names(ds_nms, proj)

        # Create feature_idxs.
        if not feature_idxs:
            max_idx = -1
            feature_idxs = {}
            for col_name, sub_col_names in unique_col_names.items():
                if col_name not in features:
                    continue

                if sub_col_names is None:
                    max_idx += 1
                    feature_idxs[col_name] = max_idx
                else:
                    for sub_col_name in sub_col_names:
                        if sub_col_name not in feature_idxs:
                            max_idx += 1
                            feature_idxs[sub_col_name] = max_idx
        else:
            max_idx = max(feature_idxs.values())

        # Calculate {[a max value] and [a standard derivation]} of each feature
        if not scaling_params:
            sample_data = [self.__make_dataset(feature_idxs, x)
                           for label_cursors in target_dataset_cursors.values()
                           for x in label_cursors['sample']]
            scaling_params = scaling_mod.scaling_params(sample_data)
        scaling_func = scaling_mod.scaling_func

        # Load ML Learner with parameters.
        params.update({'n_input': max_idx+1, 'n_output': len(target_datasets),
                       'batch_size': batch_size})
        logger.info(' [Training] Parameters: %s' % str(params))
        learner_mod.init_learner(**params)

        bytes_learner = learner.data
        if bytes_learner:
            learner_mod.load_learner(bytes_learner)

        # Start training.
        result = None
        for epoch in range(1, num_iter + 1):
            X, y, losses = [], [], []
            prev_dataset_size = 0
            eod_idx = {}
            start_time = time.time()
            while True:
                # Make a (Batch size)*(Number of features) train set.
                for idx, (label_name, csrs) in enumerate(
                                            target_dataset_cursors.items()):
                    if idx in eod_idx:
                        continue
                    col = next(csrs['train'])
                    if col is None:
                        eod_idx[idx] = True
                        continue

                    data = self.__make_dataset(feature_idxs, col)
                    X.append(data)
                    y.append(idx)
                    if batch_size == len(y):
                        break

                if batch_size == len(y):
                    # Training the batch data.
                    scaled_X = scaling_func(X, scaling_params)
                    loss = learner_mod.partial_fit(scaled_X, y)
                    losses.append(loss)
                    X, y = [], []

                elif prev_dataset_size == len(y):  # No more data to train
                    break

                prev_dataset_size = len(y)

            msg = (' [Training] Loss: %.6f (%.2f sec)' %
                   (statistics.mean(losses), time.time() - start_time))
            logger.info(msg)
            recent_training_log.append(msg)

            # If it's time to test, test it.
            if epoch % eval_period == 0 and epoch != num_iter:
                result = self.__test_loaded_classification_learner(
                    learner_name, target_dataset_cursors, attrs, learner_mod,
                    feature_idxs, scaling_func, scaling_params, batch_size,
                    recent_training_log)
            else:
                result = None

        if result is None:
            created_datetime = datetime.now()
            result = self.__test_loaded_classification_learner(
                learner_name, target_dataset_cursors, attrs, learner_mod,
                feature_idxs, scaling_func, scaling_params, batch_size,
                recent_training_log, save_prediction_result, created_datetime)

        # Calculate metrics
        # TODO: (accuracy, confusion_matrix, other_metrics, learning_time)
        metrics = {}

        learner_info = {
            'scaling_params': scaling_params, 'features': features,
            'feature_idxs': feature_idxs, 'attrs': attrs, 'params': params,
            'learner': learner_mod.export_learner(),
            'dataset_updated_datetime': dataset_updated_datetime}
        kwargs = {'slave_idx': self.slave_idx, 'msg': 'ok', 'task_id': task_id,
                  'learner_name': learner_name, 'learner_info': learner_info,
                  'metrics': metrics,
                  'created_datetime': str(created_datetime)}
        self.master_server.update_classification_learner_result(kwargs)

    def __test_loaded_classification_learner(
            self, learner_name, target_dataset_cursors, attrs, learner_ins,
            feature_idxs, scaling_func, scaling_params, batch_size,
            recent_training_log, save_prediction_result=0,
            created_datetime=None):

        # Iterate each dataset
        for set_name in ['train', 'test']:  # TODO: valid
            num_data, num_corr = 0, 0
            for y, (_, csrs) in enumerate(target_dataset_cursors.items()):
                eod = False  # End of data
                while not eod:
                    data, label, file_info = [], [], []
                    for _ in range(batch_size):
                        col = next(csrs[set_name])
                        # If there is no more data, break the loop twice.
                        if col is None:
                            eod = True
                            break

                        # Accumulate dataset until batch_size is reached
                        X, z = self.__make_dataset(feature_idxs, col, attrs)
                        data.append(X)
                        label.append(y)
                        file_info.append(z)

                    if len(data) == 0 or data[0] is None:
                        break

                    # Predict it
                    scaled_data = list(scaling_func(data, scaling_params))
                    out = learner_ins.predict(scaled_data, label)
                    rows = self.__transpose_result(out, y, file_info)

                    # Save testset result only
                    if save_prediction_result == 1 and set_name == 'test':
                        self.nosql_mgr.insert_learner_result(
                            rows, learner_name, created_datetime)

                    # Save all dataset result
                    elif save_prediction_result == 2:
                        self.nosql_mgr.insert_learner_result(
                            rows, learner_name, created_datetime)

                    num_data += len(rows)
                    num_corr += out['corrects'].count(True)

            num_miss = num_data - num_corr
            err = (num_miss / num_data) * 100
            acc = 100 - err
            msg = ' [Metrics] %s error %.2f%%, ' % (set_name.title(), err)
            msg += 'Accuracy %.2f%% (total %s, correct %s, missed %s)' % (
                acc, num_data, num_corr, num_miss)
            logger.info(msg)
            recent_training_log.append(msg)

        kwargs = {'learner_name': learner_name,
                  'recent_training_log': '\n'.join(recent_training_log)}
        self.master_server.update_classification_learner_log(kwargs)

    def __transpose_result(self, result, y=None, file_info=None):
        num_rows = len(result['predicts'])
        rows = [{} for _ in range(num_rows)]
        for i in range(num_rows):
            rows[i]['predicts'] = result['predicts'][i]
            rows[i]['probabilities'] = result['probabilities'][i]
            if y is not None:
                rows[i]['corrects'] = result['corrects'][i]
                rows[i]['label'] = y
            if file_info is not None:
                rows[i].update(file_info[i])
        return rows

    def __test_classification_learner(
            self, learner_name, algorithm, target_dataset_names,
            dataset_proportion, features, attrs, learner, params, feature_idxs,
            batch_size, num_iter, eval_period, need_num_gpus, priority):
        pass

    def __make_dataset(self, feature_idxs, col_dict, attrs=None):
        data = [0] * len(feature_idxs)
        if attrs is not None:
            info = {}
        for ft_name, val in col_dict.items():
            if type(val) == dict:
                key_errors = []
                for sub_ft_name, sub_val in val.items():
                    if sub_ft_name in feature_idxs:
                        data[feature_idxs[sub_ft_name]] = sub_val
                    else:
                        key_errors.append(sub_ft_name)
                if len(key_errors) > 0:
                    msg = ' [Feature index error] These will be ignored: %s'
                    logger.warn(msg % ', '.join(key_errors))
            else:
                if attrs is not None and ft_name in attrs:
                    info[ft_name] = val
                if ft_name in feature_idxs:
                    data[feature_idxs[ft_name]] = val
        if attrs is not None:
            return data, info
        else:
            return data

    def __connect_to_master(self):
        try:
            conn_str = (('http://%(host)s:%(port)s' %
                         self.cluster_spec['master']) + XMLRPC_PATH)
            self.master_server = xmlrpc.client.ServerProxy(conn_str)
            logger.info(' [Master Connected] %s' % conn_str)
        except Exception as e:
            msg = ' [Master Connection Error] %s\n\t' % str(e)
            msg += 'Failed to connect to the Master.'
            logger.error(msg)
            raise e

    def __run_rpc_server_forever(self):
        class SlaveRequestHandler(xmlrpc.server.SimpleXMLRPCRequestHandler):
            rpc_paths = (XMLRPC_PATH)  # Path restriction

        class SlaveRPCInterface:
            def __init__(self, parent):
                self.p = parent

            def _dispatch(self, method, params):
                # Call function with keyword arguments came from "params"
                func = getattr(self, method)
                if len(params) == 0:
                    return func()
                elif len(params) == 1:
                    if type(params[0]) == dict:
                        return func(**params[0])
                return 'Wrong function call.'

            def get_env(self):
                return {'docker_image_ids': self.p.docker_image_ids,
                        'num_gpus': len(self.p.gpus)}

            def parsing_for_dataset(self, task_id, dataset_name,
                                    file_info_list, docker_image_id):
                kwargs = locals()
                del kwargs['self']
                self.p._tasks.put({'task_name': 'parsing_for_dataset',
                                   'kwargs': kwargs})
                return 'ok'

            def full_training_for_classification_learner(
                    self, task_id, learner_name, algorithm, target_datasets,
                    dataset_proportion, scaling_func, scaling_params,
                    features, attrs, learner, params, feature_idxs,
                    save_prediction_result, batch_size=1, num_iter=1,
                    eval_period=10, need_num_gpus=1, priority=20):
                kwargs = locals()
                del kwargs['self']
                self.p._tasks.put(
                    {'task_name': 'full_training_for_classification_learner',
                     'kwargs': kwargs})
                return 'ok'

            def online_training_for_classification_learner(self, kwargs=None):
                '''dataset_paths, result_path, sha256s, params, learner,
                    feature_idxs, need_gpu
                '''
                return 'Not implemented yet.'

            def test_classification_learner(self, kwargs=None):
                '''dataset_paths, result_path, sha256s, learner,
                    feature_idxs, need_gpu
                '''
                return 'Not implemented yet.'

        # Run XMLRPC server forever to accept the Master
        slave_info = self.cluster_spec['slaves'][self.slave_idx]
        self.server = xmlrpc.server.SimpleXMLRPCServer(
            (slave_info['host'], slave_info['port']), SlaveRequestHandler)
        self.server.register_instance(SlaveRPCInterface(self))
        logger.info(' [Server Started] %s %s' %
                    (str(self.server.server_address), XMLRPC_PATH))
        self.server.serve_forever()


def run(cluster_spec, slave_idx):
    '''Run the Slave of the cluster.

    :param dict cluster_spec: e.g.
        {'mongodb': {'host': '127.0.0.1', 'port':27017}, 'nfs':...,
        'master':..., 'slaves':[{'host':...}, {...}, ...]}
    :param int slave_idx: The index number of the Slave
    '''
    global cluster_mgr

    cluster_mgr = _ClusterSlave(cluster_spec, slave_idx)
    cluster_mgr.run_forever()
