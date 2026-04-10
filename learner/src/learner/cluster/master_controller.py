# -*- coding: utf-8 -*-
'''
**This defines Master logic of connection to Slaves.**
There are **a XMLRPC server** that allow Slaves to connect to send results
and **XMLRPC clients** that send tasks generated from defined interfaces to the
Slaves.
'''
# Default packages
import time
import queue
import inspect
import logging
import threading
import xmlrpc.server
import xmlrpc.client
from copy import deepcopy

# 3rd-party packages

# Internal packages
import learner.db.rdb as rdb
from learner.db.rdb_schemas import Tables
from learner.util.essential import cursor_to_data

logger = logging.getLogger(__name__)


class _ClusterMaster:
    XMLRPC_PATH = '/LearNeR'
    num_files_per_task = 5000

    class RunningState:
        running = 'Running'
        wait = 'Wait'
        done = 'Done'

    def __init__(self, cluster_spec):
        self.cluster_spec = cluster_spec
        self.tasks = []
        self._tasks_to_send = queue.PriorityQueue()
        self.task_id = -1

    def __del__(self):
        self.server.server_close()

    def __get_task_id(self, inc=True):
        if inc:
            self.task_id += 1
        return self.task_id

    def run_forever(self):
        threading.Thread(target=self.__run_rpc_server_forever).start()
        self.__run_rpc_client_forever()

    def parsing_for_dataset(self, dataset_name, file_info_cursor,
                            docker_image_id, updated_datetime, priority=20):
        kwargs = {'dataset_name': dataset_name,
                  'docker_image_id': docker_image_id}
        # inspect.stack()[0][3] gets a name of this function
        task = {'func_name': inspect.stack()[0][3],
                'updated_datetime': updated_datetime, 'kwargs': kwargs}

        # Split a task according to self.num_files_per_task
        num_target_files = file_info_cursor.rowcount
        while True:
            file_info_list = cursor_to_data(file_info_cursor,
                                            self.num_files_per_task)
            if len(file_info_list) == 0:
                break
            partial_task = deepcopy(task)
            partial_task.update({'running_state': self.RunningState.wait,
                                 'num_target_files': num_target_files})
            task_id = self.__get_task_id()
            partial_task['kwargs'].update({'file_info_list': file_info_list,
                                           'task_id': task_id})

            # Tasks to send to Slaves
            self._tasks_to_send.put((priority, task_id, partial_task))
            # Tasks for recording status information
            self.tasks.append(partial_task)

    def full_training_for_classification_learner(
            self, learner_name, algorithm, target_datasets, dataset_proportion,
            scaling_func, features, attrs, batch_size, scaling_params='',
            learner=b'', save_prediction_result=0, params={}, feature_idxs={},
            num_iter=1, eval_period=10, need_num_gpus=1, priority=20):
        kwargs = locals()
        del kwargs['self']
        kwargs['task_id'] = self.__get_task_id()
        task = {'func_name': inspect.stack()[0][3], 'kwargs': kwargs}

        self._tasks_to_send.put((priority, kwargs['task_id'], task))
        self.tasks.append(task)

    def online_training_for_classification_learner(
            self, learner_name, algorithm, target_datasets, dataset_proportion,
            beginning_created_datetime, features, attrs, learner, params,
            need_num_gpus=1, priority=20):
        pass

    def test_classification_learner(
            self, dataset_paths, result_path, cursor, learner,
            feature_idxs, need_num_gpus, priority=20):
        pass

    @staticmethod
    def __connect_to_slave(slave):
        # Connect to the Slave
        conn_str = 'http://%(host)s:%(port)s%(path)s' % slave
        server = xmlrpc.client.ServerProxy(conn_str)
        slave['server'] = server

        # Get environments from the Slave
        state = slave['server'].get_env()
        # Get installed Docker images to recycle
        slave['docker_image_ids'] = state['docker_image_ids']
        # Get the number of GPUs to allocate tasks depending needs.
        slave['num_gpus'] = state['num_gpus']
        # Get running state to allocate tasks to waiting Slaves.
        slave['running_state'] = _ClusterMaster.RunningState.wait
        # Allocated task in the Slave.
        slave['task'] = None  # The task is empty now.
        logger.info(' [Slave Connected] %s %s' % (conn_str, slave))

    def __run_rpc_server_forever(self):
        class MasterRequestHandler(xmlrpc.server.SimpleXMLRPCRequestHandler):
            rpc_paths = (_ClusterMaster.XMLRPC_PATH)  # Path restriction

        class MasterRPCInterface:
            def __init__(self, parent):
                self.p = parent
                self.lock = threading.Lock()

            def _dispatch(self, method, params):
                func = getattr(self, method)
                if len(params) == 0:
                    return func()
                elif len(params) == 1:
                    if type(params[0]) == dict:
                        return func(**params[0])
                return 'Wrong function call.'

            def update_dataset_info(
                    self, slave_idx, msg, task_id, dataset_name):
                self.__release_slave(slave_idx)
                if msg != 'ok':
                    logger.error(msg)
                    return 'ok'

                # Get the number of done "dataset_name" task
                target_tasks = []
                num_done = 0
                for task in self.p.tasks:
                    if task['kwargs']['dataset_name'] == dataset_name:
                        target_tasks.append(task)
                        if task['kwargs']['task_id'] == task_id:
                            task['running_state'] = self.p.RunningState.done
                        if task['running_state'] == self.p.RunningState.done:
                            num_done += 1

                # If all "dataset_name" task is done, remove all recorded tasks
                # and update updated_datetime in "dataset_info table" of RDB.
                if num_done == len(target_tasks):
                    for target_task in target_tasks:
                        for task in self.p.tasks:
                            if (target_task['kwargs']['task_id'] ==
                                    task['kwargs']['task_id']):
                                self.p.tasks.remove(task)

                    rdb.update(
                        Tables.DatasetInfo.name,
                        {'updated_datetime': target_task['updated_datetime']},
                        'dataset_name=?', [dataset_name])
                    logger.info('Dataset "%s" successfully updated.'
                                % dataset_name)
                else:
                    logger.info('Dataset "%s" %s/%s processed.'
                                % (dataset_name, num_done, len(target_tasks)))
                return 'ok'

            def lock_datasets(self, dataset_names):
                # TODO: Lock dataset
                ds_updated_datetime = {}
                with self.lock:
                    for dataset_name in dataset_names:
                        row = cursor_to_data(rdb.select(
                            Tables.DatasetInfo.name, 'dataset_name=?',
                            [dataset_name], 'updated_datetime'))
                        updated_datetime = row[0]['updated_datetime']
                        ds_updated_datetime[dataset_name] = updated_datetime

                return ds_updated_datetime

            def release_dataset(self, dataset_names):
                # TODO: Release dataset
                with self.lock:
                    pass

                return 'ok'

            def update_classification_learner_log(
                    self, learner_name, recent_training_log):
                rdb.update(Tables.ClassificationLearner.name,
                           {'recent_training_log': recent_training_log},
                           'learner_name=?', [learner_name])
                return 'ok'

            def update_classification_learner_result(
                    self, slave_idx, msg, task_id, learner_name, learner_info,
                    metrics, created_datetime):
                self.__release_slave(slave_idx)
                if msg != 'ok':
                    logger.error(msg)
                    return 'ok'

                # Find a task with task_id
                task = None
                for i in range(len(self.p.tasks)):
                    if self.p.tasks[i]['kwargs']['task_id'] == task_id:
                        task = self.p.tasks.pop(i)
                        del task['kwargs']
                        break
                if task is None:
                    return "The task doesn't exist"

                # Update a "learner_name" row in classification_learner table
                rdb.update(Tables.ClassificationLearner.name, learner_info,
                           'learner_name=?', [learner_name])

                # Insert new result in the classification_learner_result_info
                # To get sequence number, query it again
                result_info = cursor_to_data(rdb.select(
                    Tables.ClassificationLearner.name,
                    'learner_name=?', [learner_name]))[0]
                result_info.update(learner_info)
                result_info.update(metrics)
                result_info['created_datetime'] = created_datetime
                rdb.insert(
                    Tables.ClassificationLearnerResultInfo.name, result_info)

                return 'ok'

            def request_connection(self, client_address):
                slave = {'host': client_address[0], 'port': client_address[0],
                         'path': _ClusterMaster.XMLRPC_PATH}
                try:
                    _ClusterMaster.__connect_to_slave(slave)
                    self.cluster_spec['slaves'].append(slave)
                except Exception as e:
                    msg = ' [Slave Connection Error] %s\n\t' % str(e)
                    msg += 'The Slave ask to connect, but failed.'
                    logger.warn(msg)

            def __release_slave(self, slave_idx):
                self.p.cluster_spec['slaves'][slave_idx]['running_state'] = (
                                                      self.p.RunningState.wait)
                self.p.cluster_spec['slaves'][slave_idx]['task'] = None

        # Run XMLRPC server forever to accept Slaves
        self.server = xmlrpc.server.SimpleXMLRPCServer(
                (self.cluster_spec['master']['host'],
                 self.cluster_spec['master']['port']),
                requestHandler=MasterRequestHandler)
        self.server.register_instance(MasterRPCInterface(self))
        logger.info(' [Start Server] %s %s' % (str(self.server.server_address),
                                               _ClusterMaster.XMLRPC_PATH))
        self.server.serve_forever()

    def __run_rpc_client_forever(self):
        # Connect to the master of the cluster.
        for slave in self.cluster_spec['slaves']:
            slave.update({'path': _ClusterMaster.XMLRPC_PATH})
            num_try = 0
            while True:
                try:
                    _ClusterMaster.__connect_to_slave(slave)
                    break
                except Exception as e:
                    msg = ' [Slave Connection Error] %s\n\t' % str(e)
                    if num_try < 3:
                        msg += ('%s. It will retry after 3 seconds.'
                                % str(slave))
                        logger.warn(msg)
                        time.sleep(3)
                        num_try += 1
                    else:
                        msg += 'Failed 3 times..'
                        msg += 'This Slave will be disposed..'
                        logger.warn(msg)
                        break

        # Take a task from _tasks_to_send and send it to the slave forever
        while True:
            candidate_slaves = []
            priority, task_datetime, task = self._tasks_to_send.get()

            # Get candidate Slaves for the task.
            # Assignment rules are as follows.
            # Rule1: If GPU is needed, the task will be  assigned to GPU slave.
            #        If GPU is not needed, the task will be assigned
            #         to GPU-free slave
            # Rule2: Assign the task to Slave that already has required Docker
            #         image.
            for slave in self.cluster_spec['slaves']:
                if slave['running_state'] == self.RunningState.running:
                    continue
                elif 'need_num_gpus' in task['kwargs']:
                    if slave['num_gpus'] >= task['kwargs']['need_num_gpus']:
                        candidate_slaves = [slave]
                        break
                    elif slave['num_gpus'] > 0:
                        candidate_slaves.insert(0, slave)
                elif task['kwargs']['docker_image_id'] in slave[
                                                        'docker_image_ids']:
                    candidate_slaves = [slave]
                    break
                else:
                    candidate_slaves.append(slave)

            # If candidate Slaves exist
            if len(candidate_slaves) > 0:
                candidate_slave = candidate_slaves[-1]
                # Execute XMLRPC
                try:
                    rpc_comm = getattr(candidate_slave['server'],
                                       task['func_name'])
                    logger.info(' [Call XMLRPC] %s' % (task['func_name']))
                    out = rpc_comm(task['kwargs'])
                    if out == 'ok':
                        candidate_slave['running_state'] = task[
                            'running_state'] = self.RunningState.running
                        candidate_slave['task'] = task
                        continue
                    else:  # The Slave doesn't give a "ok" message..
                        logger.warn(' [Slave RPC Error] %s\n\t' % out)
                except xmlrpc.client.Fault as e:
                    msg = ' [Slave RPC Error] %s\n\t' % str(e)
                    msg += '%s:%s is not working.' % (candidate_slave['host'],
                                                      candidate_slave['port'])
                    msg += ' This Slave will be removed..'
                    logger.warn(msg)
                    self.cluster_spec['slaves'].remove(candidate_slave)

            # Put task into stack again if the task couldn't be allocated.
            priority -= 0.005
            self._tasks_to_send.put((priority, task_datetime, task))

            # logger.info(
            #    ' [Task Alloc. Failed] Raise priority (-0.01) of "%s(%s)"'
            #    % (task['func_name'], task['kwargs']))
            time.sleep(0.5)
