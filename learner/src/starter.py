# -*- coding: utf-8 -*-
'''
**Collections of startup script (Master and Slaves) for "Learner" Framework.**
'''
# Default packages
import sys
import logging
import multiprocessing as mp

# 3rd-party packages

# Internal packages
import learner.cluster as cluster


def run_master(cluster_spec, web_port=8000):
    cluster.master.run(cluster_spec, web_port)


def run_slave(cluster_spec, slave_idx):
    cluster.slave.run(cluster_spec, slave_idx)


def run_all_slaves_as_multiprocessing(cluster_spec):
    for i in range(len(cluster_spec['slaves'])):
        mp.Process(target=cluster.slave.run, args=(cluster_spec, i)).start()


if __name__ == '__main__':
    # To adjust output level of the console for all loggers
    logging.getLogger('').handlers = []
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    cluster_spec = {'nfs': {'host': '127.0.0.1'},
                    'mongodb': {'host': '127.0.0.1', 'port': 27017},
                    'master': {'host': '127.0.0.1', 'port': 9124},
                    'slaves': [{'host': '127.0.0.1', 'port': 9125},
                               {'host': '127.0.0.1', 'port': 9126},
                               ]
                    }

    run_all_slaves_as_multiprocessing(cluster_spec)
    # run_slave(cluster_spec, 0)
    run_master(cluster_spec)
