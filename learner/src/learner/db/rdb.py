# -*- coding: utf-8 -*-
'''
**This is RDB client helper for Learner.**

.. autoclass:: _QueryManager
'''
# Default packages
import time
import json
import logging
import threading

# 3rd-party packages
import MySQLdb

# Internal packages
from learner.util.essential import Config
from learner.db.rdb_schemas import Tables

logger = logging.getLogger(__name__)


class _QueryManager:
    '''**RDB query execution manager** (frequent commit() call preventer for
    performance improvement)

    Warning: This class should be instantiated only once. Also, you must be
    only RDB client to connect to the RDB server.

    Reason: To improve performance by not synchronizing sequence number of
    records in RDB. In addition, by reducing the number of frequent
    transactions, it provides significant performance improvements.

    Column description of file_seq in RDB:
    The file_seq to be inserted is managed here (self.cur_file_seq).
    This method can not handle multiple clients attached to the DB server.
    However, you can reduce the query volume in half(which is fairly quicker).

    Transaction description:
    To prevent commit() from being run too often, set the timer to run after
    one second after calling execute(). If the execute() is executed before
    reaching 1 second, the existing timer is canceled and the commint() is set
    to be called 1 second later. However, if there are more than 500 SQL
    statements to be executed or if the accumulated cumulative time is more
    than 3 seconds, it won't reset the timer.
    The following link explains the difference in performance when
    [commit() 200 times respectively] vs [commit() at once after].
    Reference: `<http://stackoverflow.com/questions/14675147/why-does-
    transaction-commit-improve-performance-so-much-with-php-mysql-innodb>`_
    '''
    def __init__(self, db_conf):
        # Connect to RDB
        self.__conn_db(db_conf)
        cursor = self.conn.cursor()

        # Variables for RDB synchronization
        self.sql_count = 0
        self.commit_timer = None
        self.__lock_execute = threading.Lock()
        self.__lock_timer = threading.Lock()

        # File_seq to insert into RDB
        sql = 'SELECT MAX(file_seq) from %s' % Tables.FileInfo.name
        cursor.execute(sql)
        max_file_seq = cursor.fetchone()[0]
        self.cur_file_seq = max_file_seq + 1 if max_file_seq is not None else 1

        # PARTITION information variable of RDB
        sql = '''SELECT partition_name FROM information_schema.partitions
                 WHERE table_name = "%s"''' % Tables.FileInfo.name
        cursor.execute(sql)
        self.partition_names = [row[0] for row in cursor.fetchall()]
        logger.info(' [PARTITION INFO] %s' % self.partition_names)

    @property
    def cumulative_sec(self):
        ""
        return time.time() - self.start_time

    def __conn_db(self, db_conf):
        self.conn = MySQLdb.connect(
            host=db_conf['host'], port=int(db_conf['port']), db=db_conf['db'],
            user=db_conf['user'], passwd=db_conf['passwd'])

    def execute(self, sql, vals=[], file_info=None):
        ""
        # print('SQL     ', sql, vals, file_info)
        with self.__lock_execute:
            while True:
                try:
                    cursor = self.conn.cursor()
                    if sql.lower().startswith('select'):
                        cursor.execute(sql, vals)
                        return cursor
                    elif sql.lower().startswith('alter'):
                        self.__execute_with_commit_timer(sql, vals)
                        return cursor

                    if self.sql_count == 0:
                        self.start_time = time.time()

                    logger.debug(sql + ' with ' + str(vals))
                    self.__check_partition_and_dup_file(file_info)

                    # Could raise exception!
                    self.__execute_with_commit_timer(sql, vals)
                    self.sql_count += 1

                    cursor.execute('SELECT LAST_INSERT_ID()')
                    return cursor.fetchone()[0]
                except Exception as e:
                    if str(e).find('MySQL server has gone away') != -1:
                        self.__conn_db()
                        continue

                    logger.error(' [DB ERROR]:\n' + sql + ' with ' +
                                 str(vals) + '\n' + str(e) + '\n')
                    if file_info is not None:
                        self.cur_file_seq -= 1
                    raise e

    def commit(self):
        with self.__lock_execute:
            self.conn.commit()
            logger.debug(' [RDB] %d columns are executed.' % self.sql_count)
            self.sql_count = 0

    def get_full_labels(self, data_type):
        labels = []
        for data_type_label_sublabel in self.partition_names:
            if data_type_label_sublabel.startswith(data_type):
                full_label = data_type_label_sublabel[len(data_type) + 1:-1]
                label, sublabel = full_label.split(sep='_', maxsplit=1)
                labels.append((label, sublabel))
        return labels

    def __check_partition_and_dup_file(self, file_info):
        if file_info is None:
            return
        self.cur_file_seq += 1

        # Create a partition table of file_info if necessary
        data_type_label_sublabel = (file_info['data_type'] + '_' +
                                    file_info['label'] + '_' +
                                    file_info['sublabel'] + '_')
        self.__check_and_create_file_info_partition(data_type_label_sublabel)

        # Check duplicated file from RDB
        if 'parent_file_seq' not in file_info:
            file_info['parent_file_seq'] = 0
        if not self.__is_unique_file(file_info['parent_file_seq'],
                                     file_info['sha256'],
                                     file_info['data_type']):
            raise FileExistsError('Duplicated file exists!')

    def __execute_with_commit_timer(self, sql, vals):
        if sql != '':
            self.conn.cursor().execute(sql, vals)
            self.__set_commit_timer()

    def __set_commit_timer(self):
        with self.__lock_timer:
            if self.commit_timer is not None:
                if self.sql_count < 100 or self.cumulative_sec < 5:
                    self.commit_timer.cancel()
            self.commit_timer = threading.Timer(2, self.commit)
            self.commit_timer.start()

    def __check_and_create_file_info_partition(self, data_type_label_sublabel):
        if data_type_label_sublabel in self.partition_names:
            return
        sql = ('ALTER TABLE `%s` ADD PARTITION (PARTITION %s VALUES IN ("%s"))'
               % (Tables.FileInfo.name, data_type_label_sublabel,
                  data_type_label_sublabel))
        self.__execute_with_commit_timer(sql, None)
        self.partition_names.append(data_type_label_sublabel)

    def __is_unique_file(self, parent_file_seq, sha256, data_type):
        # Make partition names for fast query
        sql_pts = ''
        for partition_name in self.partition_names:
            if partition_name.startswith(data_type):
                sql_pts += partition_name + ','
        sql_pts = sql_pts[:-1]

        # It will leverage the index table of (parent_file_seq, sha256)
        sql = ('''SELECT 1 FROM %s PARTITION (%s) WHERE
               parent_file_seq='%s' and sha256='%s' LIMIT 1''' %
               (Tables.FileInfo.name, sql_pts, parent_file_seq, sha256))
        cursor = self.conn.cursor()
        cursor.execute(sql)
        if cursor.fetchone() is None:
            return True
        else:
            return False

    # For Testing!!! #
    def drop_file_info_partition(self, data_type_label):
        sql = ('ALTER TABLE `%s` DROP PARTITION %s' %
               (Tables.FileInfo.name, data_type_label))
        self.execute(sql)
        self.partition_names.remove(data_type_label)

query_mgr = _QueryManager(Config()['RDB'])


def insert(table_name, vals_dict, partition_names=None):
    if table_name == Tables.FileInfo.name:
        vals_dict.update({'file_seq': query_mgr.cur_file_seq,
                          'root_file_seq': query_mgr.cur_file_seq})
        file_info = vals_dict
    else:
        file_info = None

    if partition_names:
        table_name += ' PARTITION (%s)' % ','.join(partition_names)

    # Make SQL statement derived from vals_dict
    colume_names = ''
    vals_format = ''
    vals = []
    for key, val in vals_dict.items():
        if (not val) and type(val) != int:
            continue
        colume_names += '%s, ' % key
        vals_format += '%s, '

        if type(val) == dict or type(val) == list:
            val = json.dumps(val)

        vals.append(val)

    colume_names = colume_names[:-2]
    vals_format = vals_format[:-2]
    sql = 'INSERT INTO %s (%s) VALUES (%s)' % (table_name, colume_names,
                                               vals_format)

    return query_mgr.execute(sql, vals, file_info)


def select(table_name, where_stmt=None, where_vals=None, column_names='*',
           order_by=None, partition_names=None):
    if partition_names:
        table_name += ' PARTITION (%s)' % ','.join(partition_names)

    if not where_stmt:
        sql = 'SELECT %s FROM %s' % (column_names, table_name)
        where_vals = []
    else:
        where_stmt = where_stmt.replace('?', '%s')
        sql = 'SELECT %s FROM %s WHERE %s' % (column_names, table_name,
                                              where_stmt)

    if order_by is not None:
        sql += ' ORDER BY %s' % order_by

    return query_mgr.execute(sql, where_vals)


def update(table_name, vals_dict, where_stmt, where_vals,
           partition_names=None):
    if partition_names:
        table_name += ' PARTITION (%s)' % ','.join(partition_names)

    # Make SQL statement derived from vals_dict
    colume_names = ''
    set_vals = []
    for key, val in vals_dict.items():
        if (not val) and type(val) != int:
            continue
        colume_names += '%s=?, ' % key

        if type(val) == dict or type(val) == list:
            val = json.dumps(val)

        set_vals.append(val)

    set_stmt = colume_names[:-2].replace('?', '%s')
    where_stmt = where_stmt.replace('?', '%s')
    sql = 'UPDATE %s SET %s WHERE %s' % (table_name, set_stmt, where_stmt)
    return query_mgr.execute(sql, set_vals + where_vals)


def delete(table_name, where_stmt, where_vals, partition_names=None):
    if partition_names:
        table_name += ' PARTITION (%s)' % ','.join(partition_names)

    where_stmt = where_stmt.replace('?', '%s')
    sql = 'DELETE FROM %s WHERE %s' % (table_name, where_stmt)
    return query_mgr.execute(sql, where_vals)


def cursor():
    return query_mgr.conn.cursor()
