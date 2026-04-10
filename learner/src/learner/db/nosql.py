# -*- coding: utf-8 -*-
'''
**This is NOSQLDB (MongoDB) client helper for Learner.**
MongoDB documentation is found here: https://docs.mongodb.com/manual/
'''
# Default packages
import logging

# 3rd-party packages
import pymongo
from pymongo.bulk import BulkWriteError

logger = logging.getLogger(__name__)


class NosqlManager:
    def __init__(self, cluster_spec):
        self.client = pymongo.MongoClient(cluster_spec['mongodb']['host'],
                                          cluster_spec['mongodb']['port'])
        self.dataset_db = self.client['datasets']
        self.learner_results_db = self.client['learner_results']

        # To generating dataset table later
        self.unique_column_names = {}
        for col in list(self.dataset_db['unique_column_names'].find({})):
            dataset_name = col['dataset_name']
            self.unique_column_names[dataset_name] = col['column_names']

    def insert_dataset(self, dataset_name, rows):
        # Use "file_seq" as default key of MongoDB which name is "_id"
        for row in rows:
            row['_id'] = row.pop('file_seq')
            self.__update_unique_column_names(dataset_name, row)
        self.__commit_unique_column_names()

        collection = self.dataset_db[dataset_name]
        try:
            collection.insert_many(rows)
        except BulkWriteError as e:
            msg = ' [BulkWriteError] Maybe duplicated row exists, but it '
            msg += 'will try to insert one by one for integrity.\n%s' % str(e)
            logger.warn(msg)
            inserted_file_seqs = []
            for row in rows:
                try:
                    collection.insert_one(row)
                    inserted_file_seqs.append(row['_id'])
                except:
                    pass
            msg = ' [Bulk Insertion Result] Inserted "file_seq"s: %s'
            logger.info(msg % str(inserted_file_seqs))

    def insert_learner_result(self, rows, learner_name, create_datetime):
        db_name = '%s_%s' % (learner_name, create_datetime)
        collection = self.learner_results_db[db_name]

        for row in rows:
            row['_id'] = row.pop('file_seq')

        collection.insert_many(rows)

    def find_dataset(self, dataset_name, where_stmt=None, projection=None):
        # Change file_seq column to _id
        if projection is not None:
            if 'file_seq' in projection:
                if projection.pop('file_seq') == 0:
                    projection['_id'] = 0

        cursor = self.dataset_db[dataset_name].find(where_stmt, projection)
        logger.info('%s row selected in %s' % (cursor.count(), dataset_name))
        while True:
            data = next(cursor, None)

            # If the cursor has no more data, rewind the cursor.
            if data is None:
                yield None
                cursor.rewind()
            else:
                # Change column name of _id to file_seq before "yield"
                if '_id' in data:
                    data['file_seq'] = data.pop('_id')
                yield data

    def find_datasets(self, dataset_names, where_stmt=None, projection=None,
                      limit=None):
        cnt = 0
        gens = []

        # Get generators of datasets
        for dataset_name in dataset_names:
            gens.append(
                    self.find_dataset(dataset_name, where_stmt, projection))
        end_gen_idxs = {}
        while True:
            # Iterate all generators one by one to mix data
            for i, gen in enumerate(gens):
                if i in end_gen_idxs:
                    if len(end_gen_idxs) == len(gens):
                        if limit is None:
                            # To notify the end of dataset, but it will iterate
                            # again from beginning of dataset after
                            end_gen_idxs = {}
                            yield None
                        else:
                            return None
                    continue

                data = next(gen)

                if data is None:  # If there's no more data, recording it
                    end_gen_idxs[i] = None
                else:  # If data exists.
                    yield data

                    # To limit the number of data
                    cnt += 1
                    if limit is not None and limit < cnt:
                        return

    def find_unique_column_names(self, dataset_names, projection=None):
        '''Merge unique column names in datasets'''
        out = {}
        new_proj = {}
        if projection is not None:
            for key in projection.keys():
                new_proj['column_names.' + key] = projection[key]

        collec = self.dataset_db['unique_column_names']
        for dataset_name in dataset_names:
            # Get previous unique_column_names related to dataset_names
            unique_column_names = collec.find_one(
                {'dataset_name': dataset_name}, new_proj)['column_names']

            # Iterate top-node of unique_column_names
            for name, subnames in unique_column_names.items():
                if subnames is None:  # If subtree doesn't exist
                    out[name] = None
                else:  # If sub-node exists
                    if name in out:
                        out[name] = list(set(out[name] + subnames))
                    else:
                        out[name] = subnames

        return out

    def __update_unique_column_names(self, dataset_name, dataset):
        if dataset_name not in self.unique_column_names:
            self.unique_column_names[dataset_name] = {}

        # Extract unique column names as they iterate the dataset
        column_names = self.unique_column_names[dataset_name]
        for name, val in dataset.items():
            if type(val) == dict:
                if name not in column_names:
                    column_names[name] = []
                for subname, _ in val.items():
                    if column_names[name].count(subname) == 0:
                        column_names[name].append(subname)
            elif val is not None:
                if name == '_id':  # Use "file_seq" column name insted of "_id"
                    column_names['file_seq'] = None
                    continue

                column_names[name] = None

    def __commit_unique_column_names(self):
        for dataset_name, column_names in self.unique_column_names.items():
            dataset_idxs_info = {
                'dataset_name': dataset_name,
                'column_names': column_names}
            self.dataset_db['unique_column_names'].find_one_and_replace(
                {'dataset_name': dataset_name}, dataset_idxs_info, upsert=True)
