# -*- coding: utf-8 -*-
'''
**Relational database schemas of Learner**
'''


class Tables:
    class FileInfo:
        name = 'file_info'

        class Columes:
            file_seq = 'file_seq'
            parent_file_seq = 'parent_file_seq'
            root_file_seq = 'root_file_seq'
            num_dup_files = 'num_dup_files'
            file_name = 'file_name'
            data_type = 'data_type'
            label = 'label'
            sublabel = 'sublabel'
            data_type_label_sublabel = 'data_type_label_sublabel'
            md5 = 'md5'
            sha1 = 'sha1'
            sha256 = 'sha256'
            file_size = 'file_size'
            importance = 'importance'
            download_url = 'download_url'
            created_datetime = 'created_datetime'
            deleted_datetime = 'deleted_datetime'
            tags = 'tags'

        attrs = [Columes.file_seq, Columes.file_name, Columes.file_size,
                 Columes.created_datetime, Columes.md5, Columes.sha256]

    class DatasetGenerator:
        name = 'dataset_generator'

        class Columes:
            generator_seq = 'generator_seq'
            generator_name = 'generator_name'
            target_data_type = 'target_data_type'
            attrs = 'attrs'
            features = 'features'
            docker_image_id = 'docker_image_id'
            created_datetime = 'created_datetime'
            tags = 'tags'

    class DatasetInfo:
        name = 'dataset_info'

        class Columes:
            dataset_seq = 'dataset_seq'
            generator_seq = 'generator_seq'
            dataset_name = 'dataset_name'
            data_type = 'data_type'
            label = 'label'
            sublabel = 'sublabel'
            created_datetime = 'created_datetime'
            updated_datetime = 'updated_datetime'
            tags = 'tags'

    class ClassificationAlgorithm:
        name = 'classification_algorithm'

        class Columes:
            classification_algorithm_seq = 'classification_algorithm_seq'
            algorithm_name = 'algorithm_name'
            sha256 = 'sha256'
            init_params = 'init_params'
            variable_params = 'variable_params'
            support_distribution = 'support_distribution'
            gen_dataset_dims = 'gen_dataset_dims'
            algorithm = 'algorithm'
            tags = 'tags'
            created_datetime = 'created_datetime'

    class ClassificationLearner:
        name = 'classification_learner'

        class Columes:
            classification_learner_seq = 'classification_learner_seq'
            classification_algorithm_seq = 'classification_algorithm_seq'
            generator_seq = 'generator_seq'
            learner_name = 'classification_learner_name'
            target_data_type = 'target_data_type'
            learner = 'learner'
            params = 'params'
            feture_idxs = 'feture_idxs'
            attrs = 'attrs'
            features = 'features'
            scaling_func = 'scaling_func'
            scaling_params = 'scaling_params'
            recent_training_log = 'recent_training_log'
            created_datetime = 'created_datetime'
            dataset_updated_datetime = 'dataset_updated_datetime'
            tags = 'tags'

    class ClassificationLearnerResultInfo:
        name = 'classification_learner_result_info'

        class Columes:
            classification_learner_result_seq = (
                                        'classification_learner_result_seq')
            classification_learner_seq = 'classification_learner_seq'
            classification_algorithm_seq = 'classification_algorithm_seq'
            generator_seq = 'generator_seq'
            learner_name = 'classification_learner_name'
            target_data_type = 'target_data_type'
            learner = 'learner'
            params = 'params'
            feture_idxs = 'feture_idxs'
            attrs = 'attrs'
            features = 'features'
            scaling_func = 'scaling_func'
            scaling_params = 'scaling_params'
            recent_training_log = 'recent_training_log'
            accuracy = 'accuracy'
            confusion_matrix = 'confusion_matrix'
            other_metrics = 'other_metrics'
            created_datetime = 'created_datetime'
            dataset_updated_datetime = 'dataset_updated_datetime'
            tags = 'tags'

    class DatasetToClassificationLearner:
        name = 'dataset_to_classification_learner'

        class Columes:
            classification_learner_seq = 'classification_learner_seq'
            dataset_seq = 'dataset_seq'
            learner_label_idx = 'learner_label_idx'
            learner_label_name = 'learner_label_name'
            dataset_proportion = 'dataset_proportion'
