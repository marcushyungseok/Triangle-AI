-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 09, 2016 at 09:46 AM
-- Server version: 10.1.19-MariaDB-1~trusty
-- PHP Version: 5.5.9-1ubuntu4.20

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `learner`
--

-- --------------------------------------------------------

--
-- Table structure for table `classification_algorithm`
--

CREATE TABLE IF NOT EXISTS `classification_algorithm` (
  `classification_algorithm_seq` int(11) NOT NULL AUTO_INCREMENT,
  `algorithm_name` varchar(20) NOT NULL,
  `sha256` char(64) NOT NULL,
  `init_params` text NOT NULL,
  `variable_params` text,
  `support_distribution` int(1) NOT NULL DEFAULT '0',
  `gen_dataset_dims` int(11) DEFAULT NULL,
  `algorithm` mediumtext NOT NULL,
  `tags` varchar(255) DEFAULT NULL,
  `created_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`classification_algorithm_seq`),
  UNIQUE KEY `model_name` (`algorithm_name`),
  UNIQUE KEY `sha256` (`sha256`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=18 ;

-- --------------------------------------------------------

--
-- Table structure for table `classification_learner`
--

CREATE TABLE IF NOT EXISTS `classification_learner` (
  `classification_learner_seq` int(11) NOT NULL AUTO_INCREMENT,
  `classification_algorithm_seq` int(11) NOT NULL,
  `generator_seq` int(11) NOT NULL,
  `learner_name` varchar(100) NOT NULL,
  `target_data_type` varchar(20) NOT NULL,
  `learner` mediumblob,
  `params` varchar(255) NOT NULL,
  `feature_idxs` mediumtext,
  `attrs` text NOT NULL,
  `features` text NOT NULL,
  `scaling_func` text NOT NULL,
  `scaling_params` text,
  `recent_training_log` mediumtext,
  `accuracy` float DEFAULT NULL,
  `confusion_matrix` text,
  `other_metrics` mediumtext,
  `created_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `dataset_updated_datetime` text,
  `tags` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`classification_learner_seq`),
  UNIQUE KEY `classification_learner_name` (`learner_name`),
  KEY `classification_model_seq` (`classification_algorithm_seq`),
  KEY `generator_seq` (`generator_seq`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=31 ;

-- --------------------------------------------------------

--
-- Table structure for table `classification_learner_result_info`
--

CREATE TABLE IF NOT EXISTS `classification_learner_result_info` (
  `classification_learner_result_seq` int(11) NOT NULL AUTO_INCREMENT,
  `classification_learner_seq` int(11) NOT NULL,
  `classification_algorithm_seq` int(11) NOT NULL,
  `generator_seq` int(11) NOT NULL,
  `learner_name` varchar(100) NOT NULL,
  `target_data_type` varchar(20) NOT NULL,
  `learner` mediumblob,
  `params` varchar(255) NOT NULL,
  `feature_idxs` mediumtext NOT NULL,
  `attrs` text NOT NULL,
  `features` text NOT NULL,
  `scaling_func` text NOT NULL,
  `scaling_params` text NOT NULL,
  `recent_training_log` text NOT NULL,
  `accuracy` float DEFAULT NULL,
  `confusion_matrix` text,
  `other_metrics` mediumtext,
  `created_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `dataset_updated_datetime` text,
  `tags` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`classification_learner_result_seq`),
  KEY `classification_model_seq` (`classification_algorithm_seq`),
  KEY `classification_learner_seq` (`classification_learner_seq`),
  KEY `generator_seq` (`generator_seq`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=60 ;

-- --------------------------------------------------------

--
-- Table structure for table `clustering_algorithm`
--

CREATE TABLE IF NOT EXISTS `clustering_algorithm` (
  `clustering_algorithm_seq` int(11) NOT NULL AUTO_INCREMENT,
  `algorithm_name` varchar(20) NOT NULL,
  `avaliable_params` text NOT NULL,
  `support_distribution` bit(1) NOT NULL,
  `pyscript` mediumtext NOT NULL,
  `tags` varchar(255) DEFAULT NULL,
  `create_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`clustering_algorithm_seq`),
  UNIQUE KEY `model_name` (`algorithm_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `clustering_learner`
--

CREATE TABLE IF NOT EXISTS `clustering_learner` (
  `clustering_learner_seq` int(11) NOT NULL AUTO_INCREMENT,
  `clustering_algorithm_seq` int(11) NOT NULL,
  `learner_name` varchar(20) NOT NULL,
  `target_data_type` varchar(20) NOT NULL,
  `validationset_ranges` text,
  `testset_ranges` text NOT NULL,
  `learner` mediumblob,
  `params` text NOT NULL,
  `feature_idxs` mediumtext NOT NULL,
  `available_attrs` text NOT NULL,
  `create_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `update_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tags` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`clustering_learner_seq`),
  UNIQUE KEY `clustering_learner_name` (`learner_name`),
  KEY `clustering_model_seq` (`clustering_algorithm_seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `clustering_learner_result_info`
--

CREATE TABLE IF NOT EXISTS `clustering_learner_result_info` (
  `clustering_learner_seq` int(11) NOT NULL AUTO_INCREMENT,
  `clustering_algorithm_seq` int(11) NOT NULL,
  `clustering_learner_name` varchar(20) NOT NULL,
  `target_data_type` varchar(20) NOT NULL,
  `validationset_ranges` text,
  `testset_ranges` text NOT NULL,
  `accuracy` float DEFAULT NULL,
  `f1_score` float DEFAULT NULL,
  `confusion_matrix` text,
  `num_clusters` int(11) NOT NULL,
  `other_performance_indicators` mediumtext,
  `learner` mediumblob,
  `params` varchar(255) NOT NULL,
  `feture_idxs` mediumtext NOT NULL,
  `attr_cols` text NOT NULL,
  `create_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `total_training_time` time NOT NULL DEFAULT '00:00:00',
  `tags` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`clustering_learner_seq`),
  KEY `clustering_model_seq` (`clustering_algorithm_seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `dataset_generator`
--

CREATE TABLE IF NOT EXISTS `dataset_generator` (
  `generator_seq` int(11) NOT NULL AUTO_INCREMENT,
  `generator_name` varchar(20) NOT NULL,
  `target_data_type` varchar(20) NOT NULL,
  `attrs` text NOT NULL,
  `features` text,
  `docker_image_id` varchar(12) DEFAULT NULL,
  `created_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tags` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`generator_seq`),
  UNIQUE KEY `uk_generator_name` (`generator_name`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=32 ;

-- --------------------------------------------------------

--
-- Table structure for table `dataset_info`
--

CREATE TABLE IF NOT EXISTS `dataset_info` (
  `dataset_seq` int(11) NOT NULL AUTO_INCREMENT,
  `generator_seq` int(11) NOT NULL,
  `dataset_name` varchar(100) NOT NULL,
  `data_type` varchar(20) NOT NULL,
  `label` varchar(20) NOT NULL,
  `sublabel` varchar(20) NOT NULL,
  `created_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_datetime` datetime DEFAULT NULL,
  `tags` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`dataset_seq`),
  UNIQUE KEY `dataset_name` (`dataset_name`),
  KEY `generator_seq` (`generator_seq`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=183 ;

-- --------------------------------------------------------

--
-- Table structure for table `dataset_to_classification_learner`
--

CREATE TABLE IF NOT EXISTS `dataset_to_classification_learner` (
  `classification_learner_seq` int(11) NOT NULL,
  `dataset_seq` int(11) NOT NULL,
  `learner_label_idx` tinyint(4) NOT NULL,
  `learner_label_name` varchar(20) NOT NULL,
  `dataset_proportion` text NOT NULL,
  UNIQUE KEY `uk_classification_learner_seq` (`classification_learner_seq`,`dataset_seq`),
  KEY `classification_learner_seq` (`classification_learner_seq`),
  KEY `dataset_seq` (`dataset_seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `dataset_to_clustering_learner`
--

CREATE TABLE IF NOT EXISTS `dataset_to_clustering_learner` (
  `clustering_learner_seq` int(11) NOT NULL,
  `dataset_seq` int(11) NOT NULL,
  `learner_label_idx` tinyint(4) NOT NULL,
  `learner_label_name` varchar(20) NOT NULL,
  `dataset_proportion` text NOT NULL,
  UNIQUE KEY `uk_clustering_learner_seq` (`clustering_learner_seq`,`dataset_seq`),
  UNIQUE KEY `clustering_learner_seq_2` (`clustering_learner_seq`,`dataset_seq`),
  KEY `clustering_learner_seq` (`clustering_learner_seq`),
  KEY `dataset_seq` (`dataset_seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `file_info`
--

CREATE TABLE IF NOT EXISTS `file_info` (
  `file_seq` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `parent_file_seq` bigint(20) unsigned NOT NULL DEFAULT '0',
  `root_file_seq` bigint(20) unsigned NOT NULL,
  `num_dup_files` tinyint(4) NOT NULL DEFAULT '1',
  `file_name` varchar(255) NOT NULL,
  `data_type` varchar(20) NOT NULL,
  `label` varchar(20) NOT NULL,
  `sublabel` varchar(20) NOT NULL,
  `data_type_label_sublabel` varchar(61) NOT NULL,
  `md5` char(32) NOT NULL,
  `sha1` char(40) NOT NULL,
  `sha256` char(64) NOT NULL,
  `file_size` int(11) NOT NULL,
  `importance` tinyint(4) NOT NULL DEFAULT '1',
  `download_url` text,
  `created_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `deleted_datetime` datetime DEFAULT NULL,
  `tags` varchar(255) DEFAULT NULL,
  KEY `k_create_datetime` (`created_datetime`),
  KEY `k_file_seq` (`file_seq`),
  KEY `k_sha256` (`sha256`),
  KEY `k_parent_file_seq_sha256` (`parent_file_seq`,`sha256`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8
/*!50500 PARTITION BY LIST  COLUMNS(data_type_label_sublabel)
(PARTITION pdf_benign_cse_ VALUES IN ('pdf_benign_cse_') ENGINE = InnoDB) */;

-- --------------------------------------------------------

--
-- Table structure for table `z_fileset_info`
--

CREATE TABLE IF NOT EXISTS `z_fileset_info` (
  `data_type` varchar(20) NOT NULL,
  `label` varchar(20) NOT NULL,
  `oldest_create_datetime` datetime NOT NULL,
  `lastest_create_datetime` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `z_file_group_info`
--

CREATE TABLE IF NOT EXISTS `z_file_group_info` (
  `file_seq` bigint(20) unsigned NOT NULL,
  `parent_file_seq` bigint(20) unsigned NOT NULL DEFAULT '0',
  `root_file_seq` bigint(20) unsigned NOT NULL,
  `num_dup_files` tinyint(4) NOT NULL DEFAULT '1',
  `file_name` varchar(255) NOT NULL,
  `file_group_name` varchar(20) NOT NULL,
  `data_type` varchar(20) NOT NULL,
  `label` varchar(20) NOT NULL,
  `file_group_name_data_type_label` varchar(60) NOT NULL,
  `md5` char(32) NOT NULL,
  `sha1` char(40) NOT NULL,
  `sha256` char(64) NOT NULL,
  `file_size` int(11) NOT NULL,
  `importance` tinyint(4) NOT NULL DEFAULT '1',
  `create_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `download_url` text,
  `delete_datetime` datetime DEFAULT NULL,
  `tags` varchar(255) DEFAULT NULL,
  UNIQUE KEY `uk_parent_file_seq_sha256` (`parent_file_seq`,`sha256`,`file_group_name_data_type_label`),
  KEY `sha256` (`sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
/*!50500 PARTITION BY LIST  COLUMNS(file_group_name_data_type_label)
(PARTITION grtest_pdf_benign VALUES IN ('grtest_pdf_benign') ENGINE = InnoDB) */;

-- --------------------------------------------------------

--
-- Table structure for table `z_skeleton_file_generator`
--

CREATE TABLE IF NOT EXISTS `z_skeleton_file_generator` (
  `generator_seq` int(11) NOT NULL AUTO_INCREMENT,
  `generator_name` varchar(20) NOT NULL,
  `generator_ver` varchar(20) NOT NULL,
  `target_data_type` varchar(20) NOT NULL,
  `docker_image_id` text NOT NULL,
  `tags` varchar(20) DEFAULT NULL,
  `create_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`generator_seq`),
  UNIQUE KEY `generator_name` (`generator_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `z_task_queue`
--

CREATE TABLE IF NOT EXISTS `z_task_queue` (
  `task_seq` int(11) NOT NULL AUTO_INCREMENT,
  `command` varchar(30) NOT NULL,
  `task_info` text NOT NULL,
  `target_name` varchar(100) NOT NULL,
  `targets` mediumtext NOT NULL,
  `need_num_gpus` tinyint(4) NOT NULL DEFAULT '0',
  `priority` float NOT NULL,
  `running_state` varchar(10) NOT NULL,
  `start_datetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`task_seq`),
  KEY `target_name` (`target_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `classification_learner`
--
ALTER TABLE `classification_learner`
  ADD CONSTRAINT `classification_learner_ibfk_1` FOREIGN KEY (`generator_seq`) REFERENCES `dataset_generator` (`generator_seq`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_classification_model` FOREIGN KEY (`classification_algorithm_seq`) REFERENCES `classification_algorithm` (`classification_algorithm_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `classification_learner_result_info`
--
ALTER TABLE `classification_learner_result_info`
  ADD CONSTRAINT `classification_learner_result_info_ibfk_1` FOREIGN KEY (`classification_learner_seq`) REFERENCES `classification_learner` (`classification_learner_seq`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `classification_learner_result_info_ibfk_2` FOREIGN KEY (`classification_algorithm_seq`) REFERENCES `classification_algorithm` (`classification_algorithm_seq`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `classification_learner_result_info_ibfk_3` FOREIGN KEY (`generator_seq`) REFERENCES `dataset_generator` (`generator_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `clustering_learner`
--
ALTER TABLE `clustering_learner`
  ADD CONSTRAINT `fk_clustering_model` FOREIGN KEY (`clustering_algorithm_seq`) REFERENCES `clustering_algorithm` (`clustering_algorithm_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `clustering_learner_result_info`
--
ALTER TABLE `clustering_learner_result_info`
  ADD CONSTRAINT `clustering_learner_result_info_ibfk_1` FOREIGN KEY (`clustering_learner_seq`) REFERENCES `clustering_learner` (`clustering_learner_seq`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `clustering_learner_result_info_ibfk_2` FOREIGN KEY (`clustering_algorithm_seq`) REFERENCES `clustering_algorithm` (`clustering_algorithm_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `dataset_info`
--
ALTER TABLE `dataset_info`
  ADD CONSTRAINT `dataset_info_ibfk_1` FOREIGN KEY (`generator_seq`) REFERENCES `dataset_generator` (`generator_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `dataset_to_classification_learner`
--
ALTER TABLE `dataset_to_classification_learner`
  ADD CONSTRAINT `fk_classification_learner` FOREIGN KEY (`classification_learner_seq`) REFERENCES `classification_learner` (`classification_learner_seq`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_dataset_info_classification` FOREIGN KEY (`dataset_seq`) REFERENCES `dataset_info` (`dataset_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `dataset_to_clustering_learner`
--
ALTER TABLE `dataset_to_clustering_learner`
  ADD CONSTRAINT `fk_clustering_learner` FOREIGN KEY (`clustering_learner_seq`) REFERENCES `clustering_learner` (`clustering_learner_seq`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_dataset_info_clustering` FOREIGN KEY (`dataset_seq`) REFERENCES `dataset_info` (`dataset_seq`) ON DELETE CASCADE ON UPDATE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
