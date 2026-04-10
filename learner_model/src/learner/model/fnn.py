# -*- coding: utf-8 -*-
# Default packages
import os
import io
import math
import tarfile
import logging
import tempfile
import functools

# 3rd-party packages
# import numpy as np
import tensorflow as tf

# Internal packages


logger = logging.getLogger(__name__)


def _lazy_property(function):
    attribute = '_' + function.__name__

    @property
    @functools.wraps(function)
    def wrapper(self):
        if not hasattr(self, attribute):
            setattr(self, attribute, function(self))
        return getattr(self, attribute)
    return wrapper


class FNN:
    def init_learner(self, n_input, n_output, batch_size, n_hiddens=[100]*3,
                     learning_rate=.1):
        tf.reset_default_graph()
        self.batch_size = batch_size
        self.learning_rate = learning_rate

        self.n_layers = [n_input] + n_hiddens + [n_output]

        self.data_pl = tf.placeholder(tf.float32, shape=(batch_size, n_input))
        self.labels_pl = tf.placeholder(tf.int32, shape=(batch_size))
        self.learning_rate_pl = tf.placeholder(tf.float32)
        self.__train_op, self.__loss_op, self.__evaluation_op
        self.saver = tf.train.Saver()

        self.sess = tf.Session()
        self.sess.run(tf.initialize_all_variables())

    def load_learner(self, bytes_learner):
        try:
            # bytes_meta_graph, bytes_vars
            fileobj_model = io.BytesIO(bytes_learner)
            with tarfile.open(fileobj=fileobj_model, mode='r:gz') as tar:
                bytes_meta_graph = tar.extractfile('meta_graph').read()
                bytes_vars = tar.extractfile('vars').read()

            tmpfile_meta_graph = self.__gen_tmpfile(bytes_meta_graph)
            # self.saver = tf.train.import_meta_graph(tmpfile_meta_graph)
            os.remove(tmpfile_meta_graph)

            tmpfile_vars = self.__gen_tmpfile(bytes_vars)
            self.saver.restore(self.sess, tmpfile_vars)
            os.remove(tmpfile_vars)
        except Exception as e:
            print(e)

    def export_learner(self):
        try:
            tmp_filename = self.__gen_tmpfile()
            self.saver.save(self.sess, tmp_filename)
            with open(tmp_filename + '.meta', 'rb') as f:
                bytes_meta_graph = f.read()
            with open(tmp_filename, 'rb') as f:
                bytes_vars = f.read()

            fileobj_meta_graph = io.BytesIO(bytes_meta_graph)
            fileobj_vars = io.BytesIO(bytes_vars)
            file0bj_out = io.BytesIO()
            with tarfile.open(fileobj=file0bj_out, mode='w:gz') as tar:
                ti_meta_graph = tarfile.TarInfo('meta_graph')
                ti_meta_graph.size = len(bytes_meta_graph)
                tar.addfile(ti_meta_graph, fileobj_meta_graph)

                ti_vars = tarfile.TarInfo('vars')
                ti_vars.size = len(bytes_vars)
                tar.addfile(ti_vars, fileobj_vars)

            return file0bj_out.getvalue()
        finally:
            try:
                os.remove(tmp_filename + '.meta')
                os.remove(tmp_filename)
                os.remove(os.path.dirname(tmp_filename) + '/checkpoint')
            except Exception as e:
                print(str(e))

    def partial_fit(self, X, y, learning_rate=None):
        if learning_rate is None:
            learning_rate = self.learning_rate

        feed_dict = {self.data_pl: X, self.labels_pl: y,
                     self.learning_rate_pl: learning_rate}
        _, loss_value = self.sess.run([self.__train_op, self.__loss_op],
                                      feed_dict=feed_dict)
        return float(loss_value)

    def predict(self, X, y=None):
        out = {'predicts': [], 'probabilities': []}
        len_X = len(X)
        bs = self.batch_size
        if y is None:
            y = [0] * len_X
            has_label = False
        else:
            out.update({'corrects': []})
            has_label = True

        steps_per_epoch = math.ceil(len_X / bs)
        len_empty_data = (bs - (len_X % bs)) % bs
        if len_empty_data != 0:
            X.extend([[0 for _ in range(len(X[0]))]
                      for y in range(len_empty_data)])
            y.extend([0]*len_empty_data)

        for i in range(steps_per_epoch):
            feed_dict = {self.data_pl: X[i*bs:(i+1)*bs],
                         self.labels_pl: y[i*bs:(i+1)*bs]}
            part_corr, part_pred, part_prob = self.sess.run(
                                    self.__evaluation_op, feed_dict=feed_dict)

            if i != steps_per_epoch - 1 or len_empty_data == 0:
                out['predicts'].extend(part_pred.tolist())
                out['probabilities'].extend(part_prob.tolist())
                if has_label:
                    out['corrects'].extend(part_corr.tolist())
            else:
                out['predicts'].extend(part_pred[:-len_empty_data].tolist())
                out['probabilities'].extend(
                                        part_prob[:-len_empty_data].tolist())
                if has_label:
                    out['corrects'].extend(
                                        part_corr[:-len_empty_data].tolist())

        return out

    def __gen_tmpfile(self, data=None):
        f = tempfile.NamedTemporaryFile(delete=False)
        if data is not None:
            f.write(data)
        filename = f.name
        f.close()
        return filename

    @_lazy_property
    def __logits_op(self):
        in_unit = self.n_layers[0]
        hidden_units = self.n_layers[1:-1]
        out_unit = self.n_layers[-1]
        layer_count = len(hidden_units)

        # Hidden 1
        with tf.name_scope('hidden1'):
            init_vars = tf.truncated_normal(
              [in_unit, hidden_units[0]], stddev=1.0/math.sqrt(float(in_unit)))
            weights = tf.Variable(init_vars, name='weights')
            biases = tf.Variable(tf.zeros([hidden_units[0]]), name='biases')
            previous_layer = tf.nn.relu(
                tf.matmul(self.data_pl, weights) + biases)

        # Hidden n
        for i in range(1, layer_count):
            with tf.name_scope('hidden%d' % (i + 1)):
                init_vars = tf.truncated_normal(
                        [hidden_units[i-1], hidden_units[i]],
                        stddev=1.0/math.sqrt(float(hidden_units[i-1])))
                weights = tf.Variable(init_vars, name='weights')
                biases = tf.Variable(tf.zeros([hidden_units[i]]),
                                     name='biases')
                previous_layer = tf.nn.relu(
                    tf.matmul(previous_layer, weights) + biases)

        # Linear
        with tf.name_scope('softmax_linear'):
            init_vars = tf.truncated_normal(
                [hidden_units[-1], out_unit],
                stddev=1.0/math.sqrt(float(hidden_units[-1])))
            weights = tf.Variable(init_vars, name='weights')
            biases = tf.Variable(tf.zeros([out_unit]), name='biases')
            logits_op = tf.matmul(previous_layer, weights) + biases
        return logits_op

    @_lazy_property
    def __loss_op(self):
        labels_op = tf.expand_dims(self.labels_pl, 1)
        indices = tf.expand_dims(tf.range(0, self.batch_size), 1)
        concated = tf.concat(1, [indices, labels_op])
        packed = tf.pack([self.batch_size, self.n_layers[-1]])
        onehot_labels = tf.sparse_to_dense(concated, packed, 1.0, 0.0)
        cross_entropy = tf.nn.softmax_cross_entropy_with_logits(
                self.__logits_op, onehot_labels, name='xentropy')
        return tf.reduce_mean(cross_entropy, name='xentropy_mean')

    @_lazy_property
    def __train_op(self):
        optimizer = tf.train.AdagradOptimizer(self.learning_rate_pl)
        # optimizer = tf.train.GradientDescentOptimizer(self.learning_rate_pl)
        train_op = optimizer.minimize(self.__loss_op)
        return train_op

    @_lazy_property
    def __evaluation_op(self):
        corrects = tf.nn.in_top_k(self.__logits_op, self.labels_pl, 1)
        predicts = tf.cast(tf.arg_max(self.__logits_op, 1), tf.int32)
        probabilities = tf.nn.softmax(self.__logits_op, name="softmax")

        return corrects, predicts, probabilities


def init_learner(n_input, n_output, batch_size, n_hiddens=[100]*3,
                 learning_rate=.1):
    global fnn
    fnn = FNN()
    fnn.init_learner(n_input, n_output, batch_size, n_hiddens, learning_rate)


def partial_fit(X, y, learning_rate=None):
    return (fnn.partial_fit(X, y, learning_rate))


def predict(X, y=None):
    return fnn.predict(X, y)


def export_learner():
    return fnn.export_learner()


def load_learner(bytes_learner):
    fnn.load_learner(bytes_learner)
