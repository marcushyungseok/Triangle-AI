# -*- coding: utf-8 -*-
import learner.model.fnn as fnn

if __name__ == '__main__':
    fnn.init_learner(2, 2, 4)
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print('Training done.')

    bb = fnn.export_learner()
    with open('test.bin', 'wb') as f:
        f.write(bb)
    print('Saved.')

    fnn.init_learner(2, 2, 4)
    with open('test.bin', 'rb') as f:
        bb = f.read()
    fnn.init_learner(2, 2, 4)
    print('Loaded.')
    fnn.load_learner(bb)
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.partial_fit([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print(fnn.predict([[1, 0], [1, 0], [0, 1], [0, 1]], [1, 1, 0, 0]))
    print('Online training done.')
