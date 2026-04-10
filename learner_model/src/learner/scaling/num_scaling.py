# -*- coding: utf-8 -*-
'''
**Auto scaling function for numbers**
'''
# 3rd-party packages
import numpy as np


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
