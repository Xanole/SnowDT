import pandas as pd
import numpy as np
import os
import joblib
from sklearn.metrics import *
# from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.tree import DecisionTreeClassifier as DT

from Snowflake_Detection.extract_features import *

np.set_printoptions(threshold=np.inf)

SNOWFLAKE = 1
NORMAL = 0

model_path_DT = 'DT.pkl'

def get_data(pcap_path):
    FLOW_LENGTH = 30

    flow = extract_flow(pcap_path, FLOW_LENGTH)
    res = []

    # F1
    for direction in [UPSTREAM, DOWNSTREAM]:
        tmp = time_bins(flow, direction)
        res += tmp
    # F2
    for direction in [UPSTREAM, DOWNSTREAM]:
        tmp = top5_size(flow, direction)
        res += tmp
    # F3
    for direction in [UPSTREAM, DOWNSTREAM]:
        tmp = top5_size_percentage(flow, direction)
        res += tmp
    # F4
    for direction in [UPSTREAM, DOWNSTREAM]:
        tmp = direction_sum(flow, direction)
        res.append(tmp)
    # F5
    for direction in [UPSTREAM, DOWNSTREAM]:
        tmp = direction_percentage(flow, direction)
        res.append(tmp)
    # F6
    tmp = direction_ratio(flow, BOTH)
    res.append(tmp)
    # # F7
    # tmp = network_speed(flow)
    # res += tmp

    data_n = pd.DataFrame([res])
    label_n = pd.Series([[NORMAL]])

    X = data_n
    Y = label_n

    return X, Y


def test_model(X, Y):
    """
    load and test machine learning algorithm
    :param DataFrame X: the matrix of the entire data
    :param Series Y: the vector of the entire labels
    """

    predict_dict = {'DT': -1}

    model = joblib.load(model_path_DT)
    predict_dict['DT'] = model.predict(X)[0]

    return predict_dict


def get_stat(ytest, ypred):
    """
    calculate the TPR/FPR/FNR/TNR/PR_AUC
    :param list ytest: the array for the labels of the test instances
    :param list ypred: the array for the predicted labels of the
    test instances
    """
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    label = "true"
    for i in range(len(ypred)):
        if ypred[i] == label and ytest[i] == label:
            tp += 1
        elif ypred[i] == label and ytest[i] != label:
            fp += 1
        elif ypred[i] != label and ytest[i] == label:
            fn += 1
        elif ypred[i] != label and ytest[i] != label:
            tn += 1
    tpr = float(tp / list(ytest).count("true"))
    fpr = float(fp / list(ytest).count("false"))
    fnr = float(fn / list(ytest).count("true"))
    tnr = float(tn / list(ytest).count("false"))
    auc = precision_score(ytest, ypred, pos_label=label)

    return [tpr, fpr, fnr, tnr, auc]


if __name__ == '__main__':

    pcap_archive = 'version'

    DT_recall = []

    sub_archive = os.listdir(pcap_archive)
    for archive in sub_archive:
        print(archive, end=' ')
        pcap_dir = os.listdir(os.path.join(pcap_archive, archive))

        DT_number = 0
        pcap_number = len(pcap_dir)
        print("total: %d" % pcap_number)

        for pcap in pcap_dir:
            pcap_path = os.path.join(pcap_archive, archive, pcap)

            # print(pcap_path)
            X, Y = get_data(pcap_path)
            predict_result = test_model(X, Y)
            # print(predict_result)
            DT_number += predict_result['DT']

        DT_recall.append(float(DT_number / pcap_number))

        print("DT %f" % float(DT_number / pcap_number))

    print('----------------------------------')
    for i in range(len(DT_recall)):
        print(round(DT_recall[i]*100, 2))


