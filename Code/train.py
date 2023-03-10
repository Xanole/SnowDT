import pandas as pd
import numpy as np
import os
import joblib
from sklearn.metrics import *
# from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.tree import DecisionTreeClassifier as DT

np.set_printoptions(threshold=np.inf)

SNOWFLAKE = 1
NORMAL = 0

model_path_DT = 'DT.pkl'

FLOW_LENGTH = 30
normal_data = 'normal_train_' + str(FLOW_LENGTH) + '.csv'
snowflake_data = 'snowflake_train_' + str(FLOW_LENGTH) + '.csv'


def get_data():
    data_m = pd.read_csv(snowflake_data, header=None, nrows=1032)
    label_m = pd.Series([SNOWFLAKE for i in range(1032)])

    data_n = pd.read_csv(normal_data, header=None, nrows=3798)
    label_n = pd.Series([NORMAL for i in range(3798)])

    X = pd.concat([data_m, data_n], axis=0, join='outer')
    Y = pd.concat([label_m, label_n], axis=0, join='outer')

    return X, Y

def train_model(X, Y):
    """
    train machine learning algorithm
    :param DataFrame X: the matrix of the entire data
    :param Series Y: the vector of the entire labels
    :param str model_name: the classification model (DT, NB or KNN)
    """
    model = DT()
    model_path = model_path_DT

    min_score = 0
    accuracy_list = []
    tpr_list = []
    fpr_list = []
    for i in range(10):
        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.3)
        # print(np.shape(X_train))
        # print(np.shape(X_test))
        model.fit(X_train, Y_train)

        score = model.score(X_test, Y_test)
        accuracy_list.append(score)

        result = get_stat(list(Y_test), model.predict(X_test).tolist())
        tpr_list.append(result[0])
        fpr_list.append(result[1])

        if score > min_score:
            min_score = score
            joblib.dump(model, model_path)
            print(score)

    avg_accuracy = sum(accuracy_list) / len(accuracy_list)
    avg_tpr = sum(tpr_list) / len(tpr_list)
    avg_fpr = sum(fpr_list) / len(fpr_list)
    return avg_accuracy, avg_tpr, avg_fpr


def test_model(X, Y, model_name):
    """
    load and test machine learning algorithm
    :param DataFrame X: the matrix of the entire data
    :param Series Y: the vector of the entire labels
    :param str model_name: the classification model (DT, NB or KNN)
    """
    model_path = model_path_DT

    model = joblib.load(model_path)
    result = get_stat(list(Y), model.predict(X).tolist())

    return result


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
    label = SNOWFLAKE
    for i in range(len(ypred)):
        # print(ypred[i], ytest[i])
        if ypred[i] == label and ytest[i] == label:
            tp += 1
        elif ypred[i] == label and ytest[i] != label:
            fp += 1
        elif ypred[i] != label and ytest[i] == label:
            fn += 1
        elif ypred[i] != label and ytest[i] != label:
            tn += 1
    tpr = float(tp / list(ytest).count(SNOWFLAKE))
    fpr = float(fp / list(ytest).count(NORMAL))
    # fnr = float(fn / list(ytest).count(SNOWFLAKE))
    # tnr = float(tn / list(ytest).count(NORMAL))
    accuracy = float((tp + tn) / (list(ytest).count(SNOWFLAKE) + list(ytest).count(NORMAL)))
    if tp + fp == 0:
        precision = 0.0
    else:
        precision = float(tp / (tp + fp))

    return [tpr, fpr, accuracy, precision]


if __name__ == '__main__':

    X, Y = get_data()

    avg_accuracy, avg_tpr, avg_fpr = train_model(X, Y)
    print('DT', round(avg_accuracy*100, 2), round(avg_tpr*100, 2), round(avg_fpr*100, 2))


