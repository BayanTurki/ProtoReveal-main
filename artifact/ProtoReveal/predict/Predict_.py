#!/usr/bin/env python

import os
import pandas as pd
import joblib
import pickle
import sklearn
print(sklearn.__version__)

script_dir = os.path.dirname(os.path.realpath(__file__))
scaler_fp = os.path.join(script_dir, "../scaler.pkl")
predictor_fp = os.path.join(script_dir, "../predictor.pt")

def Predict():
    with open(scaler_fp, "rb") as file:
        loaded_scaler = pickle.load(file)
    df = pd.read_csv("Level3_PrePredict.csv")
    X = df[[
        "Shl",
        "Shr", 
        "Mul",
        "Sub",
        "Add",
        "Div",
        "And",
        "Or",
        "Xor",
        "Cmp",
        "Succ_len",
        "pred_len",
        "GET",
        "PUT",
        "jk",
    ]]
    print(X)
    print(sklearn.__version__)
    loaded_rf = joblib.load(predictor_fp)
    pred = loaded_rf.predict(loaded_scaler.transform(X))
    df["predicted"] = pred
    df.to_json("prediction.json")
    df.to_csv("prediction.csv")


if __name__ == "__main__":
    Predict()
