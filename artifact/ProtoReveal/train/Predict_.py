#!/usr/bin/env python

import os
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
import pickle

script_dir = os.path.dirname(os.path.realpath(__file__))
minmax_scaler_fp = os.path.join(script_dir, "../minmax_scaler.pkl")
rfm_fp = os.path.join(script_dir, "../random_forest_model.pt")

with open(minmax_scaler_fp, "rb") as file:
    loaded_scaler = pickle.load(file)
df = pd.read_csv("New_Level3_depth.csv")
X = df.iloc[:, 5:-1]
y = df.iloc[:, -1]
loaded_rf = joblib.load(rfm_fp)
pred = loaded_rf.predict(loaded_scaler.transform(df.iloc[:, 5:-1]))
df["predicted"] = pred
accuracy = accuracy_score(y, pred)
print(f"Accuracy: {accuracy * 100:.2f}%")
df.to_csv("Result_1.csv")
