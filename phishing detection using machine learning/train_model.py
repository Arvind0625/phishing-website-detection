import pandas as pd
import re
import math
import whois
from datetime import datetime
from collections import Counter
from sklearn.model_selection import train_test_split
import xgboost as xgb
import pickle
import ssl
import socket
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import cross_val_score
# ----------- SMART FEATURE FUNCTIONS ------------ #

def url_entropy(url):
    counts = Counter(url)
    probs = [c/len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def keyword_score(url):
    suspicious_words = ["login", "verify", "bank", "secure", "update", "free"]
    return sum(word in url.lower() for word in suspicious_words)

def is_ip(url):
    return 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

def count_digits(url):
    return sum(c.isdigit() for c in url)
def subdomain_count(url):
    return url.count(".") - 1

def has_at_symbol(url):
    return 1 if "@" in url else 0

def has_https(url):
    return 1 if url.startswith("https") else 0

def suspicious_tld(url):
    bad_tlds = [".tk",".ml",".ga",".cf",".gq"]
    return int(any(url.endswith(tld) for tld in bad_tlds))

def slash_count(url):
    return url.count("/")

def query_length(url):
    if "?" in url:
        return len(url.split("?")[1])
    return 0

def special_char_count(url):
    return len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url))

def extract_features(url):

    return [
    len(url),
    url.count("."),
    url.count("-"),
    count_digits(url),
    is_ip(url),
    keyword_score(url),
    url_entropy(url),
    subdomain_count(url),
    has_at_symbol(url),
    has_https(url),
    suspicious_tld(url),
    slash_count(url),
    query_length(url),
    special_char_count(url)
]

# ----------- LOAD DATASET ------------ #

data = pd.read_csv("newdataset.csv")

X = data["URL"].apply(lambda x: pd.Series(extract_features(str(x))))
y = data["label"]

# ----------- TRAIN ------------ #

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42
)
model.fit(X_train, y_train)


# ----------- EVALUATE MODEL ------------ #

pred = model.predict(X_test)

accuracy = accuracy_score(y_test, pred)
precision = precision_score(y_test, pred)
recall = recall_score(y_test, pred)
f1 = f1_score(y_test, pred)

# probability predictions for ROC
probs = model.predict_proba(X_test)[:,1]
roc = roc_auc_score(y_test, probs)
scores = cross_val_score(model, X, y, cv=5)
cm = confusion_matrix(y_test, pred)

print("Model Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1 Score:", f1)
print("ROC-AUC:", roc)

print("\nConfusion Matrix:")
print(cm)
print("Cross Validation Accuracy:", scores.mean())

# ----------- SAVE MODEL ------------ #

with open("models/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model Trained & Saved Successfully")
print("Model trained with features:", model.n_features_in_)