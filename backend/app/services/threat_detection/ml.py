"""Lightweight NLP classifier: TF-IDF (word 1-2 grams) + Logistic Regression.

Trained in well under a second from the bundled synthetic CSV the first time it is
needed. Metrics are computed honestly with 5-fold stratified cross-validation on
that same dataset (see data/README.md for why they are NOT real-world accuracy).
"""
from __future__ import annotations

import csv
import logging
import threading
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline

log = logging.getLogger(__name__)

DATASET = Path(__file__).parent / "data" / "training_emails.csv"
MODEL_NAME = "tfidf-logreg-v1"

_lock = threading.Lock()
_model: Pipeline | None = None
_info: dict | None = None


def _load_dataset() -> tuple[list[str], list[str]]:
    texts, labels = [], []
    with DATASET.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            texts.append(row["text"])
            labels.append(row["label"])
    return texts, labels


def _build() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True, min_df=1, stop_words="english")),
        ("clf", LogisticRegression(max_iter=2000, C=10.0, class_weight="balanced")),
    ])


def _train() -> tuple[Pipeline, dict]:
    texts, labels = _load_dataset()
    classes = sorted(set(labels))
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    predicted = cross_val_predict(_build(), texts, labels, cv=cv)
    p, r, f1, _ = precision_recall_fscore_support(labels, predicted, average="macro", zero_division=0)
    metrics = {
        "evaluation": "5-fold stratified cross-validation on the bundled synthetic dataset",
        "n_samples": len(texts),
        "class_counts": {c: labels.count(c) for c in classes},
        "accuracy": round(float(accuracy_score(labels, predicted)), 4),
        "macro_precision": round(float(p), 4),
        "macro_recall": round(float(r), 4),
        "macro_f1": round(float(f1), 4),
        "confusion_matrix": {"labels": classes, "matrix": confusion_matrix(labels, predicted, labels=classes).tolist()},
        "caveat": "Tiny synthetic dataset: demonstrates the pipeline, does not estimate real-world performance.",
    }
    model = _build().fit(texts, labels)
    return model, {"model": MODEL_NAME, "classes": classes, "metrics": metrics}


def get_model() -> tuple[Pipeline, dict]:
    global _model, _info
    with _lock:
        if _model is None:
            _model, _info = _train()
            log.info("Trained %s (cv macro-F1 %.3f)", MODEL_NAME, _info["metrics"]["macro_f1"])
        return _model, _info


def classify(text: str) -> dict:
    model, info = get_model()
    text = (text or "").strip()
    if not text:
        return {"model": MODEL_NAME, "status": "skipped", "reason": "no text content", "predicted_category": None, "probability": None, "probabilities": {}}
    proba = model.predict_proba([text[:5000]])[0]
    classes = list(model.classes_)
    order = np.argsort(proba)[::-1]
    top = classes[order[0]]
    # most influential terms for the predicted class (transparency)
    vec: TfidfVectorizer = model.named_steps["tfidf"]
    clf: LogisticRegression = model.named_steps["clf"]
    x = vec.transform([text[:5000]])
    coef = clf.coef_[classes.index(top)]
    contrib = x.multiply(coef).toarray()[0]
    names = vec.get_feature_names_out()
    top_terms = [names[i] for i in np.argsort(contrib)[::-1][:6] if contrib[i] > 0]
    return {
        "model": MODEL_NAME,
        "status": "success",
        "predicted_category": top,
        "probability": round(float(proba[order[0]]), 4),
        "probabilities": {classes[i]: round(float(proba[i]), 4) for i in order},
        "top_terms": top_terms,
        "note": "Trained on a small synthetic dataset; treat as one supporting signal, not a verdict.",
    }


def model_info() -> dict:
    return get_model()[1]
