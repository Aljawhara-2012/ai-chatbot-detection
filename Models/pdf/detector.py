"""PDF detector used by the chatbot (revision R8).

Pipeline: full 30-feature extraction from the uploaded file (pdf_features.py, same definitions and units as the
Evasive-PDFMal2022 training data) -> fitted pipeline (in-fold feature selection -> StandardScaler -> classifier;
SMOTE is only active during training) -> prediction.  The deployed classifier is Random Forest, selected by
cross-validation on the training partition.  The SVM pipeline, trained under the same protocol, is kept for the
side-by-side comparison requested by the reviewers (Major Point 3) and is not used for alerts.
"""
import os, time
import joblib, pandas as pd
from .pdf_features import extract_features, FEATURES

def _single_thread(pipe):
    """Per-request prediction on one sample: parallel tree evaluation only adds overhead."""
    for _, step in pipe.steps:
        for obj in (step, getattr(step, 'estimator_', None), getattr(step, 'estimator', None)):
            if obj is not None and hasattr(obj, 'n_jobs'):
                obj.n_jobs = 1
    return pipe


_BASE = os.path.dirname(__file__)
_COMPARE = os.environ.get('CHATBOT_EVAL_MODE') == '1'
_RF = joblib.load(os.path.join(_BASE, 'pdf_rf_pipeline.joblib'))
_SVM = joblib.load(os.path.join(_BASE, 'pdf_svm_pipeline.joblib'))
_single_thread(_RF['pipeline']); _single_thread(_SVM['pipeline'])
assert _RF['features'] == FEATURES and _SVM['features'] == FEATURES, 'extractor/model feature order mismatch'


def _predict(bundle, X, rf=False):
    p = bundle['pipeline']
    proba = float(p.predict_proba(X)[0, 1])
    # Random Forest: predict() is the argmax of the averaged tree probabilities, so one call suffices
    label = int(proba > 0.5) if rf else int(p.predict(X)[0])
    return ('Malicious' if label == 1 else 'Benign'), proba


def analyse_pdf(path):
    t0 = time.perf_counter()
    feats = extract_features(path)
    t1 = time.perf_counter()
    X = pd.DataFrame([feats], columns=FEATURES)
    label, proba = _predict(_RF, X, rf=True)
    t2 = time.perf_counter()
    comparison = None
    if _COMPARE:  # SVM on the same extracted features, evaluation mode only (never used for alerts)
        svm_label, svm_proba = _predict(_SVM, X)
        comparison = {'svm_prediction': svm_label, 'svm_malicious_probability': round(svm_proba, 4)}
    return {'prediction': label, 'model': 'Random Forest',
            'probabilities': {'Malicious': round(proba, 4), 'Benign': round(1 - proba, 4)},
            'comparison': comparison,
            'features': feats, 'timing_s': {'feature_extraction': t1 - t0, 'classification': t2 - t1}}
