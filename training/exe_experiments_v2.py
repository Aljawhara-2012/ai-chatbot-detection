"""Leakage-free EXE experiments (v2: without the four PE-header fields that encode the 32/64-bit format:
Machine, SizeOfOptionalHeader, ImageBase, Characteristics; in the training data 64-bit files are almost exclusively
legitimate, so these fields act as a dataset shortcut rather than an indicator of maliciousness).
 (PE-header dataset, 138,047 samples, label 'legitimate': 0 = malicious, 1 = legitimate).

PRIMARY: split first (80/20 stratified, rs=42; test set keeps the natural ~70% malicious ratio).
On the training partition only: 5-fold stratified CV, with RandomUnderSampler -> ExtraTrees SelectFromModel
-> classifier inside each fold. The six Table-7 classifiers are compared on mean CV F1 (malicious class);
the selected model is refitted on the whole training partition and evaluated ONCE on the untouched test set.
Positive class = malicious.
"""
import json, sys, time, warnings
import numpy as np, pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LinearRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from imblearn.pipeline import Pipeline
from imblearn.under_sampling import RandomUnderSampler

warnings.filterwarnings("ignore")
RS = 42


class LinearRegressionClassifier(BaseEstimator, ClassifierMixin):
    """Ordinary least-squares regression on the 0/1 label, thresholded at 0.5 ('Linear Regression' in Table 7)."""
    def fit(self, X, y):
        self.m_ = LinearRegression().fit(X, y); self.classes_ = np.array([0, 1]); return self
    def predict_proba(self, X):
        p = np.clip(self.m_.predict(X), 0, 1); return np.c_[1 - p, p]
    def predict(self, X):
        return (self.m_.predict(X) >= 0.5).astype(int)


MODELS = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=RS, n_jobs=-1),
    'Decision Tree': DecisionTreeClassifier(random_state=RS),
    'Gradient Boosting': GradientBoostingClassifier(random_state=RS),
    'AdaBoost': AdaBoostClassifier(random_state=RS),
    'Linear Regression': LinearRegressionClassifier(),
    'Gaussian NB': GaussianNB(),
}


def pipe(clf):
    return Pipeline([('us', RandomUnderSampler(random_state=RS)),
                     ('fs', SelectFromModel(ExtraTreesClassifier(n_estimators=50, random_state=RS, n_jobs=-1))),
                     ('clf', clf)])


def metrics(y, pred, score):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return dict(n=int(len(y)), tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp), acc=accuracy_score(y, pred),
                prec=precision_score(y, pred), rec=recall_score(y, pred), f1=f1_score(y, pred), auc=roc_auc_score(y, score))


if __name__ == '__main__':
    df = pd.read_csv(sys.argv[1], sep='|')
    BITNESS = ['Machine', 'SizeOfOptionalHeader', 'ImageBase', 'Characteristics']
    X = df.drop(['Name', 'md5', 'legitimate'] + BITNESS, axis=1).astype(float)
    y = (df['legitimate'] == 0).astype(int)  # 1 = malicious (positive class)
    out = dict(data=dict(n=int(len(y)), malicious=int(y.sum()), benign=int((y == 0).sum()), features=X.shape[1]))
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=RS, stratify=y)
    out['split'] = dict(train=int(len(ytr)), train_mal=int(ytr.sum()), test=int(len(yte)), test_mal=int(yte.sum()), test_ben=int((yte == 0).sum()))
    print(out, flush=True)
    cv = StratifiedKFold(5, shuffle=True, random_state=RS)
    res = {}
    for name, clf in MODELS.items():
        t = time.time()
        r = cross_validate(pipe(clf), Xtr, ytr, cv=cv, scoring=['f1', 'accuracy', 'precision', 'recall'], n_jobs=1)
        m = pipe(clf).fit(Xtr, ytr)
        p = m.predict(Xte); s = m.predict_proba(Xte)[:, 1]
        res[name] = dict(cv_f1=float(r['test_f1'].mean()), cv_f1_sd=float(r['test_f1'].std(ddof=1)),
                         cv_acc=float(r['test_accuracy'].mean()), cv_prec=float(r['test_precision'].mean()), cv_rec=float(r['test_recall'].mean()),
                         n_features=int(m.named_steps['fs'].get_support().sum()),
                         features=list(X.columns[m.named_steps['fs'].get_support()]),
                         train_after_undersampling=int(2 * min(ytr.sum(), (ytr == 0).sum())),
                         test=metrics(yte, p, s), secs=time.time() - t)
        print(name, round(res[name]['cv_f1'], 4), round(res[name]['test']['acc'], 4), res[name]['n_features'], flush=True)
        if name == 'Random Forest':
            import joblib; joblib.dump(dict(pipeline=m, features=list(X.columns), positive_label=1, label_meaning='1 = malicious'), 'exe_rf_pipeline_v2.joblib')
    out['results'] = res
    out['selected'] = max(res, key=lambda k: res[k]['cv_f1'])
    json.dump(out, open('exe_results_v2.json', 'w'), indent=1, default=float)
    print('selected:', out['selected'])
