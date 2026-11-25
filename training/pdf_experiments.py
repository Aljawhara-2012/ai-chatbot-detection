"""Leakage-free PDF experiments for the R8 revision (Evasive-PDFMal2022, PDFMalware2022.csv).

E1  Reproduce the original (leaky) protocol: scaler + SMOTE on all data, then 75/25 split.
E2  PRIMARY: split first (75/25 stratified, rs=42). On the training partition only:
    5-fold stratified CV with feature selection -> StandardScaler -> SMOTE -> classifier inside each fold.
    Model (SVM vs RF) and hyper-parameters chosen on mean CV F1 (malicious class).
    Selected model refitted on the whole training partition and evaluated ONCE on the untouched test set.
E2b Same as E2 but with the predefined 16-feature list (to quantify any feature-selection leakage).
E3  Nested CV (5 outer folds) of the complete E2 selection procedure.
E4  Deployment simulation: E2 models fed the vector the original chatbot builds
    (pdfsize in BYTES, pageno = pages, all other 14 features = 0), and with the unit fixed (KB).
E5  Model restricted to the two features the original chatbot computes (pdfsize, pages).
Positive class = malicious (1).
"""
import json, sys, time, warnings
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix)
from imblearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")
RS = 42
PRE16 = ['pdfsize', 'xref Length', 'embedded files', 'images', 'text', 'obj', 'stream', 'xref', 'trailer', 'pageno',
         'Javascript', 'AA', 'OpenAction', 'EmbeddedFile', 'XFA', 'Colors']
out = {}


def load(path):
    df = pd.read_csv(path)
    df['Class'] = np.where(df['Class'].isna() | df['Class'].astype(str).str.contains("Malicious"), 1, 0)  # notebook semantics: NaN is truthy in np.where -> 1
    df = df.fillna(0)
    df['text'] = np.where(df['text'].astype(str).str.contains("Yes"), 1, 0)
    cand = [c for c in df.columns if c not in ('File name', 'header', 'Class')]
    X = df[cand].apply(pd.to_numeric, errors='coerce')
    keep = X[PRE16].notna().all(axis=1)  # same row filter as the notebook (10,004 rows)
    X, y = X[keep], df.loc[keep, 'Class']
    X = X.fillna(0)  # non-numeric values in non-selected columns (label-free constant)
    return X.astype(float), y.astype(int), cand


def metrics(y, pred, score=None):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    d = dict(n=int(len(y)), tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
             acc=accuracy_score(y, pred), prec=precision_score(y, pred, zero_division=0),
             rec=recall_score(y, pred, zero_division=0), f1=f1_score(y, pred, zero_division=0))
    if score is not None and len(set(y)) > 1:
        d['auc'] = roc_auc_score(y, score)
    return d


def score_of(m, X):
    return m.decision_function(X) if hasattr(m, 'decision_function') and not hasattr(m, 'predict_proba') else m.predict_proba(X)[:, 1]


def fs():
    return SelectFromModel(RandomForestClassifier(n_estimators=100, random_state=RS, n_jobs=-1),
                           max_features=16, threshold=-np.inf)


def make(clf, select=True):
    steps = ([('fs', fs())] if select else []) + [('sc', StandardScaler()), ('sm', SMOTE(random_state=RS)), ('clf', clf)]
    return Pipeline(steps)


CANDS = {
    'SVM': (SVC(kernel='rbf', gamma='scale', class_weight='balanced', probability=True, random_state=RS),
            {'clf__C': [1, 10]}),
    'Random Forest': (RandomForestClassifier(class_weight='balanced', random_state=RS, n_jobs=-1),
                      {'clf__n_estimators': [100, 300]}),
}


def select_and_fit(Xtr, ytr, select=True, cv_seed=RS):
    cv = StratifiedKFold(5, shuffle=True, random_state=cv_seed)
    res = {}
    for name, (clf, grid) in CANDS.items():
        g = GridSearchCV(make(clf, select), grid, scoring='f1', cv=cv, n_jobs=1, refit=True)
        g.fit(Xtr, ytr)
        i = g.best_index_
        res[name] = dict(model=g.best_estimator_, params=g.best_params_,
                         cv_f1=float(g.cv_results_['mean_test_score'][i]), cv_f1_sd=float(g.cv_results_['std_test_score'][i]))
    best = max(res, key=lambda k: res[k]['cv_f1'])
    return res, best


def deployed_vector(X, unit='bytes', cols=None):
    """Vector the original chatbot builds from an uploaded file: pdfsize from os.path.getsize (bytes),
    pageno from len(reader.pages); every other feature fixed at 0."""
    V = pd.DataFrame(0.0, index=X.index, columns=cols)
    V['pdfsize'] = X['pdfsize'] * (1024.0 if unit == 'bytes' else 1.0)
    V['pageno'] = X['pages']
    return V


if __name__ == '__main__':
    X, y, cand = load(sys.argv[1])
    out['data'] = dict(n=int(len(y)), malicious=int(y.sum()), benign=int((y == 0).sum()), candidate_features=len(cand))
    print(out['data'], flush=True)

    # ---------------- E1 original leaky protocol (reproduction)
    Xs = StandardScaler().fit_transform(X[PRE16])
    Xr, yr = SMOTE(random_state=RS).fit_resample(Xs, y)
    a, b, c, d = train_test_split(Xr, yr, test_size=0.25, random_state=RS, shuffle=True)
    e1 = {}
    for name, m in [('SVM', SVC(C=10, class_weight='balanced', probability=True)), ('Random Forest', RandomForestClassifier(class_weight='balanced', random_state=RS))]:
        m.fit(a, c); e1[name] = metrics(d, m.predict(b), m.predict_proba(b)[:, 1])
    out['E1_original_leaky'] = e1
    print('E1', {k: round(v['acc'], 4) for k, v in e1.items()}, flush=True)

    # ---------------- primary split
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=RS, stratify=y)
    out['split'] = dict(train=int(len(ytr)), train_mal=int(ytr.sum()), test=int(len(yte)), test_mal=int(yte.sum()), test_ben=int((yte == 0).sum()))
    print(out['split'], flush=True)

    # ---------------- E2 primary (all candidate features, in-fold selection)
    t = time.time(); res, best = select_and_fit(Xtr, ytr, True)
    e2 = {}
    for name, r in res.items():
        m = r['model']; p = m.predict(Xte)
        e2[name] = dict(params=r['params'], cv_f1=r['cv_f1'], cv_f1_sd=r['cv_f1_sd'], test=metrics(yte, p, m.predict_proba(Xte)[:, 1]))
        sel = m.named_steps['fs'].get_support()
        e2[name]['features'] = [f for f, s in zip(cand, sel) if s]
    out['E2_primary'] = dict(selected=best, results=e2, secs=time.time() - t)
    print('E2 selected by CV:', best, {k: (round(v['cv_f1'], 4), round(v['test']['acc'], 4)) for k, v in e2.items()}, flush=True)

    # ---------------- E2b predefined 16 features
    res_b, best_b = select_and_fit(Xtr[PRE16], ytr, False)
    out['E2b_predefined16'] = dict(selected=best_b, results={k: dict(cv_f1=r['cv_f1'], test=metrics(yte, r['model'].predict(Xte[PRE16]), r['model'].predict_proba(Xte[PRE16])[:, 1])) for k, r in res_b.items()})
    print('E2b', best_b, {k: round(v['test']['acc'], 4) for k, v in out['E2b_predefined16']['results'].items()}, flush=True)

    # ---------------- E4 deployment simulation on untouched test set (models from E2b: same 16 features as the app)
    e4 = {}
    for unit in ('bytes', 'kb'):
        V = deployed_vector(Xte, unit, PRE16)
        for name, r in res_b.items():
            m = r['model']; p = m.predict(V)
            e4[f'{name}|{unit}'] = metrics(yte, p, m.predict_proba(V)[:, 1])
            e4[f'{name}|{unit}']['pred_malicious_share'] = float(p.mean())
    out['E4_deployment_simulation'] = e4
    print('E4', {k: (round(v['acc'], 3), round(v['rec'], 3), round(v['pred_malicious_share'], 3)) for k, v in e4.items()}, flush=True)

    # ---------------- E5 runtime-only features
    rt = ['pdfsize', 'pages']
    res5, best5 = select_and_fit(Xtr[rt], ytr, False)
    out['E5_runtime_only'] = dict(selected=best5, results={k: dict(cv_f1=r['cv_f1'], test=metrics(yte, r['model'].predict(Xte[rt]), r['model'].predict_proba(Xte[rt])[:, 1])) for k, r in res5.items()})
    print('E5', {k: round(v['test']['acc'], 4) for k, v in out['E5_runtime_only']['results'].items()}, flush=True)

    # ---------------- E3 nested CV of the full procedure
    outer = StratifiedKFold(5, shuffle=True, random_state=RS)
    folds = []
    for k, (tr, te) in enumerate(outer.split(X, y)):
        r, b = select_and_fit(X.iloc[tr], y.iloc[tr], True, cv_seed=RS + k)
        m = r[b]['model']
        folds.append(dict(selected=b, **metrics(y.iloc[te], m.predict(X.iloc[te]), m.predict_proba(X.iloc[te])[:, 1])))
        print('  outer', k, b, round(folds[-1]['acc'], 4), flush=True)
    out['E3_nested'] = dict(folds=folds, **{f'{m}_mean': float(np.mean([f[m] for f in folds])) for m in ('acc', 'prec', 'rec', 'f1', 'auc')},
                            **{f'{m}_sd': float(np.std([f[m] for f in folds], ddof=1)) for m in ('acc', 'prec', 'rec', 'f1', 'auc')})

    # save final selected model for deployment
    import joblib
    for k, r in res.items():
        joblib.dump(dict(pipeline=r['model'], features=cand, positive_label=1, trained_on='split-first training partition (7,503 samples), in-fold selection/scaling/SMOTE'),
                    'pdf_%s_pipeline.joblib' % ('rf' if k == 'Random Forest' else 'svm'))
    json.dump(out, open('pdf_results.json', 'w'), indent=1, default=float)
    print('done')
