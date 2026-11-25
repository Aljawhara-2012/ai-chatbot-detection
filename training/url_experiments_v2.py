"""URL detector: model selection by 5-fold CV on the training partition only (Reviewer 9, Comment 3).
Same 80/20 split as the paper (random_state=42); phishing (-1) is the positive class.
Configurations follow the original notebook; the held-out test set is used once, after selection."""
DROP = ['WebsiteTraffic', 'PageRank', 'GoogleIndex']
import json, sys, numpy as np, pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, make_scorer
from catboost import CatBoostClassifier
from xgboost import XGBClassifier

df = pd.read_csv(sys.argv[1]).drop(columns=['Index'] + DROP)
X = df.drop(columns=['class']).values
y = (df['class'] == -1).astype(int).values  # 1 = phishing (positive)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
M = {
    'Logistic Regression': LogisticRegression(),
    'K-Nearest Neighbors': KNeighborsClassifier(n_neighbors=1),
    'Support Vector Machine': SVC(gamma=0.1, kernel='rbf', random_state=42),
    'Naive Bayes': GaussianNB(),
    'Decision Tree': DecisionTreeClassifier(max_depth=30, random_state=42),
    'Random Forest': RandomForestClassifier(n_estimators=10, random_state=42),
    'Gradient Boosting': GradientBoostingClassifier(max_depth=4, learning_rate=0.7, random_state=42),
    'CatBoost': CatBoostClassifier(learning_rate=0.1, verbose=0, random_state=42),
    'XGBoost': XGBClassifier(random_state=42, eval_metric='logloss'),
    'Multilayer Perceptron': MLPClassifier(random_state=42),
}
cv = StratifiedKFold(5, shuffle=True, random_state=42)
out = {'split': dict(train=int(len(ytr)), test=int(len(yte)), test_phishing=int(yte.sum()))}
for n, m in M.items():
    f1 = cross_val_score(m, Xtr, ytr, cv=cv, scoring='f1'); acc = cross_val_score(m, Xtr, ytr, cv=cv, scoring='accuracy')
    m.fit(Xtr, ytr); p = m.predict(Xte)
    out[n] = dict(cv_f1=f1.mean(), cv_f1_sd=f1.std(ddof=1), cv_acc=acc.mean(), test=dict(acc=accuracy_score(yte, p), f1=f1_score(yte, p),
                  rec=recall_score(yte, p), prec=precision_score(yte, p)))
    print(f"{n:24s} CV F1 {f1.mean()*100:.2f}±{f1.std(ddof=1)*100:.2f} CV acc {acc.mean()*100:.2f} | test acc {out[n]['test']['acc']*100:.1f} F1 {out[n]['test']['f1']*100:.1f} R {out[n]['test']['rec']*100:.1f} P {out[n]['test']['prec']*100:.1f}", flush=True)
out['selected_by_cv_f1'] = max((k for k in M), key=lambda k: out[k]['cv_f1'])
out['selected_by_cv_acc'] = max((k for k in M), key=lambda k: out[k]['cv_acc'])
print('selected (CV F1):', out['selected_by_cv_f1'], '| (CV acc):', out['selected_by_cv_acc'])
json.dump(out, open('url_results_v2.json', 'w'), indent=1, default=float)
