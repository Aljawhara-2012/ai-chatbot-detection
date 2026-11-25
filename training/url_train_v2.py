"""R8 correction: URL CatBoost retrained without the three features that the runtime extractor cannot compute.
WebsiteTraffic (Alexa service discontinued in 2022) and PageRank (checkpagerank query) always return -1 at runtime,
GoogleIndex always returns 1, whereas in the training data these features vary by class.
Same split (80/20, random_state=42) and configuration as url_experiments.py; fitted on the training partition only."""
import pickle, sys, json, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from catboost import CatBoostClassifier

DROP = ['WebsiteTraffic', 'PageRank', 'GoogleIndex']
df = pd.read_csv(sys.argv[1]).drop(columns=['Index'])
feats_all = [c for c in df.columns if c != 'class']
keep = [i for i, c in enumerate(feats_all) if c not in DROP]
X = df[feats_all].values
y = (df['class'] == -1).astype(int).values  # 1 = phishing (positive), exactly as in url_experiments.py
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
m = CatBoostClassifier(learning_rate=0.1, verbose=0, random_state=42).fit(Xtr[:, keep], ytr)
p = m.predict(Xte[:, keep]).ravel().astype(int)
res = dict(acc=accuracy_score(yte, p), prec=precision_score(yte, p), rec=recall_score(yte, p), f1=f1_score(yte, p))
print({k: round(v * 100, 2) for k, v in res.items()}, 'classes', list(m.classes_))
pickle.dump({'model': m, 'positive_class': 'phishing = 1', 'keep_idx': keep, 'features': [feats_all[i] for i in keep], 'dropped': DROP},
            open('Models/URL/pickle/catboost_model_v2.pkl', 'wb'))
