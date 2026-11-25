"""Compare the earlier deployed URL model (CatBoost, 30 features) with the corrected model (27 features)
on the SAME feature vectors: features are extracted once per URL, then both models score them.
Run from the chatbot folder (venv active; the server does not need to run):
    python tools\\compare_url_models.py --urls tools\\urls_eval.csv --out url_compare
Writes url_compare/per_url.csv (features + both verdicts) and url_compare/summary.txt."""
import argparse, os, pickle, sys, csv, time
import numpy as np, pandas as pd
sys.path.insert(0, os.getcwd())
from Models.URL.feature import FeatureExtraction
from Models.URL.app import gbc as new_model  # corrected model (wrapper: -1 = phishing)

NAMES = ['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen',
         'Favicon', 'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
         'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection',
         'AgeofDomain', 'DNSRecording', 'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport']

ap = argparse.ArgumentParser(); ap.add_argument('--urls', required=True); ap.add_argument('--out', default='url_compare')
a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
old_model = pickle.load(open('Models/URL/pickle/catboost_model.pkl', 'rb'))  # earlier model, 30 features, classes -1/1
urls = pd.read_csv(a.urls); rows = []
for i, r in urls.iterrows():
    t0 = time.time()
    try:
        f = np.array(FeatureExtraction(r['url']).getFeaturesList()).reshape(1, 30)
    except Exception as e:
        print('ERROR', r['url'], e); continue
    p_old = float(old_model.predict_proba(f)[0, 0]); p_new = float(new_model.predict_proba(f)[0, 0])
    row = dict(url=r['url'], set=r.get('set', ''), label=r['label'],
               old_verdict='Malicious' if p_old > 0.5 else 'Benign', old_p_malicious=round(p_old, 4),
               new_verdict='Malicious' if p_new > 0.5 else 'Benign', new_p_malicious=round(p_new, 4),
               seconds=round(time.time() - t0, 2), **dict(zip(NAMES, f[0].tolist())))
    rows.append(row); print(f"{i+1:3d}/{len(urls)} {r['label']:9s} old {row['old_verdict']:9s} {p_old:.3f} | new {row['new_verdict']:9s} {p_new:.3f}  {r['url']}", flush=True)
df = pd.DataFrame(rows); df.to_csv(os.path.join(a.out, 'per_url.csv'), index=False)
lines = []
for s, g in [('all', df)] + list(df.groupby('set')):
    for m in ('old', 'new'):
        tp = ((g.label == 'Malicious') & (g[m + '_verdict'] == 'Malicious')).sum(); fn = ((g.label == 'Malicious') & (g[m + '_verdict'] == 'Benign')).sum()
        tn = ((g.label == 'Benign') & (g[m + '_verdict'] == 'Benign')).sum(); fp = ((g.label == 'Benign') & (g[m + '_verdict'] == 'Malicious')).sum()
        lines.append(f"{s:20s} {m}: TP {tp} FN {fn} TN {tn} FP {fp}")
open(os.path.join(a.out, 'summary.txt'), 'w').write('\n'.join(lines)); print('\n'.join(lines))
