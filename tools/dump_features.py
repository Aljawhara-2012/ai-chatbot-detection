"""Save the features the deployed extractors compute for every file in the evaluation folders.

Usage (no server needed):
    python tools\\dump_features.py --benign C:\\eval\\benign --malicious C:\\eval\\malicious
Output: eval_results\\pdf_features.csv and eval_results\\exe_features.csv
"""
import argparse, csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Models.pdf.pdf_features import extract_features, FEATURES
from Models.Malware.pe_features import extract_pe_features

ap = argparse.ArgumentParser()
ap.add_argument('--benign', required=True)
ap.add_argument('--malicious', required=True)
ap.add_argument('--out', default='eval_results')
a = ap.parse_args()
os.makedirs(a.out, exist_ok=True)
pdf_rows, exe_rows = [], []
for folder, label in ((a.benign, 'Benign'), (a.malicious, 'Malicious')):
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        with open(path, 'rb') as f:
            head = f.read(1024)
        try:
            if b'%PDF' in head:
                pdf_rows.append({'file': name, 'true': label, **extract_features(path)})
            elif head[:2] == b'MZ':
                exe_rows.append({'file': name, 'true': label, **extract_pe_features(path)})
        except Exception as e:
            print('could not read', name, type(e).__name__)
for rows, fn in ((pdf_rows, 'pdf_features.csv'), (exe_rows, 'exe_features.csv')):
    if rows:
        with open(os.path.join(a.out, fn), 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'PDF rows: {len(pdf_rows)}  EXE rows: {len(exe_rows)}  -> saved in {a.out}')
