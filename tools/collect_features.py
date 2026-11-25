"""Collect runtime features of recent samples for retraining (revision R8).

Reads files on this computer, computes the same features the chatbot uses (pdf_features.py, pe_features.py),
and writes two CSV files (numbers only; no file is copied or executed):
    C:\\recent\\features\\recent_pdf.csv   C:\\recent\\features\\recent_exe.csv
Columns: sha256, label (1 = malicious, 0 = benign), split (train / test), source, size_kb, then the features.

Malicious samples: --train-dirs (earlier MalwareBazaar days) -> split 'train'; --test-dir (a later day) -> 'test'.
Benign samples: normal PDFs from your Documents/Downloads/Desktop and normal EXEs from Windows and Program Files;
they are assigned to train/test by their SHA-256 (about 70/30), so the same file never appears in both.

Usage:
    python tools\\collect_features.py --train-dirs C:\\recent\\train1 C:\\recent\\train2 --test-dir C:\\recent\\test
"""
import argparse, csv, hashlib, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Models.pdf.pdf_features import extract_features, FEATURES as PDF_FEATURES
from Models.Malware.pe_features import extract_pe_features

MAX_BYTES = 25 * 1024 * 1024
HOME = os.path.expanduser('~')
BENIGN_PDF_DIRS = [os.path.join(HOME, d) for d in ('Documents', 'Downloads', 'Desktop', 'OneDrive')]
BENIGN_EXE_DIRS = [r'C:\Windows\System32', r'C:\Windows\SysWOW64', r'C:\Program Files', r'C:\Program Files (x86)']
SKIP_DIRS = ('\\recent', '\\eval', '\\load', '\\t10', 'chatbot_r8\\uploads', '\\$Recycle.Bin', '\\WinSxS')


def kind(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(1024)
    except OSError:
        return None
    if b'%PDF' in head:
        return 'PDF'
    if head[:2] == b'MZ':
        return 'EXE'
    return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def walk(dirs, max_files=None, exts=None, skip=True):
    n = 0
    for d in dirs:
        for root, subdirs, files in os.walk(d):
            if skip and any(s.lower() in root.lower() for s in SKIP_DIRS):
                subdirs[:] = []
                continue
            for f in files:
                if exts and not f.lower().endswith(exts):
                    continue
                p = os.path.join(root, f)
                try:
                    if 0 < os.path.getsize(p) <= MAX_BYTES:
                        yield p; n += 1
                except OSError:
                    continue
                if max_files and n >= max_files:
                    return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--train-dirs', nargs='+', required=True)
    ap.add_argument('--test-dir', required=True)
    ap.add_argument('--out', default=r'C:\recent\features')
    ap.add_argument('--max-benign-exe', type=int, default=3000)
    ap.add_argument('--max-mal-per-dir', type=int, default=3000)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows = {'PDF': [], 'EXE': []}
    seen = set()
    stats = {}

    def add(path, label, split, source):
        k = kind(path)
        if k is None:
            return
        try:
            h = sha256(path)
            if h in seen:
                return
            feats = extract_features(path) if k == 'PDF' else extract_pe_features(path)
        except Exception:
            stats[(k, source, 'unreadable')] = stats.get((k, source, 'unreadable'), 0) + 1
            return
        seen.add(h)
        if split is None:  # benign: deterministic ~70/30 split by hash
            split = 'test' if int(h[:8], 16) % 10 < 3 else 'train'
        rows[k].append({'sha256': h, 'label': label, 'split': split, 'source': source,
                        'size_kb': round(os.path.getsize(path) / 1024, 1), **feats})
        stats[(k, source, split)] = stats.get((k, source, split), 0) + 1

    t0 = time.time()
    for d in a.train_dirs:
        print('malicious (train):', d, flush=True)
        for p in walk([d], a.max_mal_per_dir, skip=False):
            add(p, 1, 'train', 'malwarebazaar')
    print('malicious (test):', a.test_dir, flush=True)
    for p in walk([a.test_dir], a.max_mal_per_dir, skip=False):
        add(p, 1, 'test', 'malwarebazaar')
    print('benign PDFs from your folders ...', flush=True)
    for p in walk([d for d in BENIGN_PDF_DIRS if os.path.isdir(d)], exts=('.pdf',)):
        add(p, 0, None, 'local_pdf')
    print('benign EXEs from Windows and Program Files ...', flush=True)
    for p in walk(BENIGN_EXE_DIRS, a.max_benign_exe, exts=('.exe',)):
        add(p, 0, None, 'local_exe')

    for k, fn in (('PDF', 'recent_pdf.csv'), ('EXE', 'recent_exe.csv')):
        if rows[k]:
            cols = list(rows[k][0].keys())
            with open(os.path.join(a.out, fn), 'w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows[k])
    print(f'\nDone in {time.time() - t0:.0f} s. Saved in {a.out}')
    for (k, src, sp), n in sorted(stats.items()):
        print(f'  {k} {src:14s} {sp:10s} {n}')


if __name__ == '__main__':
    main()
