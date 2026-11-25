"""Evaluate the DEPLOYED chatbot on an independent set of real files (Major Points 1 and 3).

Every file is uploaded through the chatbot's real /upload endpoint, so it passes through the same steps as a
user upload: content-type detection, routing, runtime feature extraction, classification and agent alerting.
The script also connects to the agent room and checks that each result is delivered to the Agent Dashboard.

Start the chatbot first, in evaluation mode (Windows PowerShell):
    $env:CHATBOT_EVAL_MODE="1"; python app.py
Then, in a second terminal:
    python tools/evaluate_deployed.py --benign D:/eval/benign --malicious D:/eval/malicious

Folders may contain PDFs and EXEs together; results are reported per detected file type.
Outputs (in --out, default eval_results/): per_file.csv, summary.json, summary.txt
"""
import argparse, csv, json, os, threading, time, uuid
import requests
import socketio


def metrics(rows, verdict_key):
    tp = sum(1 for r in rows if r['true'] == 'Malicious' and r[verdict_key] == 'Malicious')
    fn = sum(1 for r in rows if r['true'] == 'Malicious' and r[verdict_key] != 'Malicious')
    tn = sum(1 for r in rows if r['true'] == 'Benign' and r[verdict_key] != 'Malicious')
    fp = sum(1 for r in rows if r['true'] == 'Benign' and r[verdict_key] == 'Malicious')
    n = tp + fn + tn + fp
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return {'n': n, 'TP': tp, 'FN': fn, 'TN': tn, 'FP': fp, 'accuracy': (tp + tn) / n if n else 0.0,
            'precision': p, 'recall': rc, 'f1': 2 * p * rc / (p + rc) if p + rc else 0.0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', default='http://127.0.0.1:5000')
    ap.add_argument('--benign', required=True)
    ap.add_argument('--malicious', required=True)
    ap.add_argument('--out', default='eval_results')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    delivered = {}
    sio = socketio.Client()
    sio.on('file_analysis_result', lambda d: delivered.__setitem__(d['request_id'], time.time()))
    sio.connect(a.server, transports=['websocket', 'polling'])
    sio.emit('agent_connect', {})
    time.sleep(1)

    files = [(os.path.join(a.benign, f), 'Benign') for f in sorted(os.listdir(a.benign))] + \
            [(os.path.join(a.malicious, f), 'Malicious') for f in sorted(os.listdir(a.malicious))]
    files = [(p, t) for p, t in files if os.path.isfile(p)]
    rows, skipped = [], []
    for i, (path, true) in enumerate(files, 1):
        rid = uuid.uuid4().hex
        t0 = time.time()
        try:
            with open(path, 'rb') as fh:
                r = requests.post(a.server + '/upload', files={'file': (os.path.basename(path), fh)}, data={'request_id': rid}, timeout=180)
            js = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
        except Exception as e:  # connection reset, timeout, non-JSON answer: record and continue
            r, js = None, {'message': f'{type(e).__name__}: {e}'}
        res = js.get('result')
        if res is None:
            status = r.status_code if r is not None else 'no response'
            if status == 200:
                raise SystemExit('The server is not in evaluation mode: start it with CHATBOT_EVAL_MODE=1')
            reason = 'too large (over 25 MB upload limit)' if status == 413 else f'server error {status}: {js.get("message", "")[:150]}'
            print(f'  ! {os.path.basename(path)}: {reason}')
            skipped.append({'file': os.path.basename(path), 'true': true, 'status': status, 'reason': reason})
            continue
        cmp = res.get('comparison') or {}
        rows.append({'file': os.path.basename(path), 'true': true, 'declared_extension': res['declared_extension'],
                     'detected_type': res['detected_type'], 'detector': res['detector'],
                     'deployed_verdict': res['content_verdict'],
                     'svm_verdict': cmp.get('svm_prediction', ''),
                     'p_malicious': res['probabilities'].get('Malicious', ''),
                     'flagged': res['flagged'], 'alert_reasons': '; '.join(res['alert_reasons']),
                     'error': res['error'] or '', 'http_s': round(time.time() - t0, 4), 'request_id': rid,
                     'link_verdict': res.get('link_verdict') or '', 'n_links': len(res.get('pdf_links') or []),
                     'malicious_links': ' '.join(l['url'] for l in (res.get('pdf_links') or []) if l.get('status') == 'Malicious')})
        if i % 25 == 0:
            print(f'{i}/{len(files)} files processed')
    time.sleep(2)
    for r in rows:
        r['delivered_to_agent'] = r['request_id'] in delivered
    sio.disconnect()

    with open(os.path.join(a.out, 'per_file.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

    with open(os.path.join(a.out, 'skipped.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['file', 'true', 'status', 'reason']); w.writeheader(); w.writerows(skipped)
    summary = {'_skipped': {'count': len(skipped), 'files': skipped}}
    for ftype in sorted({r['detected_type'] for r in rows}):  # noqa
        sub = [r for r in rows if r['detected_type'] == ftype]
        s = {'files': len(sub), 'benign': sum(r['true'] == 'Benign' for r in sub),
             'malicious': sum(r['true'] == 'Malicious' for r in sub),
             'parse_errors': sum(bool(r['error']) for r in sub),
             'delivered_to_agent': sum(r['delivered_to_agent'] for r in sub)}
        if ftype in ('PDF', 'EXE'):
            s['deployed_model'] = metrics(sub, 'deployed_verdict')
            s['alert_outcome'] = metrics([dict(r, alert='Malicious' if r['flagged'] else 'Benign') for r in sub], 'alert')
        if ftype == 'PDF':
            s['svm_same_extractor'] = metrics(sub, 'svm_verdict')
            s['link_check_only'] = metrics(sub, 'link_verdict')
            s['pdfs_with_links'] = sum(r['n_links'] > 0 for r in sub)
        summary[ftype] = s
    json.dump(summary, open(os.path.join(a.out, 'summary.json'), 'w'), indent=2)
    lines = [f"Files not analysed: {len(skipped)} (see skipped.csv)"]
    for k, s in summary.items():
        if k == '_skipped':
            continue
        lines.append(f"== {k}: {s['files']} files ({s['benign']} benign, {s['malicious']} malicious); parse errors {s['parse_errors']}; "
                     f"delivered to agent {s['delivered_to_agent']}/{s['files']}")
        if 'pdfs_with_links' in s:
            lines.append(f"   PDFs containing web links: {s['pdfs_with_links']}/{s['files']}")
        for name in ('deployed_model', 'svm_same_extractor', 'link_check_only', 'alert_outcome'):
            if name in s:
                m = s[name]
                lines.append(f"   {name:20s} TP {m['TP']} FN {m['FN']} TN {m['TN']} FP {m['FP']} | acc {m['accuracy']*100:.2f}% "
                             f"P {m['precision']*100:.2f}% R {m['recall']*100:.2f}% F1 {m['f1']*100:.2f}%")
    open(os.path.join(a.out, 'summary.txt'), 'w').write('\n'.join(lines))
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
