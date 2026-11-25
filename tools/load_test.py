"""Load test measuring the time from SUBMISSION to ALERT DELIVERY at the Agent Dashboard (Major Point 5).

For every request the script records:
  t_submit      client time immediately before the file upload / chat message is sent
  t_http        client time when the HTTP response arrives (files only)
  t_delivered   client time when the analysis result arrives at an agent Socket.IO connection (agent_room)
and the server-side stage timestamps carried in the result (received, classified, emitted).
End-to-end latency = t_delivered - t_submit. It covers upload, content-type detection, feature extraction
(including live webpage/domain retrieval for URLs), classification, and delivery of the result to the agent.
The load generator and server must run on the same host (same clock).

PDF, EXE and URL workloads are run SEPARATELY. URLs are submitted through the real chat path (Socket.IO
'send_message'), not through a separate HTTP endpoint.

Usage (server started normally:  python app.py):
    python tools/load_test.py --pdf-dir D:/load/pdf --exe-dir D:/load/exe --urls tools/urls.csv
Folder layout: <dir>/benign/*, <dir>/malicious/*;  urls.csv columns: url,label  (label = Benign or Malicious)
Outputs (in --out, default load_results/): requests.csv, summary.csv, summary.txt
"""
import argparse, csv, os, random, statistics as st, threading, time, uuid
import requests
import socketio

LEVELS = [1, 10, 25, 50, 100, 150]


def pct(v, q):
    v = sorted(v)
    if not v:
        return float('nan')
    k = (len(v) - 1) * q
    f = int(k); c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


class Agent:
    """Agent-side Socket.IO connection that timestamps every result delivered to the agent room."""
    def __init__(self, server):
        self.got, self.cv = {}, threading.Condition()
        self.sio = socketio.Client()
        for ev in ('file_analysis_result', 'url_analysis_result'):
            self.sio.on(ev, self._on)
        self.sio.connect(server, transports=['websocket', 'polling'])
        self.sio.emit('agent_connect', {})
        time.sleep(1)

    def _on(self, d):
        with self.cv:
            self.got[d['request_id']] = (time.time(), d)
            self.cv.notify_all()

    def wait(self, ids, timeout):
        end = time.time() + timeout
        with self.cv:
            while not all(i in self.got for i in ids) and time.time() < end:
                self.cv.wait(timeout=0.5)


def load_files(d):
    out = []
    for label in ('benign', 'malicious'):
        p = os.path.join(d, label)
        if os.path.isdir(p):
            for f in sorted(os.listdir(p)):
                fp = os.path.join(p, f)
                if os.path.isfile(fp):
                    out.append((f, open(fp, 'rb').read(), 'Malicious' if label == 'malicious' else 'Benign'))
    if not out:
        raise SystemExit(f'no files in {d}/benign or {d}/malicious')
    return out


def run_level(kind, n, payloads, server, agent, user_sio, timeout):
    barrier = threading.Barrier(n)
    recs = []
    lock = threading.Lock()

    def worker(i):
        name, data, label = payloads[i % len(payloads)]
        rid = uuid.uuid4().hex
        rec = {'workload': kind, 'concurrency': n, 'request_id': rid, 'payload': name, 'true': label,
               't_submit': None, 't_http': None, 'http_status': None, 'error': ''}
        barrier.wait()
        rec['t_submit'] = time.time()
        try:
            if kind == 'URL':
                user_sio.emit('send_message', {'room': 'loadtest', 'sender': 'loadtest', 'text': name, 'request_id': rid})
            else:
                r = requests.post(server + '/upload', files={'file': (name, data)}, data={'request_id': rid}, timeout=timeout)
                rec['t_http'], rec['http_status'] = time.time(), r.status_code
        except Exception as e:
            rec['error'] = f'{type(e).__name__}: {e}'
        with lock:
            recs.append(rec)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()
    agent.wait([r['request_id'] for r in recs], timeout)
    for r in recs:
        got = agent.got.get(r['request_id'])
        if got:
            t_del, d = got
            tm = d.get('timing', {})
            verdict = d.get('content_verdict') if kind != 'URL' else d.get('status')
            verdict = 'Malicious' if verdict == 'Malicious' else ('Benign' if verdict in ('Benign', 'Legitimate') else verdict)
            r.update(t_delivered=t_del, end_to_end_s=t_del - r['t_submit'],
                     http_s=(r['t_http'] - r['t_submit']) if r['t_http'] else None,
                     server_queue_s=tm.get('t_received', t_del) - r['t_submit'],
                     server_processing_s=tm.get('t_classified', t_del) - tm.get('t_received', t_del),
                     delivery_s=t_del - tm.get('t_emitted', t_del),
                     verdict=verdict, correct=(verdict == r['true']), detected_type=d.get('detected_type', 'URL'))
        else:
            r.update(t_delivered=None, end_to_end_s=None, verdict='NOT DELIVERED', correct=False)
    return recs


def summarise(recs):
    e2e = [r['end_to_end_s'] for r in recs if r.get('end_to_end_s') is not None]
    http = [r['http_s'] for r in recs if r.get('http_s') is not None]
    ok = [r for r in recs if r.get('end_to_end_s') is not None and not r['error']]
    wrong = [r for r in ok if not r['correct']]
    return {'requests': len(recs), 'delivered': len(e2e), 'success_pct': 100 * len(ok) / len(recs),
            'mean_s': st.mean(e2e) if e2e else None, 'median_s': st.median(e2e) if e2e else None,
            'p95_s': pct(e2e, .95), 'p99_s': pct(e2e, .99), 'max_s': max(e2e) if e2e else None,
            'pct_within_5s': 100 * sum(x <= 5 for x in e2e) / len(recs),
            'http_mean_s': st.mean(http) if http else None,
            'throughput_rps': len(e2e) / (max(r['t_delivered'] for r in recs if r.get('t_delivered')) - min(r['t_submit'] for r in recs)) if e2e else None,
            'classification_accuracy_pct': 100 * (len(ok) - len(wrong)) / len(ok) if ok else None,
            'misclassified': ';'.join(f"{r['payload']}({r['true']}->{r['verdict']})" for r in wrong)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', default='http://127.0.0.1:5000')
    ap.add_argument('--pdf-dir'); ap.add_argument('--exe-dir'); ap.add_argument('--urls')
    ap.add_argument('--levels', default=','.join(map(str, LEVELS)))
    ap.add_argument('--trials', type=int, default=3)
    ap.add_argument('--warmup', type=int, default=3)
    ap.add_argument('--timeout', type=float, default=180)
    ap.add_argument('--out', default='load_results')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    levels = [int(x) for x in a.levels.split(',')]

    workloads = []
    if a.pdf_dir: workloads.append(('PDF', load_files(a.pdf_dir)))
    if a.exe_dir: workloads.append(('EXE', load_files(a.exe_dir)))
    if a.urls:
        rows = list(csv.DictReader(open(a.urls, encoding='utf-8')))
        workloads.append(('URL', [(r['url'].strip(), b'', r['label'].strip().capitalize()) for r in rows]))
    if not workloads:
        raise SystemExit('give at least one of --pdf-dir, --exe-dir, --urls')

    agent = Agent(a.server)
    user_sio = socketio.Client(); user_sio.connect(a.server, transports=['websocket', 'polling'])
    user_sio.emit('join_room', {'room': 'loadtest', 'username': 'loadtest'})
    all_recs, summary = [], []
    for kind, payloads in workloads:
        random.Random(42).shuffle(payloads)
        run_level(kind, a.warmup, payloads, a.server, agent, user_sio, a.timeout)  # warm-up, discarded
        for n in levels:
            for trial in range(1, a.trials + 1):
                recs = run_level(kind, n, payloads, a.server, agent, user_sio, a.timeout)
                for r in recs: r['trial'] = trial
                all_recs += recs
                print(f'{kind:3s} c={n:3d} trial {trial}: mean {summarise(recs)["mean_s"]}', flush=True)
                time.sleep(2)
            s = summarise([r for r in all_recs if r['workload'] == kind and r['concurrency'] == n])
            summary.append({'workload': kind, 'concurrency': n, **s})
    user_sio.disconnect(); agent.sio.disconnect()

    keys = sorted({k for r in all_recs for k in r})
    with open(os.path.join(a.out, 'requests.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(all_recs)
    with open(os.path.join(a.out, 'summary.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    fmt = lambda x: '-' if x is None else f'{x:.2f}'
    lines = ['workload conc  n   mean  median  P95   P99   max   %<=5s  http  thr/s  acc%  misclassified']
    for s in summary:
        lines.append(f"{s['workload']:8s} {s['concurrency']:4d} {s['requests']:4d} {fmt(s['mean_s']):>6} {fmt(s['median_s']):>6} {fmt(s['p95_s']):>5} "
                     f"{fmt(s['p99_s']):>5} {fmt(s['max_s']):>5} {s['pct_within_5s']:6.1f} {fmt(s['http_mean_s']):>5} {fmt(s['throughput_rps']):>5} "
                     f"{fmt(s['classification_accuracy_pct']):>6}  {s['misclassified']}")
    open(os.path.join(a.out, 'summary.txt'), 'w').write('\n'.join(lines))
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
