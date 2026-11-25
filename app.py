# app.py - AI-powered chatbot for real-time detection of malicious URLs, PDFs and EXEs (revision R8)
#
# Changes in R8 (see CHANGES_R8.md):
#  * PDF and EXE detectors replaced by leakage-free pipelines with complete runtime feature extraction
#    (Models/pdf/detector.py, Models/Malware/detector.py); feature definitions and units match the training data.
#  * Uploaded files are stored under a unique random name (no collisions between concurrent uploads).
#  * Verdicts and alerts are sent only to the agent room ('agent_room'); the user receives no verdict.
#  * Files that are flagged (malicious or disguised) are quarantined: they are not offered for download.
#  * Each chat URL is analysed once, asynchronously; every result carries a request id and stage timestamps
#    so that the interval from submission to alert delivery can be measured.
import os, re, json, time, uuid
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import magic
from flask import Flask, render_template, request, jsonify, send_from_directory, abort
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename

from Models.pdf.detector import analyse_pdf
from Models.pdf.links import extract_links
from Models.Malware.detector import analyse_exe
from Models.URL.app import FeatureExtraction, gbc

AGENT_ROOM = 'agent_room'
EVAL_MODE = os.environ.get('CHATBOT_EVAL_MODE') == '1'   # returns verdicts in HTTP responses (evaluation only)
PDF_LINK_CHECK = os.environ.get('CHATBOT_PDF_LINK_CHECK', '0') == '1'   # link check inside PDFs: off by default (evaluated: 19 false alarms on 49 benign PDFs)
URL_PATTERN = re.compile(r'(https?://[^\s]+)|(www\.[^\s]+)')

app = Flask(__name__)
app.secret_key = os.environ.get('CHATBOT_SECRET_KEY', os.urandom(32))
app.config['UPLOAD_FOLDER'] = os.environ.get('CHATBOT_UPLOAD_DIR', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
executor = ThreadPoolExecutor(max_workers=int(os.environ.get('CHATBOT_URL_WORKERS', '32')))
QUARANTINE = set()

with open('templates/faq.json', 'r') as f:
    faq_data = json.load(f)

MIME_MAP = {'application/pdf': 'PDF', 'application/x-dosexec': 'EXE', 'application/vnd.microsoft.portable-executable': 'EXE'}


def detect_type(path):
    try:
        return MIME_MAP.get(magic.Magic(mime=True).from_file(path), 'OTHER')
    except Exception:
        # libmagic could not read the file: fall back to the file signature
        with open(path, 'rb') as f:
            head = f.read(1024)
        if b'%PDF' in head:
            return 'PDF'
        if head[:2] == b'MZ':
            return 'EXE'
        return 'OTHER'


def process_uploaded_file(file, sender='User', request_id=None):
    t_received = time.time()
    request_id = request_id or uuid.uuid4().hex
    original = secure_filename(file.filename) or 'upload'
    stored = f"{uuid.uuid4().hex}_{original}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    file.save(path)

    declared = original.rsplit('.', 1)[1].upper() if '.' in original else ''
    actual = detect_type(path)
    disguised = actual in ('PDF', 'EXE') and declared != actual
    detector, analysis, error = 'None', None, None
    if actual in ('PDF', 'EXE'):
        detector = f'{actual} detector (Random Forest)'
    try:
        if actual == 'PDF':
            analysis = analyse_pdf(path)
        elif actual == 'EXE':
            analysis = analyse_exe(path)
    except Exception as e:  # malformed file: flagged to the agent, service keeps running
        error = f'{type(e).__name__}: {str(e)[:200]}'
        app.logger.warning('analysis failed for %s: %s', original, error)
    content = analysis['prediction'] if analysis else ('Error' if error else 'Not analysed')
    # PDF link check: links inside the PDF are checked with the URL detector (link-based phishing PDFs)
    link_results = []
    t_links = time.perf_counter()
    if actual == 'PDF' and os.environ.get('CHATBOT_PDF_LINK_CHECK', '0') == '1':
        links = extract_links(path)
        if links:
            futures = [(u, executor.submit(url_verdict, u)) for u in links]
            for u, fut in futures:
                try:
                    link_results.append({'url': u, **fut.result(timeout=30)})
                except Exception as e:
                    link_results.append({'url': u, 'status': 'Error', 'error': type(e).__name__})
    malicious_links = [r['url'] for r in link_results if r.get('status') == 'Malicious']
    reasons = []
    if disguised:
        reasons.append(f'declared .{declared.lower() or "(none)"} but content is {actual}')
    if content == 'Malicious':
        reasons.append(f'{detector} classified the content as malicious')
    if malicious_links:
        reasons.append(f'{len(malicious_links)} of {len(link_results)} links in the PDF classified as phishing by the URL detector: '
                       + ', '.join(malicious_links[:3]))
    if error:
        reasons.append('file could not be parsed')
    flagged = bool(reasons)
    if flagged:
        QUARANTINE.add(stored)
    t_classified = time.time()

    result = {'request_id': request_id, 'filename': original, 'stored_name': stored,
              'declared_extension': declared, 'detected_type': actual, 'detector': detector,
              'content_verdict': content, 'disguised': disguised, 'flagged': flagged, 'alert_reasons': reasons,
              'probabilities': analysis['probabilities'] if analysis else {},
              'comparison': analysis.get('comparison') if analysis else None,
              'pdf_links': link_results, 'link_verdict': ('Malicious' if malicious_links else ('Benign' if link_results else 'No links')) if actual == 'PDF' else None,
              'link_check_s': round(time.perf_counter() - t_links, 3),
              'download_url': None if flagged else f'/uploads/{stored}', 'error': error,
              'timing': {'t_received': t_received, 't_classified': t_classified,
                         'stages_s': analysis['timing_s'] if analysis else {}}}
    # user side: the shared message carries no verdict and no link
    socketio.emit('message', {'sender': sender, 'text': f'Uploaded file: {original}'}, to='chatroom')
    result['timing']['t_emitted'] = time.time()
    socketio.emit('file_analysis_result', result, to=AGENT_ROOM)
    if flagged:
        socketio.emit('alert', {'request_id': request_id, 'kind': 'file', 'message': f'Suspicious file {original}: ' + '; '.join(reasons),
                                'timing': result['timing']}, to=AGENT_ROOM)
    return result


def url_verdict(url):
    """URL detector on one URL, without emitting anything (used for links inside PDFs)."""
    feats = np.array(FeatureExtraction(url).getFeaturesList()).reshape(1, 30)
    pred = gbc.predict(feats)[0]
    return {'status': 'Malicious' if pred == -1 else 'Legitimate',
            'probability_malicious': round(float(gbc.predict_proba(feats)[0, 0]), 4)}


def analyse_url(url, sender, request_id):
    t_received = time.time()
    try:
        t0 = time.perf_counter()
        feats = np.array(FeatureExtraction(url).getFeaturesList()).reshape(1, 30)
        t1 = time.perf_counter()
        pred = gbc.predict(feats)[0]
        p_mal = float(gbc.predict_proba(feats)[0, 0])
        t2 = time.perf_counter()
        status = 'Malicious' if pred == -1 else 'Legitimate'
        res = {'request_id': request_id, 'kind': 'url', 'url': url, 'sender': sender, 'status': status,
               'probability_malicious': round(p_mal, 4), 'flagged': status == 'Malicious',
               'timing': {'t_received': t_received, 't_classified': time.time(),
                          'stages_s': {'feature_extraction_incl_retrieval': t1 - t0, 'classification': t2 - t1}}}
    except Exception as e:
        res = {'request_id': request_id, 'kind': 'url', 'url': url, 'sender': sender, 'status': 'Error', 'flagged': False,
               'error': str(e), 'timing': {'t_received': t_received, 't_classified': time.time(), 'stages_s': {}}}
    res['timing']['t_emitted'] = time.time()
    socketio.emit('url_analysis_result', res, to=AGENT_ROOM)
    if res.get('flagged'):
        socketio.emit('alert', {'request_id': request_id, 'kind': 'url',
                                'message': f"Malicious URL from {sender}: {url} ({res['probability_malicious'] * 100:.1f}%)",
                                'timing': res['timing']}, to=AGENT_ROOM)
    return res


# ---------------------------------------------------------------- routes
@app.route('/')
def user_interface():
    return render_template('user_interface.html', faqs=faq_data)


@app.route('/agent')
def agent_interface():
    return render_template('agent_interface.html')


@app.route('/uploads/<path:filename>')
def download_file(filename):
    if filename in QUARANTINE:
        abort(403)  # flagged files are withheld
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file is None or file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
    sender = 'Agent' if '/agent' in str(request.referrer) else 'User'
    try:
        result = process_uploaded_file(file, sender, request.form.get('request_id'))
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    body = {'status': 'success', 'filename': result['filename']}
    if EVAL_MODE:
        body['result'] = result
    return jsonify(body), 200


@app.route('/test_url', methods=['POST'])
def test_url():
    data = request.get_json(force=True)
    res = analyse_url(data.get('url', ''), data.get('sender', 'test'), data.get('request_id') or uuid.uuid4().hex)
    return (res if EVAL_MODE else {'status': 'accepted', 'request_id': res['request_id']}), 200


# ---------------------------------------------------------------- Socket.IO events
@socketio.on('send_message')
def handle_message(data):
    room, sender, text = data['room'], data['sender'], data['text']
    emit('message', {'sender': sender, 'text': text}, to=room)
    m = URL_PATTERN.search(text)
    if m:
        executor.submit(analyse_url, m.group(0), sender, data.get('request_id') or uuid.uuid4().hex)


@socketio.on('send_faq')
def handle_faq(data):
    room, question = data.get('room', ''), data.get('question', '')
    emit('bot_response', {'response': faq_data.get(question, "Sorry, I don't have an answer for that question.")}, to=room)


@socketio.on('request_agent')
def notify_agent(data):
    emit('agent_notification', {'room': data['room'], 'username': data['username']}, to=AGENT_ROOM)


@socketio.on('join_room')
def handle_join(data):
    join_room(data['room'])
    emit('message', {'sender': data['username'], 'text': 'joined the chat.'}, to=data['room'])


@socketio.on('leave_room')
def handle_leave(data):
    leave_room(data['room'])
    emit('message', {'sender': data['username'], 'text': 'left the chat.'}, to=data['room'])


@socketio.on('agent_connect')
def agent_connect(_data=None):
    join_room(AGENT_ROOM)  # agent dashboard receives verdicts and alerts


@socketio.on('join_agent')
def agent_join(data):
    join_room(data['room'])
    join_room(AGENT_ROOM)
    emit('message', {'sender': 'Agent', 'text': 'joined the chat.'}, to=data['room'])


if __name__ == '__main__':
    socketio.run(app, debug=False, host=os.environ.get('CHATBOT_HOST', '127.0.0.1'), port=int(os.environ.get('CHATBOT_PORT', '5000')),
                 allow_unsafe_werkzeug=True)
