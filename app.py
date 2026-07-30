# app_me.py
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import json
import joblib
import pickleapp.
import pefile
import array
import math
from datetime import datetime
import magic
import re
import numpy as np
from concurrent.futures import ThreadPoolExecutor

# For asynchronous URL analysis
executor = ThreadPoolExecutor(max_workers=5)


from Models.pdf.app1 import predict_pdf, svm_model, scaler, selected_features
from Models.URL.app import FeatureExtraction, gbc

# ==========================
# Flask & SocketIO setup
# ==========================
app = Flask(__name__)
app.secret_key = 'secret_key'  # Use a secure key in production
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# ==========================
# Load FAQ data
# ==========================
with open('templates/faq.json', 'r') as f:
    faq_data = json.load(f)

# ==========================
# Utility functions
# ==========================
def get_entropy(data):
    """Calculate Shannon entropy of data."""
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1
    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def extract_pe_features(fpath):
    """Extract features from a PE file."""
    pe = pefile.PE(fpath)
    res = {**pe.FILE_HEADER.__dict__['_field_types'],
           **pe.OPTIONAL_HEADER.__dict__['_field_types']}
    sections_entropy = [s.get_entropy() for s in pe.sections]
    res['SectionsMeanEntropy'] = sum(sections_entropy)/len(sections_entropy)
    res['SectionsMinEntropy'] = min(sections_entropy)
    res['SectionsMaxEntropy'] = max(sections_entropy)
    res['SectionsNb'] = len(pe.sections)
    return res

def get_file_type(filepath):
    """Determine MIME type of file."""
    mime = magic.Magic(mime=True)
    return mime.from_file(filepath)

def process_uploaded_file(file, sender='User'):
    """Handle uploaded file analysis (PDF/EXE)."""
    filename = datetime.now().strftime('%Y%m%d%H%M%S') + "_" + file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    file_type = get_file_type(filepath)
    original_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    detection_details = {'disguised': False, 'input_extension': original_ext.upper(), 'actual_type': None, 'content_analysis': None}
    status, probabilities, model_used = "Unknown", {}, "None"

    mime_map = {'application/pdf': 'PDF', 'application/x-dosexec': 'EXE', 'application/octet-stream': 'BIN'}
    detection_details['actual_type'] = mime_map.get(file_type, file_type)

    # Check for disguised files
    if file_type == "application/x-dosexec" and original_ext != "exe":
        detection_details['disguised'] = True
        status = f"Disguised EXE (.{original_ext})"
    elif file_type == "application/pdf" and original_ext != "pdf":
        detection_details['disguised'] = True
        status = "Disguised PDF"

    # File-specific analysis
    if file_type == "application/pdf":
        model_used = "PDF Model"
        result = predict_pdf(filepath, svm_model, scaler, selected_features)
        content_status = result.get('prediction', 'Error')
        probabilities = result.get('probabilities', {})
        detection_details['content_analysis'] = content_status
        if detection_details['disguised']:
            status = f"Disguised PDF | Content: {content_status}"
        else:
            status = content_status

    elif file_type == "application/x-dosexec":
        model_used = "EXE Model"
        clf = joblib.load('Models/Malware/classifier.pkl')
        features = pickle.loads(open('Models/Malware/features.pkl', 'rb').read())
        pe_data = extract_pe_features(filepath)
        pe_features = [pe_data[x] for x in features]
        content_status = ['Legitimate', 'Malicious'][clf.predict([pe_features])[0]]
        detection_details['content_analysis'] = content_status
        if detection_details['disguised']:
            status = f"Disguised EXE (.{original_ext}) | Content: {content_status}"
        else:
            status = content_status

    

    # Emit to user
    socketio.emit('message', {'sender': sender, 'text': f"Uploaded file: <a href='/uploads/{filename}' target='_blank'>{filename}</a>"}, to='chatroom')

    # Emit full analysis to agent
    agent_response = {'status': 'success', 'filename': filename, 'result': status, 'model_used': model_used, 'detection_details': detection_details, 'probabilities': probabilities}
    socketio.emit('file_analysis_result', agent_response, to='agent_room')

    # Emit alert if suspicious
    if detection_details['disguised'] or (detection_details.get('content_analysis') == 'Malicious'):
        alert_msg = f"⚠️ Suspicious file detected: {file.filename}"
        if detection_details['disguised']:
            alert_msg += f" | Disguised {detection_details['actual_type']} (.{original_ext})"
        if detection_details.get('content_analysis') == 'Malicious':
            alert_msg += " | Malicious content detected"
        socketio.emit('alert', {'message': alert_msg}, to='chatroom')

    return filename
def analyze_url_async(url, room, sender):
    try:
        obj = FeatureExtraction(url)
        features = np.array(obj.getFeaturesList()).reshape(1, 30)
        prediction = gbc.predict(features)[0]
        prob_malicious = gbc.predict_proba(features)[0, 0] * 100
        status = "Malicious" if prediction == -1 else "Legitimate"
        alert_msg = f"⚠️ URL Analysis by {sender}: {url} -> {status} ({prob_malicious:.2f}% malicious)"
        socketio.emit('alert', {'message': alert_msg}, to=room)
    except Exception as e:
        socketio.emit('alert', {'message': f"Error analyzing URL {url}: {e}"}, to=room)

# ==========================
# Routes
# ==========================
@app.route('/')
def user_interface():
    return render_template('user_interface.html', faqs=faq_data)

@app.route('/agent')
def agent_interface():
    return render_template('agent_interface.html')

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400
    sender = 'Agent' if '/agent' in str(request.referrer) else 'AL-Gawhara'
    try:
        filename = process_uploaded_file(file, sender)
        return jsonify({'status': 'success', 'filename': filename}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/test_url', methods=['POST'])
def test_url():
    data = request.json
    url_text = data.get('url', '')
    try:
        obj = FeatureExtraction(url_text)
        features = np.array(obj.getFeaturesList()).reshape(1, 30)
        prediction = gbc.predict(features)[0]
        prob_malicious = gbc.predict_proba(features)[0, 0] * 100
        status = "Malicious" if prediction == -1 else "Legitimate"
        return {"url": url_text, "status": status, "prob_malicious": prob_malicious}, 200
    except Exception as e:
        return {"error": str(e)}, 500

# ==========================
# SocketIO events
# ==========================
@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    sender = data['sender']
    text = data['text']

    # Emit message immediately
    emit('message', {'sender': sender, 'text': text}, to=room)

    # If text is a URL, analyze asynchronously
    url_pattern = re.compile(r'(https?://[^\s]+)|(www\.[^\s]+)')
    if url_pattern.match(text):
        executor.submit(analyze_url_async, text, room, sender)


    # Detect URLs in messages
    url_pattern = re.compile(r'(https?://[^\s]+)|(www\.[^\s]+)')
    if url_pattern.match(text):
        try:
            obj = FeatureExtraction(text)
            features = np.array(obj.getFeaturesList()).reshape(1, 30)
            prediction = gbc.predict(features)[0]
            prob_malicious = gbc.predict_proba(features)[0, 0] * 100
            if prediction == -1:
                emit('alert', {'message': f"⚠️ Malicious URL detected! Probability: {prob_malicious:.2f}%"}, to=room)
        except Exception as e:
            print(f"URL analysis error: {e}")

@socketio.on('send_faq')
def handle_faq(data):
    room, question = data.get('room', ''), data.get('question', '')
    answer = faq_data.get(question, "Sorry, I don't have an answer for that question.")
    emit('bot_response', {'response': answer}, to=room)

@socketio.on('request_agent')
def notify_agent(data):
    emit('agent_notification', {'room': data['room'], 'username': data['username']}, broadcast=True)

@socketio.on('join_room')
def handle_join(data):
    room = data['room']
    username = data['username']
    join_room(room)
    emit('message', {'sender': username, 'text': "joined the chat."}, to=room)

@socketio.on('leave_room')
def handle_leave(data):
    room = data['room']
    username = data['username']
    leave_room(room)
    emit('message', {'sender': username, 'text': "left the chat."}, to=room)

@socketio.on('join_agent')
def agent_join(data):
    room = data['room']
    join_room(room)
    emit('message', {'sender': 'Agent', 'text': "joined the chat."}, to=room)

if __name__ == '__main__':
    app.config['DEBUG'] = True
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)