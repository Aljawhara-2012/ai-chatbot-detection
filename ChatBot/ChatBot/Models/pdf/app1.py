from flask import Flask, request, render_template, jsonify
import os
import pandas as pd
import PyPDF2
import joblib

# Load the trained model and scaler
import os
import joblib

# Get the directory of the current script (app1.py)
base_dir = os.path.dirname(__file__)

# Use the absolute path to load the model and scaler
svm_model = joblib.load(os.path.join(base_dir, 'svm1_model.pkl'))
scaler = joblib.load(os.path.join(base_dir, 'scaler1.pkl'))

# Selected features based on your training process
selected_features = [
    'pdfsize', 'xref Length', 'embedded files', 'images', 'text',
    'obj', 'stream', 'xref', 'trailer', 'pageno',
    'Javascript', 'AA', 'OpenAction', 'EmbeddedFile', 'XFA', 'Colors'
]

# Initialize the Flask app
app = Flask(__name__)

# Prediction function
def predict_pdf(file_path, model, scaler, features):
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            pdf_size = os.path.getsize(file_path)
            metadata_size = len(str(reader.metadata))
            num_pages = len(reader.pages)
            is_encrypted = int(reader.is_encrypted)
            
            # Extract features
            extracted_features = {
                'pdfsize': pdf_size, 'xref Length': 0, 'embedded files': 0, 'images': 0, 'text': 0,
                'obj': 0, 'stream': 0, 'xref': 0, 'trailer': 0, 'pageno': num_pages,
                'Javascript': 0, 'AA': 0, 'OpenAction': 0, 'EmbeddedFile': 0, 'XFA': 0, 'Colors': 0
            }
            
            # Scale and predict
            df_features = pd.DataFrame([extracted_features])
            df_features = df_features[features]
            df_scaled = scaler.transform(df_features)
            prediction = model.predict(df_scaled)
            prediction_proba = model.predict_proba(df_scaled)
            result = "Malicious" if prediction[0] == 1 else "Benign"
            return {
                "prediction": result,
                "probabilities": {
                    "Malicious": f"{prediction_proba[0][1]:.2f}",
                    "Benign": f"{prediction_proba[0][0]:.2f}"
                }
            }
    except Exception as e:
        return {"error": str(e)}

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')  # Create an HTML form to upload files

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and file.filename.endswith('.pdf'):
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)  # Save the file to a temporary location
        
        # Predict
        result = predict_pdf(file_path, svm_model, scaler, selected_features)
        os.remove(file_path)  # Clean up the saved file
        return jsonify(result)
    else:
        return jsonify({"error": "Unsupported file type"}), 400

if __name__ == '__main__':
    # Create the uploads directory if it doesn't exist
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    app.run(debug=True)
