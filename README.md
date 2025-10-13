# AI-Powered Chatbot for Malicious Activity Detection

## Overview
This project presents an AI-powered chatbot designed to detect malicious activities in real-time across URLs, PDF files, and EXE files. The system leverages machine learning models **Random Forest**, **Support Vector Machine (SVM)**, and **Gradient Boosting** for accurate threat detection. Built with **Flask**, it ensures scalability and real-time response.

## Features
- Real-time detection of malicious URLs, PDFs, and EXEs
- Integration of multiple machine learning models for improved accuracy
- User-friendly chatbot interface for easy interaction
- Scalable backend using Flask for deployment

## Architecture
1. **Data Input:** Users submit URLs, PDFs, or EXEs through the chatbot interface.
2. **Preprocessing:** Files and URLs are processed to extract relevant features.
3. **Prediction:** ML models (Random Forest, SVM, Gradient Boosting) classify inputs as safe or malicious.
4. **Response:** The chatbot provides immediate feedback on the detected threat.

Create a virtual environment:

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install dependencies:

pip install -r requirements.txt

Usage

Start the Flask server:

python app.py


Open the chatbot interface in your browser: http://127.0.0.1:5000

Enter a URL, PDF, or EXE to test for malicious activity.

The chatbot will provide a prediction and detailed feedback.
