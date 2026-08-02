# AI-Powered Chatbot for Malicious Activity Detection

## Overview

This repository contains the implementation of the research project **"An AI-Powered Chatbot for Malicious Activity Detection."**

The proposed framework integrates multiple machine learning models into a secure Flask-based chatbot capable of detecting malicious URLs, PDF documents, and Windows executable (EXE) files in real time. The chatbot automatically identifies the uploaded content type, routes it to the appropriate detection model, analyses the input, and generates real-time security alerts through a dedicated Agent Dashboard.

Unlike conventional malware detection systems that focus on a single data type, this framework provides a unified conversational interface capable of handling multiple cybersecurity threats within one integrated architecture.

---

# Research Contribution

The primary contribution of this work is **not** the development of new machine learning classifiers. Instead, it presents a **secure AI-powered chatbot architecture** that integrates specialised malware detection models into a unified real-time cybersecurity framework.

The proposed architecture provides:

- Secure chatbot interaction
- Intelligent input-type identification
- Modular routing of URLs, PDF documents, and EXE files
- Real-time malicious content detection
- Automated security alert generation
- Dedicated Agent Dashboard for cybersecurity analysts
- Scalable Flask-based deployment

The machine learning models act as enabling components, while the novelty lies in the secure chatbot workflow, modular threat analysis, and real-time deployment architecture.

---

# System Architecture

The proposed framework follows the workflow below:

```
                   User
                     │
                     ▼
          AI Chatbot Interface
                     │
                     ▼
      Automatic Input-Type Detection
                     │
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
 URL Detector    PDF Detector    EXE Detector
Gradient Boosting     SVM       Random Forest
     │               │               │
     └───────────────┼───────────────┘
                     ▼
         Threat Classification
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
      Benign               Malicious
                                 │
                                 ▼
                   Agent Dashboard Alert
```

---

# Features

- Real-time malicious URL detection
- PDF malware detection
- Windows executable (EXE) malware detection
- Automatic routing to specialised machine learning models
- AI-powered chatbot interface
- Agent Dashboard for security monitoring
- Real-time alert notifications
- Modular and scalable architecture
- Flask web application

---

# Machine Learning Models

| Detection Task | Selected Model |
|----------------|----------------|
| URL Detection | Gradient Boosting |
| PDF Malware Detection | Support Vector Machine (SVM) |
| EXE Malware Detection | Random Forest |

---

# Repository Structure

```
ChatBot/
│
├── Models/
│   ├── Malware/
│   ├── URL/
│   └── pdf/
│
├── static/
│   ├── chatbot_icon.png
│   └── styles.css
│
├── templates/
│   ├── user_interface.html
│   └── agent_interface.html
│
├── app.py
├── faq.json
├── scalability_test.py
├── url_scalability_test.py
├── requirements.txt
└── README.md
```

---

# Technologies

- Python
- Flask
- Scikit-learn
- NumPy
- Pandas
- Joblib
- Pickle
- PyPDF2
- PEFile
- HTML5
- CSS3
- JavaScript

---

# Installation

Clone the repository

```bash
git clone https://github.com/Aljawhara-2012/ai-chatbot-detection.git
```

Move into the project folder

```bash
cd ai-chatbot-detection
```

Create a virtual environment

```bash
python -m venv myenv
```

Activate the environment

### Windows

```bash
myenv\Scripts\activate
```

### Linux/macOS

```bash
source myenv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Application

Start the Flask server

```bash
python app.py
```

Open your browser

```
http://127.0.0.1:5000
```

---

# Workflow

1. The user uploads a URL, PDF document, or EXE file through the chatbot interface.
2. The system automatically determines the input type.
3. The corresponding machine learning model is selected.
4. Features are extracted from the uploaded content.
5. The model classifies the content as **Benign** or **Malicious**.
6. If malicious content is detected, an alert is automatically generated and displayed on the Agent Dashboard.
7. Security analysts can review the detected threats and take appropriate mitigation actions.

---



