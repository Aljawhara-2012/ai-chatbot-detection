# What to run for the R8 revision (about 2–3 hours, mostly waiting)

Everything runs on your Windows laptop, the same machine used for Table 9.
Run each command in **PowerShell, inside this folder** (the folder that contains `app.py`).

## 0. Install (once)

```powershell
python -m venv venv_r8
.\venv_r8\Scripts\activate
pip install -r requirements_r8.txt
```

Use **Python 3.10**, as in the paper. The model files need scikit-learn 1.0.2 and imbalanced-learn 0.9.0, and `requirements_r8.txt` pins both.

## 1. Collect the test files

| Folder | What to put in it | How many |
|---|---|---|
| `D:\eval\benign` | normal PDFs (papers, invoices, manuals) **and** normal EXEs (installers, tools from official sites) | ≥ 50 PDFs, ≥ 30 EXEs |
| `D:\eval\malicious` | malicious PDFs **and** malicious EXEs (VirusShare, or the Contagio PDF collection) | ≥ 50 PDFs, ≥ 30 EXEs |

* These files must **not** come from the training datasets. Any file you downloaded yourself is fine.
* ⚠️ Work on malware only inside a virtual machine or on a disconnected PC, and turn Windows Defender's real-time protection off **only for that folder**. The chatbot never runs the files; it only reads them.

For the load test, put **copies** of some of these files here:

```
D:\load\pdf\benign\     D:\load\pdf\malicious\     (10–20 files each)
D:\load\exe\benign\     D:\load\exe\malicious\     (10–20 files each)
```

and fill `tools\urls.csv` (columns `url,label`) with about 20 legitimate and 20 phishing URLs. Get the phishing URLs from PhishTank or OpenPhish **on the day you run the test**, because they go offline quickly.

## 2. Deployed evaluation (Major Points 1 and 3, Reviewer 9 Comments 1 and 4)

Terminal 1:
```powershell
.\venv_r8\Scripts\activate
$env:CHATBOT_EVAL_MODE="1"; python app.py
```
Terminal 2:
```powershell
.\venv_r8\Scripts\activate
python tools\evaluate_deployed.py --benign D:\eval\benign --malicious D:\eval\malicious
```
→ Send me the whole `eval_results` folder.

## 3. Load test (Major Point 5, Reviewer 9 Comment 5)

Stop the server (Ctrl+C) and start it **without** evaluation mode:
```powershell
Remove-Item Env:CHATBOT_EVAL_MODE; python app.py
```
Terminal 2:
```powershell
python tools\load_test.py --pdf-dir D:\load\pdf --exe-dir D:\load\exe --urls tools\urls.csv
```
This takes about 1–2 hours (3 workloads × 6 concurrency levels × 3 trials). Keep the laptop plugged in and close other programs.
→ Send me the whole `load_results` folder.

## 4. End-to-end tests (Table 10)

With the server running, open `http://127.0.0.1:5000` (user) and `http://127.0.0.1:5000/agent` (agent) in two browser windows. Repeat your nine test cases T-01 … T-09. For **each** case, write down what the agent dashboard shows:
* declared extension, detected type, detector, verdict, alert reason
* whether the file is offered for download or shown as **withheld (quarantined)**

Take new screenshots for Figures 13–15.

## 5. Also tell me
* Your laptop details, if they changed since Table 9.
* Whether you pushed this version to GitHub. The paper links to the repository, and the version there now does not run: line 6 of `app.py` is `import pickleapp.`.
