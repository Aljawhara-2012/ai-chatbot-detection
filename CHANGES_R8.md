# Changes made for the R8 revision

## Detection pipelines
| | Before | R8 |
|---|---|---|
| PDF runtime features | file size (in **bytes**, whereas training used KB) and page count; the other 14 features were fixed at 0 | all 30 Evasive-PDFMal2022 features, with the dataset's definitions and units (`Models/pdf/pdf_features.py`) |
| PDF model | SVM trained with the scaler and SMOTE fitted before the split | Random Forest trained split-first: feature selection, scaling and SMOTE fitted inside the training folds; model chosen by 5-fold CV on the training partition (`pdf_rf_pipeline.joblib`). The SVM trained under the same protocol is kept for comparison only (`pdf_svm_pipeline.joblib`). |
| EXE runtime features | header fields only; `features.pkl` listed a different set of 14 columns from those the classifier was trained on | all 54 dataset columns, Python 3 port of the dataset author's extractor (`Models/Malware/pe_features.py`) |
| EXE model | undersampling and ExtraTrees selection fitted before the split | split first; undersampling and ExtraTrees selection fitted inside the training folds; the four fields that encode the 32/64-bit format (Machine, SizeOfOptionalHeader, ImageBase, Characteristics) are excluded because 64-bit files are almost exclusively legitimate in the training data (`exe_rf_pipeline.joblib`, trained by `training/exe_experiments_v2.py`) |
| URL model | Gradient Boosting, chosen by its test-set score | CatBoost, chosen by 5-fold CV on the training partition (`Models/URL/pickle/catboost_model.pkl`); feature extraction unchanged |
| EXE label mapping | `['Legitimate','Malicious'][prediction]` (inverted for label 0 = malicious) | explicit mapping; the model bundle uses 1 = malicious |

## Chat application (`app.py`, templates)
* Fixed the syntax error `import pickleapp.`.
* Uploaded files are stored under a unique random name. Previously the name was the time to the second plus the original name, so concurrent uploads of the same file overwrote each other.
* Verdicts and alerts are sent only to the agent room. The user page no longer receives a detection result.
* Flagged files (malicious, disguised or unparsable) are quarantined: no download link is offered, and `/uploads/<name>` returns HTTP 403.
* All chat text and file names are HTML-escaped before display, which prevents script injection through a crafted file name.
* Each chat URL is analysed once, asynchronously (previously twice: once asynchronously and once synchronously).
* Every result carries a request id and server-side stage timestamps, for end-to-end latency measurement.
* `CHATBOT_EVAL_MODE=1` returns verdicts in HTTP responses, for the evaluation scripts only.

## Evaluation tools (`tools/`)
* `evaluate_deployed.py`: uploads an independent set of real files through `/upload` and reports confusion matrices and malicious-class precision, recall and F1 per file type, for the deployed model and, for PDFs, for the SVM on the same extracted features.
* `load_test.py`: PDF, EXE and URL workloads run separately; it measures submission-to-agent-delivery latency (mean, median, P95, P99, max, % within 5 s) and correctness.

## Training scripts (`training/`)
* `pdf_experiments.py`, `exe_experiments.py`: the leakage-free protocols reported in the paper.
