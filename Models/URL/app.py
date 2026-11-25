#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from .feature import FeatureExtraction


# R8: CatBoost, selected by five-fold cross-validation on the training partition.
# Correction (R8): WebsiteTraffic, PageRank and GoogleIndex are excluded because the runtime extractor cannot compute them
# (the Alexa service was discontinued in 2022 and the PageRank query fails, so both always return -1; GoogleIndex always returns 1),
# whereas in the training data they differ by class. See training/url_train_v2.py.
# The wrapper keeps the interface of the earlier model (classes -1 = phishing, 1 = legitimate; predict_proba[:, 0] = P(phishing)),
# so the calling code is unchanged. The R7 Gradient Boosting model is in legacy_r7/URL/.
class _URLModel:
    def __init__(self, bundle):
        self.m, self.keep = bundle['model'], bundle['keep_idx']
        self.classes_ = np.array([-1, 1])
    def _x(self, X):
        return np.asarray(X)[:, self.keep]
    def predict_proba(self, X):
        p = self.m.predict_proba(self._x(X))  # columns: [P(legitimate), P(phishing)]
        return np.column_stack([p[:, 1], p[:, 0]])
    def predict(self, X):
        return np.where(self.predict_proba(X)[:, 0] > 0.5, -1, 1)


with open("./Models/URL/pickle/catboost_model_v2.pkl", "rb") as file:
    gbc = _URLModel(pickle.load(file))


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =gbc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return render_template('index.html',xx =round(y_pro_non_phishing,2),url=url )
    return render_template("index.html", xx =-1)


if __name__ == "__main__":
    app.run(debug=True)