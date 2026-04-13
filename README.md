# \# 🛡️ PhishGuard AI — Phishing Website Detection System

# 

# \## 📌 Project Overview

# 

# \*\*PhishGuard AI\*\* is an AI-powered phishing detection system that analyzes URLs and predicts whether a website is \*\*phishing\*\* or \*\*legitimate\*\*.

# 

# This system uses a \*\*pretrained Machine Learning model\*\* and extracts \*\*87 security-related features\*\* from URLs to detect suspicious behavior.

# 

# The project integrates:

# 

# \* Machine Learning Model

# \* Flask Backend API

# \* Interactive Web Frontend

# \* Real-time URL Analysis

# 

# \---

# 

# \## 🎯 Objectives

# 

# \* Detect phishing websites using Machine Learning

# \* Extract meaningful security features from URLs

# \* Provide real-time phishing detection

# \* Display prediction results with confidence scores

# \* Build a complete end-to-end AI web application

# 

# \---

# 

# \## 🧠 How the System Works

# 

# 1\. User enters a website URL

# 2\. Frontend sends request to Flask backend

# 3\. Backend extracts \*\*87 features\*\* from URL

# 4\. Features are passed to the trained ML model

# 5\. Model predicts:

# 

# \* \*\*Phishing (1)\*\*

# \* \*\*Legitimate (0)\*\*

# 

# 6\. Result is displayed with:

# 

# \* Risk Score

# \* Confidence Level

# \* Key Detection Signals

# 

# \---

# 

# \## 🧮 Machine Learning Model

# 

# \* Model Type: \*\*Gradient Boosting Classifier\*\*

# \* Model Status: \*\*Pretrained\*\*

# \* Dataset Used: \*\*Web Page Phishing Detect Dataset\*\*

# \* Number of Features: \*\*87\*\*

# \* Model Accuracy: \*\*96.05%\*\*

# 

# \---

# 

# \## ⚙️ Technologies Used

# 

# \### Programming Languages

# 

# \* Python

# \* HTML

# \* CSS

# \* JavaScript

# 

# \### Libraries \& Frameworks

# 

# \* Flask

# \* Flask-CORS

# \* Scikit-learn

# \* NumPy

# \* Pandas

# \* Joblib

# 

# \---

# 

# \## 📁 Project Structure

# 

# ```

# phishing-detection-system/

# │

# ├── backend/

# │   └── app.py

# │

# ├── frontend/

# │   └── index.html

# │

# ├── utils/

# │   └── feature\_extraction.py

# │

# ├── model/

# │   └── model.pkl

# │

# ├── requirements.txt

# ├── README.md

# └── .gitignore

# ```

# 

# \---

# 

# \## 🚀 Installation \& Setup Guide

# 

# \### Step 1 — Clone Repository

# 

# git clone https://github.com/Sharanmithra/phishing-detection-system.git

# 

# cd phishing-detection-system

# 

# \---

# 

# \### Step 2 — Install Dependencies

# 

# pip install -r requirements.txt

# 

# \---

# 

# \### Step 3 — Run Flask Backend

# 

# python backend/app.py

# 

# \---

# 

# \### Step 4 — Open Frontend

# 

# Open:

# 

# frontend/index.html

# 

# in your browser.

# 

# \---

# 

# \### Step 5 — Test URLs

# 

# Example URLs:

# 

# https://www.google.com

# 

# http://paypal-secure-login.account-verify.com

# 

# \---

# 

# \## 🔍 Key Features

# 

# ✔ Detects phishing websites in real-time

# ✔ Extracts \*\*87 security features\*\*

# ✔ Uses Machine Learning prediction

# ✔ Displays confidence score

# ✔ Shows phishing risk percentage

# ✔ Interactive web interface

# ✔ API-based backend architecture

# 

# \---

# 

# \## 📊 Important Detection Features

# 

# Some extracted features include:

# 

# \* URL Length

# \* Number of Dots

# \* Suspicious Keywords

# \* IP Address Usage

# \* HTTPS Token Detection

# \* Subdomain Count

# \* URL Redirection Patterns

# 

# Total Features Used:

# 

# \*\*87 Features\*\*

# 

# \---

# 

# \## 📚 Dataset Information

# 

# Dataset Used:

# 

# \*\*Web Page Phishing Detect Dataset\*\*

# 

# Used to train phishing detection models based on URL behavior.

# 

# \---

# 

# \## 👨‍💻 Developer Information

# 

# \*\*Developed By:\*\*

# \*\*Sharan Mithra\*\*

# 

# \*\*Project Type:\*\*

# Machine Learning + Web Application

# 

# \---

# 

# \## 📌 Future Improvements

# 

# \* Deploy model on cloud

# \* Add domain WHOIS lookup

# \* Improve detection accuracy

# \* Add database logging

# \* Deploy using Docker

# 

# \---

# 

# \## ⭐ Conclusion

# 

# PhishGuard AI demonstrates how Machine Learning can be applied to cybersecurity problems such as phishing detection. The system provides real-time analysis and helps users identify suspicious websites before entering sensitive information.



