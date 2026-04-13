# PhishGuard AI — Phishing Detection System

## Project Structure
```
phishing-detection-system/
├── model/
│   └── model.pkl            ← download from Kaggle (step 1)
├── backend/
│   └── app.py               ← Flask server
├── frontend/
│   └── index.html           ← open this in browser
├── utils/
│   └── feature_extraction.py
├── requirements.txt
└── README.md
```

## How to Run (Step by Step)

### Step 1 — Download model.pkl from Kaggle
1. Go to your Kaggle notebook
2. On the right panel click "Output"
3. Navigate to model/ folder
4. Download model.pkl
5. Place it inside the `model/` folder of this project

### Step 2 — Install dependencies
Open terminal in the project folder and run:
```
pip install -r requirements.txt
```

### Step 3 — Start the Flask backend
```
python backend/app.py
```
You should see:
```
  ✅  Model loaded: GradientBoostingClassifier
  Server: http://127.0.0.1:5000
```

### Step 4 — Open the UI
Open `frontend/index.html` in your browser.
The green "Flask backend connected" banner confirms it's working.

### Step 5 — Paste any URL and click Analyze
The real model.pkl processes your URL and returns the result.

## How It Works
1. You paste a URL in the browser
2. The frontend sends it to Flask via POST /predict
3. Flask calls feature_extraction.py → extracts 87 features
4. Those features go into model.pkl (Gradient Boosting)
5. Model returns: label (0=legitimate, 1=phishing) + probability
6. Result displays in the UI with risk score and feature breakdown
