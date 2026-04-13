"""
app.py — Flask Backend for PhishGuard AI
=========================================
Run this on your local machine after downloading model.pkl from Kaggle.

Setup:
    pip install flask scikit-learn joblib numpy pandas

Run:
    python backend/app.py

Then open frontend/index.html in your browser.
"""

import os
import sys
import numpy as np
import joblib
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Add utils to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'utils'))
from feature_extraction import extract_features

# ── App setup ───────────────────────────────────────────────────
app = Flask(__name__, static_folder='../frontend')
CORS(app)   # Allow frontend to call this API

# ── Load model on startup ────────────────────────────────────────
MODEL_PATH        = os.path.join(os.path.dirname(__file__), '..', 'model', 'model.pkl')
FEAT_NAMES_PATH   = os.path.join(os.path.dirname(__file__), '..', 'model', 'feature_names.pkl')

model         = None
feature_names = None

def load_model():
    global model, feature_names
    if not os.path.exists(MODEL_PATH):
        print(f"\n  ❌  model.pkl not found at: {MODEL_PATH}")
        print("  ➜  Download model.pkl from Kaggle output and place it in the model/ folder.\n")
        return False
    model = joblib.load(MODEL_PATH)
    if os.path.exists(FEAT_NAMES_PATH):
        feature_names = joblib.load(FEAT_NAMES_PATH)
    print(f"  ✅  Model loaded: {type(model).__name__}")
    return True

# ── Routes ───────────────────────────────────────────────────────

@app.route('/')
def serve_frontend():
    """Serve the frontend HTML directly."""
    return send_from_directory('../frontend', 'index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """
    POST /predict
    Body: { "url": "https://example.com" }
    Returns:
    {
      "url":        "https://example.com",
      "prediction": "phishing" | "legitimate",
      "label":      1 | 0,
      "confidence": 0.92,
      "risk_score": 92,
      "features":   { feature_name: value, ... },
      "top_signals": [ { "name": ..., "value": ..., "flag": bool }, ... ]
    }
    """
    if model is None:
        return jsonify({
            'error': 'Model not loaded. Place model.pkl in the model/ folder and restart.'
        }), 503

    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" field in request body.'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty.'}), 400

    # Basic URL sanity check
    if len(url) > 2048:
        return jsonify({'error': 'URL too long (max 2048 chars).'}), 400

    try:
        # Extract features (87 values, same order as training)
        feat_values, feat_dict = extract_features(url)
        X = np.array(feat_values).reshape(1, -1)

        # Model prediction
        # Label encoding from training: legitimate=0, phishing=1
        label      = int(model.predict(X)[0])
        proba      = model.predict_proba(X)[0]   # [P(legit), P(phish)]
        confidence = float(proba[label])          # confidence in predicted class
        risk_score = int(round(proba[1] * 100))   # always phishing probability %

        prediction = 'phishing' if label == 1 else 'legitimate'

        # ── Top signals for UI display ──────────────────────────
        # Show the 12 most human-readable features
        KEY_FEATURES = [
            ('ip',                  'IP address in URL',         lambda v: v == 1),
            ('shortening_service',  'URL shortener used',        lambda v: v == 1),
            ('https_token',         'HTTPS token in domain',     lambda v: v == 1),
            ('nb_at',               '@ symbol count',            lambda v: v > 0),
            ('phish_hints',         'Phishing keywords',         lambda v: v > 0),
            ('nb_subdomains',       'Subdomain count',           lambda v: v > 2),
            ('prefix_suffix',       'Hyphen in domain',          lambda v: v == 1),
            ('punycode',            'Punycode / IDN attack',     lambda v: v == 1),
            ('suspecious_tld',      'Suspicious TLD',            lambda v: v == 1),
            ('random_domain',       'Random-looking domain',     lambda v: v == 1),
            ('length_url',          'URL length',                lambda v: v > 75),
            ('google_index',        'Google indexed',            lambda v: v == 0),
            ('domain_age',          'Domain age (new)',          lambda v: v == 0),
            ('login_form',          'Login form keywords',       lambda v: v == 1),
            ('statistical_report',  'In phishing report',        lambda v: v == 1),
        ]

        top_signals = []
        for feat_key, label_name, is_bad in KEY_FEATURES:
            val = feat_dict.get(feat_key, 0)
            top_signals.append({
                'name':  label_name,
                'value': val,
                'flag':  bool(is_bad(val))
            })

        return jsonify({
            'url':         url,
            'prediction':  prediction,
            'label':       label,
            'confidence':  round(confidence, 4),
            'risk_score':  risk_score,
            'features':    {k: (int(v) if isinstance(v, (int, np.integer)) else round(float(v), 4))
                            for k, v in feat_dict.items()},
            'top_signals': top_signals,
        })

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':       'ok',
        'model_loaded': model is not None,
        'model_type':   type(model).__name__ if model else None,
    })


# ── Start ────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("  PhishGuard AI — Flask Backend")
    print("=" * 50)
    load_model()
    print("  Server: http://127.0.0.1:5000")
    print("  API:    POST http://127.0.0.1:5000/predict")
    print("=" * 50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
