# =============================================================
#  PROMPTIFY — Main Flask Application
#  File: app.py  (Version 3.0 — MongoDB Auth)
# =============================================================
#
#  HOW TO RUN:
#  ───────────
#  1. pip install flask flask-cors pymongo bcrypt pyjwt python-dotenv
#  2. Create a .env file (see .env.example)
#  3. python app.py
#  4. Open http://localhost:5000/health to verify
#
# =============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys, os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.patterns import detect_pii, mask_pii, summarize_findings, RISK_WEIGHTS, ALWAYS_MASK_TYPES
from modules.intent_classifier import classify_all
from database import history_col
from auth import auth_bp, token_required
from models import PromptHistory

app = Flask(__name__)
CORS(app)

# Register authentication routes (/register, /login, /me, /history)
app.register_blueprint(auth_bp)


# =============================================================
#  HELPERS
# =============================================================

def classify_domain(email):
    domain = email.split('@')[-1].lower() if '@' in email else ''
    if any(domain.endswith(t) for t in ['.gov','.gov.pk','.mil','.edu.pk','.ac.pk']): return 'government'
    if any(domain.endswith(t) for t in ['.edu','.ac.uk','.edu.au','.ac.nz']): return 'educational'
    if domain in ['gmail.com','yahoo.com','hotmail.com','outlook.com','live.com']: return 'personal'
    return 'corporate'

def compute_risk(enhanced_findings):
    score = 0
    for f in enhanced_findings:
        weight = RISK_WEIGHTS.get(f['type'], 15)
        action = f.get('intent_result', {}).get('action', 'ask')
        if action == 'mask':   score += weight
        elif action == 'ask':  score += weight // 2
    score = min(score, 100)
    level = 'safe' if score == 0 else 'medium' if score < 40 else 'high'
    return score, level


# =============================================================
#  ROUTE: POST /check_prompt  (PROTECTED — requires login)
#
#  This is the main sanitization endpoint.
#  It now also saves the result to MongoDB (prompt_history).
# =============================================================

@app.route('/check_prompt', methods=['POST'])
@token_required
def check_prompt(current_user_email, current_user_name):
    data   = request.get_json()
    prompt = (data.get('prompt') or '').strip()
    mode   = data.get('mode', 'standard')

    if not prompt:
        return jsonify({'error': 'Prompt cannot be empty'}), 400

    # ── Detect PII ────────────────────────────────────────────
    raw_findings = detect_pii(prompt)
    enhanced = []

    for finding in raw_findings:
        pii_type = finding['type']

        if mode == 'strict':
            ir = {'action': 'mask', 'reason': 'Strict mode — all PII masked.'}

        elif mode == 'minimal':
            high_risk = {'cnic','credit_card','card_cvc','card_expiry','person_name','medical'}
            ir = {'action':'mask','reason':'High-risk PII.'} if pii_type in high_risk \
              else {'action':'ask','reason':'Minimal mode — flagged for review.'}

        else:  # standard
            if pii_type in ALWAYS_MASK_TYPES:
                ir = {'action':'mask','reason':f'{pii_type} always masked.'}
            else:
                [classified] = classify_all(prompt, [finding])
                ir = classified.get('intent_result', {'action':'ask','reason':'Unknown.'})

        enhanced.append({**finding, 'intent_result': ir})

    # ── Build sanitized prompt ────────────────────────────────
    to_mask    = [f for f in enhanced if f['intent_result']['action'] == 'mask']
    safe_prompt = mask_pii(prompt, to_mask)
    risk_score, risk_level = compute_risk(enhanced)

    mask_count = sum(1 for f in enhanced if f['intent_result']['action'] == 'mask')
    warn_count = sum(1 for f in enhanced if f['intent_result']['action'] == 'warn')
    ask_count  = sum(1 for f in enhanced if f['intent_result']['action'] == 'ask')

    domain_classifications = {
        f['value']: classify_domain(f['value'])
        for f in enhanced if f['type'] == 'email'
    }

    # ── Save to MongoDB ───────────────────────────────────────
    # Every scan is saved to prompt_history so the user can see it later
    if history_col is not None and len(enhanced) > 0:
        try:
            history_record = PromptHistory(
                user_email=current_user_email,
                user_name=current_user_name,
                original=prompt,
                sanitized=safe_prompt,
                risk_level=risk_level,
                risk_score=risk_score,
                detected=summarize_findings(enhanced),
                mode=mode
            )
            history_col.insert_one(history_record.to_dict())
        except Exception as e:
            # Prevent history save errors from breaking the sanitization process
            print(f"[DB] Error saving scan history: {e}")

    # ── Return response ───────────────────────────────────────
    return jsonify({
        'found':                  len(enhanced) > 0,
        'detected':               summarize_findings(enhanced),
        'safe_prompt':            safe_prompt,
        'risk_score':             risk_score,
        'risk_level':             risk_level,
        'mode':                   mode,
        'mask_count':             mask_count,
        'warn_count':             warn_count,
        'ask_count':              ask_count,
        'domain_classifications': domain_classifications,
        'findings': [
            {
                'type':   f['type'],
                'value':  f['value'],
                'start':  f['start'],
                'end':    f['end'],
                'action': f['intent_result']['action'],
                'reason': f['intent_result']['reason'],
            }
            for f in enhanced
        ],
    })


# =============================================================
#  ROUTE: GET /health
# =============================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':  'running',
        'version': '3.0',
        'project': 'Promptify — AI Based Sanitization',
        'auth':    'MongoDB + bcrypt + JWT',
    })


# =============================================================
#  RUN
# =============================================================

if __name__ == '__main__':
    print("=" * 55)
    print("  PROMPTIFY v3.0 — MongoDB Auth")
    print("  URL:     http://localhost:5000")
    print("  Health:  http://localhost:5000/health")
    print("=" * 55)
    app.run(debug=True, port=5000)
