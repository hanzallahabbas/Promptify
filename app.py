# =============================================================
#  PROMPTIFY — Flask Backend API
#  File: app.py
#  Version: 2.0
# =============================================================
#
#  WHAT THIS FILE DOES:
#  ────────────────────
#  This is the main backend server for Promptify.
#  It receives prompts from the frontend, runs them through
#  the detection and sanitization pipeline, and returns results.
#
#  HOW IT CONNECTS TO OTHER MODULES:
#  ──────────────────────────────────
#  app.py  ──imports──►  modules/patterns.py        (detection)
#          ──imports──►  modules/intent_classifier.py (intent)
#
#  API ENDPOINT:
#  ─────────────
#  POST /check_prompt
#  Body: { "prompt": "...", "mode": "standard" }
#  Returns: see RESPONSE FORMAT below
#
#  HOW TO RUN:
#  ───────────
#  1. Open terminal in your promptify/ folder
#  2. pip install flask flask-cors
#  3. python app.py
#  4. Backend runs at http://localhost:5000
#
# =============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add the project root to Python path so we can import from modules/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.patterns import (
    detect_pii,
    mask_pii,
    summarize_findings,
    RISK_WEIGHTS,
    ALWAYS_MASK_TYPES
)
from modules.intent_classifier import classify_all, split_by_action

# ── Create the Flask app ────────────────────────────────────
app = Flask(__name__)

# CORS = Cross-Origin Resource Sharing
# This allows the frontend (running on a different port via
# Live Server) to talk to this backend without being blocked.
CORS(app)


# =============================================================
#  HELPER: DOMAIN CLASSIFIER
#  Determines what type of organisation an email domain belongs to.
# =============================================================

def classify_domain(email):
    """
    Classifies an email address domain into one of 4 categories:
      - government   (.gov, .gov.pk, .mil, .edu.pk, .ac.pk)
      - educational  (.edu, .ac.uk, .edu.au, .ac.nz)
      - personal     (gmail.com, yahoo.com, hotmail.com, etc.)
      - corporate    (everything else)
    """
    domain = email.split("@")[-1].lower() if "@" in email else ""

    gov_tlds = [".gov", ".gov.pk", ".mil", ".edu.pk", ".ac.pk"]
    edu_tlds = [".edu", ".ac.uk", ".edu.au", ".ac.nz"]
    personal = ["gmail.com", "yahoo.com", "hotmail.com",
                "outlook.com", "live.com", "icloud.com"]

    if any(domain.endswith(t) for t in gov_tlds):
        return "government"
    if any(domain.endswith(t) for t in edu_tlds):
        return "educational"
    if domain in personal:
        return "personal"
    return "corporate"


# =============================================================
#  HELPER: RISK SCORER
#  Computes 0-100 risk score from a list of enhanced findings.
# =============================================================

def compute_risk(enhanced_findings):
    """
    Calculates risk score based on:
      - Type of PII found (CNIC = 40, card = 50, medical = 35, etc.)
      - Intent result (mask = full weight, ask = half weight)
      - Capped at 100

    Returns:
      score (int 0-100)
      level ("safe" | "medium" | "high")
    """
    score = 0
    for f in enhanced_findings:
        weight = RISK_WEIGHTS.get(f["type"], 15)
        action = f.get("intent_result", {}).get("action", "ask")
        if action == "mask":
            score += weight
        elif action == "ask":
            score += weight // 2
        # warn = 0 (public reference, not personal risk)

    score = min(score, 100)

    if score == 0:
        level = "safe"
    elif score < 40:
        level = "medium"
    else:
        level = "high"

    return score, level


# =============================================================
#  MAIN API ENDPOINT
#  POST /check_prompt
# =============================================================
#
#  REQUEST BODY (JSON):
#  {
#    "prompt": "Hi, I am Ayesha Khan...",
#    "mode":   "standard"   ← "strict" | "standard" | "minimal"
#  }
#
#  RESPONSE FORMAT (JSON):
#  {
#    "found":         true,
#    "detected":      { "person_name": 1, "medical": 2, ... },
#    "safe_prompt":   "Hi, [NAME]...",
#    "risk_score":    65,
#    "risk_level":    "high",
#    "mode":          "standard",
#    "findings": [
#      {
#        "type":   "person_name",
#        "value":  "Ayesha Khan",
#        "start":  9,
#        "end":    20,
#        "action": "mask",
#        "reason": "Personal name identified..."
#      }, ...
#    ],
#    "domain_classifications": {
#      "abc@hec.gov.pk": "government"
#    }
#  }

@app.route("/check_prompt", methods=["POST"])
def check_prompt():
    """
    Main sanitization endpoint.
    Receives a prompt, runs detection + intent + risk scoring,
    returns sanitized prompt and full analysis.
    """

    # ── 1. Parse request ─────────────────────────────────────
    data = request.get_json()

    if not data or "prompt" not in data:
        return jsonify({
            "error": "Missing 'prompt' field in request body"
        }), 400

    prompt = data.get("prompt", "").strip()
    mode   = data.get("mode", "standard")  # strict | standard | minimal

    if not prompt:
        return jsonify({
            "error": "Prompt cannot be empty"
        }), 400

    # ── 2. Detect all PII ────────────────────────────────────
    raw_findings = detect_pii(prompt)

    # ── 3. Apply intent classification based on privacy mode ─
    #
    #  STRICT   → mask everything detected, no intent check
    #  STANDARD → use intent classifier (smart masking)
    #  MINIMAL  → only mask high-risk types (CNIC, card, medical, name)

    enhanced = []

    for finding in raw_findings:
        pii_type = finding["type"]

        if mode == "strict":
            intent_result = {
                "action": "mask",
                "reason": "Strict mode — all detected PII is masked."
            }

        elif mode == "minimal":
            # In minimal mode only high-risk types are masked
            high_risk = {"cnic", "credit_card", "person_name",
                         "medical", "location"}
            if pii_type in high_risk:
                intent_result = {
                    "action": "mask",
                    "reason": "High-risk PII — masked in all modes."
                }
            else:
                intent_result = {
                    "action": "ask",
                    "reason": "Minimal mode — low-risk item flagged for review."
                }

        else:
            # STANDARD: use intent classifier
            # But always-mask types skip classification
            if pii_type in ALWAYS_MASK_TYPES:
                intent_result = {
                    "action": "mask",
                    "reason": f"{pii_type.replace('_', ' ').title()} is always treated as personal data."
                }
            else:
                # Run intent classification for email/phone
                [classified] = classify_all(prompt, [finding])
                intent_result = classified.get("intent_result", {
                    "action": "ask",
                    "reason": "Could not determine intent."
                })

        enhanced.append({**finding, "intent_result": intent_result})

    # ── 4. Build sanitized prompt ────────────────────────────
    #
    # Only items with action="mask" get replaced.
    # Items with action="warn" or "ask" are left in the prompt.

    items_to_mask = [
        f for f in enhanced if f["intent_result"]["action"] == "mask"
    ]
    safe_prompt = mask_pii(prompt, items_to_mask)

    # ── 5. Compute risk score ────────────────────────────────
    risk_score, risk_level = compute_risk(enhanced)

    # ── 6. Build domain classifications (emails only) ────────
    domain_classifications = {}
    for f in enhanced:
        if f["type"] == "email":
            domain_classifications[f["value"]] = classify_domain(f["value"])

    # ── 7. Count actions ─────────────────────────────────────
    mask_count = sum(1 for f in enhanced if f["intent_result"]["action"] == "mask")
    warn_count = sum(1 for f in enhanced if f["intent_result"]["action"] == "warn")
    ask_count  = sum(1 for f in enhanced if f["intent_result"]["action"] == "ask")

    # ── 8. Build response ────────────────────────────────────
    response = {
        "found":       len(enhanced) > 0,
        "detected":    summarize_findings(enhanced),
        "safe_prompt": safe_prompt,
        "risk_score":  risk_score,
        "risk_level":  risk_level,
        "mode":        mode,
        "mask_count":  mask_count,
        "warn_count":  warn_count,
        "ask_count":   ask_count,
        "findings": [
            {
                "type":   f["type"],
                "value":  f["value"],
                "start":  f["start"],
                "end":    f["end"],
                "action": f["intent_result"]["action"],
                "reason": f["intent_result"]["reason"],
            }
            for f in enhanced
        ],
        "domain_classifications": domain_classifications,
    }

    return jsonify(response)


# =============================================================
#  HEALTH CHECK ENDPOINT
#  GET /health
#  Use this to test if the server is running correctly.
#  Open http://localhost:5000/health in your browser.
# =============================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "running",
        "version": "2.0",
        "project": "Promptify — AI Based Sanitization",
        "modules": ["patterns", "intent_classifier"],
        "detection_types": [
            "email", "phone", "cnic", "credit_card",
            "person_name", "medical", "location"
        ]
    })


# =============================================================
#  RUN THE SERVER
# =============================================================
#
#  debug=True  → auto-restarts when you save app.py
#  port=5000   → frontend fetch() calls go to localhost:5000

if __name__ == "__main__":
    print("=" * 55)
    print("  PROMPTIFY Backend Starting...")
    print("  URL:     http://localhost:5000")
    print("  Health:  http://localhost:5000/health")
    print("  Mode:    Development (debug=True)")
    print("=" * 55)
    app.run(debug=True, port=5000)
