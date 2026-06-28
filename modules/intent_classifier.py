# =============================================================
#  PROMPTIFY — Module 2: Intent Classifier
#  File: modules/intent_classifier.py
#  Version: 2.0
# =============================================================
#
#  WHAT THIS FILE SOLVES:
#  ──────────────────────
#  Module 1 finds PII (email, phone, CNIC, etc.).
#  But it doesn't know WHY the PII is in the prompt.
#
#  Example — same phone number, different intent:
#
#    "My phone is 03224681016 call me anytime"
#    → User SHARING their own number → MASK IT
#
#    "phone is 03224681016 what country code is that?"
#    → User ASKING about a number → DON'T MASK
#
#    "03224681016"   (just the number, no context)
#    → We DON'T KNOW → ASK THE USER
#
#  NOTE: person_name, medical, location, cnic, credit_card
#  are in ALWAYS_MASK_TYPES in patterns.py — they bypass
#  this classifier entirely and are always masked.
#  This classifier only runs for email and phone.
#
#  HOW IT WORKS:
#  ─────────────
#  For each detected PII item, we look at the words around it
#  (the "context window") and check for signal words.
#
#  Signal categories:
#    POSSESSION  → user owns/is sharing the PII  → mask
#    QUERY       → user is asking a question     → warn (don't mask)
#    THIRD_PARTY → PII belongs to someone else   → warn
#
#  Output for each finding:
#    intent:     "personal" | "query" | "third_party" | "unknown"
#    confidence: "high" | "medium" | "low"
#    action:     "mask" | "warn" | "ask"
#    reason:     human-readable explanation string
#
# =============================================================


# =============================================================
#  SECTION 1: SIGNAL WORD LISTS
# =============================================================

# Words BEFORE a PII item that suggest the user owns it
POSSESSION_SIGNALS = [
    "my ", "mine", "i am", "i'm", "i use", "i have",
    "contact me", "contact me at", "reach me", "reach me at",
    "call me", "call me at", "call me on",
    "email me", "email me at", "send to me", "send it to",
    "my email", "my phone", "my cnic", "my card", "my number",
    "my address", "my id", "my identity",
    "i was diagnosed", "my doctor", "my physician",
    "my condition", "my medication", "i am taking", "i take",
    "i suffer", "prescribed to me",
]

# Words NEAR a PII item that suggest the user is asking about it
QUERY_SIGNALS = [
    "what", "which", "is this", "is that", "does this", "does that",
    "what country", "what network", "what operator", "which country",
    "belongs to", "belong to", "identify", "tell me about",
    "what is this", "what's this", "can you identify",
    "who owns", "who uses", "who does", "is it valid",
    "valid number", "valid email", "check this", "verify this",
    "is this correct", "is this real", "is this a",
    "for hec", "for the", "official", "confirm", "look up",
    "find out", "what does", "explain this",
    "phone code", "country code", "area code",
    "information about", "tell me",
]

# Words suggesting the PII belongs to a third party
THIRD_PARTY_SIGNALS = [
    "his", "her", "their", "he", "she", "they",
    "my friend", "my colleague", "my boss", "my teacher",
    "for him", "for her", "for them",
    "someone", "somebody", "person", "user", "client",
    "does he", "does she", "does it",
]

# Public/institutional domain TLDs
# Emails ending with these are likely public references
PUBLIC_DOMAINS = [
    ".gov", ".gov.pk", ".mil",
    ".edu", ".edu.pk", ".ac.pk", ".ac.uk", ".edu.au",
]

# How many words to look at on each side of the PII
CONTEXT_WINDOW = 8


# =============================================================
#  SECTION 2: SINGLE-FINDING CLASSIFIER
# =============================================================

def classify_intent(text, finding):
    """
    Classifies the intent behind a single PII finding.

    Parameters:
        text    (str)  : Full original prompt
        finding (dict) : One item from detect_pii()
                         { type, value, start, end }

    Returns:
        dict with keys: intent, confidence, action, reason
    """
    start    = finding["start"]
    end      = finding["end"]
    pii_type = finding["type"]

    # ── Extract context window ──────────────────────────────
    words_before = text[:start].lower().split()
    words_after  = text[end:].lower().split()

    context_before = " ".join(words_before[-CONTEXT_WINDOW:])
    context_after  = " ".join(words_after[:CONTEXT_WINDOW])
    full_context   = context_before + " " + context_after

    # ── Check signal categories ─────────────────────────────
    possession_hit  = any(s in context_before for s in POSSESSION_SIGNALS)
    query_hit       = any(s in full_context   for s in QUERY_SIGNALS)
    third_party_hit = any(s in context_before for s in THIRD_PARTY_SIGNALS)

    # ── Special rule: public email domain ──────────────────
    is_public_domain = False
    if pii_type == "email":
        domain = finding["value"].split("@")[-1].lower()
        is_public_domain = any(domain.endswith(tld) for tld in PUBLIC_DOMAINS)

    # ── Decision logic ──────────────────────────────────────
    #
    #  Priority order:
    #    1. Possession → mask (personal data)
    #    2. Query      → warn (not masking, it's a question)
    #    3. Public domain → warn (institutional email)
    #    4. Third-party → warn (belongs to someone else)
    #    5. Conflicting signals → ask user
    #    6. No signals → ask user (ambiguous)

    if possession_hit and not query_hit:
        return {
            "intent":     "personal",
            "confidence": "high",
            "action":     "mask",
            "reason":     f"Possession signal found before {pii_type} — treating as personal data."
        }

    if query_hit and not possession_hit:
        return {
            "intent":     "query",
            "confidence": "high",
            "action":     "warn",
            "reason":     f"Query signal found near {pii_type} — user appears to be asking, not sharing."
        }

    if is_public_domain and not possession_hit:
        return {
            "intent":     "query",
            "confidence": "high",
            "action":     "warn",
            "reason":     "Email belongs to a public/institutional domain — likely a public reference."
        }

    if third_party_hit:
        return {
            "intent":     "third_party",
            "confidence": "medium",
            "action":     "warn",
            "reason":     f"Third-party signal found — {pii_type} may belong to someone else."
        }

    if possession_hit and query_hit:
        return {
            "intent":     "unknown",
            "confidence": "medium",
            "action":     "ask",
            "reason":     "Mixed signals — both personal and query words detected. Please review."
        }

    return {
        "intent":     "unknown",
        "confidence": "low",
        "action":     "ask",
        "reason":     f"No context signals found around {pii_type}. Cannot determine intent automatically."
    }


# =============================================================
#  SECTION 3: CLASSIFY ALL FINDINGS
# =============================================================

def classify_all(text, findings):
    """
    Runs classify_intent() on every finding.

    Returns enhanced list where each finding has an
    "intent_result" key added.

    Example output item:
    {
        "type":          "phone",
        "value":         "03224681016",
        "start":         9,
        "end":           20,
        "intent_result": {
            "intent":     "query",
            "confidence": "high",
            "action":     "warn",
            "reason":     "Query signal detected..."
        }
    }
    """
    enhanced = []
    for finding in findings:
        result = classify_intent(text, finding)
        enhanced.append({**finding, "intent_result": result})
    return enhanced


# =============================================================
#  SECTION 4: SPLIT FINDINGS BY ACTION
# =============================================================

def split_by_action(enhanced_findings):
    """
    Splits enhanced findings into three groups by action.

    Returns:
    {
        "mask": [...],  → auto-mask (personal, high confidence)
        "warn": [...],  → flag for awareness (query/public)
        "ask":  [...],  → ambiguous, needs user decision
    }
    """
    groups = {"mask": [], "warn": [], "ask": []}
    for f in enhanced_findings:
        action = f.get("intent_result", {}).get("action", "ask")
        groups[action].append(f)
    return groups


# =============================================================
#  SECTION 5: SELF-TEST
#  Run: python modules/intent_classifier.py
# =============================================================

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from modules.patterns import detect_pii

    test_cases = [
        ("My phone is 03224681016 call me anytime.",               "mask"),
        ("phone is 03224681016 what country phone code is that?",  "warn"),
        ("03224681016",                                             "ask"),
        ("Is this the official email for HEC? finance@hec.gov.pk", "warn"),
        ("Contact me at sara@gmail.com",                           "mask"),
        ("My email is john@company.com, please reply.",            "mask"),
    ]

    print("=" * 65)
    print("PROMPTIFY v2.0 — Module 2: Intent Classifier Test")
    print("=" * 65)

    passed = 0
    for prompt, expected in test_cases:
        findings  = detect_pii(prompt)
        enhanced  = classify_all(prompt, findings)
        groups    = split_by_action(enhanced)

        if groups["mask"]:   actual = "mask"
        elif groups["warn"]: actual = "warn"
        else:                actual = "ask"

        ok = actual == expected
        if ok: passed += 1
        icon = "✓" if ok else "✗"

        print(f"\n  {icon} PROMPT:   {prompt[:60]}")
        print(f"    Expected: {expected}  |  Got: {actual}")
        for f in enhanced:
            ir = f["intent_result"]
            print(f"    [{f['type'].upper()}] action={ir['action']} | {ir['reason'][:60]}")

    print(f"\n{'='*65}")
    print(f"  Result: {passed}/{len(test_cases)} passed")
    print(f"{'='*65}")
