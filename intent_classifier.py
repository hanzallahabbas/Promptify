# =============================================================
#  PROMPTIFY — Module 2: Intent Classifier
#  File: modules/intent_classifier.py
# =============================================================
#
#  WHAT THIS FILE SOLVES:
#  ----------------------
#  Module 1 finds PII (email, phone, CNIC, card).
#  But it doesn't know WHY the PII is in the prompt.
#
#  Example of the SAME phone number with DIFFERENT intent:
#
#    "My phone is 03224681016 call me anytime"
#    → User is SHARING their own number → MASK IT
#
#    "phone is 03224681016 what country phone code is that"
#    → User is ASKING a question about a number → DON'T MASK
#
#    "03224681016"  (just the number, no context)
#    → We DON'T KNOW → ASK THE USER
#
#  HOW IT WORKS:
#  -------------
#  For each detected PII item, we look at the words around it
#  (called the "context window") and search for signal words.
#
#  Signal words are grouped into 3 categories:
#    1. POSSESSION signals  → suggests the user owns/is sharing PII
#    2. QUERY signals       → suggests the user is asking a question
#    3. THIRD-PARTY signals → suggests the PII belongs to someone else
#
#  Based on which signals are found, we assign:
#    - intent:     "personal" | "query" | "third_party" | "unknown"
#    - confidence: "high" | "medium" | "low"
#    - action:     "mask" | "warn" | "ask"
#
# =============================================================


# =============================================================
#  SECTION 1: SIGNAL WORD LISTS
# =============================================================

# Words that appear BEFORE a PII item suggesting the user owns it
# Example: "my phone is 03001234567"  → "my" is a possession signal
POSSESSION_SIGNALS = [
    "my", "mine", "i am", "i'm", "i use", "i have",
    "contact me", "contact me at", "reach me", "reach me at",
    "call me", "call me at", "call me on",
    "email me", "email me at", "send to me", "send it to",
    "my email", "my phone", "my cnic", "my card", "my number",
    "my address", "my id", "my identity",
]

# Words that appear NEAR a PII item suggesting user is ASKING about it
# Example: "what country does 03224681016 belong to?" → "what country", "belong to"
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
]

# Words suggesting the PII belongs to a THIRD PARTY (not the user)
# Example: "my friend's email is abc@gmail.com"
THIRD_PARTY_SIGNALS = [
    "his", "her", "their", "he", "she", "they",
    "my yusra", "my colleague", "my boss", "my teacher",
    "for him", "for her", "for them", "of him", "of her",
    "someone", "somebody", "person", "user", "client",
    "does he", "does she", "does it", "does the",
]

# Public/institutional domain patterns
# If an email ends with these, it's probably a public org, not personal
PUBLIC_DOMAINS = [
    ".gov", ".gov.pk", ".mil",
    ".edu", ".edu.pk", ".ac.pk", ".ac.uk", ".edu.au",
]

# How many words to look at BEFORE and AFTER the detected PII
CONTEXT_WINDOW = 8


# =============================================================
#  SECTION 2: MAIN CLASSIFIER FUNCTION
# =============================================================

def classify_intent(text, finding):
    """
    Classifies the intent behind a single PII finding.

    Parameters:
        text    (str)  : The full original prompt text
        finding (dict) : One item from detect_pii() output
                         e.g. { "type": "phone", "value": "03224681016",
                                 "start": 9, "end": 20 }

    Returns a dict:
        {
          "intent":     "personal" | "query" | "third_party" | "unknown",
          "confidence": "high" | "medium" | "low",
          "action":     "mask" | "warn" | "ask",
          "reason":     "human-readable explanation"
        }
    """

    start = finding["start"]
    end   = finding["end"]
    pii_type = finding["type"]

    # ---- Step 1: Extract context window ----
    # Get the words before and after the PII entity.
    # We convert to lowercase so signal matching is case-insensitive.

    words_before = text[:start].lower().split()
    words_after  = text[end:].lower().split()

    # Take only the N nearest words on each side
    context_before = " ".join(words_before[-CONTEXT_WINDOW:])
    context_after  = " ".join(words_after[:CONTEXT_WINDOW])
    full_context   = context_before + " " + context_after

    # ---- Step 2: Check each signal category ----

    possession_hit  = any(signal in context_before for signal in POSSESSION_SIGNALS)
    query_hit       = any(signal in full_context    for signal in QUERY_SIGNALS)
    third_party_hit = any(signal in context_before  for signal in THIRD_PARTY_SIGNALS)

    # Special rule: if it's an email, check if the domain is public/institutional
    is_public_domain = False
    if pii_type == "email":
        domain = finding["value"].split("@")[-1].lower()
        is_public_domain = any(domain.endswith(tld) for tld in PUBLIC_DOMAINS)

    # ---- Step 3: Decide intent, confidence, and action ----
    #
    # Priority order:
    #   1. Possession signal  → almost certainly personal PII → mask
    #   2. Query signal       → user is asking, not sharing   → warn
    #   3. Third-party signal → someone else's data           → warn
    #   4. Public domain      → institutional email           → warn
    #   5. No signals at all  → ambiguous                     → ask user

    # CNIC is a special case — it almost NEVER appears in a question.
    # People don't ask "what country is this CNIC from?" — it's always personal.
    # So CNIC always gets masked regardless of context.
    if pii_type == "cnic":
        return {
            "intent":     "personal",
            "confidence": "high",
            "action":     "mask",
            "reason":     "CNIC numbers are always treated as personal identity data."
        }

    # Possession signal found → user is sharing their own data
    if possession_hit and not query_hit:
        return {
            "intent":     "personal",
            "confidence": "high",
            "action":     "mask",
            "reason":     f"Possession signal detected before the {pii_type} (e.g. 'my', 'contact me at')."
        }

    # Query signal found → user is asking a question about the PII
    if query_hit and not possession_hit:
        return {
            "intent":     "query",
            "confidence": "high",
            "action":     "warn",
            "reason":     f"Query signal detected near the {pii_type} — this appears to be a question, not personal data."
        }

    # Public institutional email domain
    if is_public_domain and not possession_hit:
        return {
            "intent":     "query",
            "confidence": "high",
            "action":     "warn",
            "reason":     "Email belongs to a public/institutional domain (gov/edu). Likely a public reference."
        }

    # Third-party signal found
    if third_party_hit:
        return {
            "intent":     "third_party",
            "confidence": "medium",
            "action":     "warn",
            "reason":     f"Third-party signal detected — {pii_type} may belong to someone else mentioned in the prompt."
        }

    # Both possession AND query signals found — conflicting context
    if possession_hit and query_hit:
        return {
            "intent":     "unknown",
            "confidence": "medium",
            "action":     "ask",
            "reason":     "Mixed signals — both personal and query words found. Needs user confirmation."
        }

    # No signals at all — we genuinely don't know
    return {
        "intent":     "unknown",
        "confidence": "low",
        "action":     "ask",
        "reason":     f"No context signals found around the {pii_type}. Cannot determine intent automatically."
    }


# =============================================================
#  SECTION 3: CLASSIFY ALL FINDINGS IN A PROMPT
# =============================================================

def classify_all(text, findings):
    """
    Runs classify_intent() on every finding from detect_pii().

    Returns an enhanced list where each finding now also has
    an "intent_result" field attached to it.

    Example output item:
    {
        "type": "phone",
        "value": "03224681016",
        "start": 9,
        "end": 20,
        "intent_result": {
            "intent": "query",
            "confidence": "high",
            "action": "warn",
            "reason": "Query signal detected..."
        }
    }
    """
    enhanced = []
    for finding in findings:
        result = classify_intent(text, finding)
        enhanced.append({ **finding, "intent_result": result })
    return enhanced


# =============================================================
#  SECTION 4: SPLIT INTO GROUPS FOR THE SANITIZER
# =============================================================

def split_by_action(enhanced_findings):
    """
    Separates findings into three groups based on their action.

    Returns:
        {
            "mask": [...],   → auto-mask these (personal, high confidence)
            "warn": [...],   → flag these for user awareness (query/public)
            "ask":  [...],   → ask user to decide (ambiguous)
        }
    """
    groups = { "mask": [], "warn": [], "ask": [] }

    for f in enhanced_findings:
        action = f["intent_result"]["action"]
        groups[action].append(f)

    return groups


# =============================================================
#  SECTION 5: TEST IT YOURSELF
# =============================================================

if __name__ == "__main__":

    # We need Module 1 to get findings first
    import sys, os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from modules.patterns import detect_pii

    test_cases = [
        # (prompt, expected_action)
        ("My phone is 03224681016 call me anytime.",              "mask"),
        ("phone is 03224681016 what country phone code is that",  "warn"),
        ("03224681016",                                            "ask"),
        ("My CNIC is 35202-1234567-1 help me fill the form.",     "mask"),
        ("Is this the official email for HEC? finance@hec.gov.pk","warn"),
        ("Contact me at sara@gmail.com",                          "mask"),
        ("Does my yusra use 03001234567?",                        "warn"),
        ("My card number is 4111 1111 1111 1111",                 "mask"),
    ]

    print("=" * 65)
    print("PROMPTIFY — Module 2: Intent Classifier Test")
    print("=" * 65)

    passed = 0
    for prompt, expected in test_cases:
        findings  = detect_pii(prompt)
        enhanced  = classify_all(prompt, findings)
        groups    = split_by_action(enhanced)

        # Determine dominant action
        if groups["mask"]:   actual = "mask"
        elif groups["warn"]: actual = "warn"
        else:                actual = "ask"

        status = "✓ PASS" if actual == expected else "✗ FAIL"
        if actual == expected: passed += 1

        print(f"\n{status}")
        print(f"  Prompt:   {prompt}")
        print(f"  Expected: {expected}  |  Got: {actual}")

        for f in enhanced:
            ir = f["intent_result"]
            print(f"  [{f['type'].upper()}] '{f['value']}'")
            print(f"    → intent: {ir['intent']}  |  confidence: {ir['confidence']}  |  action: {ir['action']}")
            print(f"    → reason: {ir['reason']}")

    print(f"\n{'=' * 65}")
    print(f"Results: {passed}/{len(test_cases)} passed")
    print("=" * 65)
