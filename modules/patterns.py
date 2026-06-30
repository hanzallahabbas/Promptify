# =============================================================
#  PROMPTIFY — Module 1: Pattern Detection Engine
#  File: modules/patterns.py
#  Version: 2.0 — Added person_name, medical, location detection
# =============================================================
#
#  DETECTION TYPES IN THIS FILE:
#  ─────────────────────────────
#  1. email        — email addresses (any domain)
#  2. phone        — Pakistani phone numbers (+92, 0092, 03xx)
#  3. cnic         — Pakistani national identity cards
#  4. credit_card  — Visa, Mastercard, Amex, Discover
#  5. person_name  — titled names (Dr./Mr./Mrs.) + self-introductions  ← NEW
#  6. medical      — diagnoses, dosages, medication names              ← NEW
#  7. location     — Pakistani cities + hospital/clinic patterns       ← NEW
#
# =============================================================

import re


# =============================================================
#  SECTION 1: REGEX PATTERNS
# =============================================================
#
#  Each entry in this dictionary is one detection type.
#  Key   = type name (used in output + masking)
#  Value = compiled regex pattern
#
#  re.compile() pre-compiles the pattern for better performance
#  re.IGNORECASE makes matching case-insensitive where needed
#
# =============================================================

PATTERNS = {

    # ----------------------------------------------------------
    #  1. EMAIL
    #  Matches: abc@gmail.com | john.doe@hec.gov.pk
    #
    #  [a-zA-Z0-9._%+\-]+  = username (letters, digits, symbols)
    #  @                    = the @ sign
    #  [a-zA-Z0-9.\-]+     = domain name
    #  \.                   = literal dot
    #  [a-zA-Z]{2,}        = extension (.com, .pk, .gov, etc.)
    # ----------------------------------------------------------
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),

    # ----------------------------------------------------------
    #  2. PHONE — Pakistani numbers only
    #  Matches:
    #    +92-321-7654321    (international, dashes)
    #    +92 321 7654321    (international, spaces)
    #    0092-312-3456789   (international alt prefix)
    #    03001234567        (local, no separator)
    #    0300-1234567       (local, dash separator)
    #
    #  WHY TWO ALTERNATIVES:
    #    Alternative 1 (+92 / 0092): The + sign can never be
    #    preceded by a digit, so no word boundary / lookbehind needed.
    #    Alternative 2 (0xxx): We use a negative lookbehind
    #    (?<![0-9]) to stop matching numbers inside longer strings.
    #
    #  [\s\-]? = optional space OR dash between segments
    # ----------------------------------------------------------
    "phone": re.compile(
        r'(\+92|0092)[\s\-]?(3[0-9]{2})[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}'
        r'|(?<![0-9])(0)(3[0-9]{2})[\s\-]?[0-9]{7}(?![0-9])'
    ),

    # ----------------------------------------------------------
    #  3. CNIC — Pakistan National Identity Card
    #  Matches:
    #    35202-1234567-1     (standard 5-7-1 format)
    #    78238-82382338-9    (some series use 8-digit middle)
    #    3520112345671       (13 digits, no dashes)
    #
    #  WHY {7,8} in middle segment:
    #    Most CNICs use 5-7-1. However some provincial series
    #    (e.g. starting with 78) use 8 digits in the middle.
    #    Using {7,8} covers both cases.
    #
    #  CNICs never appear in questions — always mask them.
    # ----------------------------------------------------------
    "cnic": re.compile(
        r'\b[0-9]{5}[-][0-9]{7,8}[-][0-9]\b'
        r'|\b[0-9]{13}\b'
    ),

    # ----------------------------------------------------------
    #  4. CREDIT / DEBIT CARD
    #  Matches common card formats:
    #    4111 1111 1111 1111   (Visa — 16 digits, starts with 4)
    #    5500 0000 0000 0004   (Mastercard — starts with 51-55)
    #    3714 496353 98431     (Amex — 15 digits, starts with 34/37)
    #    6011 1111 1111 1117   (Discover — starts with 6011)
    #
    #  The first alternative handles space/dash-separated formats.
    #  The rest match compact number strings by their starting digits.
    # ----------------------------------------------------------
    "credit_card": re.compile(
        r'\b(?:\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{1,7}'  # 4-4-4-X (Visa/MC/Discover/etc)
        r'|\d{4}[\s\-]\d{6}[\s\-]\d{5}'                  # 4-6-5 (Amex)
        r'|\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{1,3})\b' # 4-4-4-4-X
        r'|'
        r'\b(?:\d{13,19})\b'                             # Contiguous digits
    ),

    # ----------------------------------------------------------
    #  5. PERSON NAME  ← NEW
    #  Detects names in three ways:
    #
    #  a) Titled names: "Dr. Tariq Mahmood", "Mr. Ali Khan"
    #     Titles: Dr, Mr, Mrs, Ms, Miss, Prof, Engr, Adv, Sir, Madam
    #     Followed by 1-4 TitleCase words
    #
    #  b) Self-introduction: "I am Ayesha Khan"
    #     Triggers: "I am", "I'm", "my name is"
    #     Followed by exactly 2-3 TitleCase words
    #
    #  WHY NO re.IGNORECASE:
    #    Without IGNORECASE, [A-Z] matches ONLY uppercase letters.
    #    This is the key false-positive guard:
    #      "Dr. Tariq Mahmood at Hospital"
    #      → stops at "at" because 'a' is lowercase
    #    With IGNORECASE, [A-Z] would also match 'a', capturing
    #    "Dr. Tariq Mahmood at Hospital" incorrectly.
    #    Titles are listed in both cases explicitly to compensate.
    #
    #  LIMITATION: Misses names without titles that aren't in a
    #  self-intro context. Full NER requires spaCy (future module).
    # ----------------------------------------------------------
    "person_name": re.compile(
        # Branch A: titled name — explicit case variants, NO IGNORECASE
        r'\b(?:Dr|DR|Mr|MR|Mrs|MRS|Ms|MS|Miss|MISS|Prof|PROF'
        r'|Engr|ENGR|Adv|ADV|Sir|SIR|Madam|MADAM)\.?\s+'
        r'[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\b'
        r'|'
        # Branch B: self-introduction — TitleCase guards against verb phrases
        r'(?:I\s+am|I\'m|[Mm]y\s+name\s+is)\s+'
        r'([A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20})?)'
        # NO re.IGNORECASE — this is intentional (see note above)
    ),

    # ----------------------------------------------------------
    #  6. MEDICAL PII  ← NEW
    #  Detects three sub-categories of medical information:
    #
    #  a) Dosage + medication strings:
    #     "500mg Metformin", "10 mcg Insulin", "2g Amoxicillin"
    #     Pattern: number + unit (mg/mcg/ml/g/units) + drug name
    #
    #  b) Named diagnoses:
    #     "Type 2 Diabetes", "HIV", "hepatitis", "hypertension"
    #     Covers 20+ common conditions
    #     "Type [1/2]" prefix is optional (catches both
    #     "Diabetes" and "Type 2 Diabetes")
    #
    #  c) Named medications:
    #     "Metformin", "Insulin", "Aspirin", "Paracetamol", etc.
    #     30+ common drugs by name
    #
    #  WHY medical info is always masked:
    #    Health data is among the most sensitive PII under GDPR,
    #    HIPAA, and Pakistan's PECA. Exposing it to AI systems
    #    can lead to profiling, discrimination, and data leaks.
    # ----------------------------------------------------------
    "medical": re.compile(
        # Dosage strings: "500mg Metformin", "10 ml Insulin"
        r'\b\d+\s*(?:mg|mcg|ml|g|units?)\s+[A-Za-z]+\b'
        r'|'
        # Named diagnoses
        r'\b(?:type\s+[12]\s+)?(?:diabetes|cancer|hiv|aids|hepatitis'
        r'|tuberculosis|tb|hypertension|depression|anxiety|asthma'
        r'|epilepsy|alzheimer|parkinson|schizophrenia|bipolar'
        r'|arthritis|tumor|covid[\-\s]?19?|coronavirus|cholesterol'
        r'|stroke|kidney\s+disease|heart\s+disease|liver\s+disease'
        r'|obesity|thyroid|appendicitis|pneumonia|migraine)\b'
        r'|'
        # Named medications
        r'\b(?:metformin|insulin|aspirin|paracetamol|ibuprofen'
        r'|amoxicillin|ciprofloxacin|omeprazole|lisinopril'
        r'|atorvastatin|metoprolol|amlodipine|warfarin|prednisone'
        r'|prednisolone|dexamethasone|clopidogrel|losartan'
        r'|pantoprazole|cetirizine|loratadine|diazepam|alprazolam'
        r'|sertraline|fluoxetine|azithromycin|clarithromycin'
        r'|ceftriaxone|metronidazole|ranitidine|lansoprazole)\b',
        re.IGNORECASE
    ),

    # ----------------------------------------------------------
    #  7. LOCATION  ← NEW
    #  Detects two types of location information:
    #
    #  a) Pakistani cities:
    #     "Lahore", "Karachi", "Islamabad", and 12 more cities
    #     These are matched as whole words (\b) to avoid
    #     partial matches (e.g. "Islamabad" in "Islamabad Road")
    #
    #  b) Named institutions with context:
    #     "at Shaukat Khanum Hospital"
    #     "in Aga Khan Medical Center"
    #     "from City Clinic"
    #     Triggered by prepositions (at/in/from) + TitleCase name
    #     + institution keyword (Hospital/Clinic/Institute etc.)
    #
    #  NOTE: City names can be lower-risk depending on context.
    #  You can downgrade them to "warn" in risk_scorer.py if needed.
    # ----------------------------------------------------------
    "location": re.compile(
        # Pakistani cities
        r'\b(?:Karachi|Lahore|Islamabad|Rawalpindi|Faisalabad'
        r'|Multan|Peshawar|Quetta|Sialkot|Gujranwala|Hyderabad'
        r'|Abbottabad|Murree|Bahawalpur|Sargodha|Sukkur|Larkana'
        r'|Mardan|Mingora|Nawabshah|Sahiwal|Mirpur|Muzaffarabad)\b'
        r'|'
        # Named institutions (at/in/from + TitleCase + institution keyword)
        r'(?:at|in|from)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*'
        r'\s+(?:Hospital|Clinic|Medical\s+Center|Medical\s+Centre'
        r'|Institute|University|College|School|Academy)',
        re.IGNORECASE
    ),
}


# =============================================================
#  SECTION 2: MASK LABELS
#  What replaces each sensitive item in the sanitized output
# =============================================================

MASKS = {
    "email":       "[EMAIL]",
    "phone":       "[PHONE]",
    "cnic":        "[CNIC]",
    "credit_card": "[CARD]",
    "person_name": "[NAME]",
    "medical":     "[MEDICAL-INFO]",
    "location":    "[LOCATION]",
}


# =============================================================
#  SECTION 3: RISK WEIGHTS
#  Used by risk_scorer.py to compute the 0-100 risk score.
#  Higher = more dangerous if exposed to an AI system.
# =============================================================
#
#  Scoring rationale:
#    credit_card  50 — financial fraud risk
#    cnic         40 — identity theft, biometric link
#    medical      35 — health profiling, discrimination
#    person_name  30 — identity + combination risk
#    phone        25 — harassment, social engineering
#    email        20 — spam, phishing
#    location     15 — tracking, but often semi-public

RISK_WEIGHTS = {
    "email":       20,
    "phone":       25,
    "cnic":        40,
    "credit_card": 50,
    "person_name": 30,
    "medical":     35,
    "location":    15,
}


# =============================================================
#  SECTION 4: ALWAYS-MASK TYPES
#  These types skip intent classification — they are ALWAYS
#  personal regardless of context.
#
#  Example: "My CNIC is 35202-1234567-1" → mask
#           "Is 35202-1234567-1 a valid CNIC?" → still mask
#           (contrast with email/phone which depend on context)
# =============================================================

ALWAYS_MASK_TYPES = {"cnic", "credit_card", "person_name", "medical", "location"}


# =============================================================
#  SECTION 5: DETECTOR FUNCTION
# =============================================================
#
#  detect_pii(text) → list of findings
#
#  Each finding is a dict:
#  {
#    "type":  "email",           # which pattern matched
#    "value": "abc@gmail.com",   # the matched text
#    "start": 11,                # char position (start)
#    "end":   24                 # char position (end)
#  }
#
#  Findings are sorted left-to-right by position.
#  Overlapping matches are removed (first match wins).

def detect_pii(text):
    """
    Scans text for all 7 types of sensitive information.
    Returns sorted, deduplicated list of match dictionaries.
    """
    findings = []

    for pii_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            matched_text = match.group().strip()
            if not matched_text:
                continue
            findings.append({
                "type":  pii_type,
                "value": matched_text,
                "start": match.start(),
                "end":   match.end(),
            })

    # Sort by position in text (left to right)
    findings.sort(key=lambda x: x["start"])

    # Remove overlapping matches (keep the first/leftmost one)
    deduped = []
    last_end = -1
    for f in findings:
        if f["start"] >= last_end:
            deduped.append(f)
            last_end = f["end"]

    return deduped


# =============================================================
#  SECTION 6: MASKER FUNCTION
# =============================================================
#
#  mask_pii(text, findings) → sanitized string
#
#  Replaces each matched entity with its label.
#  Works RIGHT-TO-LEFT to preserve character positions.
#
#  Why right-to-left?
#    If we replace from left to right, each replacement
#    changes the length of the string, shifting all the
#    positions of later matches. Going right-to-left means
#    earlier positions are untouched until we reach them.
#
#  Example:
#    Input:  "Email abc@gmail.com and CNIC 35202-1234567-1"
#    Output: "Email [EMAIL] and CNIC [CNIC]"

def mask_pii(text, findings):
    """
    Replaces all detected PII with safe label placeholders.
    Only masks findings that should be masked (respects intent).
    """
    safe_text = text
    for finding in reversed(findings):
        label = MASKS.get(finding["type"], "[REDACTED]")
        safe_text = (
            safe_text[:finding["start"]]
            + label
            + safe_text[finding["end"]:]
        )
    return safe_text


# =============================================================
#  SECTION 7: SUMMARY FUNCTION
# =============================================================

def summarize_findings(findings):
    """
    Groups findings by type and returns counts.
    Example output: { "email": 1, "medical": 2, "person_name": 1 }
    """
    summary = {}
    for f in findings:
        summary[f["type"]] = summary.get(f["type"], 0) + 1
    return summary


# =============================================================
#  SECTION 8: SELF-TEST
#  Run this file directly to see all 7 detection types working:
#    python modules/patterns.py
# =============================================================

if __name__ == "__main__":

    test_cases = [
        # (prompt, description)
        (
            "My email is john.doe@gmail.com, please contact me.",
            "Email detection"
        ),
        (
            "Call me at +92-321-7654321 or 03001234567.",
            "Phone detection (+92 and 03xx)"
        ),
        (
            "My CNIC is 35202-1234567-1, help me fill the form.",
            "CNIC detection"
        ),
        (
            "My card number is 4111 1111 1111 1111 for the payment.",
            "Credit card detection"
        ),
        (
            "Hi, I am Ayesha Khan (Phone: +92-321-7654321). My attending physician, "
            "Dr. Tariq Mahmood at Shaukat Khanum Hospital in Lahore, just diagnosed "
            "me with Type 2 Diabetes. He prescribed 500mg Metformin twice a day.",
            "Medical scenario — name + phone + medical + location"
        ),
        (
            "My name is Sara Ahmed. Dr. Ali Hassan prescribed 10mg Prednisolone "
            "for my arthritis. I am from Karachi.",
            "Mixed medical + name + location"
        ),
        (
            "Is this the official HEC email? finance@hec.gov.pk",
            "Public reference (email) — safe"
        ),
        (
            "Explain the difference between supervised and unsupervised ML.",
            "Safe prompt — nothing to detect"
        ),
    ]

    print("=" * 65)
    print("PROMPTIFY v2.0 — Module 1: Detection Test (7 types)")
    print("=" * 65)

    for i, (prompt, description) in enumerate(test_cases, 1):
        print(f"\nTest {i}: {description}")
        print(f"  Prompt: {prompt[:70]}{'...' if len(prompt)>70 else ''}")
        print(f"  {'-'*55}")

        findings = detect_pii(prompt)

        if not findings:
            print("  SAFE — no sensitive data detected")
        else:
            for f in findings:
                print(f"  [{f['type'].upper():12}] \"{f['value']}\"")
            safe = mask_pii(prompt, findings)
            print(f"  Sanitized: {safe[:80]}{'...' if len(safe)>80 else ''}")
            print(f"  Summary:   {summarize_findings(findings)}")

    print("\n" + "=" * 65)
    print("All tests complete.")
    print("=" * 65)
