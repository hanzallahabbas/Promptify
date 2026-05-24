# =============================================================
#  PROMPTIFY — Module 1: Pattern Detection Engine
#  File: modules/patterns.py
# =============================================================
#
#  What this file does:
#  --------------------
#  This file is the BRAIN of Promptify's detection system.
#  It contains:
#    1. Regex patterns  — the "stencils" that match sensitive data
#    2. A detector function — scans any text using those stencils
#    3. A masker function  — replaces sensitive data with safe labels
#
#  Think of it like a metal detector at an airport:
#    - The regex patterns are the detector settings (tuned for metal)
#    - detect_pii() is the person walking through with luggage
#    - mask_pii() is the security officer replacing the item with "[ITEM]"
#
# =============================================================

import re  # 're' is Python's built-in regex (pattern matching) library


# =============================================================
#  SECTION 1: THE PATTERNS (Regex Stencils)
# =============================================================
#
#  Each pattern below is a regex string.
#  Regex is a mini-language for describing text shapes.
#
#  Common regex symbols used here:
#    \b   = word boundary (edge of a word, not a letter)
#    \d   = any digit (0-9)
#    {n}  = exactly n times
#    {n,m}= between n and m times
#    +    = one or more
#    ?    = optional (0 or 1 time)
#    [ ]  = any character inside the brackets
#    ( )  = a group
#    |    = OR (this OR that)
#    \.   = a literal dot (. alone means "any character")
#
# =============================================================

PATTERNS = {

    # ----------------------------------------------------------
    #  EMAIL PATTERN
    #  Matches: abc@gmail.com  |  john.doe@hec.gov.pk
    #
    #  Breaking it down:
    #    [a-zA-Z0-9._%+\-]+   = one or more letters/digits/dots/symbols (the username)
    #    @                     = the @ sign
    #    [a-zA-Z0-9.\-]+      = one or more letters/digits/dots (the domain name)
    #    \.                    = a literal dot
    #    [a-zA-Z]{2,}         = 2 or more letters (the extension like .com, .pk)
    # ----------------------------------------------------------
    "email": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",

    # ----------------------------------------------------------
    #  PAKISTANI PHONE NUMBER PATTERN
    #  Matches: 03001234567  |  0300-1234567  |  +92 300 1234567
    #
    #  Breaking it down:
    #    (\+92[\s\-]?|0)   = starts with +92 (optional space/dash) OR just 0
    #    (3[0-9]{2})       = 3 followed by 2 digits (like 300, 321, 333)
    #    [\s\-]?           = optional space or dash separator
    #    [0-9]{7}          = exactly 7 digits
    #
    #  The \b at start/end makes sure we don't match numbers
    #  that are part of a longer number (like a credit card)
    # ----------------------------------------------------------
    "phone": r"\b(\+92[\s\-]?|0)(3[0-9]{2})[\s\-]?[0-9]{7}\b",

    # ----------------------------------------------------------
    #  CNIC PATTERN (Pakistan National Identity Card)
    #  Matches: 35202-1234567-1
    #
    #  Breaking it down:
    #    [0-9]{5}   = exactly 5 digits (division code)
    #    \-         = literal dash
    #    [0-9]{7}   = exactly 7 digits (serial number)
    #    \-         = literal dash
    #    [0-9]{1}   = exactly 1 digit (check digit: 0 or 1)
    #
    #  CNIC is very specific — this pattern almost never
    #  matches something that ISN'T a CNIC. High confidence.
    # ----------------------------------------------------------
    "cnic": r"\b[0-9]{5}\-[0-9]{7}\-[0-9]\b",

    # ----------------------------------------------------------
    #  CREDIT/DEBIT CARD PATTERN
    #  Matches common card formats:
    #    4111 1111 1111 1111   (Visa — starts with 4)
    #    5500 0000 0000 0004   (Mastercard — starts with 51-55)
    #    3714 496353 98431     (Amex — starts with 34 or 37)
    #    6011 1111 1111 1117   (Discover — starts with 6011)
    #
    #  This pattern checks the STARTING DIGITS of real card types.
    #  It uses | (OR) to combine all four card type rules.
    # ----------------------------------------------------------
    "credit_card": (
        r"\b("
        r"4[0-9]{12}(?:[0-9]{3})?"           # Visa: 13 or 16 digits starting with 4
        r"|5[1-5][0-9]{14}"                   # Mastercard: 16 digits starting with 51-55
        r"|3[47][0-9]{13}"                    # Amex: 15 digits starting with 34 or 37
        r"|6(?:011|5[0-9]{2})[0-9]{12}"      # Discover: 16 digits
        r")\b"
        r"|"                                  # OR — also match space/dash separated formats:
        r"\b([0-9]{4}[\s\-]){3}[0-9]{4}\b"   # e.g. 4111 1111 1111 1111
    ),
}


# ----------------------------------------------------------
#  REPLACEMENT LABELS
#  When we find sensitive data, we replace it with these.
#  The labels are wrapped in [ ] so they're clearly visible.
# ----------------------------------------------------------
MASKS = {
    "email":       "[EMAIL]",
    "phone":       "[PHONE]",
    "cnic":        "[CNIC]",
    "credit_card": "[CARD]",
}


# =============================================================
#  SECTION 2: THE DETECTOR FUNCTION
# =============================================================
#
#  detect_pii(text) scans a piece of text and returns
#  everything it found — what type, what value, and where.
#
#  Input:  any string of text (the user's prompt)
#  Output: a list of dictionaries, one per match found
#
#  Example output:
#  [
#    { "type": "email", "value": "abc@gmail.com", "start": 11, "end": 24 },
#    { "type": "cnic",  "value": "35202-1234567-1", "start": 40, "end": 56 }
#  ]
#
# =============================================================

def detect_pii(text):
    """
    Scans text for all types of sensitive information.
    Returns a list of matches, each with type, value, and position.
    """

    findings = []  # We'll collect all matches here

    # Loop through each pattern type (email, phone, cnic, card)
    for pii_type, pattern in PATTERNS.items():

        # re.finditer() finds ALL matches in the text (not just the first)
        # It returns match objects — each has the matched text and its position
        for match in re.finditer(pattern, text):

            matched_text = match.group().strip()  # The actual text that matched

            # Skip empty matches (can happen with complex patterns)
            if not matched_text:
                continue

            # Save this finding as a dictionary
            findings.append({
                "type":  pii_type,        # e.g. "email"
                "value": matched_text,    # e.g. "abc@gmail.com"
                "start": match.start(),   # character position where it starts
                "end":   match.end(),     # character position where it ends
            })

    # Sort findings by their position in the text (left to right)
    # This is important later when we highlight them in order
    findings.sort(key=lambda x: x["start"])

    return findings


# =============================================================
#  SECTION 3: THE MASKER FUNCTION
# =============================================================
#
#  mask_pii(text, findings) takes the original text and the
#  list of findings, and returns a new version of the text
#  with all sensitive data replaced by safe labels.
#
#  It works from RIGHT TO LEFT through the text.
#  Why? Because if we replace from left to right, the positions
#  of later matches shift after each replacement.
#  Going right to left means earlier positions stay correct.
#
#  Example:
#    Input:  "Email abc@gmail.com and CNIC 35202-1234567-1"
#    Output: "Email [EMAIL] and CNIC [CNIC]"
#
# =============================================================

def mask_pii(text, findings):
    """
    Replaces all detected PII in text with safe label placeholders.
    Works right-to-left to preserve character positions.
    """

    safe_text = text  # Start with the original text

    # Go through findings in REVERSE order (right to left)
    for finding in reversed(findings):
        start = finding["start"]
        end   = finding["end"]
        label = MASKS[finding["type"]]  # e.g. "[EMAIL]"

        # Replace the sensitive text with the label
        # text[:start]  = everything BEFORE the sensitive part
        # label         = the replacement e.g. "[EMAIL]"
        # text[end:]    = everything AFTER the sensitive part
        safe_text = safe_text[:start] + label + safe_text[end:]

    return safe_text


# =============================================================
#  SECTION 4: QUICK SUMMARY FUNCTION
# =============================================================
#
#  summarize_findings(findings) takes the raw findings list
#  and groups them by type with counts.
#
#  Useful for the frontend to show:
#    "Found: 2 emails, 1 CNIC"
#
# =============================================================

def summarize_findings(findings):
    """
    Groups findings by type and returns counts.
    Example: { "email": 2, "cnic": 1 }
    """

    summary = {}

    for finding in findings:
        pii_type = finding["type"]

        # If we haven't seen this type before, start at 0
        if pii_type not in summary:
            summary[pii_type] = 0

        summary[pii_type] += 1  # Increment the count

    return summary


# =============================================================
#  SECTION 5: TEST IT YOURSELF
#  (This only runs when you execute this file directly,
#   not when it's imported by app.py)
# =============================================================

if __name__ == "__main__":

    # Test prompts — mix of sensitive and safe content
    test_prompts = [
        "My email is john.doe@gmail.com, please contact me.",
        "Call me at 03001234567 or +92 321 9876543.",
        "My CNIC is 35202-1234567-1, help me fill this form.",
        "My card number is 4111 1111 1111 1111 for the payment.",
        "Can you explain what machine learning is?",
        "Hi, I'm Sara. Email: sara@hec.gov.pk, CNIC: 42101-9876543-2, phone 0312-3456789.",
    ]

    print("=" * 60)
    print("PROMPTIFY — Module 1: Detection Test")
    print("=" * 60)

    for i, prompt in enumerate(test_prompts, 1):
        print(f"\nTest {i}: {prompt}")
        print("-" * 50)

        findings = detect_pii(prompt)

        if not findings:
            print("  Result: SAFE — no sensitive data found")
        else:
            print(f"  Found {len(findings)} item(s):")
            for f in findings:
                print(f"    [{f['type'].upper()}] '{f['value']}'  (position {f['start']}–{f['end']})")

            safe = mask_pii(prompt, findings)
            print(f"  Sanitized: {safe}")
            print(f"  Summary: {summarize_findings(findings)}")

    print("\n" + "=" * 60)
    print("Module 1 test complete.")
    print("=" * 60)
