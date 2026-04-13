#!/usr/bin/env python3
"""
Argus — Data Breach Checker
Checks if an email has appeared in known data breaches using HaveIBeenPwned API.
Author: Aryan Khanna, Purdue University
"""

import urllib.request, urllib.parse, json, hashlib

def check_breach(email):
    """
    Check HaveIBeenPwned for breaches associated with this email.
    Returns list of breach objects or empty list.
    """
    try:
        encoded = urllib.parse.quote(email)
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Argus-Security-Monitor",
            "hibp-api-key": ""  # Free tier works without key for basic checks
        })
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []  # No breaches found
        raise
    except Exception:
        return []

def check_password_pwned(password):
    """
    Check if a password appears in known breach databases using k-anonymity.
    Never sends the full password - only first 5 chars of SHA1 hash.
    """
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "Argus-Security-Monitor"})
        with urllib.request.urlopen(req, timeout=10) as r:
            hashes = r.read().decode()
        for line in hashes.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except:
        return -1

def ai_explain_breach(breach_name, breach_date, data_types, email):
    """Use local Ollama to explain a breach in plain English."""
    try:
        prompt = f"""Explain this data breach to someone non-technical in 2 short sentences.
Sentence 1: What happened and what data was exposed.
Sentence 2: What the person should do right now.
Keep it simple, friendly, under 50 words total.

Breach: {breach_name} ({breach_date})
Data exposed: {', '.join(data_types[:5])}"""

        payload = json.dumps({
            "model": "llama3.2",
            "prompt": prompt,
            "stream": False
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode()).get("response", "").strip()
    except:
        return f"Your data was exposed in the {breach_name} breach. Change any passwords you used on that site and enable two-factor authentication."

def severity_score(breaches):
    """Calculate how serious the breaches are overall."""
    if not breaches:
        return 0, "safe"
    serious_types = {"Passwords", "Credit cards", "Bank account numbers", "Social security numbers", "Passport numbers"}
    serious_count = sum(1 for b in breaches if any(d in serious_types for d in b.get("DataClasses", [])))
    if serious_count >= 3 or len(breaches) >= 10:
        return len(breaches), "critical"
    elif serious_count >= 1 or len(breaches) >= 5:
        return len(breaches), "high"
    elif len(breaches) >= 2:
        return len(breaches), "medium"
    else:
        return len(breaches), "low"

if __name__ == "__main__":
    import sys
    email = input("Enter email to check: ").strip() if len(sys.argv) < 2 else sys.argv[1]
    print(f"\nChecking {email}...")
    breaches = check_breach(email)
    if not breaches:
        print("Good news - no breaches found for this email!")
    else:
        print(f"Found {len(breaches)} breach(es):")
        for b in breaches:
            print(f"  - {b['Name']} ({b['BreachDate']}): {', '.join(b['DataClasses'][:3])}")
