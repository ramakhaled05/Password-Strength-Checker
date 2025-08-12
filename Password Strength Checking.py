import re
import math

# Small list of common passwords
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty",
    "abc123", "111111", "12345678", "password1"
}

def charset_size(password):
    size = 0
    if re.search(r'[a-z]', password):
        size += 26
    if re.search(r'[A-Z]', password):
        size += 26
    if re.search(r'\d', password):
        size += 10
    if re.search(r'[^A-Za-z0-9]', password):
        size += 32
    return size

def entropy_bits(password):
    cs = charset_size(password)
    if cs == 0:
        return 0.0
    return len(password) * math.log2(cs)

def pattern_issues(password):
    issues = []
    pw_lower = password.lower()

    if pw_lower in COMMON_PASSWORDS:
        issues.append("common")

    if re.search(r'(.)\1{2,}', password):
        issues.append("repeats")

    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwerty"]
    for seq in sequences:
        if seq in pw_lower or seq[::-1] in pw_lower:
            issues.append("sequence")
            break

    if len(password) < 8:
        issues.append("short")

    return issues

def score(password):
    e = entropy_bits(password)
    base = int(min(100, round((e / 128) * 100)))
    issues = pattern_issues(password)

    if "common" in issues:
        return {"score": 10, "entropy": round(e, 3), "issues": issues}

    s = base
    if "repeats" in issues:
        s -= 20
    if "sequence" in issues:
        s -= 20
    if "short" in issues:
        s -= 20

    s = max(0, s)
    return {"score": s, "entropy": round(e, 3), "issues": issues}

def explain(password):
    r = score(password)
    print("\n--- Password Analysis ---")
    print(f"Entropy (bits): {r['entropy']}")
    print(f"Score (0-100): {r['score']}")
    if r['issues']:
        print("Issues detected:")
        for it in r['issues']:
            if it == "common":
                print(" - This is a very common password.")
            if it == "repeats":
                print(" - Contains repeated characters.")
            if it == "sequence":
                print(" - Contains a sequence of characters.")
            if it == "short":
                print(" - Too short; use at least 8 characters.")
    else:
        print("No major issues detected. Good password.")

    print("Tip: Use a longer passphrase with a mix of upper/lowercase, numbers, and symbols.")

if __name__ == "__main__":
    print("Password Strength Checker (type 'exit' to quit)")
    while True:
        pw = input("\nEnter password: ").strip()
        if not pw:
            print("Please enter something or type 'exit' to quit.")
            continue
        if pw.lower() in ("exit", "quit"):
            break
        explain(pw)
    print("Goodbye!")
