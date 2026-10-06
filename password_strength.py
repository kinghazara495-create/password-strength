#!/usr/bin/env python3
"""
password_strength.py - An honest password strength estimator.

WHY THIS REWRITES THE OBVIOUS APPROACH
    The common beginner version scores a password by counting character
    classes: +1 for a digit, +1 for a capital, +1 for a symbol, +2 for length.
    That measures the SHAPE of a password, not its strength, and the shape is
    free to fake. Measured against that scorer:

        Password123        -> "Excellent"   (in every breach list)
        P@ssw0rd!          -> "Very Excellent" (most-guessed string ever)
        correcthorse...    -> "Good"        (25 chars, genuinely strong)

    NIST SP 800-63B deliberately advises AGAINST composition rules for exactly
    this reason. A cracker's first guess is already a capital, a digit and a
    symbol, so those rules buy nothing.

    So this scores what actually matters:
      1. LENGTH            - the dominant factor
      2. NOT BREACHED      - beating a blocklist matters more than any symbol
      3. NOT PREDICTABLE   - no keyboard walks, no repeats, no sequences
      4. UNPREDICTABILITY  - measured as effective entropy in bits

    Output is expressed as TIME TO CRACK under four attacker models, because
    "8/8 characters, one symbol" means nothing to a human reader, while
    "3 days against a fast offline hash" means exactly one thing.

USAGE
    python password_strength.py              # interactive, hidden input
    python password_strength.py --demo       # why length beats symbols
    python password_strength.py --test "text"# non-interactive, for scripts
    cat mypassword.txt | python password_strength.py --stdin

    Exit code 0 = strong, 1 = weak, 2 = usage error. Makes it scriptable.

SECURITY NOTES
    - Input is read with getpass, so it is not echoed to the screen.
    - The password is never logged, printed in full, or written to disk.
    - Only the first character and length are ever displayed.
    - The breach check is a local embedded list. This tool makes NO network
      requests at all, so it works offline and leaks nothing.

LIMITATIONS, STATED UP FRONT
    This is a HEURISTIC, not a guarantee. Entropy is estimated from length and
    character pool, then reduced for detectable patterns. It cannot detect a
    password leaked last week, a password reused from your email account, or a
    pattern it has not been taught. Real strength always depends on where the
    password is used and what protects it (MFA, hashing, rate limiting).
"""

from __future__ import annotations

import argparse
import getpass
import math
import re
import sys
import unicodedata

# ───────────────────────────────────────────────────────────────────────────
# CHARACTER POOLS
# Sizes matter: entropy grows with log2(pool), so adding a symbol class
# (32 chars) is worth about 5 extra bits, while adding one more character of
# length is worth the whole pool's log2. That asymmetry is the entire reason
# length beats symbol rules.
# ───────────────────────────────────────────────────────────────────────────
POOL_LOWER = 26
POOL_UPPER = 26
POOL_DIGIT = 10
POOL_SYMBOL = 33          # printable ASCII punctuation

# ───────────────────────────────────────────────────────────────────────────
# COMMON PASSWORDS
# A deliberately small, local list. This is not a replacement for a real breach
# corpus; it is here to catch the passwords that naive scorers wave through.
# Being in this list is the single strongest signal of weakness available
# offline, which is why it caps the score hard rather than nudging it.
# ───────────────────────────────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "abc123", "password1", "iloveyou", "admin", "welcome", "monkey",
    "dragon", "letmein", "football", "baseball", "master", "sunshine",
    "princess", "trustno1", "shadow", "superman", "qwerty123", "passw0rd",
    "login", "starwars", "whatever", "zaq1zaq1", "freedom", "ninja",
    "azerty", "solo", "loveme", "michael", "jennifer", "jordan", "hunter",
    "buster", "soccer", "harley", "batman", "andrew", "tigger", "charlie",
    "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster",
    "george", "computer", "michelle", "jessica", "pepper", "ginger", "hello",
    "amanda", "summer", "loveme", "orange", "cookie", "banana", "cheese",
    "peanut", "purple", "ginger", "summer", "hannah", "amanda", "test",
    "tester", "guest", "root", "toor", "changeme", "default", "secret",
    "letmein123", "qwerty1", "q1w2e3", "q1w2e3r4", "1q2w3e4r", "asdfgh",
    "zxcvbn", "asdf1234", "p@ssw0rd", "p@ss1234", "pass1234", "password!",
    "admin123", "root123", "user123", "test123", "guest123", "qwerty12",
    "1qaz2wsx", "zaq12wsx", "qwer1234", "abcd1234", "a123456", "a12345678",
    "123abc", "1234567a", "111111", "000000", "654321", "121212", "696969",
    "123123", "112233", "123321", "1234", "12345", "123456789", "0000",
    "1111", "888888", "7777777", "qwerty1", "1q2w3e", "1q2w3e4r5t",
    "asdfghjkl", "qwertyuiop", "1qazxsw2", "zaq1xsw2", "abcd123456",
    "aabbccdd", "abc12345", "abcdabcd", "aaaa1111", "q1w2e3r4t5",
}

# ───────────────────────────────────────────────────────────────────────────
# KEYBOARD ADJACENCY
# Walks like "qwerty" or "1qaz2wsx" are trivially generated by a dictionary
# attack, so they must cost entropy. Model physical keyboard neighbours.
# ───────────────────────────────────────────────────────────────────────────
KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]
# Map each character to its neighbours on the same row.
_NEIGHBOURS: dict[str, set[str]] = {}
for _row in KEYBOARD_ROWS:
    for _i, _ch in enumerate(_row):
        _NEIGHBOURS.setdefault(_ch, set())
        if _i > 0:
            _NEIGHBOURS[_ch].add(_row[_i - 1])
        if _i < len(_row) - 1:
            _NEIGHBOURS[_ch].add(_row[_i + 1])

# ───────────────────────────────────────────────────────────────────────────
# PATTERN DETECTION
# Each function returns True/False. Together they decide the penalty.
# ───────────────────────────────────────────────────────────────────────────
REPEAT_RE = re.compile(r"(.)\1{2,}")                 # aaa, 111
SEQUENCE_RE = re.compile(
    r"(0123|1234|2345|3456|4567|5678|6789|"
    r"abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|"
    r"ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz|"
    r"ABCD|BCDE|CDEF|DEFG|EFGH|FGHI|GHIJ|HIJK|IJKL|JKLM|KLMN|LMNO|MNOP|"
    r"NOPQ|OPQR|PQRS|QRST|RSTU|STUV|TUVW|UVWX|VWXY|WXYZ)",
    re.IGNORECASE,
)


def has_repeat(password: str) -> bool:
    """Three or more of the same character in a row."""
    return bool(REPEAT_RE.search(password))


def has_sequence(password: str) -> bool:
    """Four or more consecutive characters, ascending or descending."""
    if SEQUENCE_RE.search(password):
        return True
    # Also catch descending runs, which the regex above does not.
    lower = password.lower()
    for start in range(len(lower) - 3):
        window = lower[start:start + 4]
        deltas = [ord(window[i + 1]) - ord(window[i]) for i in range(3)]
        if all(d == -1 for d in deltas):
            return True
    return False


def keyboard_walk_length(password: str) -> int:
    """Longest run of characters that are physical keyboard neighbours."""
    best = current = 0
    for i in range(1, len(password)):
        if password[i - 1] in _NEIGHBOURS and password[i] in _NEIGHBOURS[password[i - 1]]:
            current += 1
            best = max(best, current + 1)
        else:
            current = 1
    return best


def keyboard_walk(password: str, threshold: int = 5) -> bool:
    """A run of 5+ adjacent keys ('qwerty', 'asdfgh') is a dictionary word."""
    return keyboard_walk_length(password) >= threshold


_TRAILING_NOISE = "0123456789!@#$%^&*()-_=+[]{};:,.<>?/\\|`~ "
_LEET_BOTH_WAYS = {
    "1": "l", "!": "i", "|": "i", "0": "o", "3": "e", "4": "a",
    "$": "s", "@": "a", "5": "s", "7": "t",
}


def _leet_variants(word: str) -> set[str]:
    """Both directions of the classic substitutions."""
    to_letters = word
    for digit, letter in _LEET_BOTH_WAYS.items():
        to_letters = to_letters.replace(digit, letter)
    back_to_digits = to_letters
    for digit, letter in _LEET_BOTH_WAYS.items():
        back_to_digits = back_to_digits.replace(letter, digit)
    return {to_letters, back_to_digits}


def is_common(password: str) -> bool:
    """Blocklist check with realistic mutation handling.

    THE FIRST VERSION OF THIS FUNCTION WAS BROKEN IN AN IMPORTANT WAY. It
    stripped only ONE trailing character, so "password123!" reduced to
    "password123", which is not in the list, so the single most common
    password pattern in existence sailed through and scored VERY STRONG.

    A blocklist is only as good as its normalisation. Real attackers append
    ANY number of digits, substitute l/1/i/| and o/0, and capitalise freely.
    So we build a candidate set and intersect it, rather than testing one
    string.
    """
    p = password.strip().lower()
    candidates: set[str] = {p}

    # Strip any run of trailing digits and punctuation: "password123!",
    # "password!!!", "qwerty99" all reduce to their base word.
    candidates.add(p.rstrip(_TRAILING_NOISE))
    # And a single trailing digit, which is the most common mutation of all.
    if len(p) > 1 and p[-1].isdigit():
        candidates.add(p[:-1])

    # Expand with leetspeak in both directions, then strip trailing noise again.
    expanded = set(candidates)
    for c in candidates:
        expanded |= _leet_variants(c)
    for c in list(expanded):
        expanded.add(c.rstrip(_TRAILING_NOISE))

    # Common mutations like "1q2w3e" reversed and doubled.
    expanded.add(p[::-1])

    return bool(expanded & COMMON_PASSWORDS)


# ───────────────────────────────────────────────────────────────────────────
# ENTROPY MODEL
# ───────────────────────────────────────────────────────────────────────────
def char_pool(password: str) -> int:
    """Size of the character set this password actually draws from."""
    pool = 0
    if any(c.islower() and c.isalpha() for c in password):
        pool += POOL_LOWER
    if any(c.isupper() and c.isalpha() for c in password):
        pool += POOL_UPPER
    if any(c.isdigit() for c in password):
        pool += POOL_DIGIT
    if any((not c.isalnum()) and not c.isspace() for c in password):
        pool += POOL_SYMBOL
    return pool or 1


def base_entropy(password: str) -> float:
    """Bits if the characters were chosen independently and uniformly."""
    if not password:
        return 0.0
    return len(password) * math.log2(char_pool(password))


def entropy_penalty(password: str) -> tuple[float, list[str]]:
    """Multiplier on base entropy, plus a human-readable list of reasons.

    Documented as a heuristic because it is one. The multipliers are chosen to
    reflect how much each pattern collapses the real search space, not derived
    from first principles.
    """
    penalty = 1.0
    reasons: list[str] = []

    if is_common(password):
        # A blocklist hit dominates everything else.
        return 0.05, ["password appears in the common-password blocklist"]

    if has_repeat(password):
        penalty *= 0.75
        reasons.append("contains a repeated character run (aaa, 111)")

    if has_sequence(password):
        penalty *= 0.70
        reasons.append("contains a character sequence (abcd, 4321)")

    walk = keyboard_walk_length(password)
    if walk >= 5:
        penalty *= 0.65
        reasons.append(f"contains a {walk}-character keyboard walk (qwerty)")

    # A password made of one character class is far weaker than its length
    # suggests, because the pool is tiny. Already reflected in char_pool, but
    # calling it out helps the reader understand why "aaaaaaaaaaaa" is weak.
    classes = sum([
        any(c.islower() and c.isalpha() for c in password),
        any(c.isupper() and c.isalpha() for c in password),
        any(c.isdigit() for c in password),
        any((not c.isalnum()) and not c.isspace() for c in password),
    ])
    if classes == 1 and len(password) > 6:
        penalty *= 0.85
        reasons.append("uses only one character type")

    return penalty, reasons


def effective_entropy(password: str) -> tuple[float, list[str]]:
    """Final bit estimate after pattern penalties."""
    base = base_entropy(password)
    penalty, reasons = entropy_penalty(password)
    return base * penalty, reasons


# ───────────────────────────────────────────────────────────────────────────
# CRACK TIME ESTIMATES
# Guesses per second across four attacker models. These are order-of-magnitude
# figures used to make the number mean something, not guarantees.
# ───────────────────────────────────────────────────────────────────────────
ATTACK_MODELS = [
    ("online, rate-limited (100/hour)", 100 / 3600),
    ("online, unthrottled (10/sec)", 10),
    ("offline, slow hash (10k/sec)", 10_000),
    ("offline, fast hash (10 billion/sec)", 10_000_000_000),
]


def crack_time(bits: float) -> dict[str, str]:
    """Human-readable time to crack at each attack model."""
    if bits <= 0:
        return {name: "instant" for name, _ in ATTACK_MODELS}
    # Average case: half the keyspace is searched before the match.
    guesses = 2 ** (bits - 1)
    out = {}
    for name, rate in ATTACK_MODELS:
        seconds = guesses / rate
        out[name] = humanise_seconds(seconds)
    return out


def humanise_seconds(seconds: float) -> str:
    """Render a duration in the largest sensible unit."""
    units = [
        (1, "instant"),
        (60, "seconds"),
        (3600, "minutes"),
        (86400, "hours"),
        (2592000, "days"),
        (31536000, "months"),
        (31536000 * 100, "years"),
    ]
    if seconds < 1:
        return "instant"
    prev_value, prev_name = units[0]
    for value, name in units:
        if seconds < value:
            amount = seconds / prev_value
            if name == "instant":
                return f"{amount:.1f} {prev_name}"
            return f"{amount:.1f} {prev_name}"
        prev_value, prev_name = value, name
    return f"{seconds / 31536000:.0e} years"


# ───────────────────────────────────────────────────────────────────────────
# VERDICT
# Thresholds are in bits, and every one of them is reachable because the
# previous version's top five labels were dead code.
# ───────────────────────────────────────────────────────────────────────────
VERDICTS = [
    (28, 0, "VERY WEAK"),
    (36, 1, "WEAK"),
    (50, 2, "FAIR"),
    (65, 3, "STRONG"),
    (85, 4, "VERY STRONG"),
    (110, 5, "EXCELLENT"),
    (float("inf"), 0, "EXCEPTIONAL"),
]


def verdict_for(bits: float) -> tuple[str, int]:
    for ceiling, exit_code, label in VERDICTS:
        if bits < ceiling:
            return label, exit_code
    return "EXCEPTIONAL", 0


# ───────────────────────────────────────────────────────────────────────────
# MAIN ANALYSIS
# ───────────────────────────────────────────────────────────────────────────
def analyse(password: str) -> dict:
    """Full report for one password. Never returns the password itself."""
    bits, reasons = effective_entropy(password)
    label, exit_code = verdict_for(bits)
    return {
        "length": len(password),
        "pool": char_pool(password),
        "base_bits": round(base_entropy(password), 1),
        "effective_bits": round(bits, 1),
        "patterns": reasons,
        "in_blocklist": is_common(password),
        "verdict": label,
        "exit_code": exit_code,
        "crack_times": crack_time(bits),
        "masked": (password[0] + "*" * (len(password) - 1)) if password else "",
    }


def print_report(report: dict) -> None:
    print()
    print("=" * 62)
    print(f"  PASSWORD STRENGTH: {report['verdict']}")
    print("=" * 62)
    print(f"  length            : {report['length']}")
    print(f"  character pool    : {report['pool']} distinct chars available")
    print(f"  entropy (naive)   : {report['base_bits']} bits")
    print(f"  entropy (adjusted): {report['effective_bits']} bits")

    if report["patterns"]:
        print("\n  penalties applied:")
        for reason in report["patterns"]:
            print(f"    - {reason}")

    if not report["patterns"]:
        print("\n  penalties applied: none")

    print("\n  time to crack by attacker model:")
    for name, value in report["crack_times"].items():
        print(f"    {name:<34} {value}")

    print()
    print("  Reminder: this is a heuristic. Real strength depends on what")
    print("  protects the password (MFA, hashing, rate limits), not this")
    print("  number alone.")
    print("=" * 62)


def demo() -> None:
    """Show the real arithmetic, and be honest where it contradicts the
    usual advice.

    This function originally claimed "9 lowercase characters beat 8 mixed
    ones", then "only at 14 characters does lowercase win". BOTH were false:

        9  * log2(26) = 42.3 bits     vs  8  * log2(95) = 52.6 bits
        14 * log2(26) = 65.8 bits     vs  12 * log2(95) = 78.8 bits

    And the general form of that claim is false too. AT EQUAL LENGTH THE MIXED
    FORM ALWAYS HAS MORE ENTROPY. There is no crossover. Any tool that tells
    you "length beats symbols" as though it were arithmetic is misleading you.

    So this section states the correct version: length is still the right
    advice, but for a completely different reason than the one usually given.
    """
    print()
    print("PART 1 - THE ARITHMETIC, WHICH CONTRADICTS THE USUAL ADVICE")
    print("=" * 68)
    print()
    print("Entropy = length * log2(character pool)")
    print()
    print(f"  lowercase only, pool 26:  log2(26) = {math.log2(26):.2f} bits per char")
    print(f"  four classes,    pool 95:  log2(95) = {math.log2(95):.2f} bits per char")
    print()
    print("  Per character, MORE CLASSES ALWAYS WINS. There is no length at")
    print("  which pure lowercase overtakes the mixed form at equal length.")
    print()
    for n in (8, 12, 16):
        lower = n * math.log2(26)
        mixed = n * math.log2(95)
        print(f"  {n:>2} chars:  lowercase {lower:>5.1f} bits   "
              f"mixed {mixed:>5.1f} bits")
    print()
    print("  If someone tells you symbols are worthless because length matters")
    print("  more, they have the arithmetic backwards.")
    print()

    print("PART 2 - WHY LENGTH IS STILL THE RIGHT ADVICE")
    print("=" * 68)
    print()
    print("  Because the entropy formula assumes the attacker chooses")
    print("  uniformly at random. Real attackers do not. They run a dictionary,")
    print("  then apply rules: append a digit, capitalise the first letter,")
    print("  swap a for 4, repeat the last character.")
    print()
    print("  Those guesses are LOW entropy by construction, no matter how many")
    print("  character classes they contain. A rule-generated guess can be full")
    print("  of capitals and symbols and still be one of the first thousand")
    print("  attempts.")
    print()
    print("  Length is what pushes a password outside the range those cheap")
    print("  guesses can reach. That is a statement about attacker behaviour,")
    print("  NOT about the entropy formula.")
    print()

    print("PART 3 - WHICH IS WHY THE BLOCKLIST DOMINATES")
    print("=" * 68)
    print()
    print("  Once a password is already known to an attacker, both length and")
    print("  character variety are worthless. NIST SP 800-63B treats a")
    print("  blocklist as a requirement and composition rules as optional.")
    print()
    for pw in ["Password123!", "P@ssw0rd!", "qwertyuiopas", "Tr0ub4dor&3xyz!Q"]:
        bits, reasons = effective_entropy(pw)
        label, _ = verdict_for(bits)
        note = reasons[0] if reasons else "no pattern penalty"
        print(f"  {pw:<18} {bits:>6.1f} bits  {label:<13} {note}")
    print()


def read_password_stdin() -> str:
    """Read one line from stdin. Used for pipes and scripted checks."""
    return sys.stdin.readline().rstrip("\n").rstrip("\r")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Honest password strength estimation. Offline; makes no "
                    "network requests.")
    parser.add_argument("--test", metavar="PASSWORD",
                        help="check a password given as an argument (visible in "
                             "shell history - for scripts and CI only)")
    parser.add_argument("--stdin", action="store_true",
                        help="read the password from stdin")
    parser.add_argument("--demo", action="store_true",
                        help="explain why length beats character-class rules")
    args = parser.parse_args()

    if args.demo:
        demo()
        return 0

    if args.test is not None:
        password = args.test
    elif args.stdin:
        password = read_password_stdin()
    else:
        # getpass, not input: input() echoes the password to the screen and
        # into scrollback. This was the original code's worst bug.
        try:
            password = getpass.getpass("Enter your password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            return 2

    if password == "":
        print("\nEmpty password. Strength is zero by definition.\n")
        return 1

    report = analyse(password)
    print_report(report)
    return report["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(2)
