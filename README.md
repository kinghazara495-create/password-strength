# password-strength

A password strength estimator that reports **time to crack** instead of
inventing tiers, and ships with 33 unit tests.

Pure standard library. No dependencies, no network calls, works offline.

```bash
python password_strength.py            # interactive, hidden input
python password_strength.py --demo     # the arithmetic, honestly
python password_strength.py --test 'Tr0ub4dor&3xyz!Q'
echo "$PW" | python password_strength.py --stdin
python -m unittest discover -s tests   # run the suite
```

---

## Why this exists

This is a rewrite of a common beginner password checker that scores a password
by counting character classes: +1 for a digit, +1 for a capital, +1 for a
symbol, +2 for length.

That measures the **shape** of a password rather than its strength, and shape is
free to fake. Measured against the original scorer:

| Password | Original verdict | This tool |
|---|---|---|
| `P@ssw0rd!` | Very Excellent | **VERY WEAK** (3.0 bits) |
| `Password123` | Excellent | **VERY WEAK** (3.3 bits) |
| `password123` | Good | **VERY WEAK** (2.8 bits) |
| `123456789012` | Good | **VERY WEAK** (15.4 bits) |
| `qwertyuiopas` | BAD | WEAK (31.2 bits, 10-char keyboard walk) |
| `correcthorsebatterystaple` | Good | **EXCELLENT** (99.9 bits) |
| `Tr0ub4dor&3xyz!Q` | Great | **EXCELLENT** (105.1 bits) |

The original rated the most famous weak password on the internet as "Very
Excellent".

---

## Five real bugs this rewrite fixes

**1. The password was echoed to the screen.** The original used `input()`.
That displays the password in cleartext and drops it into your scrollback and
shell history. This uses `getpass.getpass()`.

**2. Five of ten labels were unreachable.** The original's maximum possible
score was `2 + 1 + 1 + 1 = 5`, so "Perfect", "Very perfect", "Mastered" and
"perfectionist" could never print. Dead code. There is now a test
(`TestVerdictsAreAllReachable`) that fails if the threshold table ever develops
a gap.

**3. The blocklist missed the most common pattern in existence.** A first
version of the rewrite stripped only *one* trailing character, so
`"password123!"` reduced to `"password123"`, which is not in the list, and the
result rated VERY STRONG. Blocklists are only as good as their normalisation:
real attackers append any number of digits and swap `l/1/i/|`, `o/0`, `e/3`.
Now a candidate set is built and intersected.

**4. The documentation made a false mathematical claim.** An earlier draft of
`--demo` asserted "9 lowercase characters beat 8 mixed ones". That is
arithmetic nonsense:

```
9  * log2(26) = 42.3 bits     vs    8  * log2(95) = 52.6 bits
14 * log2(26) = 65.8 bits     vs    12 * log2(95) = 78.8 bits
```

**At equal length the mixed form always has more entropy. There is no
crossover.** Any tool that tells you length beats symbols *as arithmetic* has
it backwards. A test now pins the true relationship.

**5. A `NameError` waiting to happen.** `keyboard_walk_length` referenced an
undefined name. It never fired because the function was never called on the
tested inputs.

---

## What actually determines strength

### 1. Length

The dominant factor, but not for the reason usually given. Length is not about
entropy arithmetic, since at equal length a mixed-class password always has
more bits. Length matters because of **attacker behaviour**: crackers run a
dictionary, then apply rules — append a digit, capitalise the first letter,
swap `a` for `4`. Those guesses are low entropy by construction regardless of
how many character classes they contain.

### 2. Not being breached

Once a password is known to an attacker, both length and character variety are
worthless. This is why **NIST SP 800-63B** treats a blocklist as a *requirement*
and composition rules as *optional advice*.

### 3. Not being predictable

Keyboard walks (`qwerty`, `1qaz2wsx`), character runs (`abcd`, `4321`), and
repeated characters collapse the real search space. This tool detects all three
and reduces the estimate accordingly, with the reason printed so you can see
why.

### 4. Unpredictability, measured

Output is **effective entropy in bits**, then converted to crack time under four
attacker models, because "8 characters, 1 symbol" means nothing to a human while
"cracked in 4 hours against a fast offline hash" means exactly one thing.

| Model | Rate |
|---|---|
| online, rate-limited | 100 / hour |
| online, unthrottled | 10 / second |
| offline, slow hash | 10 thousand / second |
| offline, fast hash | 10 billion / second |

The fast-hash row is the one that matters. SHA-256 and bcrypt are not the only
things a stolen database holds, and the cost of guessing depends entirely on how
the target password was stored.

---

## How the entropy is computed

```
base_bits   = length * log2(character pool)
penalty     = 1.0, multiplied down by detected patterns
effective   = base_bits * penalty
```

| Pattern | Multiplier | Why |
|---|---|---|
| On the blocklist | 0.05 | a known password is a known password |
| Repeated run (`aaa`) | 0.75 | one decision, not three |
| Sequence (`abcd`) | 0.70 | enumerable |
| 5+ keyboard walk | 0.65 | usually a dictionary word |
| Single character class | 0.85 | tiny pool, already in `log2` |

**These multipliers are heuristics, not derived from first principles.** They
are documented as such in the code so nobody mistakes them for physics.

---

## Limitations

Stated plainly, because a strength meter that oversells itself is worse than
none:

- **It is a heuristic.** It estimates from length, pool, and patterns. It cannot
  know a password leaked last week.
- **It does not check real breach corpora.** The embedded blocklist is ~150
  entries to catch the worst cases offline. Real deployment should check a
  full corpus via k-anonymity (see the `osint-tool` repo, which does exactly
  that for emails).
- **It cannot model your threat model.** A 12-character password in an offline
  breach is fine. The same password reused across three sites is not.
- **Unicode is counted by ASCII class**, so a password in a non-Latin script is
  measured against the wrong pool.
- **No dictionary beyond the embedded list.** A real diceware wordlist check
  would catch far more.

---

## Security properties of the tool itself

- Input read with `getpass`, never echoed
- The password is **never** logged, printed in full, or written to disk
- Only the first character and length are ever displayed
- A test (`TestNoSecretLeak`) asserts the password never appears in the report
  object, and that the mask never reveals the middle
- Zero network requests, so nothing can leak
- `--test` is documented as unsafe for real passwords since it lands in shell
  history; `--stdin` is provided for that case

## Exit codes

`0` strong · `1` weak · `2` usage error. Makes it usable in a CI gate or
pre-commit hook.

## Licence

MIT. See `LICENSE`.