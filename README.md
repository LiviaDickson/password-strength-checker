# Password Strength Checker

A command-line tool that scores a password and explains, in plain language, why
it's weak or strong. Built to practice the security concept of **password
entropy** and safe handling of secrets.

## What it checks

- **Length** – the single biggest factor in password strength
- **Character variety** – lowercase, uppercase, digits, symbols
- **Common-password list** – rejects known-bad passwords like `password1`
- **Entropy (in bits)** – a math estimate of how hard the password is to guess

## The security idea behind it: entropy

A password's real strength isn't how complicated it *looks* to a person — it's
how many guesses an attacker's computer needs to crack it. **Entropy** measures
that as a number of bits, where each extra bit roughly *doubles* the work to
crack it.

- under ~28 bits → trivial to crack
- 60+ bits → strong
- 80+ bits → very strong

A long, simple passphrase like `Coffee-Sunset-River-92!` beats a short, messy
password like `Tr0ub4d` because length grows entropy faster than symbols do.
That's a well-known result and this tool demonstrates it.

## Why I built it this way

- **It never prints or stores the password.** If you run it without arguments it
  prompts you with a hidden input (the characters don't show on screen). A tool
  about password security that leaked the password would defeat its own purpose.
- **The common-password list overrides the math.** `password1` has okay-looking
  entropy on paper, but because it's on every attacker's wordlist it's cracked
  instantly. So a common password is rated Very Weak no matter what the entropy
  number says. Real attackers guess common passwords *first*, so the tool does too.
- **No external libraries** – runs on any machine with Python 3.

## How to run it

Prompt privately (recommended — your password stays hidden):

```bash
python3 strength.py
```

Or pass one in directly (fine for testing with fake passwords):

```bash
python3 strength.py "Coffee-Sunset-River-92!"
```

## Example

```
$ python3 strength.py "password1"
Rating       : Very Weak
Entropy      : 46.5 bits
Issues:
  - too short - aim for at least 12 characters
  - no uppercase letters
  - no symbols
  - this is a known common password - never use it
```

## What I'd add next

- A bigger common-password list (the real ones have millions of entries)
- Detecting predictable patterns like `qwerty` or `abc` runs
- Checking against the Have I Been Pwned breached-password API
