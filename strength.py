#!/usr/bin/env python3
"""
Password Strength Checker
-------------------------
Scores a password and explains, in plain language, what makes it weak or strong.

It checks the things that actually matter for password security:
  - length (the single biggest factor)
  - variety of character types (lower, upper, digits, symbols)
  - whether it's on a list of known-common passwords
  - rough "entropy" - a math estimate of how hard it is to guess

Why entropy matters:
A password's real strength isn't about looking complicated to a human, it's
about how many guesses an attacker needs. Entropy estimates that as a number of
bits. Each extra bit roughly doubles the work to crack it. Under ~28 bits is
trivial to crack; 60+ bits is strong.

Runs with plain Python 3 - no libraries to install.
"""

import math
import argparse
import os
import getpass


def load_common_passwords(path):
    """Load the list of known-bad passwords into a set for fast lookup."""
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def character_pool_size(password):
    """
    Estimate how big the 'alphabet' an attacker must guess from is, based on
    which character types the password uses. A bigger pool = harder to brute force.
    """
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32  # rough count of common symbols
    return pool


def entropy_bits(password):
    """
    Entropy estimate: length * log2(pool size).
    This approximates how many random guesses an attacker would need.
    """
    pool = character_pool_size(password)
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def check(password, common):
    """Run every check and return a result dictionary."""
    issues = []

    if len(password) < 12:
        issues.append("too short - aim for at least 12 characters")
    if not any(c.islower() for c in password):
        issues.append("no lowercase letters")
    if not any(c.isupper() for c in password):
        issues.append("no uppercase letters")
    if not any(c.isdigit() for c in password):
        issues.append("no numbers")
    if not any(not c.isalnum() for c in password):
        issues.append("no symbols")
    if password.lower() in common:
        issues.append("this is a known common password - never use it")

    bits = entropy_bits(password)

    # Turn the entropy number into a plain-language rating.
    if password.lower() in common:
        rating = "Very Weak"
    elif bits < 28:
        rating = "Very Weak"
    elif bits < 36:
        rating = "Weak"
    elif bits < 60:
        rating = "Reasonable"
    elif bits < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return {"rating": rating, "entropy_bits": bits, "issues": issues}


def main():
    parser = argparse.ArgumentParser(description="Check how strong a password is.")
    parser.add_argument("password", nargs="?", help="password to check (omit to be prompted privately)")
    parser.add_argument("--list", default="common_passwords.txt", help="path to common-password list")
    args = parser.parse_args()

    common = load_common_passwords(args.list)

    # If no password was given on the command line, ask for it without echoing
    # it to the screen - you should never print a real password.
    password = args.password or getpass.getpass("Enter password to check: ")

    result = check(password, common)

    print(f"\nRating       : {result['rating']}")
    print(f"Entropy      : {result['entropy_bits']} bits")
    if result["issues"]:
        print("Issues:")
        for i in result["issues"]:
            print(f"  - {i}")
    else:
        print("No issues found.")
    print()


if __name__ == "__main__":
    main()
