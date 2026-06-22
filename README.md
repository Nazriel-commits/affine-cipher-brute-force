# Affine Cipher Brute-Force Attack

A Python tool that performs a brute-force attack on Affine ciphers, testing all 312 valid key pairs to find the most likely plaintext.

## Overview

The Affine cipher encrypts using the formula: E(x) = (a·x + b) mod 26. This program performs a complete brute-force attack by:
- Generating all valid keys where gcd(a,26) = 1 (12 a values × 26 b values = 312 total keys)
- Decrypting the ciphertext with every valid key
- Scoring each decryption using multiple heuristics
- Ranking candidates by English-likeness

## Features

- **Complete Key Coverage**: Tests all 312 valid (a,b) key pairs
- **Composite Scoring**: Uses multiple heuristics:
  - Chi-square against English letter frequencies
  - Common English word detection (THE, AND, TO, etc.)
  - Short word detection (A, I)
  - Rare letter penalty (Q, X, Z)
  - Common bigram bonuses (TH, HE, IN, etc.)
- **Ranked Output**: Displays top 15 candidates with scores
- **Verification**: Includes comprehensive test suite to verify correctness

## Technologies Used

- Python 3
- Collections (Counter)

## Usage

```bash
python affine_brute.py intercepted_message.txt
