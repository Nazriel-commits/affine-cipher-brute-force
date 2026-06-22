###########################################################################
#Task2.py - Affine Cipher Brute-Force Attack
#
#Overview:
# This program performs a brute-force attack on an Affine cipher by testing all 312 possible key pairs where gcd(a,26)=1. 
# It decrypts the ciphertext with each key and scores the results using English frequency analysis.
#
#What it does:
#  - Generates all valid (a,b) key pairs (12 a values × 26 b values)
#  -Decrypts ciphertext using each key
#  - Scores results using chi-square, cmmon word detection, and bigram analysis
#  - Outputs top 15 candidates ranked by English likeness
#  - Proves whether the ciphertext was encrypted with an Affine cipher
#
#Author: Nazriel Al-Hafidz
###########################################################################
import sys
from collections import Counter

#More accurate English letter frequencies (from ~4.5 billion chars)
ENGLISH_FREQ = {
    'A': 8.55, 'B': 1.60, 'C': 3.16, 'D': 3.87, 'E': 12.10,
    'F': 2.18, 'G': 2.09, 'H': 4.96, 'I': 7.33, 'J': 0.22,
    'K': 0.81, 'L': 4.21, 'M': 2.53, 'N': 7.17, 'O': 7.47,
    'P': 2.07, 'Q': 0.10, 'R': 6.33, 'S': 6.73, 'T': 8.94,
    'U': 2.68, 'V': 1.06, 'W': 1.83, 'X': 0.19, 'Y': 1.72,
    'Z': 0.11
}

#Extended Euclidean Algorithm

#Returns (gcd, x, y) such that a*x + b*y = gcd(a,b)
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

#Returns modular inverse of a modulo m
def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

#Basic GCD function
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

#Return all a values where gcd(a,26)=1 (12 values total)
def get_valid_a_values():
    valid_a = []
    for a in range(1, 26):
        if gcd(a, 26) == 1:
            valid_a.append(a)
    return valid_a

#Decrypt a single uppercase letter: P = a_inv * (C - b) mod 26
def affine_decrypt_char(c, a_inv, b):
    if c < 'A' or c > 'Z':
        return c
    x = ord(c) - ord('A')
    p = (a_inv * (x - b)) % 26
    return chr(p + ord('A'))

#Decrypt entire ciphertext using key (a, b)
def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return ciphertext
    
    result = []
    for ch in ciphertext:
        result.append(affine_decrypt_char(ch, a_inv, b))
    return ''.join(result)

#Score text based on multiple heuristic: Letter frequency, Common English word detection and Common bigram detection
def score_plaintext(text):

    text_upper = text.upper()
    
    #Letter frequency analysis
    letters_only = [c for c in text_upper if c.isalpha()]
    if not letters_only:
        return -10000
    
    total = len(letters_only)
    freq_count = Counter(letters_only)
    
    chi_square = 0
    for letter, expected_pct in ENGLISH_FREQ.items():
        expected = (expected_pct / 100) * total
        observed = freq_count.get(letter, 0)
        if expected > 0:
            chi_square += ((observed - expected) ** 2) / expected
    
    #Common word detection (strong signal)
    common_words = ['THE', 'AND', 'TO', 'OF', 'IN', 'IS', 'THAT', 'FOR', 
                    'THIS', 'WITH', 'YOU', 'ARE', 'FROM', 'HAVE', 'NOT']
    word_score = 0
    for word in common_words:
        #Count word boundaries
        word_score += text_upper.count(' ' + word + ' ') * 15
        word_score += text_upper.count(' ' + word + '\n') * 15
        word_score += text_upper.count(' ' + word + '.') * 15
        word_score += text_upper.count(' ' + word + ',') * 15
    
    #Common short words (even stronger signal for small texts)
    short_words = ['A', 'I']
    for word in short_words:
        word_score += text_upper.count(' ' + word + ' ') * 20
    
    #Penalize texts with too many rare letters (Q, X, Z)
    rare_penalty = (freq_count.get('Q', 0) + freq_count.get('X', 0) + 
                    freq_count.get('Z', 0)) * 5
    
    #Extra common bigrams check
    common_bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ES', 'ON']
    bigram_score = 0
    for i in range(len(text_upper) - 1):
        bigram = text_upper[i:i+2]
        if bigram in common_bigrams:
            bigram_score += 1
    
    #Combine scores, I made chi-square score negative since higher means better, and with how big the number gets, it makes more sense to make it negative
    #Weight the components: letter frequency matters but words matter more
    total_score = -chi_square + word_score + (bigram_score * 0.5) - rare_penalty
    
    return total_score

#Try all valid (a,b) pairs and rank results by score
def brute_force_affine(ciphertext):
    valid_a = get_valid_a_values()
    results = []
    
    print(f"Trying {len(valid_a)} 'a' values × 26 'b' values = {len(valid_a) * 26} total keys")
    print("Processing...")
    
    for a in valid_a:
        for b in range(26):
            plaintext = affine_decrypt(ciphertext, a, b)
            score = score_plaintext(plaintext)
            results.append((a, b, score, plaintext))
    
    print(f"Total keys tested and stored: {len(results)}")
    results.sort(key=lambda x: x[2], reverse=True)
    return results

#Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python task2.py <ciphertext_file>")
        print("Example: python task2.py intercepted_message.txt")
        return
    
    filename = sys.argv[1]
    
    try:
        with open(filename, 'r') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return
    
    print("=" * 70)
    print("Affine Cipher Brute Force Attack")
    print("=" * 70)
    print(f"Ciphertext file: {filename}")
    print(f"Ciphertext length: {len(ciphertext)} characters")
    print()
    
    results = brute_force_affine(ciphertext)
    
    print("\n" + "=" * 70)
    print("Top 15 Candidates")
    print("=" * 70)
    
    for i in range(min(15, len(results))):
        a, b, score, plaintext = results[i]
        print(f"\n--- Candidate #{i+1} ---")
        print(f"Key: a={a}, b={b}")
        print(f"Score: {score:.2f}")
        print("First 400 characters:")
        print(plaintext[:400])
        if len(plaintext) > 400:
            print("...")
    
    print("\n" + "=" * 70)
    print("Best candidate")
    print("=" * 70)
    best_a, best_b, best_score, best_plaintext = results[0]
    print(f"Key: a={best_a}, b={best_b}")
    print(f"Score: {best_score:.2f}")
    print("\nFull decrypted message:")
    print(best_plaintext)

if __name__ == "__main__":
    main()
