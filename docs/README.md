# 📚 ccipher — Cryptographic Algorithms & Cryptanalysis Reference

This directory contains comprehensive mathematical, algorithmic, and implementation documentation for every cipher, encoding codec, and automated cryptanalysis algorithm in **ccipher** ([`src/ciphers.rs`](../src/ciphers.rs)).

---

## 🗂️ Documentation Structure

| Document | Category | Algorithms Covered |
| :--- | :--- | :--- |
| **[`01-monoalphabetic-ciphers.md`](01-monoalphabetic-ciphers.md)** | Monoalphabetic Substitution | **Caesar Cipher**, **ROT47**, **Atbash Cipher**, **Affine Cipher** |
| **[`02-polyalphabetic-and-digraph-ciphers.md`](02-polyalphabetic-and-digraph-ciphers.md)** | Polyalphabetic & Digraph | **Vigenère Cipher**, **Beaufort Cipher**, **Autokey Cipher**, **Playfair Cipher** |
| **[`03-transposition-and-bitwise-ciphers.md`](03-transposition-and-bitwise-ciphers.md)** | Transposition & Bitwise | **Rail Fence Cipher**, **Repeating-Key XOR (Hex)** |
| **[`04-encodings-and-codecs.md`](04-encodings-and-codecs.md)** | Encodings & Codecs | **Base64 (RFC 4648)**, **Hexadecimal Codec**, **Encoding Layer Chaining** |
| **[`05-cryptanalysis-and-auto-cracking.md`](05-cryptanalysis-and-auto-cracking.md)** | Automated Cryptanalysis | **Letter Frequency Analysis**, **Pearson's $\chi^2$ Statistic**, **English Bigram Scoring**, **Brute-Force Crackers** |

---

## 📊 Quick Comparison Matrix

| Algorithm | Function in `src/ciphers.rs` | Key Space / Parameters | Preserves Case & Punctuation? | Symmetric (Reciprocal)? | Auto-Crack (`-b`) |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Caesar Cipher** | `caesar_cipher(input, shift)` | $25$ non-trivial shifts ($\mathbb{Z}_{26}$) | ✅ Yes | ❌ No (`-shift` to decrypt) | ✅ Yes ($\chi^2$) |
| **ROT47** | `rot47(input)` | Fixed shift $47$ over $94$ printable ASCII chars | Transforms ASCII `33..=126` | ✅ Yes ($47 + 47 = 94$) | — |
| **Atbash** | `atbash(input)` | Fixed mirror ($x \mapsto 25 - x$) | ✅ Yes | ✅ Yes | — |
| **Affine Cipher** | `affine(input, a, b, decrypt)` | $12 \times 26 - 1 = 311$ non-trivial keys | ✅ Yes | ❌ No ($a^{-1} \bmod 26$) | ✅ Yes ($\chi^2$) |
| **Vigenère Cipher** | `vigenere(input, key, decrypt)` | $26^L$ for keyword length $L$ | ✅ Yes | ❌ No | — |
| **Beaufort Cipher** | `beaufort(input, key)` | $26^L$ for keyword length $L$ | ✅ Yes | ✅ Yes ($C \equiv K - P$) | — |
| **Autokey Cipher** | `autokey(input, key, decrypt)` | $26^L$ primer + running plaintext | ✅ Yes | ❌ No | — |
| **Playfair Cipher** | `playfair(input, key, decrypt)` | $5 \times 5$ matrix ($25!$ permutations) | ❌ Uppercase digraph pairs (`I`/`J` merged) | ❌ No | — |
| **Rail Fence** | `rail_fence(input, rails, decrypt)` | $R \in [2, N-1]$ rails | ✅ Yes (transposes all chars) | ❌ No | ✅ Yes (Bigrams) |
| **XOR Cipher** | `xor_hex_cipher(input, key, decrypt)` | $256^L$ byte key + Hex encoding | Full UTF-8 byte stream | Involution + Hex wrapper | — |
| **Base64 Codec** | `base64_encode` / `base64_decode` | No key (RFC 4648 representation) | Full UTF-8 byte stream | Encode / Decode | — |
| **Hex Codec** | `hex_encode` / `hex_decode` | No key (Base-16 representation) | Full UTF-8 byte stream | Encode / Decode | — |
