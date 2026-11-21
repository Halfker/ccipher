# 🔤 Monoalphabetic Substitution Ciphers

Monoalphabetic substitution ciphers replace each character of the plaintext with a corresponding character from a fixed permuted alphabet throughout the entire message. Because a given plaintext letter always maps to the same ciphertext letter, single-letter frequency distributions are preserved (merely shifted or permuted), making these ciphers vulnerable to frequency analysis.

In **ccipher**, four monoalphabetic algorithms are implemented in [`src/ciphers.rs`](../src/ciphers.rs):
1. [Caesar Cipher](#1-caesar-cipher)
2. [ROT47 Cipher](#2-rot47-cipher)
3. [Atbash Cipher](#3-atbash-cipher)
4. [Affine Cipher](#4-affine-cipher)

---

## 1. Caesar Cipher

### Historical & Conceptual Overview
Named after Julius Caesar, who used a shift of 3 to protect military correspondence, the Caesar cipher is an additive shift cipher operating on the 26-letter Latin alphabet. Every ASCII alphabetic character is shifted forward (or backward) by a constant integer offset modulo 26.

### Mathematical Formulation
Map each letter $A\text{–}Z$ (or $a\text{–}z$) to an integer $x \in \{0, 1, \dots, 25\}$:

$$E_k(x) = (x + k) \bmod 26$$

$$D_k(y) = (y - k) \bmod 26$$

where $k \in \mathbb{Z}$ is the shift key. Because modular arithmetic is cyclic with period 26:
- Shifting by $k$ is equivalent to shifting by $k \bmod 26$.
- `ROT13` is a special case of Caesar with $k = 13$, which is self-inverse ($13 + 13 \equiv 0 \pmod{26}$).

### Step-by-Step Worked Example
**Input:** `"Hello!"`, **Shift:** $k = 3$

| Character | Base (`'A'` or `'a'`) | Index $x$ | $(x + 3) \bmod 26$ | Output Character |
| :---: | :---: | :---: | :---: | :---: |
| `'H'` | `'A'` (65) | $7$ | $(7 + 3) \bmod 26 = 10$ | `'K'` |
| `'e'` | `'a'` (97) | $4$ | $(4 + 3) \bmod 26 = 7$ | `'h'` |
| `'l'` | `'a'` (97) | $11$ | $(11 + 3) \bmod 26 = 14$ | `'o'` |
| `'l'` | `'a'` (97) | $11$ | $(11 + 3) \bmod 26 = 14$ | `'o'` |
| `'o'` | `'a'` (97) | $14$ | $(14 + 3) \bmod 26 = 17$ | `'r'` |
| `'!'` | Non-alphabetic | — | Unchanged | `'!'` |

**Result:** `"Khoor!"`

### Implementation Details in `ccipher`
Implemented in `shift_char` and `caesar_cipher` (`src/ciphers.rs:126-139`):
- **Case & Punctuation Preservation:** Non-ASCII-alphabetic characters (digits, spaces, punctuation, Unicode symbols) pass through unmodified. Uppercase letters stay uppercase (`base = b'A'`), and lowercase letters stay lowercase (`base = b'a'`).
- **Negative Shifts via Euclidean Modulo:** Rust's standard `%` operator computes the remainder (which can be negative for negative dividends). `ccipher` uses `.rem_euclid(26)` so negative shifts (such as `-3` during decryption or user-supplied negative shifts) always wrap cleanly into $0..=25$.
- **Constant-Memory Unix Pipe Streaming:** Because Caesar transforms each character independently without state, `try_stream_lines` in `src/main.rs` streams arbitrarily large inputs line-by-line when piped in raw mode.

### CLI Usage
```bash
# Encrypt with shift 3
ccipher -c caesar -s 3 "Attack at dawn!"

# Decrypt with shift 3
ccipher -d -c caesar -s 3 "Dwwdfn dw gdzq!"

# Auto-crack unknown shift
ccipher -b "Dwwdfn dw gdzq!"
```

---

## 2. ROT47 Cipher

### Conceptual Overview
While Caesar and ROT13 only transform letters (`A-Z` and `a-z`), **ROT47** rotates all **94 printable ASCII characters** from `'!'` (ASCII 33) through `'~'` (ASCII 126) by 47 positions. This means digits, punctuation, brackets, and mathematical symbols are also obfuscated alongside letters.

### Mathematical Formulation
For any character with ASCII code $c \in [33, 126]$:

$$\text{ROT47}(c) = 33 + \bigl((c - 33 + 47) \bmod 94\bigr)$$

Because the printable range has size $126 - 33 + 1 = 94$, and $47 = \frac{94}{2}$, applying ROT47 twice shifts by $47 + 47 = 94 \equiv 0 \pmod{94}$:

$$\text{ROT47}\bigl(\text{ROT47}(c)\bigr) = c$$

Thus, ROT47 is an **involution** (a symmetric, reciprocal cipher where encryption and decryption are identical).

### Step-by-Step Worked Example
**Input:** `"Rust 2026!"`
- `'R'` (ASCII 82): $33 + ((82 - 33 + 47) \bmod 94) = 33 + (96 \bmod 94) = 35$ (`'#'`)
- `'u'` (ASCII 117): $33 + ((117 - 33 + 47) \bmod 94) = 33 + (131 \bmod 94) = 70$ (`'F'`)
- `' '` (ASCII 32, space): Outside $33..=126$, so it remains `' '` (preserving word boundaries and newlines).
- `'!'` (ASCII 33): $33 + ((33 - 33 + 47) \bmod 94) = 80$ (`'P'`)

### Implementation Details in `ccipher`
Implemented in `rot47` (`src/ciphers.rs:164-177`):
- Checks `(33..=126).contains(&code)` on each `char as u32`.
- Whitespace (`' '`, `'\t'`, `'\n'`, `'\r'`) and non-ASCII Unicode characters are left untouched.

### CLI Usage
```bash
# Encrypt or Decrypt (symmetric)
ccipher --rot47 "Rust Cipher 2026!"
```

---

## 3. Atbash Cipher

### Historical & Conceptual Overview
Originally used for the Hebrew alphabet (mapping *Aleph* to *Tav*, *Beth* to *Shin*, etc.), the **Atbash cipher** mirrors the alphabet so the first letter becomes the last, the second becomes the second-to-last, and so on:

```text
Plain : A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Cipher: Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
```

### Mathematical Formulation
For a 0-indexed alphabetic letter $x \in \{0, \dots, 25\}$:

$$E(x) = D(x) = (25 - x) \bmod 26$$

Note that Atbash is mathematically equivalent to an [Affine cipher](#4-affine-cipher) with multiplier $a = 25 \equiv -1 \pmod{26}$ and intercept $b = 25$. Like ROT47, Atbash is **self-inverse (symmetric)**:

$$25 - (25 - x) = x$$

### Implementation Details in `ccipher`
Implemented in `atbash` (`src/ciphers.rs:180-192`):
- Computes `let offset = c as u8 - base;` and maps directly to `(base + (25 - offset)) as char`.
- Preserves uppercase/lowercase distinction and leaves non-alphabetic characters unchanged.

### CLI Usage
```bash
# Encrypt or Decrypt (symmetric)
ccipher --atbash "ABC xyz"
# Output: ZYX cba
```

---

## 4. Affine Cipher

### Conceptual Overview
The **Affine cipher** generalizes both the Caesar cipher and the Atbash cipher by combining a multiplicative key $a$ with an additive shift key $b$ over the ring $\mathbb{Z}_{26}$.

### Mathematical Formulation
- **Encryption:**
  $$E_{a,b}(x) = (a \cdot x + b) \bmod 26$$

- **Decryption:**
  $$D_{a,b}(y) = a^{-1} \cdot (y - b) \bmod 26$$

#### The Coprimality Requirement ($\gcd(a, 26) = 1$)
For decryption to be uniquely reversible (a bijection on $\mathbb{Z}_{26}$), $a$ must have a **modular multiplicative inverse** $a^{-1} \pmod{26}$ satisfying:

$$(a \cdot a^{-1}) \equiv 1 \pmod{26}$$

By number theory, $a^{-1} \pmod{26}$ exists if and only if $\gcd(a, 26) = 1$ (i.e., $a$ is neither even nor divisible by 13). There are $\varphi(26) = 12$ valid multipliers in $\mathbb{Z}_{26}$ (`VALID_AFFINE_A` in `src/ciphers.rs:8`):

| Multiplier $a$ | $1$ | $3$ | $5$ | $7$ | $9$ | $11$ | $15$ | $17$ | $19$ | $21$ | $23$ | $25$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Inverse $a^{-1} \pmod{26}$** | $1$ | $9$ | $21$ | $15$ | $3$ | $19$ | $7$ | $23$ | $11$ | $5$ | $17$ | $25$ |

Since there are $12$ valid choices for $a$ and $26$ choices for $b \in \{0, \dots, 25\}$, the total key space is $12 \times 26 = 312$ keys (or **311 non-trivial keys**, excluding the identity key $a=1, b=0$).

### Step-by-Step Worked Example
**Input:** `"Affine"`, **Key:** $a = 5, b = 8$ (so $a^{-1} = 21$, since $5 \times 21 = 105 = 4 \times 26 + 1 \equiv 1 \pmod{26}$)

**Encryption ($y = (5x + 8) \bmod 26$):**
- `'A'` ($x = 0$): $(5 \cdot 0 + 8) \bmod 26 = 8 \rightarrow$ `'I'`
- `'f'` ($x = 5$): $(5 \cdot 5 + 8) \bmod 26 = 33 \bmod 26 = 7 \rightarrow$ `'h'`
- `'f'` ($x = 5$): $7 \rightarrow$ `'h'`
- `'i'` ($x = 8$): $(5 \cdot 8 + 8) \bmod 26 = 48 \bmod 26 = 22 \rightarrow$ `'w'`
- `'n'` ($x = 13$): $(5 \cdot 13 + 8) \bmod 26 = 73 \bmod 26 = 21 \rightarrow$ `'v'`
- `'e'` ($x = 4$): $(5 \cdot 4 + 8) \bmod 26 = 28 \bmod 26 = 2 \rightarrow$ `'c'`

**Ciphertext:** `"Ihhwvc"`

**Decryption of `'w'` ($y = 22$) with $a^{-1} = 21, b = 8$:**
$$D(22) = 21 \cdot (22 - 8) \bmod 26 = (21 \cdot 14) \bmod 26 = 294 \bmod 26 = 8 \rightarrow \text{'i'}$$

### Implementation Details in `ccipher`
Implemented in `mod26_inverse` and `affine` (`src/ciphers.rs:462-496`):
- `mod26_inverse(a)` normalizes `a` with `a.rem_euclid(26)` and searches `1..26` for `x` where `(a_mod * x).rem_euclid(26) == 1`.
- If `a` is not coprime with 26 (e.g., `a = 2` or `a = 13`), `affine()` returns a descriptive error listing all 12 valid multipliers.

### CLI Usage
```bash
# Encrypt with a=5, b=8
ccipher --affine 5,8 "Affine Cipher"
# Output: Ihhwvc Swfrcp

# Decrypt with a=5, b=8
ccipher -d --affine 5,8 "Ihhwvc Swfrcp"

# Auto-crack across all 311 valid (a, b) key pairs
ccipher -c affine -b "Ihhwvc Swfrcp"
```
