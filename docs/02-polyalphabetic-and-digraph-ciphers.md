# 🔑 Polyalphabetic & Digraph Substitution Ciphers

To defeat simple single-letter frequency analysis, **polyalphabetic ciphers** cycle through multiple substitution alphabets using a keyword or key stream, while **digraph ciphers** encrypt pairs of letters simultaneously to flatten single-letter frequency peaks.

In **ccipher**, four algorithms in this category are implemented in [`src/ciphers.rs`](../src/ciphers.rs):
1. [Vigenère Cipher](#1-vigenère-cipher)
2. [Beaufort Cipher](#2-beaufort-cipher)
3. [Autokey Cipher](#3-autokey-cipher)
4. [Playfair Cipher (5×5 Digraph Matrix)](#4-playfair-cipher-55-digraph-matrix)

---

## 1. Vigenère Cipher

### Historical & Conceptual Overview
Described by Giovan Battista Bellaso in 1553 and later misattributed to Blaise de Vigenère, the **Vigenère cipher** uses an alphabetic keyword to define a repeating sequence of Caesar shifts. If the keyword has length $L$, every $i$-th alphabetic character in the message is shifted by the $(i \bmod L)$-th letter of the keyword.

### Mathematical Formulation
Let the cleaned alphabetic keyword be $K = (k_0, k_1, \dots, k_{L-1})$ where each $k_j \in \{0, \dots, 25\}$. For the $i$-th alphabetic letter of the message ($i = 0, 1, 2, \dots$):

- **Encryption:**
  $$C_i = \bigl(P_i + k_{i \bmod L}\bigr) \bmod 26$$

- **Decryption:**
  $$P_i = \bigl(C_i - k_{i \bmod L}\bigr) \bmod 26$$

### Step-by-Step Worked Example
**Plaintext:** `"Attack at dawn!"`, **Keyword:** `"LEMON"` ($L=11, E=4, M=12, O=14, N=13$)

| Alphabetic Index $i$ | Plaintext Char ($P_i$) | Key Char ($k_{i \bmod 5}$) | Calculation $(P_i + k) \bmod 26$ | Ciphertext Char ($C_i$) |
| :---: | :---: | :---: | :---: | :---: |
| 0 | `'A'` ($0$) | `'L'` ($11$) | $(0 + 11) \bmod 26 = 11$ | `'L'` |
| 1 | `'t'` ($19$) | `'E'` ($4$) | $(19 + 4) \bmod 26 = 23$ | `'x'` |
| 2 | `'t'` ($19$) | `'M'` ($12$) | $(19 + 12) \bmod 26 = 5$ | `'f'` |
| 3 | `'a'` ($0$) | `'O'` ($14$) | $(0 + 14) \bmod 26 = 14$ | `'o'` |
| 4 | `'c'` ($2$) | `'N'` ($13$) | $(2 + 13) \bmod 26 = 15$ | `'p'` |
| 5 | `'k'` ($10$) | `'L'` ($11$) | $(10 + 11) \bmod 26 = 21$ | `'v'` |
| — | `' '` (space) | *(not advanced)* | Non-alphabetic preserved | `' '` |
| 6 | `'a'` ($0$) | `'E'` ($4$) | $(0 + 4) \bmod 26 = 4$ | `'e'` |
| 7 | `'t'` ($19$) | `'M'` ($12$) | $(19 + 12) \bmod 26 = 5$ | `'f'` |

**Output:** `"Lxfopv ef rnhr!"`

### Implementation Details in `ccipher`
Implemented in `vigenere` (`src/ciphers.rs:195-222`):
- **Key Sanitization:** Non-alphabetic characters in the keyword are ignored (`filter(|c| c.is_ascii_alphabetic())`), and letters are converted to lowercase offsets `0..=25`. If the key contains no ASCII letters, an `Err` is returned.
- **Key Index Advancement:** `key_idx` increments **only** when an ASCII alphabetic character is encountered in the input text. Spaces and punctuation do not consume key positions.

### CLI Usage
```bash
# Encrypt
ccipher -c vigenere -k LEMON "Attack at dawn!"

# Decrypt
ccipher -d -c vigenere -k LEMON "Lxfopv ef rnhr!"
```

---

## 2. Beaufort Cipher

### Historical & Conceptual Overview
Created by Sir Francis Beaufort (inventor of the Beaufort wind force scale), the **Beaufort cipher** is a reciprocal polyalphabetic variant of the Vigenère cipher used notably in the M-209 rotor machine. Instead of adding the key to the plaintext ($P + K$), Beaufort subtracts the plaintext from the key ($K - P$).

### Mathematical Formulation
For the $i$-th alphabetic letter $P_i \in \{0, \dots, 25\}$ and key shift $k_{i \bmod L} \in \{0, \dots, 25\}$:

$$C_i = \bigl(k_{i \bmod L} - P_i\bigr) \bmod 26$$

#### Why Beaufort is Symmetric (Self-Inverse)
Substituting $C_i$ back into the same formula yields:

$$\bigl(k_{i \bmod L} - C_i\bigr) \bmod 26 = \bigl(k_{i \bmod L} - (k_{i \bmod L} - P_i)\bigr) \bmod 26 = P_i$$

Therefore, **encryption and decryption use the exact same operation**. Note also that a Beaufort cipher with a single-letter key `'Z'` ($k = 25$) reduces to $(25 - P_i) \bmod 26$, which is the **Atbash cipher**.

### Implementation Details in `ccipher`
Implemented in `beaufort` (`src/ciphers.rs:225-254`):
- Uses `(k - p).rem_euclid(26)` for every alphabetic character.
- Preserves original character case (`base = b'a'` or `b'A'`) and only advances `key_idx` on alphabetic characters.

### CLI Usage
```bash
# Encrypt or Decrypt (identical operation)
ccipher -c beaufort -k FORTIFICATION "Defend the east wall"
```

---

## 3. Autokey Cipher

### Historical & Conceptual Overview
Invented by Blaise de Vigenère in 1586, the **Autokey cipher** eliminates the periodic repetition of the Vigenère keyword (which makes standard Vigenère vulnerable to Kasiski examination and Index of Coincidence attacks). It uses a short keyword as an initial *primer*, and then appends the **plaintext itself** to form an non-repeating, running key stream.

### Mathematical Formulation
Let the primer keyword have length $L$: $(k_0, k_1, \dots, k_{L-1})$. The full key stream $S_i$ for the $i$-th alphabetic character is defined as:

$$S_i = \begin{cases} k_i & \text{if } 0 \le i < L \\ P_{i - L} & \text{if } i \ge L \end{cases}$$

- **Encryption:**
  $$C_i = (P_i + S_i) \bmod 26$$
  As each plaintext letter $P_i$ is processed, $P_i$ is pushed onto the end of the key stream.

- **Decryption:**
  $$P_i = (C_i - S_i) \bmod 26$$
  During decryption, only the primer $(k_0, \dots, k_{L-1})$ is initially known. However, decrypting the first $L$ characters recovers $P_0, \dots, P_{L-1}$, which are immediately appended to the key stream to decrypt $C_L, C_{L+1}, \dots$ dynamically!

### Step-by-Step Worked Example
**Plaintext:** `"DEFEND THE EAST"`, **Primer Keyword:** `"QUEENLY"`

```text
Plaintext Letters : D  E  F  E  N  D  T  H  E  E  A  S  T
Key Stream (Si)   : Q  U  E  E  N  L  Y  D  E  F  E  N  D   <-- "QUEENLY" followed by "DEFEND..."
Ciphertext Letters: T  Y  J  I  A  O  R  K  I  J  E  F  W
```

### Implementation Details in `ccipher`
Implemented in `autokey` (`src/ciphers.rs:258-294`):
- Initializes `key_stream: Vec<i32>` with the alphabetic values of `key`.
- As each alphabetic letter is processed at `idx`, it reads `k = key_stream[idx]` and pushes the **plaintext letter value** (`plain_val` when decrypting, or `x` when encrypting) onto `key_stream`.

### CLI Usage
```bash
# Encrypt
ccipher -c autokey -k QUEENLY "Defend the east wall"

# Decrypt
ccipher -d -c autokey -k QUEENLY "Tyjiao rki jefw..."
```

---

## 4. Playfair Cipher (5×5 Digraph Matrix)

### Historical & Conceptual Overview
Invented by Charles Wheatstone in 1854 and promoted by Lord Playfair, the **Playfair cipher** was the first practical **digraph substitution cipher**. Instead of encrypting single letters, it encrypts pairs of letters (digraphs) using a $5 \times 5$ key square, destroying single-letter frequency characteristics and making frequency analysis require $25 \times 25 = 625$ digraph frequencies.

### Algorithm Mechanics

#### Step 1: Constructing the $5 \times 5$ Polybius Key Square
Since a $5 \times 5$ grid holds 25 letters and the English alphabet has 26, **`'J'` is merged into `'I'`**.
1. Concatenate the uppercase keyword with the remaining alphabet `'A'..='Z'`.
2. Replace every `'J'` with `'I'`.
3. Insert each letter into the 25-cell grid upon its first appearance, skipping duplicates.

For example, with keyword `"PLAYFAIR EXAMPLE"`:
```text
      Col 0  Col 1  Col 2  Col 3  Col 4
Row 0:  P      L      A      Y      F
Row 1:  I      R      E      X      M
Row 2:  B      C      D      G      H
Row 3:  K      N      O      Q      S
Row 4:  T      U      V      W      Z
```

#### Step 2: Preparing Plaintext Digraphs
1. Strip all non-alphabetic characters, convert to uppercase, and map `'J' -> 'I'`.
2. Walk through the letters to form pairs $(a, b)$:
   - **Duplicate rule (Encryption):** If the two letters in a pair are identical ($a == b$), insert `'X'` as the second letter of the pair `(a, 'X')` and advance by only 1 letter.
   - **Odd-length padding:** If one letter remains at the end, pad it with `'X'` to form `(a, 'X')`.

For `"HIDE THE GOLD"` $\rightarrow$ `"HIDETHEGOLD"` (11 letters):
- Pairs: `HI`, `DE`, `TH`, `EG`, `OL`, `DX` (padded with `'X'`).

#### Step 3: The Three Grid Transformation Rules
For each pair $(a, b)$ at grid coordinates $(r_1, c_1)$ and $(r_2, c_2)$:

1. **Same Row ($r_1 == r_2$):**
   - **Encrypt:** Shift both columns **right** by 1 ($\bmod 5$): $(r_1, (c_1 + 1) \bmod 5)$ and $(r_2, (c_2 + 1) \bmod 5)$.
   - **Decrypt:** Shift both columns **left** by 1 ($\equiv +4 \pmod 5$).
2. **Same Column ($c_1 == c_2$):**
   - **Encrypt:** Shift both rows **down** by 1 ($\bmod 5$): $((r_1 + 1) \bmod 5, c_1)$ and $((r_2 + 1) \bmod 5, c_2)$.
   - **Decrypt:** Shift both rows **up** by 1 ($\equiv +4 \pmod 5$).
3. **Rectangle ($r_1 \ne r_2$ and $c_1 \ne c_2$):**
   - **Encrypt & Decrypt:** Swap column coordinates (take the opposite corners on the same row):
     $$(r_1, c_1) \mapsto (r_1, c_2) \quad \text{and} \quad (r_2, c_2) \mapsto (r_2, c_1)$$

### Step-by-Step Worked Example
Using the `"PLAYFAIR EXAMPLE"` grid above on `"HIDE THE GOLD"`:
- `HI`: `'H'` is at $(2, 4)$, `'I'` is at $(1, 0)$ $\rightarrow$ Rectangle $\rightarrow$ $(2, 0)=\text{'B'}$, $(1, 4)=\text{'M'}$ $\rightarrow$ `BM`
- `DE`: `'D'` is at $(2, 2)$, `'E'` is at $(1, 2)$ $\rightarrow$ Same Column (Col 2) $\rightarrow$ shift rows down $\rightarrow$ $(3, 2)=\text{'O'}$, $(2, 2)=\text{'D'}$ $\rightarrow$ `OD`
- `TH`: `'T'` is at $(4, 0)$, `'H'` is at $(2, 4)$ $\rightarrow$ Rectangle $\rightarrow$ $(4, 4)=\text{'Z'}$, $(2, 0)=\text{'B'}$ $\rightarrow$ `ZB`
- `EG`: `'E'` is at $(1, 2)$, `'G'` is at $(2, 3)$ $\rightarrow$ Rectangle $\rightarrow$ $(1, 3)=\text{'X'}$, $(2, 2)=\text{'D'}$ $\rightarrow$ `XD`
- `OL`: `'O'` is at $(3, 2)$, `'L'` is at $(0, 1)$ $\rightarrow$ Rectangle $\rightarrow$ $(3, 1)=\text{'N'}$, $(0, 2)=\text{'A'}$ $\rightarrow$ `NA`
- `DX`: `'D'` is at $(2, 2)$, `'X'` is at $(1, 3)$ $\rightarrow$ Rectangle $\rightarrow$ $(2, 3)=\text{'G'}$, $(1, 2)=\text{'E'}$ $\rightarrow$ `GE`

**Encrypted Output:** `"BM OD ZB XD NA GE"`  
**Decrypted Output:** `"HI DE TH EG OL DX"`

### Implementation Details in `ccipher`
Implemented in `playfair` (`src/ciphers.rs:297-394`):
- Outputs space-separated uppercase digraph pairs (`"BM OD ZB XD NA GE"`) for readability.
- When decrypting, non-alphabetic characters (including the spaces between digraphs) are stripped automatically before pairing.

### CLI Usage
```bash
# Encrypt
ccipher -c playfair -k "PLAYFAIR EXAMPLE" "HIDE THE GOLD"
# Output: BM OD ZB XD NA GE

# Decrypt
ccipher -d -c playfair -k "PLAYFAIR EXAMPLE" "BM OD ZB XD NA GE"
# Output: HI DE TH EG OL DX
```
