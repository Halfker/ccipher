# 🔀 Transposition & Bitwise Ciphers

Unlike substitution ciphers (which replace characters while keeping their positions fixed), **transposition ciphers** permute the positions of the original characters without changing their identities, while **bitwise ciphers** operate directly on the underlying binary representation of the data.

In **ccipher**, two algorithms in this category are implemented in [`src/ciphers.rs`](../src/ciphers.rs):
1. [Rail Fence Cipher (Zig-Zag Transposition)](#1-rail-fence-cipher-zig-zag-transposition)
2. [Repeating-Key XOR Cipher (with Hex I/O)](#2-repeating-key-xor-cipher-with-hex-io)

---

## 1. Rail Fence Cipher (Zig-Zag Transposition)

### Conceptual Overview
The **Rail Fence cipher** is a classical transposition cipher that writes the plaintext characters diagonally downward and upward across $R$ imaginary horizontal "rails" of a fence, then reads off the characters row by row from top rail ($0$) to bottom rail ($R - 1$).

### Mathematical Formulation: Zig-Zag Periodicity
Given $R \ge 2$ rails, the vertical movement completes one full down-and-up cycle every:

$$T = 2(R - 1) \text{ characters}$$

For any 0-indexed character position $i \in \{0, 1, \dots, N-1\}$, its position within the current cycle is:

$$p = i \bmod T$$

The rail (row) index $r(i) \in \{0, 1, \dots, R-1\}$ is determined by:

$$r(i) = \begin{cases} p & \text{if } p < R \quad (\text{moving downward}) \\ T - p & \text{if } p \ge R \quad (\text{moving upward}) \end{cases}$$

### Step-by-Step Worked Example
**Plaintext:** `"WEAREDISCOVEREDFLEEATONCE"` ($N = 25$), **Rails:** $R = 3$

Here the cycle length is $T = 2(3 - 1) = 4$. The row pattern repeats $(0, 1, 2, 1, 0, 1, 2, 1, \dots)$:

```text
Rail 0: W . . . E . . . C . . . R . . . L . . . T . . . E   -->  "WECRLTE" (7 chars)
Rail 1: . E . R . D . S . O . E . E . F . E . A . O . C .   -->  "ERDSOEEFEAOC" (12 chars)
Rail 2: . . A . . . I . . . V . . . D . . . E . . . N . .   -->  "AIVDEN" (6 chars)
```

- **Encryption:** Concatenate Rail 0 + Rail 1 + Rail 2:
  $$\text{"WECRLTE"} + \text{"ERDSOEEFEAOC"} + \text{"AIVDEN"} = \text{"WECRLTEERDSOEEFEAOCAIVDEN"}$$

- **Decryption:**
  1. Compute the exact original character indices belonging to each rail by running $i \in 0..N$ through the formula $r(i)$:
     - `rail_indices[0] = [0, 4, 8, 12, 16, 20, 24]`
     - `rail_indices[1] = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23]`
     - `rail_indices[2] = [2, 6, 10, 14, 18, 22]`
  2. Walk sequentially through the ciphertext with a `cursor = 0..N` and place each ciphertext character directly into `result[orig_idx]` for each rail's position list.

### Implementation Details in `ccipher`
Implemented in `rail_fence` (`src/ciphers.rs:397-435`):
- **Unicode-Safe Indexing:** Collects `input.chars().collect()` into `Vec<char>` so multi-byte UTF-8 characters are transposed as intact scalar values rather than splitting UTF-8 byte sequences.
- **Boundary Conditions:**
  - If `rails == 0`, returns `Err("Number of rails must be at least 1.")`.
  - If `rails == 1 || rails >= n`, the zig-zag never folds back, so `input.to_string()` is returned immediately in $O(N)$ time.

### CLI Usage
```bash
# Encrypt across 3 rails
ccipher -c rail-fence -r 3 "WEAREDISCOVEREDFLEEATONCE"

# Decrypt across 3 rails
ccipher -d -c rail-fence -r 3 "WECRLTEERDSOEEFEAOCAIVDEN"

# Auto-crack unknown rail count using English bigram scoring
ccipher -c rail-fence -b "WECRLTEERDSOEEFEAOCAIVDEN"
```

---

## 2. Repeating-Key XOR Cipher (with Hex I/O)

### Conceptual Overview
The **Exclusive-OR (XOR)** cipher is the foundational building block of modern stream ciphers and the One-Time Pad (Vernam cipher). It operates at the **bit level** on raw UTF-8 bytes rather than alphabetic characters.

### Mathematical Formulation
The bitwise XOR operator ($\oplus$) follows the truth table:

| $A$ | $B$ | $A \oplus B$ |
| :-: | :-: | :-: |
| `0` | `0` | `0` |
| `0` | `1` | `1` |
| `1` | `0` | `1` |
| `1` | `1` | `0` |

Key algebraic properties of $\oplus$:
1. **Identity:** $x \oplus 0 = x$
2. **Self-Inverse:** $x \oplus x = 0$
3. **Reciprocal Involution:** $(P \oplus K) \oplus K = P \oplus (K \oplus K) = P \oplus 0 = P$

Given a plaintext byte array $P = (p_0, p_1, \dots, p_{N-1})$ and a key byte array $K = (k_0, k_1, \dots, k_{L-1})$:

$$c_i = p_i \oplus k_{i \bmod L} \quad \text{and} \quad p_i = c_i \oplus k_{i \bmod L}$$

### Why Hex Wrapping is Built In
XORing two printable ASCII bytes frequently produces **non-printable control characters** (e.g., `'A' ^ 'B' = 0x41 ^ 0x42 = 0x03`, which is ASCII `ETX` / End-of-Text, or `'A' ^ 'A' = 0x00` NULL byte) or invalid UTF-8 byte sequences.
To ensure the ciphertext is always terminal-safe, copy-pasteable, and pipe-friendly:
- **Encryption (`decrypt == false`):**
  $$\text{UTF-8 Plaintext} \xrightarrow{\oplus K} \text{Raw Cipher Bytes} \xrightarrow{\text{hex\_encode\_bytes}} \text{Lowercase Hex String}$$
- **Decryption (`decrypt == true`):**
  $$\text{Hex String} \xrightarrow{\text{hex\_decode\_bytes}} \text{Raw Cipher Bytes} \xrightarrow{\oplus K} \text{UTF-8 Plaintext}$$

### Step-by-Step Worked Example
**Input:** `"Hi"`, **Key:** `"K"` (`0x4B` = `01001011₂`)
1. `'H'` = `0x48` (`01001000₂`):
   $$\mathtt{0x48} \oplus \mathtt{0x4B} = \mathtt{01001000_2} \oplus \mathtt{01001011_2} = \mathtt{00000011_2} = \mathtt{0x03} \rightarrow \text{"03"}$$
2. `'i'` = `0x69` (`01101001₂`):
   $$\mathtt{0x69} \oplus \mathtt{0x4B} = \mathtt{01101001_2} \oplus \mathtt{01001011_2} = \mathtt{00100010_2} = \mathtt{0x22} \rightarrow \text{"22"}$$
3. **Encrypted Output:** `"0322"`

### Implementation Details in `ccipher`
Implemented in `xor_hex_cipher` (`src/ciphers.rs:528-551`):
- Rejects empty keys with `Err("XOR key cannot be empty.")`.
- During decryption, strips whitespace from the hex input via `hex_decode_bytes`, XORs each byte with `key_bytes[i % key_bytes.len()]`, and reconstructs the string using `String::from_utf8_lossy`.

### CLI Usage
```bash
# Encrypt text with XOR key "KEY42" (outputs lowercase hex)
ccipher -c xor -k KEY42 "Top Secret Payload 123!"

# Decrypt hex string back to plaintext with the same key
ccipher -d -c xor -k KEY42 "1f2a296b63..."
```
