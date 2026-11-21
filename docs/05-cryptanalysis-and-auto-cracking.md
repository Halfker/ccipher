# 🔎 Automated Cryptanalysis & Statistical Auto-Cracking

One of **ccipher**'s core capabilities is automated cryptanalysis (`--brute-force` / `-b`) and visual frequency analysis (`--freq` / `-f`). Rather than relying on a human to inspect dozens or hundreds of decrypted candidates manually, **ccipher** evaluates candidates mathematically and ranks them by their statistical closeness to natural English.

Because substitution ciphers and transposition ciphers affect text statistics differently, **ccipher** implements two distinct statistical scoring engines in [`src/ciphers.rs`](../src/ciphers.rs):
1. **[Pearson's Chi-Squared ($\chi^2$) Monogram Fit](#1-letter-frequency-analysis--pearsons-chi2-test)** — used to crack **Caesar** and **Affine** substitution ciphers.
2. **[Normalized English Bigram Scoring](#2-english-bigram-scoring-for-transposition-ciphers)** — used to crack the **Rail Fence** transposition cipher.

---

## 1. Letter Frequency Analysis & Pearson's $\chi^2$ Test

### Expected English Letter Distribution (`ENGLISH_FREQ`)
In natural English prose, letters appear with characteristic relative frequencies (`src/ciphers.rs:2-5`):

| Letter | Freq (%) | Letter | Freq (%) | Letter | Freq (%) | Letter | Freq (%) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **E** | `12.702%` | **S** | `6.327%` | **U** | `2.758%` | **B** | `1.492%` |
| **T** | `9.056%` | **H** | `6.094%` | **M** | `2.406%` | **V** | `0.978%` |
| **A** | `8.167%` | **R** | `5.987%` | **W** | `2.360%` | **K** | `0.772%` |
| **O** | `7.507%` | **D** | `4.253%` | **F** | `2.228%` | **J** | `0.153%` |
| **I** | `6.966%` | **L** | `4.025%` | **G** | `2.015%` | **X** | `0.150%` |
| **N** | `6.749%` | **C** | `2.782%` | **Y** | `1.974%` | **Q** | `0.095%` |
| | | | | **P** | `1.929%` | **Z** | `0.074%` |

### Observed Frequencies (`letter_frequencies`)
Given a candidate text, `letter_frequencies` (`src/ciphers.rs:19-38`) counts all ASCII alphabetic letters (case-insensitively), yielding observed counts $O_0, O_1, \dots, O_{25}$ and total alphabetic count $N = \sum_{i=0}^{25} O_i$. The observed percentage for letter $i$ is:

$$f_i = \frac{O_i}{N} \times 100\%$$

### Pearson's Chi-Squared ($\chi^2$) Goodness-of-Fit (`english_chi_squared`)
To measure how closely a candidate decryption matches English, `english_chi_squared` (`src/ciphers.rs:42-66`) computes the expected count $E_i$ for each letter $i \in \{0, \dots, 25\}$ in a text of $N$ alphabetic characters:

$$E_i = N \times \frac{\text{ENGLISH\_FREQ}[i]}{100}$$

It then sums the squared difference between observed and expected counts, normalized by $E_i$:

$$\chi^2 = \sum_{i=0}^{25} \frac{(O_i - E_i)^2}{E_i}$$

#### Properties of the $\chi^2$ Score
- **Lower is better:** $\chi^2 \ge 0$, where $\chi^2 = 0$ represents an exact match with standard English proportions.
- **Penalty on rare letters:** Because each term is divided by $E_i$, an incorrect decryption that produces many rare letters like `'Z'`, `'Q'`, `'X'`, or `'J'` (where $E_i$ is tiny, e.g., $0.00074 N$) causes $(O_i - E_i)^2 / E_i$ to explode, sharply penalizing wrong keys.
- If the input contains no alphabetic letters ($N = 0$), `f64::INFINITY` is returned.

---

## 2. English Bigram Scoring for Transposition Ciphers

### Why $\chi^2$ Single-Letter Frequency Cannot Crack Transposition Ciphers
A transposition cipher like **Rail Fence** only rearranges the positions of the letters without changing any letter into another. Consequently, the single-letter counts $O_0, \dots, O_{25}$ — and therefore the $\chi^2$ monogram score — are **100% identical** for every possible rail key!

### The Bigram Plausibility Model (`english_bigram_score`)
To evaluate whether a Rail Fence candidate has restored the right letter order, `english_bigram_score` (`src/ciphers.rs:70-123`) measures the density of the **30 most frequent English bigrams (2-letter pairs)** weighted by their natural English percentage frequencies:

| Bigram | Weight | Bigram | Weight | Bigram | Weight | Bigram | Weight | Bigram | Weight |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `"th"` | `3.56` | `"on"` | `1.76` | `"or"` | `1.28` | `"al"` | `1.09` | `"se"` | `0.93` |
| `"he"` | `3.07` | `"at"` | `1.49` | `"te"` | `1.20` | `"ar"` | `1.07` | `"ha"` | `0.93` |
| `"in"` | `2.43` | `"en"` | `1.45` | `"of"` | `1.17` | `"st"` | `1.05` | `"as"` | `0.87` |
| `"er"` | `2.05` | `"nd"` | `1.35` | `"ed"` | `1.17` | `"to"` | `1.04` | `"ou"` | `0.87` |
| `"an"` | `1.99` | `"ti"` | `1.34` | `"is"` | `1.13` | `"nt"` | `1.04` | `"io"` | `0.83` |
| `"re"` | `1.85` | `"es"` | `1.34` | `"it"` | `1.12` | `"ng"` | `0.95` | `"le"` | `0.83` |

For a lowercased candidate text of byte length $L \ge 2$:
1. Slide a 2-byte window (`bytes.windows(2)`) across the string and sum the weights of all matching bigrams (`hit_weight`).
2. Normalize by text length:
   $$\text{normalized} = \frac{\text{hit\_weight}}{L} \times 100$$
3. Convert into a minimization score (so lower = better match, matching the convention of $\chi^2$):
   $$\text{score} = \max(100.0 - \text{normalized},\; 0.01)$$

---

## 3. Brute-Force Auto-Cracker Implementations

All three auto-crackers return a sorted `Vec<CrackCandidate>`, where each candidate holds:
```rust
pub struct CrackCandidate {
    pub key_label: String, // Human-readable key description
    pub plaintext: String, // Decrypted candidate text
    pub score: f64,        // Statistical score (lower = better match)
}
```

### A. Caesar Auto-Cracker (`caesar_brute_force`)
- **Search Space:** All $25$ non-trivial shifts $s \in \{1, 2, \dots, 25\}$ (`src/ciphers.rs:142-161`).
- **Process:** Decrypts with `caesar_cipher(input, -s)`, scores each candidate using `english_chi_squared(&plaintext)`, labels it as `"Shift  s (- s / +26-s)"`, and sorts ascending by score.

### B. Affine Auto-Cracker (`affine_brute_force`)
- **Search Space:** All **311 non-trivial $(a, b)$ key pairs** (`src/ciphers.rs:499-523`), iterating over all 12 valid coprime multipliers $a \in \text{VALID\_AFFINE\_A}$ and all 26 shifts $b \in 0..26$ (skipping the identity key $a=1, b=0$).
- **Process:** Decrypts with `affine(input, a, b, true)`, scores with `english_chi_squared`, sorts ascending by score, and truncates to the top `top_n` (15) candidates.

### C. Rail Fence Auto-Cracker (`rail_fence_brute_force`)
- **Search Space:** Rail counts $r \in 2..=\min(\text{max\_rails}, N - 1)$ (`src/ciphers.rs:438-459`), default `max_rails = 15`.
- **Process:** Decrypts with `rail_fence(input, r, true)`, scores with `english_bigram_score(&plaintext)`, and sorts ascending by score.

---

## 4. Visual Frequency Histogram (`--freq` / `-f`)

Implemented in `format_frequency_chart` (`src/tui.rs:230-273`), the frequency analyzer renders a two-column (A–M and N–Z) terminal bar chart comparing the observed letter distribution against expected English frequencies:
- Computes a 12-cell bar where $15\%$ corresponds to 12 full blocks (`((pct / 15.0) * 12.0).round()`).
- Color-codes each bar cell:
  - **Green `█`**: Both observed and expected frequencies reach this level (overlap).
  - **Yellow `█`**: Observed frequency exceeds expected English frequency (surplus).
  - **Cyan `▒`**: Expected English frequency exceeds observed frequency (deficit).
  - **Dim `·`**: Unused scale capacity.
