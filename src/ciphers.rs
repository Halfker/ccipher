/// Expected English letter frequencies (A-Z) in percentages.
pub const ENGLISH_FREQ: [f64; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
];

/// Valid `a` values for Affine cipher (coprime with 26).
pub const VALID_AFFINE_A: [i32; 12] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

#[derive(Debug, Clone, PartialEq)]
pub struct CrackCandidate {
    pub key_label: String,
    pub plaintext: String,
    pub score: f64,
}

/// Computes the observed percentage frequency (0.0..=100.0) of each letter A-Z
/// and returns `(frequencies, total_alphabetic_chars)`.
pub fn letter_frequencies(text: &str) -> ([f64; 26], usize) {
    let mut counts = [0usize; 26];
    let mut total = 0usize;

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let idx = (c.to_ascii_lowercase() as u8 - b'a') as usize;
            counts[idx] += 1;
            total += 1;
        }
    }

    let mut freqs = [0.0f64; 26];
    if total > 0 {
        for i in 0..26 {
            freqs[i] = (counts[i] as f64 / total as f64) * 100.0;
        }
    }
    (freqs, total)
}

/// Computes the Chi-Squared statistic against English letter frequencies.
/// Lower scores indicate closer match to natural English text.
pub fn english_chi_squared(text: &str) -> f64 {
    let mut counts = [0usize; 26];
    let mut total = 0usize;

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let idx = (c.to_ascii_lowercase() as u8 - b'a') as usize;
            counts[idx] += 1;
            total += 1;
        }
    }

    if total == 0 {
        return f64::INFINITY;
    }

    let total_f = total as f64;
    let mut chi_sq = 0.0;
    for i in 0..26 {
        let expected = total_f * (ENGLISH_FREQ[i] / 100.0);
        let diff = counts[i] as f64 - expected;
        chi_sq += (diff * diff) / expected;
    }
    chi_sq
}

/// Scores English plausibility for transposition ciphers (where single-letter frequencies don't change)
/// using common English bigrams and words. Lower score = better match.
pub fn english_bigram_score(text: &str) -> f64 {
    const COMMON_BIGRAMS: &[(&str, f64)] = &[
        ("th", 3.56),
        ("he", 3.07),
        ("in", 2.43),
        ("er", 2.05),
        ("an", 1.99),
        ("re", 1.85),
        ("on", 1.76),
        ("at", 1.49),
        ("en", 1.45),
        ("nd", 1.35),
        ("ti", 1.34),
        ("es", 1.34),
        ("or", 1.28),
        ("te", 1.20),
        ("of", 1.17),
        ("ed", 1.17),
        ("is", 1.13),
        ("it", 1.12),
        ("al", 1.09),
        ("ar", 1.07),
        ("st", 1.05),
        ("to", 1.04),
        ("nt", 1.04),
        ("ng", 0.95),
        ("se", 0.93),
        ("ha", 0.93),
        ("as", 0.87),
        ("ou", 0.87),
        ("io", 0.83),
        ("le", 0.83),
    ];

    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    if bytes.len() < 2 {
        return 100.0;
    }

    let mut hit_weight = 0.0;
    for w in bytes.windows(2) {
        if let Ok(pair) = std::str::from_utf8(w) {
            for &(bg, weight) in COMMON_BIGRAMS {
                if pair == bg {
                    hit_weight += weight;
                    break;
                }
            }
        }
    }
    let normalized = (hit_weight / (bytes.len() as f64)) * 100.0;
    (100.0 - normalized).max(0.01)
}

/// Shifts a single ASCII alphabetic character by `shift` positions (wrapping mod 26).
pub fn shift_char(c: char, shift: i32) -> char {
    if !c.is_ascii_alphabetic() {
        return c;
    }
    let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
    let offset = (c as u8 - base) as i32;
    let shifted = (offset + shift).rem_euclid(26) as u8;
    (base + shifted) as char
}

/// Caesar cipher: shifts ASCII letters by `shift` (use `-shift` to decrypt).
pub fn caesar_cipher(input: &str, shift: i32) -> String {
    input.chars().map(|c| shift_char(c, shift)).collect()
}

/// Brute-forces all 25 Caesar shifts and returns candidates sorted by best English match.
pub fn caesar_brute_force(input: &str) -> Vec<CrackCandidate> {
    let mut candidates: Vec<CrackCandidate> = (1..26)
        .map(|s| {
            let plaintext = caesar_cipher(input, -s);
            let score = english_chi_squared(&plaintext);
            CrackCandidate {
                key_label: format!("Shift {:2} (-{:2} / +{:2})", s, s, 26 - s),
                plaintext,
                score,
            }
        })
        .collect();

    candidates.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates
}

/// ROT47 cipher: shifts printable ASCII characters ('!' = 33 to '~' = 126) by 47 positions.
pub fn rot47(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            let code = c as u32;
            if (33..=126).contains(&code) {
                let shifted = 33 + ((code - 33 + 47) % 94);
                char::from_u32(shifted).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Atbash cipher: mirrors the alphabet ('A' <-> 'Z', 'a' <-> 'z'). Symmetric.
pub fn atbash(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            let offset = c as u8 - base;
            (base + (25 - offset)) as char
        })
        .collect()
}

/// Vigenère cipher: polyalphabetic shift using an alphabetic keyword.
pub fn vigenere(input: &str, key: &str, decrypt: bool) -> Result<String, String> {
    let shifts: Vec<i32> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| (c.to_ascii_lowercase() as u8 - b'a') as i32)
        .collect();

    if shifts.is_empty() {
        return Err("Vigenère key must contain at least one ASCII letter (A-Z).".to_string());
    }

    let mut key_idx = 0usize;
    let out = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let s = shifts[key_idx % shifts.len()];
                key_idx += 1;
                let effective_shift = if decrypt { -s } else { s };
                shift_char(c, effective_shift)
            } else {
                c
            }
        })
        .collect();

    Ok(out)
}

/// Beaufort cipher: symmetric reciprocal polyalphabetic cipher where C = (K - P) mod 26.
pub fn beaufort(input: &str, key: &str) -> Result<String, String> {
    let shifts: Vec<i32> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| (c.to_ascii_lowercase() as u8 - b'a') as i32)
        .collect();

    if shifts.is_empty() {
        return Err("Beaufort key must contain at least one ASCII letter (A-Z).".to_string());
    }

    let mut key_idx = 0usize;
    let out = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let k = shifts[key_idx % shifts.len()];
                key_idx += 1;
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let p = (c as u8 - base) as i32;
                let mapped = (k - p).rem_euclid(26) as u8;
                (base + mapped) as char
            } else {
                c
            }
        })
        .collect();

    Ok(out)
}

/// Autokey cipher: polyalphabetic substitution where the key stream is the keyword
/// followed by the plaintext letters themselves.
pub fn autokey(input: &str, key: &str, decrypt: bool) -> Result<String, String> {
    let mut key_stream: Vec<i32> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| (c.to_ascii_lowercase() as u8 - b'a') as i32)
        .collect();

    if key_stream.is_empty() {
        return Err("Autokey keyword must contain at least one ASCII letter (A-Z).".to_string());
    }

    let mut idx = 0usize;
    let mut out = String::with_capacity(input.len());

    for c in input.chars() {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            let x = (c as u8 - base) as i32;
            let k = key_stream[idx];
            idx += 1;

            if decrypt {
                let plain_val = (x - k).rem_euclid(26);
                key_stream.push(plain_val);
                out.push((base + plain_val as u8) as char);
            } else {
                let cipher_val = (x + k).rem_euclid(26);
                key_stream.push(x);
                out.push((base + cipher_val as u8) as char);
            }
        } else {
            out.push(c);
        }
    }

    Ok(out)
}

/// Playfair 5x5 digraph cipher (combines J into I).
pub fn playfair(input: &str, key: &str, decrypt: bool) -> Result<String, String> {
    let mut grid = Vec::with_capacity(25);
    let mut seen = [false; 26];
    seen[(b'J' - b'A') as usize] = true; // Merge J into I

    for c in key.chars().chain('A'..='Z') {
        if c.is_ascii_alphabetic() {
            let mut up = c.to_ascii_uppercase();
            if up == 'J' {
                up = 'I';
            }
            let idx = (up as u8 - b'A') as usize;
            if !seen[idx] {
                seen[idx] = true;
                grid.push(up);
            }
        }
    }

    let find_pos = |ch: char| -> (usize, usize) {
        let pos = grid.iter().position(|&x| x == ch).unwrap_or(0);
        (pos / 5, pos % 5)
    };

    let letters: Vec<char> = input
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| {
            let up = c.to_ascii_uppercase();
            if up == 'J' {
                'I'
            } else {
                up
            }
        })
        .collect();

    if letters.is_empty() {
        return Ok(String::new());
    }

    // Build digraph pairs (inserting 'X' between identical letters when encrypting)
    let mut pairs = Vec::new();
    if decrypt {
        let mut i = 0;
        while i < letters.len() {
            let a = letters[i];
            let b = if i + 1 < letters.len() {
                letters[i + 1]
            } else {
                'X'
            };
            pairs.push((a, b));
            i += 2;
        }
    } else {
        let mut i = 0;
        while i < letters.len() {
            let a = letters[i];
            if i + 1 < letters.len() {
                let b = letters[i + 1];
                if a == b {
                    pairs.push((a, 'X'));
                    i += 1;
                } else {
                    pairs.push((a, b));
                    i += 2;
                }
            } else {
                pairs.push((a, 'X'));
                i += 1;
            }
        }
    }

    let shift = if decrypt { 4 } else { 1 }; // -1 mod 5 == 4
    let mut out = String::with_capacity(pairs.len() * 3);
    for (idx, (a, b)) in pairs.into_iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let (r1, c1) = find_pos(a);
        let (r2, c2) = find_pos(b);

        let (nr1, nc1, nr2, nc2) = if r1 == r2 {
            (r1, (c1 + shift) % 5, r2, (c2 + shift) % 5)
        } else if c1 == c2 {
            ((r1 + shift) % 5, c1, (r2 + shift) % 5, c2)
        } else {
            (r1, c2, r2, c1)
        };

        out.push(grid[nr1 * 5 + nc1]);
        out.push(grid[nr2 * 5 + nc2]);
    }

    Ok(out)
}

/// Rail Fence (zig-zag) transposition cipher.
pub fn rail_fence(input: &str, rails: usize, decrypt: bool) -> Result<String, String> {
    if rails == 0 {
        return Err("Number of rails must be at least 1.".to_string());
    }
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    if rails == 1 || rails >= n {
        return Ok(input.to_string());
    }

    let cycle = 2 * (rails - 1);

    if !decrypt {
        let mut rows = vec![String::new(); rails];
        for (i, &ch) in chars.iter().enumerate() {
            let pos = i % cycle;
            let row = if pos < rails { pos } else { cycle - pos };
            rows[row].push(ch);
        }
        Ok(rows.concat())
    } else {
        let mut rail_indices = vec![Vec::new(); rails];
        for i in 0..n {
            let pos = i % cycle;
            let row = if pos < rails { pos } else { cycle - pos };
            rail_indices[row].push(i);
        }

        let mut result = vec![' '; n];
        let mut cursor = 0;
        for row_positions in rail_indices {
            for orig_idx in row_positions {
                result[orig_idx] = chars[cursor];
                cursor += 1;
            }
        }
        Ok(result.into_iter().collect())
    }
}

/// Brute-forces Rail Fence cipher across rails 2..=max_rails.
pub fn rail_fence_brute_force(input: &str, max_rails: usize) -> Vec<CrackCandidate> {
    let char_count = input.chars().count();
    let limit = max_rails.min(char_count.saturating_sub(1)).max(2);
    let mut candidates = Vec::new();

    for r in 2..=limit {
        if let Ok(plaintext) = rail_fence(input, r, true) {
            let score = english_bigram_score(&plaintext);
            candidates.push(CrackCandidate {
                key_label: format!("{:2} Rails", r),
                plaintext,
                score,
            });
        }
    }
    candidates.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates
}

/// Finds the modular multiplicative inverse of `a` modulo 26.
pub fn mod26_inverse(a: i32) -> Option<i32> {
    let a_mod = a.rem_euclid(26);
    (1..26).find(|&x| (a_mod * x).rem_euclid(26) == 1)
}

/// Affine cipher:
/// Encrypt: E(x) = (a * x + b) mod 26
/// Decrypt: D(x) = a^-1 * (x - b) mod 26
pub fn affine(input: &str, a: i32, b: i32, decrypt: bool) -> Result<String, String> {
    let a_inv = mod26_inverse(a).ok_or_else(|| {
        format!(
            "Invalid Affine multiplier a={a}: must be coprime with 26 (valid values: {:?})",
            VALID_AFFINE_A
        )
    })?;

    let out = input
        .chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            let x = (c as u8 - base) as i32;
            let y = if decrypt {
                (a_inv * (x - b)).rem_euclid(26)
            } else {
                (a * x + b).rem_euclid(26)
            };
            (base + y as u8) as char
        })
        .collect();

    Ok(out)
}

/// Brute-forces all 311 non-trivial Affine keys (a, b) and returns the top candidates ranked by English score.
pub fn affine_brute_force(input: &str, top_n: usize) -> Vec<CrackCandidate> {
    let mut candidates = Vec::with_capacity(312);
    for &a in &VALID_AFFINE_A {
        for b in 0..26 {
            if a == 1 && b == 0 {
                continue;
            }
            if let Ok(plaintext) = affine(input, a, b, true) {
                let score = english_chi_squared(&plaintext);
                candidates.push(CrackCandidate {
                    key_label: format!("a={:2}, b={:2}", a, b),
                    plaintext,
                    score,
                });
            }
        }
    }
    candidates.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates.truncate(top_n);
    candidates
}

/// Repeating-key XOR cipher.
/// On encrypt (`decrypt == false`), XORs UTF-8 bytes with `key` and outputs lowercase Hex.
/// On decrypt (`decrypt == true`), decodes Hex input first, then XORs with `key`.
pub fn xor_hex_cipher(input: &str, key: &str, decrypt: bool) -> Result<String, String> {
    if key.is_empty() {
        return Err("XOR key cannot be empty.".to_string());
    }
    let key_bytes = key.as_bytes();

    if !decrypt {
        let xored: Vec<u8> = input
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();
        Ok(hex_encode_bytes(&xored))
    } else {
        let raw = hex_decode_bytes(input.trim())?;
        let plain: Vec<u8> = raw
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();
        Ok(String::from_utf8_lossy(&plain).into_owned())
    }
}

pub fn hex_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_encode(input: &str) -> String {
    hex_encode_bytes(input.as_bytes())
}

pub fn hex_decode_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("Hex string must have an even number of hex digits.".to_string());
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| format!("Invalid hex byte: '{}'", &clean[i..i + 2]))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub fn hex_decode(hex_str: &str) -> Result<String, String> {
    let bytes = hex_decode_bytes(hex_str)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(input: &str) -> Result<String, String> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.len() % 4 != 0 {
        return Err("Invalid Base64 length (must be a multiple of 4).".to_string());
    }

    let val_of = |b: u8| -> Result<u32, String> {
        match b {
            b'A'..=b'Z' => Ok((b - b'A') as u32),
            b'a'..=b'z' => Ok((b - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((b - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("Invalid Base64 character: '{}'", b as char)),
        }
    };

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.chunks(4) {
        let v0 = val_of(chunk[0])?;
        let v1 = val_of(chunk[1])?;
        let v2 = val_of(chunk[2])?;
        let v3 = val_of(chunk[3])?;

        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }

    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caesar() {
        let original = "Hello, World! 123";
        let enc = caesar_cipher(original, 3);
        assert_eq!(enc, "Khoor, Zruog! 123");
        assert_eq!(caesar_cipher(&enc, -3), original);
    }

    #[test]
    fn test_rot47() {
        let msg = "Rust Cipher 2026!";
        assert_eq!(rot47(&rot47(msg)), msg);
        assert_ne!(rot47(msg), msg);
    }

    #[test]
    fn test_atbash() {
        assert_eq!(atbash("ABC xyz"), "ZYX cba");
        assert_eq!(atbash(&atbash("Secret!")), "Secret!");
    }

    #[test]
    fn test_vigenere() {
        let plain = "Attack at dawn!";
        let enc = vigenere(plain, "LEMON", false).unwrap();
        assert_eq!(enc, "Lxfopv ef rnhr!");
        let dec = vigenere(&enc, "LEMON", true).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_beaufort_and_autokey() {
        let msg = "Defend the east wall of the castle";
        let bf = beaufort(msg, "FORTIFICATION").unwrap();
        assert_eq!(beaufort(&bf, "FORTIFICATION").unwrap(), msg);

        let ak_enc = autokey(msg, "QUEENLY", false).unwrap();
        let ak_dec = autokey(&ak_enc, "QUEENLY", true).unwrap();
        assert_eq!(ak_dec, msg);
    }

    #[test]
    fn test_playfair() {
        let enc = playfair("HIDE THE GOLD", "PLAYFAIR EXAMPLE", false).unwrap();
        assert_eq!(enc, "BM OD ZB XD NA GE");
        let dec = playfair(&enc, "PLAYFAIR EXAMPLE", true).unwrap();
        assert_eq!(dec, "HI DE TH EG OL DX");
    }

    #[test]
    fn test_rail_fence() {
        let msg = "WEAREDISCOVEREDFLEEATONCE";
        let enc = rail_fence(msg, 3, false).unwrap();
        assert_eq!(enc, "WECRLTEERDSOEEFEAOCAIVDEN");
        let dec = rail_fence(&enc, 3, true).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_xor_hex_base64() {
        let msg = "Top Secret Payload 123!";
        let b64 = base64_encode(msg);
        assert_eq!(base64_decode(&b64).unwrap(), msg);

        let hx = hex_encode(msg);
        assert_eq!(hex_decode(&hx).unwrap(), msg);

        let xored = xor_hex_cipher(msg, "KEY42", false).unwrap();
        assert_eq!(xor_hex_cipher(&xored, "KEY42", true).unwrap(), msg);
    }

    #[test]
    fn test_affine() {
        let plain = "Affine Cipher";
        let enc = affine(plain, 5, 8, false).unwrap();
        assert_eq!(enc, "Ihhwvc Swfrcp");
        let dec = affine(&enc, 5, 8, true).unwrap();
        assert_eq!(dec, plain);
        assert!(affine(plain, 2, 3, false).is_err());
    }

    #[test]
    fn test_frequency_cracking() {
        let sample = "The quick brown fox jumps over the lazy dog near the riverbank.";
        let enc = caesar_cipher(sample, 17);
        let ranked = caesar_brute_force(&enc);
        assert_eq!(ranked[0].plaintext, sample);
    }
}
