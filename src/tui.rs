use std::fs;
use std::io::{self, Write};

use crate::ciphers::{
    affine, affine_brute_force, atbash, autokey, base64_decode, base64_encode, beaufort,
    caesar_brute_force, caesar_cipher, english_chi_squared, hex_decode, hex_encode,
    letter_frequencies, playfair, rail_fence, rail_fence_brute_force, rot47, vigenere,
    xor_hex_cipher, CrackCandidate, ENGLISH_FREQ, VALID_AFFINE_A,
};

// ANSI styling constants
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const CYAN: &str = "\x1b[36m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const MAGENTA: &str = "\x1b[35m";
pub const RED: &str = "\x1b[31m";
pub const BLUE: &str = "\x1b[34m";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Caesar,
    Rot47,
    Atbash,
    Vigenere,
    Beaufort,
    Autokey,
    Playfair,
    Affine,
    RailFence,
    XorHex,
    Base64,
    Hex,
}

impl CipherKind {
    pub fn name(&self) -> &'static str {
        match self {
            CipherKind::Caesar => "Caesar Cipher",
            CipherKind::Rot47 => "ROT47 (ASCII 33..126 Shift 47)",
            CipherKind::Atbash => "Atbash (Alphabet Mirror)",
            CipherKind::Vigenere => "Vigenère (Keyword Polyalphabetic)",
            CipherKind::Beaufort => "Beaufort (Reciprocal Polyalphabetic)",
            CipherKind::Autokey => "Autokey (Running-Plaintext Keyword)",
            CipherKind::Playfair => "Playfair (5x5 Digraph Matrix)",
            CipherKind::Affine => "Affine ((a·x + b) mod 26)",
            CipherKind::RailFence => "Rail Fence (Zig-Zag Transposition)",
            CipherKind::XorHex => "XOR (Repeating Key + Hex)",
            CipherKind::Base64 => "Base64 Codec",
            CipherKind::Hex => "Hex Codec",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            CipherKind::Caesar | CipherKind::Rot47 | CipherKind::Atbash | CipherKind::Affine => {
                "Monoalphabetic Substitution"
            }
            CipherKind::Vigenere
            | CipherKind::Beaufort
            | CipherKind::Autokey
            | CipherKind::Playfair => "Polyalphabetic & Digraph",
            CipherKind::RailFence | CipherKind::XorHex => "Transposition & Bitwise",
            CipherKind::Base64 | CipherKind::Hex => "Encodings & Codecs",
        }
    }

    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            CipherKind::Rot47 | CipherKind::Atbash | CipherKind::Beaufort
        )
    }

    pub fn supports_crack(&self) -> bool {
        matches!(
            self,
            CipherKind::Caesar | CipherKind::Affine | CipherKind::RailFence
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
    Crack,
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Operation::Encrypt => "Encrypt / Encode",
            Operation::Decrypt => "Decrypt / Decode",
            Operation::Crack => "Auto-Crack",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingLayer {
    None,
    Base64,
    Hex,
}

impl EncodingLayer {
    pub fn name(&self) -> &'static str {
        match self {
            EncodingLayer::None => "None (Raw Text)",
            EncodingLayer::Base64 => "Base64 Layer",
            EncodingLayer::Hex => "Hex Layer",
        }
    }
}

/// Applies the optional pre-decode / post-encode layer around a core cipher transformation.
pub fn apply_encoding_layer<F>(
    input: &str,
    op: Operation,
    layer: EncodingLayer,
    core_fn: F,
) -> Result<String, String>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    let pre_decoded = match (op, layer) {
        (Operation::Decrypt | Operation::Crack, EncodingLayer::Base64) => base64_decode(input)?,
        (Operation::Decrypt | Operation::Crack, EncodingLayer::Hex) => hex_decode(input)?,
        _ => input.to_string(),
    };

    let transformed = core_fn(&pre_decoded)?;

    let post_encoded = match (op, layer) {
        (Operation::Encrypt, EncodingLayer::Base64) => base64_encode(&transformed),
        (Operation::Encrypt, EncodingLayer::Hex) => hex_encode(&transformed),
        _ => transformed,
    };

    Ok(post_encoded)
}

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub cipher: &'static str,
    pub operation: &'static str,
    pub key_info: String,
    pub input_preview: String,
    pub output: String,
}

pub fn print_banner(history_len: usize) {
    println!();
    println!("{CYAN}{BOLD}╭──────────────────────────────────────────────────────────────────╮{RESET}");
    println!(
        "{CYAN}{BOLD}│{RESET}  {MAGENTA}{BOLD}🔐 CCIPHER STUDIO{RESET} — Classic Cryptography & Auto-Cracker TUI     {CYAN}{BOLD}│{RESET}"
    );
    println!(
        "{CYAN}{BOLD}│{RESET}  {DIM}Substitution • Polyalphabetic • Transposition • Codecs{RESET}          {CYAN}{BOLD}│{RESET}"
    );
    println!("{CYAN}{BOLD}╰──────────────────────────────────────────────────────────────────╯{RESET}");
    if history_len > 0 {
        println!(
            "  {DIM}Session History: {BOLD}{history_len}{RESET}{DIM} operation(s) recorded{RESET}"
        );
    }
}

pub fn print_result_box(title: &str, subtitle: &str, body: &str) {
    println!();
    println!("{GREEN}{BOLD}╭─ {title} ────────────────────────────────────────────────────{RESET}");
    if !subtitle.is_empty() {
        println!("{GREEN}{BOLD}│{RESET} {DIM}{subtitle}{RESET}");
        println!("{GREEN}{BOLD}├──────────────────────────────────────────────────────────────────{RESET}");
    }
    for line in body.lines() {
        println!("{GREEN}{BOLD}│{RESET} {line}");
    }
    println!("{GREEN}{BOLD}╰──────────────────────────────────────────────────────────────────{RESET}");
}

pub fn print_crack_table(cipher_name: &str, candidates: &[CrackCandidate]) {
    println!();
    println!(
        "{CYAN}{BOLD}╭─ 🔎 Auto-Crack & Frequency Analysis ({cipher_name}) ──────────────{RESET}"
    );
    println!(
        "{CYAN}{BOLD}│{RESET} {DIM}Ranked by English plausibility score (lower = better match){RESET}"
    );
    println!(
        "{CYAN}{BOLD}├────────┬──────────────────────────┬──────────┬───────────────────{RESET}"
    );
    println!(
        "{CYAN}{BOLD}│{RESET} {BOLD}Rank{RESET}   {CYAN}│{RESET} {BOLD}Key{RESET}                      {CYAN}│{RESET} {BOLD}Score{RESET}    {CYAN}│{RESET} {BOLD}Decrypted Candidate{RESET}"
    );
    println!(
        "{CYAN}{BOLD}├────────┼──────────────────────────┼──────────┼───────────────────{RESET}"
    );

    for (idx, c) in candidates.iter().enumerate() {
        let rank = idx + 1;
        let preview = c.plaintext.replace('\n', " ↵ ");
        if idx == 0 {
            println!(
                "{CYAN}{BOLD}│{RESET} {GREEN}{BOLD}#1 ★{RESET}   {CYAN}│{RESET} {GREEN}{BOLD}{:<24}{RESET} {CYAN}│{RESET} {GREEN}{BOLD}{:8.2}{RESET} {CYAN}│{RESET} {GREEN}{BOLD}{preview}{RESET}",
                c.key_label, c.score
            );
        } else if idx < 3 {
            println!(
                "{CYAN}{BOLD}│{RESET} {YELLOW}#{:<5}{RESET} {CYAN}│{RESET} {YELLOW}{:<24}{RESET} {CYAN}│{RESET} {YELLOW}{:8.2}{RESET} {CYAN}│{RESET} {preview}",
                rank, c.key_label, c.score
            );
        } else {
            println!(
                "{CYAN}{BOLD}│{RESET} {DIM}#{:<5}{RESET} {CYAN}│{RESET} {DIM}{:<24}{RESET} {CYAN}│{RESET} {DIM}{:8.2}{RESET} {CYAN}│{RESET} {DIM}{preview}{RESET}",
                rank, c.key_label, c.score
            );
        }
    }
    println!(
        "{CYAN}{BOLD}╰────────┴──────────────────────────┴──────────┴───────────────────{RESET}"
    );
}

/// Renders a side-by-side 26-letter (A-Z) ASCII/Unicode histogram comparing
/// observed letter frequencies against standard English frequencies.
pub fn format_frequency_chart(text: &str) -> Vec<String> {
    let (freqs, total) = letter_frequencies(text);
    let chi = english_chi_squared(text);
    let mut lines = Vec::new();

    lines.push(format!(
        "{BOLD}Letters:{RESET} {total}   {BOLD}English χ² Fit:{RESET} {:.2} {DIM}(lower = closer to English){RESET}",
        if chi.is_finite() { chi } else { 0.0 }
    ));
    lines.push(format!(
        "{DIM}Legend: {GREEN}█ Observed %{RESET}   {CYAN}▒ Expected English %{RESET}"
    ));

    for row in 0..13 {
        let left_idx = row;
        let right_idx = row + 13;

        let format_col = |idx: usize| -> String {
            let ch = (b'A' + idx as u8) as char;
            let obs = freqs[idx];
            let exp = ENGLISH_FREQ[idx];
            let obs_bars = ((obs / 15.0) * 12.0).round().clamp(0.0, 12.0) as usize;
            let exp_bars = ((exp / 15.0) * 12.0).round().clamp(0.0, 12.0) as usize;

            let mut bar = String::new();
            for b in 0..12 {
                if b < obs_bars && b < exp_bars {
                    bar.push_str(&format!("{GREEN}█{RESET}"));
                } else if b < obs_bars {
                    bar.push_str(&format!("{YELLOW}█{RESET}"));
                } else if b < exp_bars {
                    bar.push_str(&format!("{CYAN}▒{RESET}"));
                } else {
                    bar.push_str(&format!("{DIM}·{RESET}"));
                }
            }
            format!("{BOLD}{ch}{RESET} {bar} {obs:5.1}% {DIM}({exp:4.1}%){RESET}")
        };

        lines.push(format!("{}   │   {}", format_col(left_idx), format_col(right_idx)));
    }

    lines
}

pub fn print_frequency_chart(title: &str, text: &str) {
    println!();
    println!("{MAGENTA}{BOLD}╭─ 📊 Letter Frequency Distribution ({title}) ─────────────────────{RESET}");
    for line in format_frequency_chart(text) {
        println!("{MAGENTA}{BOLD}│{RESET} {line}");
    }
    println!("{MAGENTA}{BOLD}╰──────────────────────────────────────────────────────────────────{RESET}");
}

fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut buf = String::new();
    let n = io::stdin().read_line(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    Ok(buf.trim_end_matches(&['\r', '\n'][..]).to_string())
}

enum MenuSelection {
    Cipher(CipherKind),
    History,
    ClearScreen,
    Quit,
}

fn prompt_main_menu(has_history: bool) -> io::Result<MenuSelection> {
    loop {
        println!();
        println!("{BOLD}Select a Cipher or Action:{RESET}");

        println!("\n  {MAGENTA}{BOLD}▸ Monoalphabetic Substitution{RESET}");
        println!("    {CYAN}[1]{RESET}  Caesar Cipher        {DIM}(numeric shift ±N + auto-crack){RESET}");
        println!("    {CYAN}[2]{RESET}  ROT47                {DIM}(printable ASCII !..~ shift, symmetric){RESET}");
        println!("    {CYAN}[3]{RESET}  Atbash               {DIM}(A ↔ Z alphabet mirror, symmetric){RESET}");
        println!("    {CYAN}[4]{RESET}  Affine Cipher        {DIM}((a·x + b) mod 26 + auto-crack){RESET}");

        println!("\n  {MAGENTA}{BOLD}▸ Polyalphabetic & Digraph{RESET}");
        println!("    {CYAN}[5]{RESET}  Vigenère Cipher      {DIM}(polyalphabetic keyword shift){RESET}");
        println!("    {CYAN}[6]{RESET}  Beaufort Cipher      {DIM}(reciprocal polyalphabetic keyword){RESET}");
        println!("    {CYAN}[7]{RESET}  Autokey Cipher       {DIM}(running-plaintext keyword cipher){RESET}");
        println!("    {CYAN}[8]{RESET}  Playfair Cipher      {DIM}(5x5 digraph matrix with keyword){RESET}");

        println!("\n  {MAGENTA}{BOLD}▸ Transposition & Bitwise{RESET}");
        println!("    {CYAN}[9]{RESET}  Rail Fence Cipher    {DIM}(zig-zag transposition + auto-crack){RESET}");
        println!("    {CYAN}[10]{RESET} XOR Cipher           {DIM}(repeating-key XOR with Hex I/O){RESET}");

        println!("\n  {MAGENTA}{BOLD}▸ Encodings & Codecs{RESET}");
        println!("    {CYAN}[11]{RESET} Base64 Codec         {DIM}(encode / decode Base64){RESET}");
        println!("    {CYAN}[12]{RESET} Hex Codec            {DIM}(encode / decode Hex){RESET}");

        println!("\n  {MAGENTA}{BOLD}▸ Session & Actions{RESET}");
        if has_history {
            println!("    {MAGENTA}[H]{RESET}  View Session History");
        }
        println!("    {BLUE}[C]{RESET}  Clear Screen");
        println!("    {RED}[Q]{RESET}  Quit");

        let choice = prompt_line(&format!("\n{BOLD}❯ Choice:{RESET} "))?;
        match choice.trim().to_ascii_lowercase().as_str() {
            "1" | "caesar" => return Ok(MenuSelection::Cipher(CipherKind::Caesar)),
            "2" | "rot47" => return Ok(MenuSelection::Cipher(CipherKind::Rot47)),
            "3" | "atbash" => return Ok(MenuSelection::Cipher(CipherKind::Atbash)),
            "4" | "affine" => return Ok(MenuSelection::Cipher(CipherKind::Affine)),
            "5" | "vigenere" | "vig" => return Ok(MenuSelection::Cipher(CipherKind::Vigenere)),
            "6" | "beaufort" => return Ok(MenuSelection::Cipher(CipherKind::Beaufort)),
            "7" | "autokey" => return Ok(MenuSelection::Cipher(CipherKind::Autokey)),
            "8" | "playfair" => return Ok(MenuSelection::Cipher(CipherKind::Playfair)),
            "9" | "rail" | "rail-fence" | "railfence" => {
                return Ok(MenuSelection::Cipher(CipherKind::RailFence))
            }
            "10" | "xor" => return Ok(MenuSelection::Cipher(CipherKind::XorHex)),
            "11" | "base64" | "b64" => return Ok(MenuSelection::Cipher(CipherKind::Base64)),
            "12" | "hex" => return Ok(MenuSelection::Cipher(CipherKind::Hex)),
            "h" | "history" if has_history => return Ok(MenuSelection::History),
            "c" | "clear" => return Ok(MenuSelection::ClearScreen),
            "q" | "quit" | "exit" => return Ok(MenuSelection::Quit),
            _ => println!("{YELLOW}  ⚠ Invalid choice. Enter 1-12, C, or Q.{RESET}"),
        }
    }
}

fn prompt_operation(cipher: CipherKind) -> io::Result<Operation> {
    if cipher.is_symmetric() {
        println!(
            "  {DIM}ℹ {} is symmetric (encryption and decryption are identical).{RESET}",
            cipher.name()
        );
        return Ok(Operation::Encrypt);
    }

    loop {
        println!();
        println!("{BOLD}Select Operation for {}:{RESET}", cipher.name());
        println!("  {GREEN}[1]{RESET} Encrypt / Encode");
        println!("  {YELLOW}[2]{RESET} Decrypt / Decode");
        if cipher.supports_crack() {
            println!(
                "  {MAGENTA}[3]{RESET} Auto-Crack / Brute-Force {DIM}(English frequency/bigram ranking){RESET}"
            );
        }

        let prompt_str = if cipher.supports_crack() {
            format!("\n{BOLD}❯ Operation (1/2/3 or e/d/b):{RESET} ")
        } else {
            format!("\n{BOLD}❯ Operation (1/2 or e/d):{RESET} ")
        };

        let choice = prompt_line(&prompt_str)?;
        match choice.trim().to_ascii_lowercase().as_str() {
            "1" | "e" | "enc" | "encrypt" => return Ok(Operation::Encrypt),
            "2" | "d" | "dec" | "decrypt" => return Ok(Operation::Decrypt),
            "3" | "b" | "c" | "crack" | "brute" if cipher.supports_crack() => {
                return Ok(Operation::Crack)
            }
            _ => println!("{YELLOW}  ⚠ Invalid operation selection.{RESET}"),
        }
    }
}

fn prompt_shift() -> io::Result<i32> {
    loop {
        let s = prompt_line(&format!("{BOLD}❯ Enter shift key (integer, e.g. 3):{RESET} "))?;
        match s.trim().parse::<i32>() {
            Ok(n) => return Ok(n),
            Err(_) => println!("{YELLOW}  ⚠ Please enter a valid integer.{RESET}"),
        }
    }
}

fn prompt_rails() -> io::Result<usize> {
    loop {
        let s = prompt_line(&format!(
            "{BOLD}❯ Enter number of rails (integer ≥ 2, e.g. 3):{RESET} "
        ))?;
        match s.trim().parse::<usize>() {
            Ok(n) if n >= 2 => return Ok(n),
            _ => println!("{YELLOW}  ⚠ Please enter an integer ≥ 2.{RESET}"),
        }
    }
}

fn prompt_keyword(cipher_label: &str, require_alpha: bool) -> io::Result<String> {
    loop {
        let key = prompt_line(&format!(
            "{BOLD}❯ Enter {cipher_label} keyword (e.g. SECRET):{RESET} "
        ))?;
        let trimmed = key.trim();
        if !trimmed.is_empty() && (!require_alpha || trimmed.chars().any(|c| c.is_ascii_alphabetic()))
        {
            return Ok(trimmed.to_string());
        }
        println!("{YELLOW}  ⚠ Please enter a valid non-empty keyword.{RESET}");
    }
}

fn prompt_affine_keys() -> io::Result<(i32, i32)> {
    let a = loop {
        let input = prompt_line(&format!(
            "{BOLD}❯ Enter multiplier 'a' (valid coprimes: {:?}):{RESET} ",
            VALID_AFFINE_A
        ))?;
        if let Ok(val) = input.trim().parse::<i32>() {
            if VALID_AFFINE_A.contains(&val.rem_euclid(26)) {
                break val;
            }
        }
        println!(
            "{YELLOW}  ⚠ 'a' must be coprime with 26. Choose from: {:?}{RESET}",
            VALID_AFFINE_A
        );
    };

    let b = loop {
        let input = prompt_line(&format!(
            "{BOLD}❯ Enter intercept 'b' (integer, e.g. 8):{RESET} "
        ))?;
        if let Ok(val) = input.trim().parse::<i32>() {
            break val;
        }
        println!("{YELLOW}  ⚠ Please enter a valid integer for 'b'.{RESET}");
    };

    Ok((a, b))
}

fn prompt_input_text(last_output: Option<&str>) -> Result<String, String> {
    loop {
        println!();
        println!("{BOLD}Input Source:{RESET}");
        println!("  {CYAN}[T]{RESET} Type text directly {DIM}(default){RESET}");
        println!("  {CYAN}[F]{RESET} Load from a file");
        if let Some(prev) = last_output {
            let preview: String = prev.chars().take(36).collect();
            println!(
                "  {MAGENTA}[L]{RESET} Reuse last output {DIM}(\"{preview}...\"){RESET}"
            );
        }

        let choice = prompt_line(&format!(
            "{BOLD}❯ Source [T/F{}]:{RESET} ",
            if last_output.is_some() { "/L" } else { "" }
        ))
        .map_err(|e| e.to_string())?;

        match choice.trim().to_ascii_lowercase().as_str() {
            "" | "t" | "text" => {
                let text = prompt_line(&format!("{BOLD}❯ Enter text:{RESET} "))
                    .map_err(|e| e.to_string())?;
                return Ok(text);
            }
            "f" | "file" => {
                let path = prompt_line(&format!("{BOLD}❯ File path:{RESET} "))
                    .map_err(|e| e.to_string())?;
                match fs::read_to_string(path.trim()) {
                    Ok(content) => return Ok(content),
                    Err(e) => println!("{RED}  ✖ Failed to read '{}': {e}{RESET}", path.trim()),
                }
            }
            "l" | "last" if last_output.is_some() => {
                return Ok(last_output.unwrap().to_string());
            }
            _ => println!("{YELLOW}  ⚠ Invalid source choice.{RESET}"),
        }
    }
}

fn print_history(history: &[HistoryEntry]) {
    println!();
    println!(
        "{MAGENTA}{BOLD}╭─ 📜 Session History ({}) ─────────────────────────────────────────{RESET}",
        history.len()
    );
    for (i, item) in history.iter().enumerate() {
        let out_preview: String = item.output.replace('\n', " ↵ ").chars().take(50).collect();
        println!(
            "{MAGENTA}{BOLD}│{RESET} {BOLD}#{:<2}{RESET} [{CYAN}{}{RESET} • {YELLOW}{}{RESET} • {}]",
            i + 1,
            item.cipher,
            item.operation,
            item.key_info
        );
        println!(
            "{MAGENTA}{BOLD}│{RESET}    {DIM}In :{RESET} {}\n{MAGENTA}{BOLD}│{RESET}    {GREEN}Out:{RESET} {out_preview}",
            item.input_preview
        );
        if i + 1 < history.len() {
            println!("{MAGENTA}{BOLD}├──────────────────────────────────────────────────────────────────{RESET}");
        }
    }
    println!("{MAGENTA}{BOLD}╰──────────────────────────────────────────────────────────────────{RESET}");
}

pub fn run_interactive_tui() -> Result<(), String> {
    let mut history: Vec<HistoryEntry> = Vec::new();
    print_banner(0);

    loop {
        let selection = match prompt_main_menu(!history.is_empty()) {
            Ok(sel) => sel,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                println!("\n{DIM}Goodbye!{RESET}");
                break;
            }
            Err(e) => return Err(e.to_string()),
        };

        let cipher = match selection {
            MenuSelection::Quit => {
                println!("\n{CYAN}👋 Goodbye!{RESET}");
                break;
            }
            MenuSelection::ClearScreen => {
                print!("\x1b[2J\x1b[H");
                io::stdout().flush().ok();
                print_banner(history.len());
                continue;
            }
            MenuSelection::History => {
                print_history(&history);
                continue;
            }
            MenuSelection::Cipher(c) => c,
        };

        let op = prompt_operation(cipher).map_err(|e| e.to_string())?;
        let dec = op == Operation::Decrypt;

        // Gather cipher parameters
        let (caesar_shift, rails, keyword, affine_ab, key_summary) = match (cipher, op) {
            (_, Operation::Crack) => (0, 0, String::new(), (1, 0), "Auto-Crack".to_string()),
            (CipherKind::Caesar, _) => {
                let s = prompt_shift().map_err(|e| e.to_string())?;
                (s, 0, String::new(), (1, 0), format!("shift={s}"))
            }
            (CipherKind::Rot47, _) => (47, 0, String::new(), (1, 0), "shift=47".to_string()),
            (CipherKind::Atbash, _) => (0, 0, String::new(), (1, 0), "A↔Z".to_string()),
            (CipherKind::RailFence, _) => {
                let r = prompt_rails().map_err(|e| e.to_string())?;
                (0, r, String::new(), (1, 0), format!("rails={r}"))
            }
            (
                CipherKind::Vigenere
                | CipherKind::Beaufort
                | CipherKind::Autokey
                | CipherKind::Playfair,
                _,
            ) => {
                let k = prompt_keyword(cipher.name(), true).map_err(|e| e.to_string())?;
                let summary = format!("key=\"{k}\"");
                (0, 0, k, (1, 0), summary)
            }
            (CipherKind::XorHex, _) => {
                let k = prompt_keyword("XOR", false).map_err(|e| e.to_string())?;
                let summary = format!("key=\"{k}\"");
                (0, 0, k, (1, 0), summary)
            }
            (CipherKind::Affine, _) => {
                let (a, b) = prompt_affine_keys().map_err(|e| e.to_string())?;
                (0, 0, String::new(), (a, b), format!("a={a}, b={b}"))
            }
            (CipherKind::Base64 | CipherKind::Hex, _) => {
                (0, 0, String::new(), (1, 0), "Codec".to_string())
            }
        };

        let last_out = history.last().map(|h| h.output.as_str());
        let input_text = prompt_input_text(last_out)?;

        // Execute operation
        let (final_output, op_label) = match (cipher, op) {
            (CipherKind::Caesar, Operation::Crack) => {
                let candidates = caesar_brute_force(&input_text);
                print_crack_table(cipher.name(), &candidates);
                let best = candidates
                    .first()
                    .map(|c| c.plaintext.clone())
                    .unwrap_or_default();
                (best, "Auto-Crack (Top #1)")
            }
            (CipherKind::Affine, Operation::Crack) => {
                let candidates = affine_brute_force(&input_text, 15);
                print_crack_table("Affine Cipher — Top 15 of 311 Keys", &candidates);
                let best = candidates
                    .first()
                    .map(|c| c.plaintext.clone())
                    .unwrap_or_default();
                (best, "Auto-Crack (Top #1)")
            }
            (CipherKind::RailFence, Operation::Crack) => {
                let candidates = rail_fence_brute_force(&input_text, 15);
                print_crack_table("Rail Fence Cipher", &candidates);
                let best = candidates
                    .first()
                    .map(|c| c.plaintext.clone())
                    .unwrap_or_default();
                (best, "Auto-Crack (Top #1)")
            }
            _ => {
                let res = match cipher {
                    CipherKind::Caesar => caesar_cipher(
                        &input_text,
                        if dec { -caesar_shift } else { caesar_shift },
                    ),
                    CipherKind::Rot47 => rot47(&input_text),
                    CipherKind::Atbash => atbash(&input_text),
                    CipherKind::Vigenere => vigenere(&input_text, &keyword, dec)?,
                    CipherKind::Beaufort => beaufort(&input_text, &keyword)?,
                    CipherKind::Autokey => autokey(&input_text, &keyword, dec)?,
                    CipherKind::Playfair => playfair(&input_text, &keyword, dec)?,
                    CipherKind::Affine => {
                        let (a, b) = affine_ab;
                        affine(&input_text, a, b, dec)?
                    }
                    CipherKind::RailFence => rail_fence(&input_text, rails, dec)?,
                    CipherKind::XorHex => xor_hex_cipher(&input_text, &keyword, dec)?,
                    CipherKind::Base64 => {
                        if dec {
                            base64_decode(&input_text)?
                        } else {
                            base64_encode(&input_text)
                        }
                    }
                    CipherKind::Hex => {
                        if dec {
                            hex_decode(&input_text)?
                        } else {
                            hex_encode(&input_text)
                        }
                    }
                };
                let label = if cipher.is_symmetric() {
                    "Transform"
                } else if dec {
                    "Decrypt"
                } else {
                    "Encrypt"
                };
                print_result_box(cipher.name(), &format!("{label} • {key_summary}"), &res);
                (res, label)
            }
        };

        // Record in session history
        let input_preview: String = input_text.replace('\n', " ↵ ").chars().take(40).collect();
        history.push(HistoryEntry {
            cipher: cipher.name(),
            operation: op_label,
            key_info: key_summary,
            input_preview,
            output: final_output.clone(),
        });

        // Optional frequency chart or save to file
        let post_ans = prompt_line(&format!(
            "\n{DIM}📊 Press [F] for Letter Frequency Chart, enter a file path to save, or press Enter to continue:{RESET} "
        ))
        .map_err(|e| e.to_string())?;
        let trimmed = post_ans.trim();
        if trimmed.eq_ignore_ascii_case("f") || trimmed.eq_ignore_ascii_case("freq") {
            print_frequency_chart(cipher.name(), &final_output);
        } else if !trimmed.is_empty() {
            match fs::write(trimmed, &final_output) {
                Ok(_) => println!("{GREEN}  ✔ Saved output to '{trimmed}'.{RESET}"),
                Err(e) => println!("{RED}  ✖ Failed to write '{trimmed}': {e}{RESET}"),
            }
        }
    }

    Ok(())
}
