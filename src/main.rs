pub mod ciphers;
pub mod tui;

use std::env;
use std::fs;
use std::io::{self, BufRead, BufWriter, IsTerminal, Read, Write};
use std::process;

use ciphers::{
    affine, affine_brute_force, atbash, autokey, base64_decode, base64_encode, beaufort,
    caesar_brute_force, caesar_cipher, hex_decode, hex_encode, playfair, rail_fence,
    rail_fence_brute_force, rot47, vigenere, xor_hex_cipher,
};
use tui::{
    apply_encoding_layer, print_crack_table, print_frequency_chart, print_result_box,
    run_interactive_tui, CipherKind, EncodingLayer, Operation, BOLD, CYAN, GREEN, RED, RESET,
};

#[derive(Debug)]
struct CliConfig {
    cipher: CipherKind,
    cipher_explicit: bool,
    operation: Option<Operation>,
    encoding_layer: EncodingLayer,
    shift: Option<i32>,
    rails: Option<usize>,
    keyword: Option<String>,
    affine_keys: Option<(i32, i32)>,
    input_file: Option<String>,
    output_file: Option<String>,
    text: Option<String>,
    raw_output: bool,
    show_freq: bool,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            cipher: CipherKind::Caesar,
            cipher_explicit: false,
            operation: None,
            encoding_layer: EncodingLayer::None,
            shift: None,
            rails: None,
            keyword: None,
            affine_keys: None,
            input_file: None,
            output_file: None,
            text: None,
            raw_output: false,
            show_freq: false,
        }
    }
}

fn print_help(program: &str) {
    println!(
        "{CYAN}{BOLD}CCIPHER LIVE STUDIO{RESET} — Multi-Cipher CLI, Unix Pipe Tool & Arrow-Key TUI

{BOLD}Usage:{RESET}
  {program}                        Launch full-screen arrow-key live TUI studio
  {program} [OPTIONS] [TEXT]       Run CLI operation
  cat file.txt | {program} [OPTS]  Stream via Unix stdin/stdout pipes

{BOLD}Ciphers (-c / --cipher <NAME>):{RESET}
  caesar (default)         Caesar shift cipher (-s <NUM>)
  rot47 / --rot47          ROT47 printable ASCII shift
  atbash / --atbash        Atbash alphabet mirror
  vigenere                 Vigenère polyalphabetic cipher (-k <KEY>)
  beaufort                 Beaufort symmetric polyalphabetic cipher (-k <KEY>)
  autokey                  Autokey running-plaintext cipher (-k <KEY>)
  playfair                 Playfair 5x5 digraph cipher (-k <KEY>)
  affine                   Affine cipher (--affine <A,B>)
  rail-fence               Rail Fence zig-zag transposition (--rails <N>)
  xor                      Repeating-key XOR cipher with hex output (-k <KEY>)
  base64                   Standalone Base64 encode/decode
  hex                      Standalone Hex encode/decode

{BOLD}Operations & Keys:{RESET}
  -e, --encrypt            Encrypt / encode mode (default)
  -d, --decrypt            Decrypt / decode mode
  -b, --brute-force        Auto-crack mode (Caesar, Affine, Rail Fence)
  -s, --shift <NUM>        Caesar shift key (integer, e.g. 3)
  -r, --rails <NUM>        Rail Fence rail count (e.g. 3)
  -k, --key <KEYWORD>      Keyword for Vigenère, Beaufort, Autokey, Playfair, or XOR
      --affine <A,B>       Affine cipher keys, e.g. --affine 5,8

{BOLD}Encoding Chaining & Analysis:{RESET}
      --base64             Wrap output in Base64 (or run Base64 if no cipher set)
      --hex                Wrap output in Hex (or run Hex if no cipher set)
  -f, --freq               Display visual letter frequency histogram (A-Z vs English)
  -q, --raw                Emit raw output only (auto-enabled when stdout is piped)

{BOLD}File I/O:{RESET}
  -i, --input <FILE>       Read input text from file
  -o, --output <FILE>      Write result to file
  -h, --help               Show this help message"
    );
}

fn parse_cipher_name(s: &str) -> Result<CipherKind, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "caesar" => Ok(CipherKind::Caesar),
        "rot47" => Ok(CipherKind::Rot47),
        "atbash" => Ok(CipherKind::Atbash),
        "vigenere" | "vig" => Ok(CipherKind::Vigenere),
        "beaufort" => Ok(CipherKind::Beaufort),
        "autokey" => Ok(CipherKind::Autokey),
        "playfair" => Ok(CipherKind::Playfair),
        "affine" => Ok(CipherKind::Affine),
        "rail" | "railfence" | "rail-fence" | "rails" => Ok(CipherKind::RailFence),
        "xor" | "xor-hex" => Ok(CipherKind::XorHex),
        "base64" | "b64" => Ok(CipherKind::Base64),
        "hex" => Ok(CipherKind::Hex),
        other => Err(format!(
            "Unknown cipher '{other}'. Supported: caesar, rot47, atbash, vigenere, beaufort, autokey, playfair, affine, rail-fence, xor, base64, hex"
        )),
    }
}

fn parse_affine_pair(s: &str) -> Result<(i32, i32), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid Affine key format '{s}'. Expected 'A,B' (e.g. --affine 5,8)"
        ));
    }
    let a = parts[0]
        .trim()
        .parse::<i32>()
        .map_err(|_| format!("Invalid Affine 'a' multiplier: '{}'", parts[0]))?;
    let b = parts[1]
        .trim()
        .parse::<i32>()
        .map_err(|_| format!("Invalid Affine 'b' intercept: '{}'", parts[1]))?;
    Ok((a, b))
}

fn parse_args() -> Result<Option<CliConfig>, String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "ccipher".to_string());
    let remaining: Vec<String> = args.collect();

    if remaining.is_empty() && io::stdin().is_terminal() {
        return Ok(None);
    }

    let mut cfg = CliConfig::default();
    let mut it = remaining.into_iter();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help(&program);
                process::exit(0);
            }
            "-c" | "--cipher" => {
                let val = it.next().ok_or("Missing cipher name after --cipher (-c)")?;
                cfg.cipher = parse_cipher_name(&val)?;
                cfg.cipher_explicit = true;
            }
            "--rot47" => {
                cfg.cipher = CipherKind::Rot47;
                cfg.cipher_explicit = true;
            }
            "--atbash" => {
                cfg.cipher = CipherKind::Atbash;
                cfg.cipher_explicit = true;
            }
            "--base64" => {
                cfg.encoding_layer = EncodingLayer::Base64;
            }
            "--hex" => {
                cfg.encoding_layer = EncodingLayer::Hex;
            }
            "-k" | "--key" => {
                let val = it.next().ok_or("Missing keyword after --key (-k)")?;
                if !cfg.cipher_explicit {
                    cfg.cipher = CipherKind::Vigenere;
                }
                cfg.keyword = Some(val);
            }
            "--affine" => {
                let val = it.next().ok_or("Missing 'A,B' after --affine")?;
                cfg.cipher = CipherKind::Affine;
                cfg.cipher_explicit = true;
                cfg.affine_keys = Some(parse_affine_pair(&val)?);
            }
            "-r" | "--rails" => {
                let val = it.next().ok_or("Missing rail count after --rails (-r)")?;
                let parsed = val
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid rail count: '{val}'"))?;
                cfg.cipher = CipherKind::RailFence;
                cfg.cipher_explicit = true;
                cfg.rails = Some(parsed);
            }
            "-e" | "--encrypt" => cfg.operation = Some(Operation::Encrypt),
            "-d" | "--decrypt" => cfg.operation = Some(Operation::Decrypt),
            "-b" | "--brute-force" | "--crack" => cfg.operation = Some(Operation::Crack),
            "-s" | "--shift" => {
                let val = it.next().ok_or("Missing value for --shift (-s)")?;
                let parsed = val
                    .parse::<i32>()
                    .map_err(|_| format!("Invalid shift number: '{val}'"))?;
                cfg.shift = Some(parsed);
                cfg.cipher_explicit = true;
            }
            "-f" | "--freq" => cfg.show_freq = true,
            "-q" | "--raw" => cfg.raw_output = true,
            "-i" | "--input" => {
                let path = it.next().ok_or("Missing file path for --input (-i)")?;
                cfg.input_file = Some(path);
            }
            "-o" | "--output" => {
                let path = it.next().ok_or("Missing file path for --output (-o)")?;
                cfg.output_file = Some(path);
            }
            other if other.starts_with('-') => {
                return Err(format!("Unknown option: '{other}'. Use --help for usage."));
            }
            positional => {
                if cfg.text.is_none() {
                    cfg.text = Some(positional.to_string());
                } else {
                    let existing = cfg.text.as_mut().unwrap();
                    existing.push(' ');
                    existing.push_str(positional);
                }
            }
        }
    }

    // If `--base64` or `--hex` was passed without any other cipher flag/key/shift, treat it as the main cipher
    if !cfg.cipher_explicit && cfg.shift.is_none() && cfg.keyword.is_none() {
        match cfg.encoding_layer {
            EncodingLayer::Base64 => {
                cfg.cipher = CipherKind::Base64;
                cfg.encoding_layer = EncodingLayer::None;
            }
            EncodingLayer::Hex => {
                cfg.cipher = CipherKind::Hex;
                cfg.encoding_layer = EncodingLayer::None;
            }
            EncodingLayer::None => {}
        }
    }

    Ok(Some(cfg))
}

/// Fast line-by-line streaming path for character-wise substitution ciphers when piped in raw mode.
fn try_stream_lines(cfg: &CliConfig, op: Operation, raw_mode: bool) -> Result<bool, String> {
    if !raw_mode
        || cfg.show_freq
        || cfg.encoding_layer != EncodingLayer::None
        || cfg.text.is_some()
        || cfg.input_file.is_some()
        || cfg.output_file.is_some()
        || op == Operation::Crack
    {
        return Ok(false);
    }

    let can_stream = matches!(
        cfg.cipher,
        CipherKind::Caesar | CipherKind::Rot47 | CipherKind::Atbash
    );
    if !can_stream {
        return Ok(false);
    }

    let shift = if cfg.cipher == CipherKind::Caesar {
        let s = cfg.shift.ok_or("Missing --shift (-s) for Caesar cipher")?;
        if op == Operation::Decrypt { -s } else { s }
    } else {
        0
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = BufWriter::new(stdout.lock());
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let transformed = match cfg.cipher {
            CipherKind::Caesar => caesar_cipher(&line, shift),
            CipherKind::Rot47 => rot47(&line),
            CipherKind::Atbash => atbash(&line),
            _ => unreachable!(),
        };
        writer
            .write_all(transformed.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    Ok(true)
}

fn run_cli(cfg: CliConfig) -> Result<(), String> {
    let op = cfg.operation.unwrap_or(Operation::Encrypt);
    let raw_mode = cfg.raw_output || (!io::stdout().is_terminal() && !cfg.show_freq);

    // Use constant-memory streaming if reading from stdin pipe into raw stdout
    if try_stream_lines(&cfg, op, raw_mode)? {
        return Ok(());
    }

    let input_text = if let Some(path) = &cfg.input_file {
        fs::read_to_string(path).map_err(|e| format!("Failed to read input file '{path}': {e}"))?
    } else if let Some(text) = cfg.text {
        text
    } else if !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read from stdin: {e}"))?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    } else {
        return Err(
            "No input text provided. Pass text as an argument, use -i <FILE>, pipe via stdin, or run without flags for the live TUI."
                .to_string(),
        );
    };

    let dec = op == Operation::Decrypt;

    if op == Operation::Crack {
        let pre_decoded = match cfg.encoding_layer {
            EncodingLayer::None => input_text.clone(),
            EncodingLayer::Base64 => base64_decode(&input_text)?,
            EncodingLayer::Hex => hex_decode(&input_text)?,
        };
        let candidates = match cfg.cipher {
            CipherKind::Caesar => caesar_brute_force(&pre_decoded),
            CipherKind::Affine => affine_brute_force(&pre_decoded, 15),
            CipherKind::RailFence => rail_fence_brute_force(&pre_decoded, 15),
            other => {
                return Err(format!(
                    "Auto-crack is supported for Caesar, Affine, and Rail Fence (not {}).",
                    other.name()
                ))
            }
        };

        let best = candidates
            .first()
            .map(|c| c.plaintext.clone())
            .unwrap_or_default();

        if raw_mode {
            println!("{best}");
        } else {
            print_crack_table(cfg.cipher.name(), &candidates);
            if cfg.show_freq {
                print_frequency_chart("Top #1 Crack Candidate", &best);
            }
        }

        if let Some(path) = cfg.output_file {
            fs::write(&path, &best)
                .map_err(|e| format!("Failed to write output file '{path}': {e}"))?;
            if !raw_mode {
                println!("{GREEN}  ✔ Saved output to '{path}'.{RESET}");
            }
        }
        return Ok(());
    }

    let mut subtitle = op.name().to_string();
    let output = apply_encoding_layer(&input_text, op, cfg.encoding_layer, |txt| {
        match cfg.cipher {
            CipherKind::Caesar => {
                let s = cfg.shift.ok_or("Missing --shift (-s) for Caesar cipher")?;
                subtitle.push_str(&format!(" • shift={s}"));
                Ok(caesar_cipher(txt, if dec { -s } else { s }))
            }
            CipherKind::Rot47 => Ok(rot47(txt)),
            CipherKind::Atbash => Ok(atbash(txt)),
            CipherKind::Vigenere => {
                let key = cfg
                    .keyword
                    .as_deref()
                    .ok_or("Missing Vigenère keyword (-k / --key)")?;
                subtitle.push_str(&format!(" • key=\"{key}\""));
                vigenere(txt, key, dec)
            }
            CipherKind::Beaufort => {
                let key = cfg
                    .keyword
                    .as_deref()
                    .ok_or("Missing Beaufort keyword (-k / --key)")?;
                subtitle.push_str(&format!(" • key=\"{key}\""));
                beaufort(txt, key)
            }
            CipherKind::Autokey => {
                let key = cfg
                    .keyword
                    .as_deref()
                    .ok_or("Missing Autokey keyword (-k / --key)")?;
                subtitle.push_str(&format!(" • key=\"{key}\""));
                autokey(txt, key, dec)
            }
            CipherKind::Playfair => {
                let key = cfg
                    .keyword
                    .as_deref()
                    .ok_or("Missing Playfair keyword (-k / --key)")?;
                subtitle.push_str(&format!(" • key=\"{key}\""));
                playfair(txt, key, dec)
            }
            CipherKind::Affine => {
                let (a, b) = cfg
                    .affine_keys
                    .ok_or("Missing Affine keys (--affine A,B)")?;
                subtitle.push_str(&format!(" • a={a}, b={b}"));
                affine(txt, a, b, dec)
            }
            CipherKind::RailFence => {
                let r = cfg
                    .rails
                    .ok_or("Missing rail count (--rails / -r) for Rail Fence cipher")?;
                subtitle.push_str(&format!(" • rails={r}"));
                rail_fence(txt, r, dec)
            }
            CipherKind::XorHex => {
                let key = cfg
                    .keyword
                    .as_deref()
                    .ok_or("Missing XOR key (-k / --key)")?;
                subtitle.push_str(&format!(" • key=\"{key}\""));
                xor_hex_cipher(txt, key, dec)
            }
            CipherKind::Base64 => {
                if dec {
                    base64_decode(txt)
                } else {
                    Ok(base64_encode(txt))
                }
            }
            CipherKind::Hex => {
                if dec {
                    hex_decode(txt)
                } else {
                    Ok(hex_encode(txt))
                }
            }
        }
    })?;

    if cfg.encoding_layer != EncodingLayer::None {
        subtitle.push_str(&format!(" • {}", cfg.encoding_layer.name()));
    }

    if raw_mode {
        println!("{output}");
    } else {
        print_result_box(cfg.cipher.name(), &subtitle, &output);
        if cfg.show_freq {
            print_frequency_chart(cfg.cipher.name(), &output);
        }
    }

    if let Some(path) = cfg.output_file {
        fs::write(&path, &output)
            .map_err(|e| format!("Failed to write output file '{path}': {e}"))?;
        if !raw_mode {
            println!("{GREEN}  ✔ Saved output to '{path}'.{RESET}");
        }
    }

    Ok(())
}

fn main() {
    let result = match parse_args() {
        Ok(None) => run_interactive_tui(),
        Ok(Some(cfg)) => run_cli(cfg),
        Err(e) => Err(e),
    };

    if let Err(err) = result {
        eprintln!("{RED}{BOLD}Error:{RESET} {err}");
        process::exit(1);
    }
}
