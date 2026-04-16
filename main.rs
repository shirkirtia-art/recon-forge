use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const HTTPX_OUTPUT: &str = "httpx_raw.jsonl";
const LIVE_URLS: &str = "live_urls.txt";
const WHATWEB_RESULTS: &str = "whatweb_results.json";
const WHATWEB_DETAILED: &str = "whatweb_detailed.json";
const WEBANALYZE_OUTPUT: &str = "webanalyze.jsonl";
const FINAL_OUTPUT: &str = "HTWW.json";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: htww <path/to/subdomains.txt>");
        std::process::exit(1);
    }

    let subdomains_file = PathBuf::from(&args[1]);
    if !subdomains_file.exists() {
        eprintln!("Error: file not found: {}", subdomains_file.display());
        std::process::exit(1);
    }

    println!("[*] Starting HTWW recon pipeline");
    println!("[*] Input: {}", subdomains_file.display());

    // Step 1: Run httpx
    run_httpx(&subdomains_file).await?;

    // Step 2: Extract live URLs
    extract_live_urls().await?;

    let live_urls_path = PathBuf::from(LIVE_URLS);
    if !live_urls_path.exists() || std::fs::metadata(&live_urls_path)?.len() == 0 {
        eprintln!("[!] No live URLs found. Exiting.");
        std::process::exit(1);
    }

    // Step 3: Run WhatWeb and Webanalyze in parallel
    println!("[*] Running WhatWeb and Webanalyze...");
    let (whatweb_result, webanalyze_result) =
        tokio::join!(run_whatweb(&live_urls_path), run_webanalyze(&live_urls_path));

    whatweb_result?;
    webanalyze_result?;

    // Step 4: Merge
    merge_outputs()?;

    // Step 5: Cleanup
    cleanup()?;

    println!("[+] Done. Output: {FINAL_OUTPUT}");
    println!("[+] Live URLs: {LIVE_URLS}");
    Ok(())
}

async fn run_httpx(subdomains: &Path) -> Result<()> {
    println!("[*] Running httpx...");
    let status = Command::new("httpx")
        .args([
            "-l", subdomains.to_str().unwrap(),
            "-silent",
            "-sc", "-title", "-web-server", "-td", "-ct", "-cl", "-bp", "-rt",
            "-hash", "sha256",
            "-ip", "-cname", "-cdn", "-location",
            "-follow-redirects", "-max-redirects", "3",
            "-fep",
            "-json", "-irh", "-irr",
            "-o", HTTPX_OUTPUT,
            "-stats", "-random-agent",
            "-timeout", "10",
            "-t", "100",
            "-rl", "250",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute httpx — is it installed and in PATH?")?;

    if !status.success() {
        eprintln!("[!] httpx exited with status: {status}");
    }
    println!("[+] httpx complete");
    Ok(())
}

async fn extract_live_urls() -> Result<()> {
    println!("[*] Extracting live URLs from httpx output...");

    let raw = std::fs::read_to_string(HTTPX_OUTPUT).unwrap_or_default();
    let mut urls: Vec<String> = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => {
                if let Some(url) = v.get("url").or_else(|| v.get("input"))
                    .and_then(|u| u.as_str())
                    .filter(|s| !s.is_empty())
                {
                    urls.push(url.to_string());
                }
            }
            Err(_) => eprintln!("[!] Skipping non-JSON line in httpx output"),
        }
    }

    std::fs::write(LIVE_URLS, urls.join("\n") + "\n")?;
    println!("[+] Extracted {} live URLs", urls.len());
    Ok(())
}

async fn run_whatweb(live_urls: &Path) -> Result<()> {
    println!("[*] Running WhatWeb...");

    // WhatWeb --log-json writes a JSON array but may have a trailing comma on
    // the last entry (known WhatWeb quirk). Our load_whatweb_json() handles this.
    let status = Command::new("whatweb")
        .args([
            "-i", live_urls.to_str().unwrap(),
            "-a", "3",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "-v",
            "--no-errors",
            &format!("--log-json={WHATWEB_RESULTS}"),
            &format!("--log-json-verbose={WHATWEB_DETAILED}"),
            "-t", "50",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute whatweb — is it installed and in PATH?")?;

    if !status.success() {
        eprintln!("[!] whatweb exited with status: {status}");
    }
    println!("[+] WhatWeb complete");
    Ok(())
}

async fn run_webanalyze(live_urls: &Path) -> Result<()> {
    println!("[*] Updating webanalyze signatures...");
    let _ = Command::new("webanalyze")
        .arg("-update")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await;

    println!("[*] Running webanalyze...");

    // ROOT CAUSE: webanalyze's -output flag only sets the FORMAT ("json"/"csv"/"text").
    // It does NOT accept a filename — the prior code treated "webanalyze.json" as a
    // host to scan. All JSON output goes to stdout and was being lost.
    // FIX: pipe stdout, capture it, write it to our file ourselves.
    // Also: do NOT use -silent — that suppresses the JSON stdout we need to capture.
    let mut child = Command::new("webanalyze")
        .args([
            "-hosts", live_urls.to_str().unwrap(),
            "-crawl", "1",
            "-output", "json",   // format only — no filename here
            "-worker", "32",
        ])
        .stdout(Stdio::piped())   // capture stdout → save to file
        .stderr(Stdio::inherit()) // show stderr in terminal normally
        .spawn()
        .context("Failed to execute webanalyze — is it installed and in PATH?")?;

    let mut stdout_bytes = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut stdout_bytes).await
            .context("Failed to read webanalyze stdout")?;
    }

    let status = child.wait().await.context("Failed to wait for webanalyze")?;
    if !status.success() {
        eprintln!("[!] webanalyze exited with status: {status}");
    }

    if stdout_bytes.trim_ascii().is_empty() {
        eprintln!("[!] webanalyze produced no output — saving empty file");
        std::fs::write(WEBANALYZE_OUTPUT, "")?;
    } else {
        // webanalyze -output json writes JSONL (one object per line) to stdout
        std::fs::write(WEBANALYZE_OUTPUT, &stdout_bytes)
            .context("Failed to save webanalyze output")?;
        let line_count = stdout_bytes.iter().filter(|&&b| b == b'\n').count();
        println!("[+] webanalyze: captured ~{line_count} entries → {WEBANALYZE_OUTPUT}");
    }

    println!("[+] webanalyze complete");
    Ok(())
}

fn merge_outputs() -> Result<()> {
    println!("[*] Merging outputs into {FINAL_OUTPUT}...");

    // WhatWeb writes a JSON array but may have trailing-comma quirks.
    // Use our robust three-stage loader.
    let whatweb_basic    = load_whatweb_json(WHATWEB_RESULTS);
    let whatweb_detailed = load_whatweb_json(WHATWEB_DETAILED);
    let mut whatweb_combined = whatweb_basic;
    whatweb_combined.extend(whatweb_detailed);

    // webanalyze stdout is JSONL (one object per line)
    let webanalyze = load_jsonl_or_empty(WEBANALYZE_OUTPUT);

    // httpx output file is also JSONL
    let httpx = load_jsonl_or_empty(HTTPX_OUTPUT);

    println!(
        "[*] Counts — httpx: {}, whatweb: {}, webanalyze: {}",
        httpx.len(), whatweb_combined.len(), webanalyze.len()
    );

    let merged = serde_json::json!({
        "whatweb_output":    whatweb_combined,
        "webanalyze_output": webanalyze,
        "httpx_output":      httpx,
    });

    let out = std::fs::File::create(FINAL_OUTPUT)
        .context("Failed to create HTWW.json")?;
    serde_json::to_writer_pretty(out, &merged)
        .context("Failed to write HTWW.json")?;

    println!("[+] Merge complete → {FINAL_OUTPUT}");
    Ok(())
}

/// Robust loader for WhatWeb's --log-json output.
///
/// WhatWeb writes a JSON array, but is known to emit a trailing comma after
/// the last entry, making the file invalid JSON. We try three strategies:
///
///   1. Parse whole file as JSON array (fast path — works for valid output).
///   2. Strip the trailing comma before `]` and retry (fixes WhatWeb's quirk).
///   3. Line-by-line fallback: skip `[` / `]` lines, strip trailing commas
///      from each entry, parse individually (always works).
fn load_whatweb_json(path: &str) -> Vec<Value> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[!] Could not read {path} (may not exist)");
            return vec![];
        }
    };

    if content.trim().is_empty() {
        return vec![];
    }

    // Stage 1: try as-is
    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&content) {
        println!("[+] {path}: loaded {} entries (valid JSON array)", arr.len());
        return arr;
    }

    // Stage 2: fix trailing comma before closing ]
    let fixed = fix_trailing_comma(&content);
    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&fixed) {
        println!("[+] {path}: loaded {} entries (fixed trailing comma)", arr.len());
        return arr;
    }

    // Stage 3: line-by-line fallback
    eprintln!("[!] {path}: falling back to line-by-line parsing");
    let results: Vec<Value> = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            if trimmed.is_empty() || trimmed == "[" || trimmed == "]" {
                return None;
            }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(v) => Some(v),
                Err(_) => {
                    eprintln!("[!] {path}: skipping line: {}…",
                        &trimmed[..trimmed.len().min(80)]);
                    None
                }
            }
        })
        .collect();

    println!("[+] {path}: line-by-line got {} entries", results.len());
    results
}

/// Remove a trailing comma that appears just before the closing `]`.
/// e.g. `[{...},{...},\n]` → `[{...},{...}\n]`
fn fix_trailing_comma(s: &str) -> String {
    // Find the last `]`
    if let Some(close) = s.rfind(']') {
        let before_close = s[..close].trim_end();
        if before_close.ends_with(',') {
            let trimmed = &before_close[..before_close.len() - 1];
            return format!("{}{}", trimmed, &s[close..]);
        }
    }
    s.to_string()
}

/// Load a JSONL file (one JSON object per line) into a Vec<Value>.
fn load_jsonl_or_empty(path: &str) -> Vec<Value> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[!] Could not read {path} (may not exist)");
            return vec![];
        }
    };

    content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() { return None; }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(v) => Some(v),
                Err(e) => {
                    eprintln!("[!] {path} line {}: invalid JSON — {e}", i + 1);
                    None
                }
            }
        })
        .collect()
}

fn cleanup() -> Result<()> {
    println!("[*] Cleaning up intermediate files...");
    for f in &[WHATWEB_RESULTS, WHATWEB_DETAILED, WEBANALYZE_OUTPUT, HTTPX_OUTPUT] {
        match std::fs::remove_file(f) {
            Ok(_)  => println!("    Deleted: {f}"),
            Err(e) => eprintln!("    Could not delete {f}: {e}"),
        }
    }
    Ok(())
}
