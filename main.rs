use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

const HTTPX_OUTPUT: &str = "httpx_raw.jsonl";
const LIVE_URLS: &str = "live_urls.txt";
const WHATWEB_RESULTS: &str = "whatweb_results.json";
const WHATWEB_DETAILED: &str = "whatweb_detailed.json";
const WEBANALYZE_OUTPUT: &str = "webanalyze.json";
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

    // Step 2: Extract live URLs from httpx_raw.jsonl
    extract_live_urls().await?;

    let live_urls_path = PathBuf::from(LIVE_URLS);
    if !live_urls_path.exists() || std::fs::metadata(&live_urls_path)?.len() == 0 {
        eprintln!("[!] No live URLs found. Exiting.");
        std::process::exit(1);
    }

    // Step 3: Run WhatWeb and Webanalyze (sequentially — webanalyze needs update first)
    println!("[*] Running WhatWeb and Webanalyze...");
    let (whatweb_result, webanalyze_result) =
        tokio::join!(run_whatweb(&live_urls_path), run_webanalyze(&live_urls_path));
    whatweb_result?;
    webanalyze_result?;

    // Step 4: Merge outputs
    merge_outputs()?;

    // Step 5: Cleanup intermediate files
    cleanup()?;

    println!("[+] Done. Output: {FINAL_OUTPUT}");
    println!("[+] Live URLs: {LIVE_URLS}");
    Ok(())
}

async fn run_httpx(subdomains: &Path) -> Result<()> {
    println!("[*] Running httpx...");
    let status = Command::new("httpx")
        .args([
            "-l",
            subdomains.to_str().unwrap(),
            "-silent",
            "-sc",
            "-title",
            "-web-server",
            "-td",
            "-ct",
            "-cl",
            "-bp",
            "-rt",
            "-hash",
            "sha256",
            "-ip",
            "-cname",
            "-cdn",
            "-location",
            "-follow-redirects",
            "-max-redirects",
            "3",
            "-fep",
            "-json",
            "-irh",
            "-irr",
            "-o",
            HTTPX_OUTPUT,
            "-stats",
            "-random-agent",
            "-timeout",
            "10",
            "-t",
            "100",
            "-rl",
            "250",
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
    let raw = std::fs::read_to_string(HTTPX_OUTPUT)
        .unwrap_or_default();
    let mut urls: Vec<String> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => {
                let url = v
                    .get("url")
                    .or_else(|| v.get("input"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                if !url.is_empty() {
                    urls.push(url);
                }
            }
            Err(_) => {
                eprintln!("[!] Skipping non-JSON line in httpx output");
            }
        }
    }
    std::fs::write(LIVE_URLS, urls.join("\n") + "\n")?;
    println!("[+] Extracted {} live URLs", urls.len());
    Ok(())
}

async fn run_whatweb(live_urls: &Path) -> Result<()> {
    println!("[*] Running WhatWeb...");
    let status = Command::new("whatweb")
        .args([
            "-i",
            live_urls.to_str().unwrap(),
            "-a",
            "3",
            "-U",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "-v",
            "--no-errors",
            &format!("--log-json={WHATWEB_RESULTS}"),
            &format!("--log-json-verbose={WHATWEB_DETAILED}"),
            "-t",
            "50",
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
    let status = Command::new("webanalyze")
        .args([
            "-hosts",
            live_urls.to_str().unwrap(),
            "-crawl",
            "1",
            "-output",
            "json",
            "-silent",
            "-worker",
            "32",
        ])
        .stdout(Stdio::piped())   // Capture output for redirection
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute webanalyze — is it installed and in PATH?")?;

    if !status.success() {
        eprintln!("[!] webanalyze exited with status: {status}");
    } else {
        println!("[+] webanalyze complete");
    }
    Ok(())
}

fn merge_outputs() -> Result<()> {
    println!("[*] Merging outputs into {FINAL_OUTPUT}...");
    let whatweb_basic = load_json_array_or_empty(WHATWEB_RESULTS);
    let whatweb_detailed = load_json_array_or_empty(WHATWEB_DETAILED);
    // Combine both whatweb files into one array
    let mut whatweb_combined = whatweb_basic;
    whatweb_combined.extend(whatweb_detailed);

    let webanalyze = load_json_array_or_empty(WEBANALYZE_OUTPUT);
    let httpx = load_jsonl_or_empty(HTTPX_OUTPUT);

    let merged = serde_json::json!({
        "whatweb_output": whatweb_combined,
        "webanalyze_output": webanalyze,
        "httpx_output": httpx,
    });

    let out = std::fs::File::create(FINAL_OUTPUT)
        .context("Failed to create HTWW.json")?;
    serde_json::to_writer_pretty(out, &merged)
        .context("Failed to write HTWW.json")?;
    println!("[+] Merge complete");
    Ok(())
}

/// Load a file as a JSON array. If the file is missing or invalid, return an empty array.
fn load_json_array_or_empty(path: &str) -> Vec<Value> {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<Value>(&content) {
            Ok(Value::Array(arr)) => arr,
            Ok(other) => vec![other],
            Err(_) => {
                eprintln!("[!] Could not parse {path} as JSON");
                vec![]
            }
        },
        Err(_) => {
            eprintln!("[!] Could not read {path} (may not exist)");
            vec![]
        }
    }
}

/// Load a JSONL file (one JSON object per line) into a Vec<Value>.
fn load_jsonl_or_empty(path: &str) -> Vec<Value> {
    match std::fs::read_to_string(path) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| match serde_json::from_str::<Value>(line) {
                Ok(v) => Some(v),
                Err(_) => {
                    eprintln!("[!] Skipping invalid JSON line in {path}");
                    None
                }
            })
            .collect(),
        Err(_) => {
            eprintln!("[!] Could not read {path} (may not exist)");
            vec![]
        }
    }
}

fn cleanup() -> Result<()> {
    println!("[*] Cleaning up intermediate files...");
    for f in &[WHATWEB_RESULTS, WHATWEB_DETAILED, WEBANALYZE_OUTPUT, HTTPX_OUTPUT] {
        match std::fs::remove_file(f) {
            Ok(_) => println!(" Deleted: {f}"),
            Err(e) => eprintln!(" Could not delete {f}: {e}"),
        }
    }
    Ok(())
}