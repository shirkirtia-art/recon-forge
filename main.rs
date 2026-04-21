use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

const HTTPX_OUTPUT: &str = "httpx_raw.jsonl";
const LIVE_URLS: &str = "live_urls.txt";
const WHATWEB_RESULTS: &str = "whatweb_results.json";
const WEBANALYZE_OUTPUT: &str = "webanalyze.json";
const FINAL_OUTPUT: &str = "HTWW_v2.json";
const STATS_OUTPUT: &str = "HTWW_stats.json";

#[derive(Debug, Serialize, Deserialize)]
struct ScanStats {
    total_subdomains: usize,
    live_urls: usize,
    unique_final_urls: usize,
    status_breakdown: HashMap<u16, usize>,
    tech_frequency: HashMap<String, usize>,
    server_distribution: HashMap<String, usize>,
    cdn_usage: HashMap<String, usize>,
    scan_timestamp: String,
    tools_used: Vec<String>,
    errors: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: htww_v2 <path/to/subdomains.txt>");
        std::process::exit(1);
    }
    
    let subdomains_file = PathBuf::from(&args[1]);
    if !subdomains_file.exists() {
        eprintln!("Error: file not found: {}", subdomains_file.display());
        std::process::exit(1);
    }

    let start_time = std::time::Instant::now();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║           HTWW v2 - Enhanced Recon Pipeline              ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("[*] Input: {}", subdomains_file.display());
    println!("[*] Start time: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    
    let mut stats = ScanStats {
        total_subdomains: count_lines(&subdomains_file)?,
        live_urls: 0,
        unique_final_urls: 0,
        status_breakdown: HashMap::new(),
        tech_frequency: HashMap::new(),
        server_distribution: HashMap::new(),
        cdn_usage: HashMap::new(),
        scan_timestamp: chrono::Local::now().to_rfc3339(),
        tools_used: vec!["httpx".to_string()],
        errors: vec![],
    };

    println!("[*] Total subdomains to scan: {}", stats.total_subdomains);
    
    // Phase 1: HTTP probing
    run_httpx(&subdomains_file, &mut stats).await?;
    extract_live_urls(&mut stats).await?;
    
    let live_urls_path = PathBuf::from(LIVE_URLS);
    if !live_urls_path.exists() || std::fs::metadata(&live_urls_path)?.len() == 0 {
        eprintln!("[!] No live URLs found. Exiting.");
        std::process::exit(1);
    }

    println!("[*] Live URLs discovered: {}", stats.live_urls);
    println!("[*] Running technology fingerprinting tools in parallel...");
    
    // Phase 2: Technology detection (parallel)
    // Note: Run sequentially to avoid multiple mutable borrows of stats
    let wr = run_whatweb(&live_urls_path, &mut stats).await;
    let war = run_webanalyze(&live_urls_path, &mut stats).await;
    
    if let Err(e) = wr { stats.errors.push(format!("WhatWeb error: {}", e)); }
    if let Err(e) = war { stats.errors.push(format!("Webanalyze error: {}", e)); }

    // Phase 3: Merge and enrich
    let mut records = merge_outputs(&mut stats)?;
    enrich_records(&mut records, &mut stats)?;
    
    // Phase 4: Write outputs
    write_final_output(&records, &stats)?;
    write_stats(&stats)?;
    cleanup()?;
    
    let elapsed = start_time.elapsed();
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║                    Scan Complete                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("[+] Total time: {:.2}s", elapsed.as_secs_f64());
    println!("[+] URLs scanned: {} → {} unique endpoints", stats.live_urls, stats.unique_final_urls);
    println!("[+] Main output: {}", FINAL_OUTPUT);
    println!("[+] Statistics: {}", STATS_OUTPUT);
    println!("[+] Live URLs: {}", LIVE_URLS);
    
    if !stats.errors.is_empty() {
        println!("\n[!] Warnings/Errors: {}", stats.errors.len());
        for err in &stats.errors { println!("    - {}", err); }
    }
    
    Ok(())
}

fn count_lines(path: &Path) -> Result<usize> {
    Ok(std::fs::read_to_string(path)?.lines().count())
}

async fn run_httpx(subdomains: &Path, stats: &mut ScanStats) -> Result<()> {
    println!("\n[Phase 1] Running httpx...");
    let status = Command::new("httpx")
        .args([
            "-l", subdomains.to_str().unwrap(),
            "-silent",
            "-sc", "-title", "-web-server", "-td", "-ct", "-cl", "-bp", "-rt",
            "-hash", "sha256",
            "-ip", "-cname", "-cdn", "-location",
            "-follow-redirects", "-max-redirects", "3",
            "-fep", "-json",
            "-o", HTTPX_OUTPUT,
            "-stats", "-random-agent",
            "-timeout", "10", "-t", "100", "-rl", "250",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute httpx")?;
    
    if !status.success() {
        let msg = format!("httpx exited with status: {}", status);
        eprintln!("[!] {}", msg);
        stats.errors.push(msg);
    } else {
        println!("[✓] httpx completed successfully");
    }
    
    Ok(())
}

async fn extract_live_urls(stats: &mut ScanStats) -> Result<()> {
    println!("[*] Extracting live URLs...");
    let raw = std::fs::read_to_string(HTTPX_OUTPUT).unwrap_or_default();
    let mut urls: Vec<String> = Vec::new();
    let mut failed_parses = 0;
    
    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() { continue; }
        
        match serde_json::from_str::<Value>(line) {
            Ok(v) => {
                let url = v.get("url")
                    .or_else(|| v.get("input"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                if !url.is_empty() { urls.push(url); }
            }
            Err(e) => {
                failed_parses += 1;
                if failed_parses <= 3 {
                    stats.errors.push(format!("Parse error at line {}: {}", idx + 1, e));
                }
            }
        }
    }
    
    if failed_parses > 3 {
        stats.errors.push(format!("... and {} more parse errors", failed_parses - 3));
    }
    
    stats.live_urls = urls.len();
    std::fs::write(LIVE_URLS, urls.join("\n") + "\n")?;
    println!("[✓] Extracted {} live URLs", urls.len());
    Ok(())
}

async fn run_whatweb(live_urls: &Path, stats: &mut ScanStats) -> Result<()> {
    println!("[Phase 2a] Running WhatWeb...");
    stats.tools_used.push("whatweb".to_string());
    
    let status = Command::new("whatweb")
        .args([
            "-i", live_urls.to_str().unwrap(),
            "-a", "3",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "--no-errors",
            &format!("--log-json={}", WHATWEB_RESULTS),
            "-t", "50",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .context("Failed to execute whatweb")?;
    
    if !status.success() {
        let msg = format!("whatweb exited with status: {}", status);
        eprintln!("[!] {}", msg);
        return Err(anyhow::anyhow!(msg));
    }
    
    // Validate output
    let output_size = std::fs::metadata(WHATWEB_RESULTS)
        .map(|m| m.len())
        .unwrap_or(0);
    
    if output_size == 0 {
        let msg = "WhatWeb produced empty output".to_string();
        eprintln!("[!] {}", msg);
        return Err(anyhow::anyhow!(msg));
    }
    
    println!("[✓] WhatWeb completed ({} bytes)", output_size);
    Ok(())
}

async fn run_webanalyze(live_urls: &Path, stats: &mut ScanStats) -> Result<()> {
    println!("[Phase 2b] Running webanalyze...");
    stats.tools_used.push("webanalyze".to_string());
    
    // Update signatures first
    let _ = Command::new("webanalyze")
        .arg("-update")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    
    let status = Command::new("webanalyze")
        .args([
            "-hosts", live_urls.to_str().unwrap(),
            "-crawl", "1",
            "-output", "json",
            WEBANALYZE_OUTPUT,
            "-silent",
            "-worker", "32",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .context("Failed to execute webanalyze")?;
    
    if !status.success() {
        let msg = format!("webanalyze exited with status: {}", status);
        eprintln!("[!] {}", msg);
        return Err(anyhow::anyhow!(msg));
    }
    
    // Validate output
    let output_size = std::fs::metadata(WEBANALYZE_OUTPUT)
        .map(|m| m.len())
        .unwrap_or(0);
    
    if output_size == 0 {
        let msg = "Webanalyze produced empty output".to_string();
        eprintln!("[!] {}", msg);
        return Err(anyhow::anyhow!(msg));
    }
    
    println!("[✓] webanalyze completed ({} bytes)", output_size);
    Ok(())
}

// Normalize technology names for deduplication
fn normalize_tech_name(name: &str) -> String {
    name.split_whitespace()
        .next()
        .unwrap_or(name)
        .to_lowercase()
        .trim_end_matches(".js")
        .trim_end_matches(".css")
        .to_string()
}

// Enhanced technology merging with confidence scoring
fn merge_techs_advanced(rec: &mut Map<String, Value>, new_techs: Vec<String>, source: &str) {
    if new_techs.is_empty() { return; }
    
    let existing = rec.entry("techs").or_insert(Value::Array(vec![]));
    if let Value::Array(arr) = existing {
        // Build existing tech map
        let mut existing_map: HashMap<String, String> = HashMap::new();
        for tech in arr.iter() {
            if let Some(s) = tech.as_str() {
                let normalized = normalize_tech_name(s);
                existing_map.insert(normalized, s.to_string());
            }
        }
        
        // Add new techs, preferring versioned entries
        for tech in &new_techs {  // Borrow instead of move
            let normalized = normalize_tech_name(tech);
            
            match existing_map.get(&normalized) {
                Some(existing_tech) => {
                    // If new tech has version and existing doesn't, replace
                    if tech.contains(' ') && !existing_tech.contains(' ') {
                        if let Some(pos) = arr.iter().position(|v| v.as_str() == Some(existing_tech)) {
                            arr[pos] = Value::String(tech.clone());
                        }
                        existing_map.insert(normalized, tech.clone());
                    }
                }
                None => {
                    arr.push(Value::String(tech.clone()));
                    existing_map.insert(normalized, tech.clone());
                }
            }
        }
    }
    
    // Track detection sources
    let sources = rec.entry("tech_sources").or_insert(Value::Object(Map::new()));
    if let Value::Object(src_map) = sources {
        for tech in &new_techs {  // Borrow instead of move
            let normalized = normalize_tech_name(tech);
            let tech_sources = src_map.entry(normalized).or_insert(Value::Array(vec![]));
            if let Value::Array(arr) = tech_sources {
                let src_val = Value::String(source.to_string());
                if !arr.contains(&src_val) {
                    arr.push(src_val);
                }
            }
        }
    }
}

fn canonical_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    if let Some(pos) = url.find("://") {
        let scheme = url[..pos].to_lowercase();
        let rest = &url[pos + 3..];
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if path.is_empty() {
            return format!("{}://{}", scheme, host.to_lowercase());
        }
        return format!("{}://{}/{}", scheme, host.to_lowercase(), path);
    }
    format!("https://{}", url.to_lowercase())
}

fn merge_outputs(stats: &mut ScanStats) -> Result<HashMap<String, Map<String, Value>>> {
    println!("\n[Phase 3] Merging outputs...");
    let mut records: HashMap<String, Map<String, Value>> = HashMap::new();

    // ══════════════════════════════════════════════════════════════
    // 1. Parse httpx
    // ══════════════════════════════════════════════════════════════
    println!("[*] Processing httpx data...");
    let httpx_raw = std::fs::read_to_string(HTTPX_OUTPUT).unwrap_or_default();
    let mut httpx_count = 0;
    
    for line in httpx_raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        httpx_count += 1;

        let url_key = v.get("final_url")
            .or_else(|| v.get("url"))
            .or_else(|| v.get("input"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        
        if url_key.is_empty() { continue; }

        let input_url = v.get("url")
            .or_else(|| v.get("input"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();

        let key = canonical_url(&url_key);
        let rec = records.entry(key.clone()).or_default();

        // Status code
        if let Some(code) = v.get("status_code").and_then(|c| c.as_u64()) {
            let code_u16 = code as u16;
            rec.entry("status").or_insert(Value::Number(code.into()));
            *stats.status_breakdown.entry(code_u16).or_insert(0) += 1;
        }

        // Track input sources
        if !input_url.is_empty() && canonical_url(&input_url) != key {
            let inputs = rec.entry("inputs").or_insert(Value::Array(vec![]));
            if let Value::Array(arr) = inputs {
                let vi = Value::String(input_url);
                if !arr.contains(&vi) { arr.push(vi); }
            }
        }

        // Basic fields
        set_str(rec, "title", &v, "title");
        set_str(rec, "server", &v, "webserver");
        set_str(rec, "content_type", &v, "content_type");
        set_num(rec, "content_length", &v, "content_length");
        set_str(rec, "ip", &v, "ip");
        set_str(rec, "cdn_name", &v, "cdn_name");

        if let Some(b) = v.get("cdn").and_then(|x| x.as_bool()) {
            rec.insert("cdn".into(), Value::Bool(b));
            if b {
                if let Some(cdn_name) = v.get("cdn_name").and_then(|c| c.as_str()) {
                    *stats.cdn_usage.entry(cdn_name.to_string()).or_insert(0) += 1;
                }
            }
        }

        // Response time
        if let Some(rt) = v.get("response_time").and_then(|x| x.as_f64()) {
            if let Some(n) = serde_json::Number::from_f64((rt * 100.0).round() / 100.0) {
                rec.insert("response_time".into(), Value::Number(n));
            }
        }

        // CNAME
        if let Some(c) = v.get("cname") {
            rec.insert("cname".into(), c.clone());
        }

        // Redirect chain
        {
            let codes: Vec<u64> = v.get("chain_status_codes")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                .unwrap_or_default();
            
            let locs: Vec<String> = v.get("redirects")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_else(|| {
                    v.get("location")
                        .and_then(|x| x.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default()
                });
            
            if !codes.is_empty() {
                let chain: Vec<Value> = codes.iter().enumerate().map(|(i, code)| {
                    Value::String(match locs.get(i) {
                        Some(loc) => format!("{} → {}", code, loc),
                        None => code.to_string(),
                    })
                }).collect();
                rec.insert("redirect_chain".into(), Value::Array(chain));
            }
        }

        // Hashes
        let sha = v.get("hash")
            .and_then(|h| h.get("body_sha256"))
            .or_else(|| v.get("body_sha256"))
            .cloned();
        
        if let Some(sha) = sha {
            let mut h: Map<String, Value> = Map::new();
            h.insert("body_sha256".into(), sha);
            rec.insert("hashes".into(), Value::Object(h));
        }

        // Security headers (expanded list)
        if let Some(hdrs) = v.get("response_headers").and_then(|h| h.as_object()) {
            let keep: HashSet<&str> = [
                "server", "x-powered-by", "content-security-policy",
                "x-frame-options", "strict-transport-security",
                "x-content-type-options", "access-control-allow-origin",
                "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
                "x-drupal-cache", "x-varnish", "via", "cf-ray",
                "www-authenticate", "x-wp-total", "permissions-policy",
                "referrer-policy", "x-xss-protection", "expect-ct",
                "alt-svc", "link", "x-cache", "age",
            ].iter().copied().collect();
            
            let filtered: Map<String, Value> = hdrs.iter()
                .filter(|(k, _)| keep.contains(k.to_lowercase().as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            
            if !filtered.is_empty() {
                rec.insert("headers".into(), Value::Object(filtered));
            }
        }

        // TLS info
        if let Some(tls) = v.get("tls") {
            let mut t: Map<String, Value> = Map::new();
            
            if let Some(s) = tls.get("subject_cn").and_then(|x| x.as_str()) {
                t.insert("subject_cn".into(), Value::String(s.to_string()));
            }
            if let Some(s) = tls.get("not_after").and_then(|x| x.as_str()) {
                t.insert("expiry".into(), Value::String(s.to_string()));
            }
            if let Some(arr) = tls.get("issuer_org").and_then(|x| x.as_array()) {
                if let Some(first) = arr.first().and_then(|x| x.as_str()) {
                    t.insert("issuer".into(), Value::String(first.to_string()));
                }
            }
            
            if !t.is_empty() {
                rec.insert("tls".into(), Value::Object(t));
            }
        }

        // Extract httpx techs
        merge_techs_advanced(rec, extract_httpx_techs(&v), "httpx");
        
        // Track server distribution
        if let Some(server) = v.get("webserver").and_then(|s| s.as_str()) {
            let server_base = server.split('/').next().unwrap_or(server);
            *stats.server_distribution.entry(server_base.to_string()).or_insert(0) += 1;
        }
    }
    
    println!("[✓] Processed {} httpx records", httpx_count);

    // ══════════════════════════════════════════════════════════════
    // 2. Parse WhatWeb
    // ══════════════════════════════════════════════════════════════
    println!("[*] Processing WhatWeb data...");
    
    let ww_noise: HashSet<&str> = [
        "RedirectLocation", "IP", "Country", "HTTPServer", "UncommonHeaders",
        "Via-Proxy", "Cookies", "Meta-Author", "Meta-Refresh", "Title",
        "Email", "Script", "PasswordField", "Frame", "HTML5", "Bootstrap",
        "JQuery", "Open-Graph-Protocol", "Google-Analytics", "Modernizr",
        "Prototype", "Varnish", "HTTP-Status",
    ].iter().copied().collect();

    let ww_raw = std::fs::read_to_string(WHATWEB_RESULTS).unwrap_or_default();
    let ww_entries = parse_whatweb_json(&ww_raw);
    let mut ww_count = 0;
    
    for entry in ww_entries {
        let target = entry.get("target").and_then(|t| t.as_str()).unwrap_or("");
        if target.is_empty() { continue; }
        
        let key = canonical_url(target);
        let rec = records.entry(key).or_default();
        ww_count += 1;

        if let Some(plugins) = entry.get("plugins").and_then(|p| p.as_object()) {
            let mut techs: Vec<String> = Vec::new();
            
            for (name, data) in plugins {
                if ww_noise.contains(name.as_str()) { continue; }
                
                let ver = data.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                
                techs.push(if ver.is_empty() {
                    name.clone()
                } else {
                    format!("{} {}", name, ver)
                });
            }
            
            merge_techs_advanced(rec, techs, "whatweb");
        }
        
        // Extract status if not already set
        if let Some(s) = entry.get("http_status").and_then(|x| x.as_u64()) {
            rec.entry("status").or_insert(Value::Number(s.into()));
        }
    }
    
    println!("[✓] Processed {} WhatWeb records", ww_count);

    // ══════════════════════════════════════════════════════════════
    // 3. Parse Webanalyze
    // ══════════════════════════════════════════════════════════════
    println!("[*] Processing webanalyze data...");
    
    let wa_raw = std::fs::read_to_string(WEBANALYZE_OUTPUT).unwrap_or_default();
    let wa_entries = match serde_json::from_str::<Value>(&wa_raw) {
        Ok(Value::Array(arr)) => arr,
        Ok(other) => vec![other],
        Err(_) => vec![],
    };
    
    let mut wa_count = 0;
    
    for entry in wa_entries {
        let host = entry.get("hostname")
            .or_else(|| entry.get("host"))
            .or_else(|| entry.get("url"))
            .and_then(|h| h.as_str())
            .unwrap_or("");
        
        if host.is_empty() { continue; }
        
        let key = canonical_url(host);
        let rec = records.entry(key).or_default();
        wa_count += 1;

        if let Some(Value::Array(matches)) = entry.get("matches") {
            let mut techs: Vec<String> = Vec::new();
            let mut cats: HashSet<String> = HashSet::new();
            
            for m in matches {
                let app = m.get("app").and_then(|a| a.as_str()).unwrap_or("");
                if app.is_empty() { continue; }
                
                let ver = m.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                
                techs.push(if ver.is_empty() {
                    app.to_string()
                } else {
                    format!("{} {}", app, ver)
                });
                
                if let Some(Value::Array(ac)) = m.get("categories") {
                    for c in ac {
                        if let Some(s) = c.as_str() {
                            cats.insert(s.to_string());
                        }
                    }
                }
            }
            
            merge_techs_advanced(rec, techs, "webanalyze");
            
            // Merge categories
            if !cats.is_empty() {
                let existing = rec.entry("categories").or_insert(Value::Array(vec![]));
                if let Value::Array(arr) = existing {
                    for c in cats {
                        let v = Value::String(c);
                        if !arr.contains(&v) {
                            arr.push(v);
                        }
                    }
                }
            }
        }
    }
    
    println!("[✓] Processed {} webanalyze records", wa_count);

    stats.unique_final_urls = records.len();
    Ok(records)
}

fn enrich_records(records: &mut HashMap<String, Map<String, Value>>, stats: &mut ScanStats) -> Result<()> {
    println!("[*] Enriching records...");
    
    for (_url, rec) in records.iter_mut() {
        // Sort and deduplicate arrays
        sort_str_arr(rec, "techs");
        sort_str_arr(rec, "categories");
        sort_str_arr(rec, "inputs");
        
        // Calculate tech confidence scores
        if let Some(Value::Object(tech_sources)) = rec.get("tech_sources") {
            let mut confidence_map: Map<String, Value> = Map::new();
            
            for (tech, sources) in tech_sources {
                if let Value::Array(source_arr) = sources {
                    let confidence = match source_arr.len() {
                        3 => "high",      // All 3 tools agree
                        2 => "medium",    // 2 tools agree
                        _ => "low",       // Single tool detection
                    };
                    confidence_map.insert(tech.clone(), Value::String(confidence.to_string()));
                }
            }
            
            if !confidence_map.is_empty() {
                rec.insert("tech_confidence".into(), Value::Object(confidence_map));
            }
        }
        
        // Build tech frequency stats
        if let Some(Value::Array(techs)) = rec.get("techs") {
            for tech in techs {
                if let Some(s) = tech.as_str() {
                    let normalized = normalize_tech_name(s);
                    *stats.tech_frequency.entry(normalized).or_insert(0) += 1;
                }
            }
        }
        
        // Add risk indicators
        let mut risk_flags: Vec<String> = Vec::new();
        
        // Missing security headers
        if let Some(Value::Object(headers)) = rec.get("headers") {
            if !headers.contains_key("strict-transport-security") {
                risk_flags.push("no_hsts".to_string());
            }
            if !headers.contains_key("x-frame-options") && !headers.contains_key("content-security-policy") {
                risk_flags.push("no_clickjacking_protection".to_string());
            }
            if !headers.contains_key("x-content-type-options") {
                risk_flags.push("no_mime_sniffing_protection".to_string());
            }
        } else {
            risk_flags.push("no_security_headers".to_string());
        }
        
        // Outdated/vulnerable techs (basic detection)
        if let Some(Value::Array(techs)) = rec.get("techs") {
            for tech in techs {
                if let Some(s) = tech.as_str() {
                    let lower = s.to_lowercase();
                    
                    // Check for very old versions (heuristic)
                    if lower.contains("php 5") || lower.contains("php 4") {
                        risk_flags.push("outdated_php".to_string());
                    }
                    if lower.contains("apache 2.2") || lower.contains("apache 2.0") {
                        risk_flags.push("outdated_apache".to_string());
                    }
                    if lower.contains("wordpress") && !lower.contains("6.") {
                        risk_flags.push("potentially_outdated_wordpress".to_string());
                    }
                    if lower.contains("jquery 1.") || lower.contains("jquery 2.") {
                        risk_flags.push("outdated_jquery".to_string());
                    }
                }
            }
        }
        
        if !risk_flags.is_empty() {
            rec.insert("risk_indicators".into(), Value::Array(
                risk_flags.into_iter().map(Value::String).collect()
            ));
        }
        
        // Add metadata timestamp
        rec.insert("scanned_at".into(), Value::String(
            chrono::Local::now().to_rfc3339()
        ));
    }
    
    println!("[✓] Enrichment complete");
    Ok(())
}

fn write_final_output(records: &HashMap<String, Map<String, Value>>, stats: &ScanStats) -> Result<()> {
    println!("[*] Writing final output...");
    
    let mut sorted_keys: Vec<String> = records.keys().cloned().collect();
    sorted_keys.sort();
    
    let mut final_obj: Map<String, Value> = Map::new();
    
    // Add metadata header
    let mut meta = Map::new();
    meta.insert("version".into(), Value::String("2.0".to_string()));
    meta.insert("timestamp".into(), Value::String(stats.scan_timestamp.clone()));
    meta.insert("total_urls".into(), Value::Number(stats.unique_final_urls.into()));
    meta.insert("tools".into(), Value::Array(
        stats.tools_used.iter().map(|s| Value::String(s.clone())).collect()
    ));
    final_obj.insert("_metadata".into(), Value::Object(meta));
    
    // Add URL records
    for k in sorted_keys {
        if let Some(rec) = records.get(&k) {
            if rec.contains_key("status") || rec.contains_key("techs") || rec.contains_key("title") {
                final_obj.insert(k, Value::Object(rec.clone()));
            }
        }
    }
    
    let out = std::fs::File::create(FINAL_OUTPUT)
        .context("Failed to create output file")?;
    
    let record_count = final_obj.len() - 1; // Subtract 1 for _metadata
    serde_json::to_writer_pretty(out, &Value::Object(final_obj))
        .context("Failed to write output file")?;
    
    println!("[✓] Wrote {} URL records to {}", record_count, FINAL_OUTPUT);
    Ok(())
}

fn write_stats(stats: &ScanStats) -> Result<()> {
    println!("[*] Writing statistics...");
    
    // Sort frequency maps
    let mut tech_freq: Vec<_> = stats.tech_frequency.iter().collect();
    tech_freq.sort_by(|a, b| b.1.cmp(a.1));
    let top_techs: HashMap<String, usize> = tech_freq.into_iter()
        .take(20)
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    
    let mut server_dist: Vec<_> = stats.server_distribution.iter().collect();
    server_dist.sort_by(|a, b| b.1.cmp(a.1));
    let top_servers: HashMap<String, usize> = server_dist.into_iter()
        .take(10)
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    
    let output = serde_json::json!({
        "scan_summary": {
            "total_subdomains": stats.total_subdomains,
            "live_urls": stats.live_urls,
            "unique_endpoints": stats.unique_final_urls,
            "timestamp": stats.scan_timestamp,
        },
        "status_codes": stats.status_breakdown,
        "top_technologies": top_techs,
        "top_servers": top_servers,
        "cdn_usage": stats.cdn_usage,
        "tools_used": stats.tools_used,
        "errors": stats.errors,
    });
    
    let out = std::fs::File::create(STATS_OUTPUT)?;
    serde_json::to_writer_pretty(out, &output)?;
    
    println!("[✓] Statistics written to {}", STATS_OUTPUT);
    Ok(())
}

// Helper functions
fn set_str(rec: &mut Map<String, Value>, out_key: &str, src: &Value, src_key: &str) {
    if rec.contains_key(out_key) { return; }
    if let Some(s) = src.get(src_key).and_then(|v| v.as_str()) {
        if !s.is_empty() {
            rec.insert(out_key.into(), Value::String(s.to_string()));
        }
    }
}

fn set_num(rec: &mut Map<String, Value>, out_key: &str, src: &Value, src_key: &str) {
    if rec.contains_key(out_key) { return; }
    if let Some(n) = src.get(src_key) {
        if n.is_number() {
            rec.insert(out_key.into(), n.clone());
        }
    }
}

fn sort_str_arr(rec: &mut Map<String, Value>, key: &str) {
    if let Some(Value::Array(arr)) = rec.get_mut(key) {
        arr.sort_by(|a, b| {
            a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or(""))
        });
        arr.dedup_by(|a, b| {
            a.as_str().unwrap_or("") == b.as_str().unwrap_or("")
        });
    }
}

fn extract_httpx_techs(v: &Value) -> Vec<String> {
    let mut techs = Vec::new();
    
    if let Some(obj) = v.get("tech").and_then(|t| t.as_object()) {
        for (name, data) in obj {
            let ver = data.get("version")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            
            techs.push(if ver.is_empty() {
                name.clone()
            } else {
                format!("{} {}", name, ver)
            });
        }
    }
    
    if let Some(Value::Array(arr)) = v.get("technologies") {
        for t in arr {
            if let Some(s) = t.as_str() {
                techs.push(s.to_string());
            }
        }
    }
    
    techs
}

fn parse_whatweb_json(raw: &str) -> Vec<Value> {
    let raw = raw.trim();
    if raw.is_empty() { return vec![]; }
    
    // Try parsing as JSON array first
    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(raw) {
        return arr;
    }
    
    // Fall back to line-by-line JSONL parsing
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

fn cleanup() -> Result<()> {
    println!("[*] Cleaning up intermediate files...");
    
    for f in &[WHATWEB_RESULTS, WEBANALYZE_OUTPUT, HTTPX_OUTPUT] {
        match std::fs::remove_file(f) {
            Ok(_) => println!("    ✓ Deleted: {}", f),
            Err(e) => eprintln!("    ! Could not delete {}: {}", f, e),
        }
    }
    
    Ok(())
}
