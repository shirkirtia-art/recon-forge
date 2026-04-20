use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

const HTTPX_OUTPUT: &str = "httpx_raw.jsonl";
const LIVE_URLS: &str = "live_urls.txt";
const WHATWEB_RESULTS: &str = "whatweb_results.json";
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
    run_httpx(&subdomains_file).await?;
    extract_live_urls().await?;
    let live_urls_path = PathBuf::from(LIVE_URLS);
    if !live_urls_path.exists() || std::fs::metadata(&live_urls_path)?.len() == 0 {
        eprintln!("[!] No live URLs found. Exiting.");
        std::process::exit(1);
    }
    println!("[*] Running WhatWeb and Webanalyze in parallel...");
    let (wr, war) = tokio::join!(run_whatweb(&live_urls_path), run_webanalyze(&live_urls_path));
    wr?; war?;
    merge_outputs()?;
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
            "-fep", "-json",
            "-o", HTTPX_OUTPUT,
            "-stats", "-random-agent",
            "-timeout", "10", "-t", "100", "-rl", "250",
        ])
        .stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .status().await
        .context("Failed to execute httpx")?;
    if !status.success() { eprintln!("[!] httpx exited: {status}"); }
    println!("[+] httpx complete");
    Ok(())
}

async fn extract_live_urls() -> Result<()> {
    println!("[*] Extracting live URLs...");
    let raw = std::fs::read_to_string(HTTPX_OUTPUT).unwrap_or_default();
    let mut urls: Vec<String> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            let url = v.get("url").or_else(|| v.get("input"))
                .and_then(|u| u.as_str()).unwrap_or("").to_string();
            if !url.is_empty() { urls.push(url); }
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
            "-i", live_urls.to_str().unwrap(),
            "-a", "3",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "--no-errors",
            &format!("--log-json={WHATWEB_RESULTS}"),
            "-t", "50",
        ])
        .stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .status().await
        .context("Failed to execute whatweb")?;
    if !status.success() { eprintln!("[!] whatweb exited: {status}"); }
    println!("[+] WhatWeb complete");
    Ok(())
}

async fn run_webanalyze(live_urls: &Path) -> Result<()> {
    println!("[*] Updating webanalyze signatures...");
    let _ = Command::new("webanalyze").arg("-update")
        .stdout(Stdio::inherit()).stderr(Stdio::inherit()).status().await;
    println!("[*] Running webanalyze...");
    let status = Command::new("webanalyze")
        .args([
            "-hosts", live_urls.to_str().unwrap(),
            "-crawl", "1", "-output", "json",
            WEBANALYZE_OUTPUT, "-silent", "-worker", "32",
        ])
        .stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .status().await
        .context("Failed to execute webanalyze")?;
    if !status.success() { eprintln!("[!] webanalyze exited: {status}"); }
    println!("[+] webanalyze complete");
    Ok(())
}

// Canonical key: lowercase scheme+host, strip trailing slash
fn canonical_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    if let Some(pos) = url.find("://") {
        let scheme = url[..pos].to_lowercase();
        let rest   = &url[pos + 3..];
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if path.is_empty() {
            return format!("{}://{}", scheme, host.to_lowercase());
        }
        return format!("{}://{}/{}", scheme, host.to_lowercase(), path);
    }
    format!("https://{}", url.to_lowercase())
}

// Output schema (URL-keyed object):
// {
//   "https://target.com": {
//     "status": 200, "title": "...", "server": "nginx/1.18",
//     "ip": "1.2.3.4", "cdn": true, "cdn_name": "cloudflare",
//     "cname": ["x.cloudfront.net"],
//     "redirect_chain": ["301 → https://other.com", "200"],
//     "hashes": {"body_sha256": "abc123"},
//     "techs": ["WordPress 6.4", "PHP 8.1"],
//     "categories": ["CMS", "Programming Languages"],
//     "headers": {"X-Powered-By": "PHP/8.1"},
//     "tls": {"subject_cn": "*.target.com", "expiry": "2026-01-01", "issuer": "Let's Encrypt"},
//     "content_type": "text/html", "content_length": 42312,
//     "response_time": 0.34,
//     "inputs": ["sub1.target.com", "sub2.target.com"]   // subdomains pointing here
//   }
// }
fn merge_outputs() -> Result<()> {
    println!("[*] Merging outputs (URL-keyed schema)...");

    let mut records: HashMap<String, Map<String, Value>> = HashMap::new();

    // ── 1. httpx ─────────────────────────────────────────────────────────────
    let httpx_raw = std::fs::read_to_string(HTTPX_OUTPUT).unwrap_or_default();
    for line in httpx_raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };

        // Key by final_url (post-redirect) so duplicate redirectors collapse
        let url_key = v.get("final_url")
            .or_else(|| v.get("url"))
            .or_else(|| v.get("input"))
            .and_then(|u| u.as_str()).unwrap_or("").trim().to_string();
        if url_key.is_empty() { continue; }

        let input_url = v.get("url")
            .or_else(|| v.get("input"))
            .and_then(|u| u.as_str()).unwrap_or("").to_string();

        let key = canonical_url(&url_key);
        let rec = records.entry(key.clone()).or_default();

        // status
        if let Some(n) = v.get("status_code") {
            if n.is_number() { rec.entry("status").or_insert(n.clone()); }
        }

        // track all input subdomains pointing to this URL
        if !input_url.is_empty() && canonical_url(&input_url) != key {
            let inputs = rec.entry("inputs").or_insert(Value::Array(vec![]));
            if let Value::Array(arr) = inputs {
                let vi = Value::String(input_url);
                if !arr.contains(&vi) { arr.push(vi); }
            }
        }

        set_str(rec, "title",         &v, "title");
        set_str(rec, "server",        &v, "webserver");
        set_str(rec, "content_type",  &v, "content_type");
        set_num(rec, "content_length",&v, "content_length");
        set_str(rec, "ip",            &v, "ip");
        set_str(rec, "cdn_name",      &v, "cdn_name");

        if let Some(b) = v.get("cdn").and_then(|x| x.as_bool()) {
            rec.insert("cdn".into(), Value::Bool(b));
        }

        // response_time rounded to 2dp
        if !rec.contains_key("response_time") {
            if let Some(rt) = v.get("response_time").and_then(|x| x.as_f64()) {
                if let Some(n) = serde_json::Number::from_f64((rt * 100.0).round() / 100.0) {
                    rec.insert("response_time".into(), Value::Number(n));
                }
            }
        }

        // cname
        if let Some(c) = v.get("cname") {
            rec.insert("cname".into(), c.clone());
        }

        // redirect_chain: ["301 → https://loc", "200"]
        {
            let codes: Vec<u64> = v.get("chain_status_codes")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                .unwrap_or_default();
            let locs: Vec<String> = v.get("redirects")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_else(|| v.get("location")
                    .and_then(|x| x.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
                    .unwrap_or_default());
            if !codes.is_empty() {
                let chain: Vec<Value> = codes.iter().enumerate().map(|(i, code)| {
                    Value::String(match locs.get(i) {
                        Some(loc) => format!("{} \u{2192} {}", code, loc),
                        None      => code.to_string(),
                    })
                }).collect();
                rec.insert("redirect_chain".into(), Value::Array(chain));
            }
        }

        // hashes
        let sha = v.get("hash").and_then(|h| h.get("body_sha256"))
            .or_else(|| v.get("body_sha256")).cloned();
        if let Some(sha) = sha {
            let mut h: Map<String, Value> = Map::new();
            h.insert("body_sha256".into(), sha);
            rec.insert("hashes".into(), Value::Object(h));
        }

        // security-relevant headers only (from -bp structured map)
        if let Some(hdrs) = v.get("response_headers").and_then(|h| h.as_object()) {
            let keep: HashSet<&str> = [
                "server","x-powered-by","content-security-policy","x-frame-options",
                "strict-transport-security","x-content-type-options",
                "access-control-allow-origin","x-aspnet-version","x-aspnetmvc-version",
                "x-generator","x-drupal-cache","x-varnish","via","cf-ray",
                "www-authenticate","x-wp-total",
            ].iter().copied().collect();
            let filtered: Map<String, Value> = hdrs.iter()
                .filter(|(k, _)| keep.contains(k.to_lowercase().as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if !filtered.is_empty() {
                rec.insert("headers".into(), Value::Object(filtered));
            }
        }

        // tls compact
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
            if !t.is_empty() { rec.insert("tls".into(), Value::Object(t)); }
        }

        merge_techs(rec, extract_httpx_techs(&v));
    }

    // ── 2. WhatWeb ───────────────────────────────────────────────────────────
    let ww_noise: HashSet<&str> = [
        "RedirectLocation","IP","Country","HTTPServer","UncommonHeaders","Via-Proxy",
        "Cookies","Meta-Author","Meta-Refresh","Title","Email","Script","PasswordField",
        "Frame","HTML5","Bootstrap","JQuery","Open-Graph-Protocol","Google-Analytics",
        "Modernizr","Prototype","Varnish",
    ].iter().copied().collect();

    let ww_raw = std::fs::read_to_string(WHATWEB_RESULTS).unwrap_or_default();
    for entry in parse_whatweb_json(&ww_raw) {
        let target = entry.get("target").and_then(|t| t.as_str()).unwrap_or("");
        if target.is_empty() { continue; }
        let key = canonical_url(target);
        let rec = records.entry(key).or_default();

        if let Some(plugins) = entry.get("plugins").and_then(|p| p.as_object()) {
            let mut techs: Vec<String> = Vec::new();
            for (name, data) in plugins {
                if ww_noise.contains(name.as_str()) { continue; }
                let ver = data.get("version").and_then(|v| v.as_str()).unwrap_or("").trim();
                techs.push(if ver.is_empty() { name.clone() } else { format!("{} {}", name, ver) });
            }
            merge_techs(rec, techs);

            if let Some(code) = plugins.get("HTTP-Status")
                .and_then(|h| h.get("string")).and_then(|s| s.as_array())
                .and_then(|a| a.first()).and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                rec.entry("status").or_insert(Value::Number(code.into()));
            }
        }
        if let Some(s) = entry.get("http_status").and_then(|x| x.as_u64()) {
            rec.entry("status").or_insert(Value::Number(s.into()));
        }
    }

    // ── 3. Webanalyze ────────────────────────────────────────────────────────
    let wa_raw = std::fs::read_to_string(WEBANALYZE_OUTPUT).unwrap_or_default();
    let wa_entries = match serde_json::from_str::<Value>(&wa_raw) {
        Ok(Value::Array(arr)) => arr,
        Ok(other) => vec![other],
        Err(_)    => vec![],
    };
    for entry in wa_entries {
        let host = entry.get("hostname").or_else(|| entry.get("host"))
            .or_else(|| entry.get("url")).and_then(|h| h.as_str()).unwrap_or("");
        if host.is_empty() { continue; }
        let key = canonical_url(host);
        let rec = records.entry(key).or_default();

        if let Some(Value::Array(matches)) = entry.get("matches") {
            let mut techs: Vec<String> = Vec::new();
            let mut cats:  HashSet<String> = HashSet::new();
            for m in matches {
                let app = m.get("app").and_then(|a| a.as_str()).unwrap_or("");
                if app.is_empty() { continue; }
                let ver = m.get("version").and_then(|v| v.as_str()).unwrap_or("").trim();
                techs.push(if ver.is_empty() { app.to_string() } else { format!("{} {}", app, ver) });
                if let Some(Value::Array(ac)) = m.get("categories") {
                    for c in ac { if let Some(s) = c.as_str() { cats.insert(s.to_string()); } }
                }
            }
            merge_techs(rec, techs);
            if !cats.is_empty() {
                let existing = rec.entry("categories").or_insert(Value::Array(vec![]));
                if let Value::Array(arr) = existing {
                    for c in cats {
                        let v = Value::String(c);
                        if !arr.contains(&v) { arr.push(v); }
                    }
                }
            }
        }
    }

    // ── 4. Sort/dedup arrays, build final keyed object ────────────────────────
    for rec in records.values_mut() {
        sort_str_arr(rec, "techs");
        sort_str_arr(rec, "categories");
        sort_str_arr(rec, "inputs");
    }

    let mut sorted_keys: Vec<String> = records.keys().cloned().collect();
    sorted_keys.sort();

    let mut final_obj: Map<String, Value> = Map::new();
    for k in sorted_keys {
        if let Some(rec) = records.remove(&k) {
            if rec.contains_key("status") || rec.contains_key("techs") || rec.contains_key("title") {
                final_obj.insert(k, Value::Object(rec));
            }
        }
    }

    println!("[*] Writing {} URL records...", final_obj.len());
    let out = std::fs::File::create(FINAL_OUTPUT).context("Failed to create HTWW.json")?;
    serde_json::to_writer_pretty(out, &Value::Object(final_obj)).context("Failed to write HTWW.json")?;
    println!("[+] Merge complete");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sort_str_arr(rec: &mut Map<String, Value>, key: &str) {
    if let Some(Value::Array(arr)) = rec.get_mut(key) {
        arr.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
        arr.dedup_by(|a, b| a.as_str().unwrap_or("") == b.as_str().unwrap_or(""));
    }
}

fn merge_techs(rec: &mut Map<String, Value>, new_techs: Vec<String>) {
    if new_techs.is_empty() { return; }
    let existing = rec.entry("techs").or_insert(Value::Array(vec![]));
    if let Value::Array(arr) = existing {
        let bases: HashSet<String> = arr.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.split_whitespace().next().unwrap_or(s).to_lowercase())
            .collect();
        for tech in new_techs {
            let base = tech.split_whitespace().next().unwrap_or(&tech).to_lowercase();
            if !bases.contains(&base) { arr.push(Value::String(tech)); }
        }
    }
}

fn extract_httpx_techs(v: &Value) -> Vec<String> {
    let mut techs = Vec::new();
    if let Some(obj) = v.get("tech").and_then(|t| t.as_object()) {
        for (name, data) in obj {
            let ver = data.get("version").and_then(|v| v.as_array())
                .and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("").trim();
            techs.push(if ver.is_empty() { name.clone() } else { format!("{} {}", name, ver) });
        }
    }
    if let Some(Value::Array(arr)) = v.get("technologies") {
        for t in arr { if let Some(s) = t.as_str() { techs.push(s.to_string()); } }
    }
    techs
}

fn set_str(rec: &mut Map<String, Value>, out_key: &str, src: &Value, src_key: &str) {
    if rec.contains_key(out_key) { return; }
    if let Some(s) = src.get(src_key).and_then(|v| v.as_str()) {
        if !s.is_empty() { rec.insert(out_key.into(), Value::String(s.to_string())); }
    }
}

fn set_num(rec: &mut Map<String, Value>, out_key: &str, src: &Value, src_key: &str) {
    if rec.contains_key(out_key) { return; }
    if let Some(n) = src.get(src_key) {
        if n.is_number() { rec.insert(out_key.into(), n.clone()); }
    }
}

fn parse_whatweb_json(raw: &str) -> Vec<Value> {
    let raw = raw.trim();
    if raw.is_empty() { return vec![]; }
    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(raw) { return arr; }
    raw.lines().filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok()).collect()
}

fn cleanup() -> Result<()> {
    println!("[*] Cleaning up intermediate files...");
    for f in &[WHATWEB_RESULTS, WEBANALYZE_OUTPUT, HTTPX_OUTPUT] {
        match std::fs::remove_file(f) {
            Ok(_)  => println!("    Deleted: {f}"),
            Err(e) => eprintln!("    Could not delete {f}: {e}"),
        }
    }
    Ok(())
}
