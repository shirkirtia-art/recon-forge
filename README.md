# HTWW

> **H**ttpx · **T**ech-detection · **W**hatWeb · **W**ebanalyze — one command, one JSON.

A fast Rust CLI that orchestrates three web recon tools in the right order, then collapses every output into a single structured `HTWW.json`. Built for bug bounty reconnaissance pipelines.

```
subdomains.txt
      │
      ▼
   httpx          →  live probing, response metadata, hashes
      │
      ▼
 live_urls.txt
      ├──▶ whatweb     →  CMS, frameworks, headers fingerprinting
      └──▶ webanalyze  →  Wappalyzer-style tech detection
                │
                ▼
           HTWW.json   ✓  (intermediates auto-deleted)
```

---

## Why

Running httpx → WhatWeb → webanalyze manually means juggling four output files, remembering flags, and writing jq oneliners to stitch results together. HTWW does all of that in one command and hands you two clean files when it's done.

---

## Prerequisites

Make sure these are on your `PATH`:

| Tool | Install |
|------|---------|
| **httpx** | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **whatweb** | `sudo apt install whatweb` · [github.com/urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) |
| **webanalyze** | `go install github.com/rverton/webanalyze/cmd/webanalyze@latest` |

---

## Install

```bash
git clone https://github.com/shirkirtia-art/recon-forge
cd recon-forge
cargo install --path .
~/.cargo/bin/recon-forge
```

Run from anywhere after that:

```bash
htww /path/to/subdomains.txt
```

---

## Usage

```bash
htww subdomains.txt
```

That's it. HTWW will:

1. Run **httpx** with aggressive flag set (status codes, titles, tech detection, hashes, CDN, CNAME, redirects …)
2. Extract live URLs from the jsonl output (no `jq` dependency)
3. Run **WhatWeb** and **webanalyze** in parallel against live URLs
4. Merge everything into `HTWW.json`
5. Delete the four intermediate files

---

## Output

Two files are left when the pipeline finishes:

```
live_urls.txt   — one live URL per line
HTWW.json       — merged recon data
```

`HTWW.json` structure:

```json
{
  "whatweb_output":    [ ...whatweb_results.json + whatweb_detailed.json... ],
  "webanalyze_output": [ ...webanalyze.json... ],
  "httpx_output":      [ ...httpx_raw.jsonl... ]
}
```

Full raw data — nothing truncated.

---

## Exact flags used

<details>
<summary>httpx</summary>

```
httpx -l subdomains.txt \
  -silent \
  -sc -title -web-server -td -ct -cl -bp -rt -hash sha256 -ip -cname -cdn -location \
  -follow-redirects -max-redirects 3 \
  -fep \
  -json -irh -irr \
  -o httpx_raw.jsonl \
  -stats -random-agent -timeout 10 -t 100 -rl 250
```
</details>

<details>
<summary>WhatWeb</summary>

```
whatweb -i live_urls.txt \
  -a 3 \
  -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..." \
  -v --no-errors \
  --log-json=whatweb_results.json \
  --log-json-verbose=whatweb_detailed.json \
  -t 50
```
</details>

<details>
<summary>webanalyze</summary>

```
webanalyze -update
webanalyze -hosts live_urls.txt -crawl 1 -output json webanalyze.json -silent -worker 32
```
</details>

---

## Build from source

```bash
cargo build --release
# binary at ./target/release/htww
```

---

