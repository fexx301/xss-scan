# XSS Scan

A hybrid XSS discovery pipeline that chains WAF detection, JS-rendered crawling, context-aware canary injection, DOM sink analysis, and targeted fuzzing into a single command.

Built for authorized bug bounty testing.

```
  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║
   ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

---

## What it does

| Stage | Tool | What happens |
|---|---|---|
| 1. WAF Detection | wafw00f | Identifies Cloudflare / Akamai / AWS WAF / none, selects bypass wordlist |
| 2. Crawl | katana | JS-rendered crawl, discovers all URLs and parameters |
| 3. Canary Injection | Python / httpx | Injects unique canary into every param, detects reflections and context |
| 4. JS Bundle Analysis | Python | Downloads JS chunks, hunts DOM sinks and sources, flags exposed source maps |
| 5. XSS Fuzzing | dalfox | Fires context-aware payloads + WAF-specific bypasses against all endpoints |
| 6. Report | Python | Generates a markdown report with all findings, payloads, and next steps |

---

## Features

- **WAF-aware** — detects Cloudflare, Akamai, and AWS WAF before fuzzing, then loads the right bypass wordlist automatically
- **Context detection** — identifies whether reflection lands in HTML body, HTML attribute, JS string, or JS block, and adjusts payloads accordingly
- **DOM sink hunting** — downloads JS bundles (including Next.js chunks), greps for `innerHTML`, `dangerouslySetInnerHTML`, `eval(`, `document.write`, and 20+ other dangerous sinks
- **Source map detection** — checks every JS bundle for an exposed `.js.map` file that would allow full source reconstruction
- **OOB support** — blind XSS via interactsh or canarytokens with `--oob`
- **Markdown report** — clean output with findings table, reflection points, DOM sink analysis, and recommended next steps

---

## Requirements

### Python
```
Python 3.8+
httpx
beautifulsoup4
```

### Go tools
```
katana      (crawling)
dalfox      (XSS fuzzing)
wafw00f     (WAF detection)
```

Install Python deps:
```bash
pip3 install httpx beautifulsoup4
```

Install Go tools:
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
pip3 install wafw00f
```

---

## Usage

```bash
# Full scan
python3 scanner.py -u https://target.com

# With OOB callback for blind XSS
python3 scanner.py -u https://target.com --oob https://your.interactsh.com

# Skip crawl — only scan the given URL
python3 scanner.py -u https://target.com/search?q=test --skip-crawl

# Skip JS bundle analysis
python3 scanner.py -u https://target.com --skip-js

# Save report to a specific file
python3 scanner.py -u https://target.com --report findings.md

# Fastest — no crawl, no JS analysis
python3 scanner.py -u https://target.com/page?id=1 --skip-crawl --skip-js
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | required | Target URL |
| `--oob` | none | OOB callback URL (interactsh / canarytokens) |
| `--depth` | 3 | Katana crawl depth |
| `--report` | auto | Output report path |
| `--deep` | off | Deep scan with more payloads |
| `--skip-crawl` | off | Skip katana crawl, only scan the given URL |
| `--skip-js` | off | Skip JS bundle and source map analysis |

---

## Output

```
============================================================
  XSS Confirmed:  12
  Reflection pts: 1
  DOM Sinks:      21
  WAF:            CLOUDFLARE
============================================================

Report saved → xss_report_target_com_20260629_141023.md
```

The markdown report includes:
- All confirmed XSS findings with exact dalfox output
- Reflection point table (parameter, URL, context)
- DOM sink table (severity, sink name, bundle, surrounding code)
- Exposed source map URLs
- Recommended next steps

---

## Files

```
xss-scanner/
├── scanner.py          main script
├── payloads.txt        60+ XSS payloads across all injection contexts
└── waf_bypasses.json   bypass wordlists for Cloudflare, Akamai, AWS WAF, generic
```

### payloads.txt categories
- HTML context
- Attribute break-out
- JavaScript string break
- URL / href context
- HTML entity encoding
- Unicode encoding
- Base64 encoded
- Case variation
- Whitespace tricks
- Alternative event handlers
- Tag substitution
- Comment splitting
- Template literals
- Cloudflare-specific
- Polyglot
- DOM XSS with fetch callback

### waf_bypasses.json
Separate bypass payload lists for Cloudflare, Akamai, AWS WAF, and generic WAFs. The scanner selects the right list automatically based on wafw00f output.

---

## DOM Sinks Tracked

```
innerHTML           outerHTML           document.write
document.writeln    insertAdjacentHTML  eval(
setTimeout(         setInterval(        new Function(
location.href       location.assign     location.replace
window.open(        dangerouslySetInnerHTML  __html
$.html(             postMessage         router.query
searchParams.get    location.hash       location.search
```

---

## Disclaimer

For authorized security testing only. Only run this tool against targets you have explicit permission to test (bug bounty programs, your own applications, authorized engagements). Unauthorized use is illegal.
