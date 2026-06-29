# XSS Scan

A hybrid web security scanner that chains WAF detection, JS-rendered crawling, context-aware canary injection, DOM sink analysis, targeted XSS fuzzing, and 10+ additional misconfiguration checks into a single command.

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
| 6. Report | Python | Generates a full markdown report with all findings and next steps |
| 7. Firebase | Python / httpx | Detects exposed Firebase config, tests unauthenticated Firestore/RTDB/Storage access |
| 8. Secrets | Python | Scans JS bundles for AWS keys, GitHub tokens, Stripe keys, JWTs, and more |
| 9. CORS | Python / httpx | Tests for origin reflection and credentials=true misconfigurations |
| 10. Open Redirect | Python / httpx | Injects evil.com into 30+ redirect params, follows to confirm |
| 11. Cloud Storage | Python / httpx | Extracts S3/GCS bucket names from bundles, tests unauthenticated listing |
| 12. CSP | Python / httpx | Parses Content-Security-Policy, flags unsafe-inline, unsafe-eval, wildcards, missing header |
| 13. JSONP | Python / httpx | Detects callback params that reflect unquoted function calls |
| 14. GraphQL | Python / httpx | Probes common GraphQL endpoints, confirms if introspection is enabled |
| 15. Clickjacking | Python / httpx | Checks X-Frame-Options and CSP frame-ancestors |
| 16. Nuclei | nuclei | Runs exposure + misconfiguration templates; CVEs added in --deep mode |

---

## Features

- **WAF-aware** — detects Cloudflare, Akamai, and AWS WAF before fuzzing, then loads the right bypass wordlist automatically
- **Context detection** — identifies whether reflection lands in HTML body, HTML attribute, JS string, or JS block
- **DOM sink hunting** — downloads JS bundles (including Next.js chunks), greps for `innerHTML`, `dangerouslySetInnerHTML`, `eval(`, `document.write`, and 20+ other dangerous sinks
- **Source map detection** — checks every JS bundle for an exposed `.js.map` file
- **Secrets scanning** — finds AWS access keys, GitHub tokens, Stripe live keys, Twilio SIDs, Slack tokens, JWTs, and private key headers in JS bundles
- **Firebase misconfiguration** — tests unauthenticated read/write on Firestore, Realtime Database, and Storage
- **CORS misconfiguration** — flags origin reflection with credentials=true as CRITICAL
- **Open redirect** — tests 30+ common redirect param names automatically
- **Cloud storage** — finds and tests S3 and GCS bucket exposure from bundle references
- **CSP analysis** — detects missing headers and weak directives that allow XSS bypass
- **JSONP detection** — finds endpoints where callback params reflect unquoted
- **GraphQL introspection** — confirms open schema exposure across common endpoint paths
- **Clickjacking** — checks both X-Frame-Options and CSP frame-ancestors
- **Nuclei integration** — runs maintained template library for exposures and misconfigurations
- **OOB support** — blind XSS via interactsh or canarytokens with `--oob`
- **Markdown report** — 14-section report covering all finding types with severity, evidence, and next steps

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
nuclei      (misconfiguration templates)
```

### Other
```
wafw00f     (WAF detection)
```

Install Python deps:
```bash
pip3 install httpx beautifulsoup4 wafw00f
```

Install Go tools:
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Usage

```bash
# Full scan
python3 scanner.py -u https://target.com

# With OOB callback for blind XSS
python3 scanner.py -u https://target.com --oob https://your.interactsh.com

# Deep scan — more dalfox payloads + nuclei CVE templates
python3 scanner.py -u https://target.com --deep

# Skip crawl — only scan the given URL
python3 scanner.py -u https://target.com/search?q=test --skip-crawl

# Skip JS bundle analysis (also skips Firebase, secrets, cloud storage)
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
| `--deep` | off | Deep scan — more payloads + nuclei CVE/vulnerability templates |
| `--skip-crawl` | off | Skip katana crawl, only scan the given URL |
| `--skip-js` | off | Skip JS bundle analysis, secrets, Firebase, and cloud storage checks |

---

## Output

```
============================================================
  XSS Confirmed:   0 (browser-verified)
  XSS PoC:         3 (needs manual verify)
  Reflection pts:  2
  DOM Sinks:       21
  Secrets:         1 (1 CRITICAL)
  CORS:            0 (0 CRITICAL)
  Open Redirects:  0
  Cloud Storage:   0
  CSP Issues:      2
  JSONP Endpoints: 0
  GraphQL:         0
  Clickjacking:    1
  Nuclei:          4 (1 CRIT / 2 HIGH)
  Firebase Crit:   0
  Firebase High:   0
  WAF:             CLOUDFLARE
============================================================

Report saved → xss_report_target_com_20260629_141023.md
```

The markdown report includes 14 sections:
1. Confirmed XSS findings
2. Reflection points
3. JS DOM sink analysis
4. Firebase misconfiguration
5. Secrets in JS bundles
6. CORS misconfiguration
7. Open redirect
8. Cloud storage
9. Content Security Policy
10. JSONP endpoints
11. GraphQL introspection
12. Clickjacking
13. Nuclei findings
14. Next steps

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
