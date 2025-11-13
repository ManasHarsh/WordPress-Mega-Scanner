#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# wp_mega_enum.py
#
# ALL-IN-ONE passive WordPress enumerator + vulnerability intelligence
# Includes:
#   - WordPress detection
#   - Exposure checks
#   - Directory listing detection
#   - Plugin/theme fingerprinting
#   - CRT.sh passive enumeration
#   - API integrations:
#         --use-wpvuln (WPVulnerability API)
#         --use-wpscan (WPScan API via --wpscan-api-key)
#         --use-vulncheck (VulnCheck WordPress API)
#         --use-nvd (NVD API)
#         --use-local-cve <file.json> (local CVE mapping)
#   - Outputs: CSV, TXT, JSON + colored console
#   - Safe: passive, no exploitation, no brute force
#
# NOTE: This is PART 1 of 7 — paste into the full file.

import argparse
import concurrent.futures
import csv
import json
import os
import random
import re
import sys
import time
import socket
import ssl
from pathlib import Path
from urllib.parse import urljoin, urlencode

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with:")
    print("   python3 -m pip install requests")
    sys.exit(1)

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------
#  ANSI COLOR ENGINE
# ---------------------------------------------------------

class Colors:
    ENABLED = True

    # Basic colors
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    RESET   = "\033[0m"

    @classmethod
    def disable(cls):
        cls.ENABLED = False

    @classmethod
    def c(cls, text, color):
        if not cls.ENABLED:
            return text
        return f"{color}{text}{cls.RESET}"

# ---------------------------------------------------------
#  GLOBAL CONSTANTS
# ---------------------------------------------------------

USER_AGENT = "wp-mega-enum/1.0 (+https://example.local)"
DEFAULT_TIMEOUT = 8
DEFAULT_THREADS = 10
DEFAULT_MAX_HOSTS = 500

HEADERS = {"User-Agent": USER_AGENT}

# Passive exposure checks will be defined later in Part 3

# CRT.sh endpoint
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# ---------------------------------------------------------
#  ARG PARSER
# ---------------------------------------------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="All-in-one passive WordPress enumerator & vulnerability intelligence tool."
    )

    # Input sources
    p.add_argument("-i", "--input", help="Input file: one domain/URL per line")
    p.add_argument("--crtsh", help="Passive domain enumeration using crt.sh")
    p.add_argument("--list-only", action="store_true",
                   help="With --crtsh, list discovered hosts and exit")
    p.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
                   help="Maximum number of hosts to scan")

    # Output
    p.add_argument("-o", "--output", default="mega_enum.csv",
                   help="CSV output file")
    p.add_argument("-x", "--txt", help="TXT output file")
    p.add_argument("--json", help="JSON output file")

    # API usage flags
    p.add_argument("--use-wpvuln", action="store_true",
                   help="Query WPVulnerability API")
    p.add_argument("--use-wpscan", action="store_true",
                   help="Query WPScan API (requires --wpscan-api-key)")
    p.add_argument("--wpscan-api-key", help="WPScan API key")
    p.add_argument("--use-vulncheck", action="store_true",
                   help="Query VulnCheck WordPress API")
    p.add_argument("--use-nvd", action="store_true",
                   help="Query NVD CVE API")
    p.add_argument("--use-local-cve", help="Local CVE JSON file (mapping)")

    # Enumeration depth
    p.add_argument("--deep-enum", action="store_true",
                   help="Enable deep plugin/theme version fingerprinting")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                   help="Thread count (default 10)")

    # Color control
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored terminal output")

    return p

# ---------------------------------------------------------
#  INPUT LOADING
# ---------------------------------------------------------

def normalize_host(h: str):
    h = h.strip()
    if not h:
        return None

    # If URL already contains scheme:
    if h.startswith("http://") or h.startswith("https://"):
        return h.rstrip("/")

    # Remove trailing path if given
    if "/" in h:
        h = h.split("/")[0]

    return h.rstrip("/")


def load_from_file(path: str):
    hosts = []
    p = Path(path)
    if not p.exists():
        print(Colors.c(f"[!] Input file not found: {path}", Colors.RED))
        sys.exit(1)

    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            n = normalize_host(line)
            if n:
                hosts.append(n)

    return hosts


def fetch_crtsh(domain: str):
    """Passive subdomain enumeration via crt.sh (no active scanning)."""
    url = CRT_SH_URL.format(domain=domain)
    print(Colors.c(f"[i] Fetching crt.sh for {domain}", Colors.BLUE))

    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
    except Exception as e:
        print(Colors.c(f"[!] crt.sh error: {e}", Colors.RED))
        return []

    hosts = set()
    try:
        data = r.json()
        for entry in data:
            nv = entry.get("name_value", "")
            for h in nv.splitlines():
                h = h.strip().lstrip("*.").rstrip(".")
                if h:
                    hosts.add(h)
    except Exception:
        print(Colors.c("[!] crt.sh JSON parse failed, falling back to regex...", Colors.YELLOW))
        for m in re.findall(r"[A-Za-z0-9\-_.]+\." + re.escape(domain), r.text):
            hosts.add(m.strip().lstrip("*."))

    return sorted(hosts)
# =========================================================
#  PART 3 — EXPOSURE CHECKS (CONFIG LEAKS, BACKUPS, LOGS,
#            DIRECTORY LISTING, INSTALLERS, SENSITIVE FILES)
# =========================================================

# List of passive endpoints that often expose sensitive info.
# These checks are NON-DESTRUCTIVE. They only perform GET/HEAD requests.

EXPOSURE_PATHS = {
    # Core leaks / backups
    "/wp-config.php.bak":         "Backup wp-config.php (CRITICAL)",
    "/wp-config.php.save":        "Backup wp-config.php (CRITICAL)",
    "/wp-config.php.old":         "Backup wp-config.php (CRITICAL)",
    "/wp-config.php.zip":         "Zipped wp-config (CRITICAL)",
    "/wp-config.php.tar.gz":      "Tar config (CRITICAL)",
    "/wp-config.old":             "Old config file",
    "/wp-config.bak":             "Config backup file",

    # Installer leftovers
    "/wp-admin/install.php":      "WP installer still present",
    "/wp-admin/setup-config.php": "WP setup wizard still accessible",

    # Directory listings
    "/wp-content/uploads/":       "Uploads directory – possible listing",
    "/wp-includes/":              "WP includes directory – should not be public",
    "/wp-content/":               "WP content directory – check for listing",

    # Logs
    "/wp-content/debug.log":      "Debug log exposed (sensitive information)",
    "/debug.log":                 "Debug log at root",
    "/error_log":                 "PHP error_log exposed",
    "/wp-admin/error_log":        "Admin error log exposed",

    # General sensitive files
    "/.env":                      "Environment file exposed",
    "/.git/HEAD":                 "Git repo exposed",
    "/.svn/entries":              "SVN repo exposed",

    # Readme/license (version disclosure)
    "/readme.html":               "WP version disclosure",
    "/readme.txt":                "WP readme (info leak)",
    "/license.txt":               "License file (version info)",

    # REST API user enumeration
    "/wp-json/wp/v2/users":       "WP REST users endpoint",

    # Misc backups
    "/backup.zip":                "Backup zip at root",
    "/backup.tar.gz":             "Backup tar.gz at root",
    "/site-backup.zip":           "Site backup",
    "/db.zip":                    "Database dump",
    "/database.sql":              "Database SQL dump",
}


def check_directory_listing(text):
    """Detect classic Apache/Nginx directory index pages."""
    if not text:
        return False
    return (
        "Index of /" in text or
        "<title>Index of" in text or
        "Directory listing for" in text
    )


def run_exposure_checks(canonical_url: str):
    """Run passive exposure checks on known sensitive paths."""
    findings = []

    for path, description in EXPOSURE_PATHS.items():
        target = urljoin(canonical_url.rstrip("/") + "/", path.lstrip("/"))
        r = http_fetch(target)
        if not r:
            continue

        # Only flag 200/301/302 status codes.
        if r.status_code in (200, 301, 302):
            body = r.text or ""

            # Detect directory listings
            if check_directory_listing(body):
                findings.append(f"{path} -> Directory listing enabled")

            # Detect REST user enumeration
            elif path.endswith("/wp-json/wp/v2/users"):
                if '"slug"' in body or '"name"' in body:
                    findings.append(f"{path} -> User enumeration possible")

            # Detect exposed debug logs
            elif "PHP" in body and "Warning" in body and "on line" in body:
                findings.append(f"{path} -> Debug log with stack traces")

            else:
                findings.append(f"{path} -> {description}")

    return findings
# =========================================================
#  PART 4 — PLUGIN & THEME ENUMERATION
#         (LIGHTWEIGHT + DEEP FINGERPRINTING)
# =========================================================

# Popular WordPress plugins & themes — used to attempt slug detection.
POPULAR_PLUGINS = [
    "akismet", "wordfence", "contact-form-7", "woocommerce",
    "jetpack", "yoast-seo", "elementor", "revslider",
    "wp-super-cache", "w3-total-cache", "all-in-one-seo-pack",
    "gravityforms", "ninja-forms", "tablepress", "updraftplus",
    "mailpoet", "rank-math", "polylang", "sitepress-multilingual-cms"
]

POPULAR_THEMES = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
    "twentytwentyone", "twentytwenty", "astra", "hello-elementor",
    "oceanwp", "generatepress", "neve", "storefront"
]

# Files used for lightweight and deep fingerprinting
PLUGIN_CHECK_PATHS_LIGHT = [
    "/wp-content/plugins/{slug}/",
    "/wp-content/plugins/{slug}/{slug}.php",
]

PLUGIN_CHECK_PATHS_DEEP = [
    "/wp-content/plugins/{slug}/readme.txt",
    "/wp-content/plugins/{slug}/readme.md",
    "/wp-content/plugins/{slug}/changelog.txt",
    "/wp-content/plugins/{slug}/CHANGELOG.md",
    "/wp-content/plugins/{slug}/assets/",
]

THEME_CHECK_PATHS_LIGHT = [
    "/wp-content/themes/{slug}/style.css",
    "/wp-content/themes/{slug}/",
]

THEME_CHECK_PATHS_DEEP = [
    "/wp-content/themes/{slug}/readme.txt",
    "/wp-content/themes/{slug}/README.md",
    "/wp-content/themes/{slug}/screenshot.png",
]


# -----------------------------
#  Version extraction helpers
# -----------------------------

PLUGIN_VERSION_RE = re.compile(
    r"(?:Version|Stable tag)\s*[:=]\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE
)

THEME_VERSION_RE = re.compile(
    r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE
)


def extract_plugin_version(text: str):
    """Parse plugin metadata from readme or header files."""
    if not text:
        return None
    m = PLUGIN_VERSION_RE.search(text)
    if m:
        return m.group(1)
    return None


def extract_theme_version(text: str):
    """Parse theme metadata from style.css."""
    if not text:
        return None
    m = THEME_VERSION_RE.search(text)
    if m:
        return m.group(1)
    return None


# -----------------------------
#  ENUMERATION FUNCTIONS
# -----------------------------

def check_plugin_slug(canonical, slug, deep=False):
    """Check if a plugin slug exists and optionally fingerprint deeply."""
    findings = []
    version = None

    # LIGHTWEIGHT CHECKS
    for tpl in PLUGIN_CHECK_PATHS_LIGHT:
        path = tpl.format(slug=slug)
        url = urljoin(canonical + "/", path.lstrip("/"))
        r = http_fetch(url, method="head")
        if r and r.status_code in (200, 301, 302):
            findings.append(path)
            break  # slug exists, proceed

    if not findings:
        return None  # slug not present

    # DEEP MODE
    if deep:
        for tpl in PLUGIN_CHECK_PATHS_DEEP:
            path = tpl.format(slug=slug)
            url = urljoin(canonical + "/", path.lstrip("/"))
            r = http_fetch(url)
            if not r:
                continue

            if r.status_code in (200, 301, 302):
                findings.append(path)

                # Extract version
                ver = extract_plugin_version(r.text or "")
                if ver and not version:
                    version = ver

    return {"slug": slug, "paths": findings, "version": version}


def check_theme_slug(canonical, slug, deep=False):
    """Check if a theme slug exists and optionally fingerprint deeply."""
    findings = []
    version = None

    # LIGHTWEIGHT CHECKS
    for tpl in THEME_CHECK_PATHS_LIGHT:
        path = tpl.format(slug=slug)
        url = urljoin(canonical + "/", path.lstrip("/"))
        r = http_fetch(url, method="head")
        if r and r.status_code in (200, 301, 302):
            findings.append(path)
            break

    if not findings:
        return None

    # DEEP MODE
    if deep:
        for tpl in THEME_CHECK_PATHS_DEEP:
            path = tpl.format(slug=slug)
            url = urljoin(canonical + "/", path.lstrip("/"))
            r = http_fetch(url)
            if not r:
                continue

            if r.status_code in (200, 301, 302):
                findings.append(path)

                # Extract theme version
                ver = extract_theme_version(r.text or "")
                if ver and not version:
                    version = ver

    return {"slug": slug, "paths": findings, "version": version}


def enumerate_plugins_and_themes(canonical_url, deep=False):
    """
    Scan for installed WordPress plugins and themes using slug-method probing.
    Returns:
        {
          "plugins": {slug: {paths: [...], version: x}},
          "themes":  {slug: {paths: [...], version: x}},
        }
    """
    detected_plugins = {}
    detected_themes = {}

    # -------------------------
    #  PLUGIN DISCOVERY
    # -------------------------
    for slug in POPULAR_PLUGINS:
        res = check_plugin_slug(canonical_url, slug, deep=deep)
        if res:
            detected_plugins[slug] = res

    # -------------------------
    #  THEME DISCOVERY
    # -------------------------
    for slug in POPULAR_THEMES:
        res = check_theme_slug(canonical_url, slug, deep=deep)
        if res:
            detected_themes[slug] = res

    return {
        "plugins": detected_plugins,
        "themes": detected_themes
    }
# =========================================================
#  PART 5 — VULNERABILITY INTELLIGENCE ENGINES
#         (WPVulnerability, WPScan, VulnCheck, NVD, Local)
# =========================================================

from hashlib import sha1
from datetime import datetime, timedelta

CACHE_DIR = Path(".cache")
CACHE_TTL = timedelta(hours=24)


# ---------------------------------------------------------
#  CACHE HANDLING
# ---------------------------------------------------------

def ensure_cache():
    if not CACHE_DIR.exists():
        CACHE_DIR.mkdir(parents=True, exist_ok=True)


def cache_key(prefix, value):
    """Generate stable cache key."""
    h = sha1(value.encode()).hexdigest()
    return CACHE_DIR / f"{prefix}_{h}.json"


def cache_get(prefix, value):
    """Return cached data if fresh."""
    f = cache_key(prefix, value)
    if not f.exists():
        return None
    try:
        # Check TTL
        mtime = datetime.fromtimestamp(f.stat().st_mtime)
        if datetime.now() - mtime > CACHE_TTL:
            return None
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def cache_set(prefix, value, data):
    """Write data to cache."""
    try:
        f = cache_key(prefix, value)
        f.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------
#  WPVULNERABILITY API (NO KEY)
# ---------------------------------------------------------

WPVULN_BASE = "https://www.wpvulnerability.com/api"

def query_wpvuln_plugin(slug):
    url = f"{WPVULN_BASE}/plugins/{slug}"
    cached = cache_get("wpvuln_plugin", slug)
    if cached:
        return cached

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("wpvuln_plugin", slug, data)
            return data
    except Exception:
        return None
    return None


def query_wpvuln_theme(slug):
    url = f"{WPVULN_BASE}/themes/{slug}"
    cached = cache_get("wpvuln_theme", slug)
    if cached:
        return cached

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("wpvuln_theme", slug, data)
            return data
    except Exception:
        return None
    return None


def query_wpvuln_core(version):
    url = f"{WPVULN_BASE}/wordpress/"
    cached = cache_get("wpvuln_core", version)
    if cached:
        return cached

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # The API returns vulnerabilities for all versions;
            # We filter locally.
            vulns = [
                v for v in data.get("vulnerabilities", [])
                if v.get("affected_versions") and version in v["affected_versions"]
            ]
            result = {"version": version, "vulnerabilities": vulns}
            cache_set("wpvuln_core", version, result)
            return result
    except Exception:
        return None
    return None


# ---------------------------------------------------------
#  WPSCAN API (REQUIRES KEY)
# ---------------------------------------------------------

WPSCAN_BASE = "https://wpscan.com/api/v3"

def query_wpscan_plugin(slug, api_key):
    url = f"{WPSCAN_BASE}/plugins/{slug}"
    cached = cache_get("wpscan_plugin", slug)
    if cached:
        return cached

    headers = {"Authorization": f"Token token={api_key}", "User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("wpscan_plugin", slug, data)
            return data
    except Exception:
        pass
    return None


def query_wpscan_theme(slug, api_key):
    url = f"{WPSCAN_BASE}/themes/{slug}"
    cached = cache_get("wpscan_theme", slug)
    if cached:
        return cached

    headers = {"Authorization": f"Token token={api_key}", "User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("wpscan_theme", slug, data)
            return data
    except Exception:
        pass
    return None


def query_wpscan_core(version, api_key):
    url = f"{WPSCAN_BASE}/wordpresses/{version}"
    cached = cache_get("wpscan_core", version)
    if cached:
        return cached

    headers = {"Authorization": f"Token token={api_key}", "User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("wpscan_core", version, data)
            return data
    except Exception:
        pass
    return None


# ---------------------------------------------------------
#  VULNCHECK PUBLIC API (NO KEY)
# ---------------------------------------------------------

VULNCHECK_BASE = "https://api.vulncheck.com/wordpress"

def query_vulncheck_plugin(slug):
    url = f"{VULNCHECK_BASE}/plugins/{slug}"
    cached = cache_get("vulncheck_plugin", slug)
    if cached:
        return cached

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("vulncheck_plugin", slug, data)
            return data
    except Exception:
        return None
    return None


def query_vulncheck_theme(slug):
    url = f"{VULNCHECK_BASE}/themes/{slug}"
    cached = cache_get("vulncheck_theme", slug)
    if cached:
        return cached

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("vulncheck_theme", slug, data)
            return data
    except Exception:
        return None
    return None


def query_vulncheck_core(version):
    url = f"{VULNCHECK_BASE}/core/{version}"
    cached = cache_get("vulncheck_core", version)
    if cached:
        return cached

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            cache_set("vulncheck_core", version, data)
            return data
    except Exception:
        return None
    return None


# ---------------------------------------------------------
#  NVD API LOOKUP (KEYWORD SEARCH)
# ---------------------------------------------------------

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def query_nvd(keyword):
    cached = cache_get("nvd", keyword)
    if cached:
        return cached

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20
    }
    try:
        r = requests.get(NVD_BASE, params=params, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # Simple flatten of CVE data
            vulns = []
            for v in data.get("vulnerabilities", []):
                cve = v.get("cve", {})
                vulns.append({
                    "id": cve.get("id"),
                    "description": cve.get("descriptions", [{}])[0].get("value"),
                    "published": cve.get("published"),
                })
            cache_set("nvd", keyword, vulns)
            return vulns
    except Exception:
        return None
    return None


# ---------------------------------------------------------
#  LOCAL CVE JSON MAP
# ---------------------------------------------------------

def load_local_cve(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def lookup_local_cve(local_map, key):
    """Return CVEs from local map based on substring match."""
    if not local_map:
        return []
    hits = []
    key_l = key.lower()
    for k, v in local_map.items():
        if k.lower() in key_l:
            if isinstance(v, list):
                hits.extend(v)
            else:
                hits.append(v)
    return hits
# =========================================================
#  PART 6 — RESULT AGGREGATION & OUTPUT WRITERS
# =========================================================

def merge_vulns(*lists):
    """Merge multiple vulnerability lists into a unique list of dicts/strings."""
    seen = set()
    output = []
    for lst in lists:
        if not lst:
            continue
        for v in lst:
            key = None
            if isinstance(v, dict):
                key = v.get("id") or v.get("url") or json.dumps(v, sort_keys=True)
            else:
                key = str(v)
            if key not in seen:
                seen.add(key)
                output.append(v)
    return output


def summarize_vulns(vulns):
    """Turn vulnerability dicts into readable one-line summaries."""
    summary = []
    for v in vulns:
        if isinstance(v, dict):
            if "id" in v:
                s = f"{v['id']}: {v.get('description','')}"
            elif "title" in v:
                s = f"{v.get('title')} - {v.get('severity','')}"
            else:
                s = json.dumps(v)
        else:
            s = str(v)
        summary.append(s)
    return summary


# ---------------------------------------------------------
#  WRITE CSV OUTPUT
# ---------------------------------------------------------

def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "host", "is_wordpress", "canonical", "version",
            "evidence", "exposures", "plugins", "themes", "vulns"
        ])
        for r in rows:
            w.writerow([
                r["host"],
                r["is_wordpress"],
                r.get("canonical") or "",
                r.get("version") or "",
                " || ".join(r.get("evidence", [])),
                " || ".join(r.get("exposures", [])),
                " || ".join([f"{slug}:{d.get('version','?')}" for slug, d in r.get("plugins", {}).items()]),
                " || ".join([f"{slug}:{d.get('version','?')}" for slug, d in r.get("themes", {}).items()]),
                " || ".join(summarize_vulns(r.get("vulns", []))),
            ])
    print(Colors.c(f"[+] CSV saved to {path}", Colors.GREEN))


# ---------------------------------------------------------
#  WRITE TXT OUTPUT
# ---------------------------------------------------------

def write_txt(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(f"{r['host']} -> {'WordPress' if r['is_wordpress'] else 'Not WP'}\n")
            if r.get("canonical"):
                f.write(f"  canonical: {r['canonical']}\n")
            if r.get("version"):
                f.write(f"  version: {r['version']}\n")

            if r.get("evidence"):
                f.write("  evidence:\n")
                for e in r["evidence"]:
                    f.write(f"    - {e}\n")

            if r.get("exposures"):
                f.write("  exposures:\n")
                for e in r["exposures"]:
                    f.write(f"    - {e}\n")

            if r.get("plugins"):
                f.write("  plugins:\n")
                for slug, d in r["plugins"].items():
                    f.write(f"    - {slug}: version={d.get('version')}, paths={','.join(d['paths'])}\n")

            if r.get("themes"):
                f.write("  themes:\n")
                for slug, d in r["themes"].items():
                    f.write(f"    - {slug}: version={d.get('version')}, paths={','.join(d['paths'])}\n")

            if r.get("vulns"):
                f.write("  vulnerabilities:\n")
                for v in summarize_vulns(r["vulns"]):
                    f.write(f"    - {v}\n")

            f.write("\n")

    print(Colors.c(f"[+] TXT saved to {path}", Colors.GREEN))


# ---------------------------------------------------------
#  WRITE JSON OUTPUT
# ---------------------------------------------------------

def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(Colors.c(f"[+] JSON saved to {path}", Colors.GREEN))


# ---------------------------------------------------------
#  PRETTY CONSOLE OUTPUT
# ---------------------------------------------------------

def print_pretty_result(r):
    """Nicely formatted colored console output."""
    print()
    print(Colors.c("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", Colors.CYAN))
    print(Colors.c(f"TARGET: {r['host']}", Colors.MAGENTA))
    print(Colors.c("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", Colors.CYAN))

    if not r["is_wordpress"]:
        print(Colors.c("Not a WordPress site", Colors.RED))
        return

    print(Colors.c("✔ WordPress detected", Colors.GREEN))

    if r.get("canonical"):
        print(Colors.c(f"  Canonical URL: {r['canonical']}", Colors.BLUE))

    if r.get("version"):
        print(Colors.c(f"  Version: {r['version']}", Colors.YELLOW))

    if r.get("evidence"):
        print(Colors.c("  Evidence:", Colors.CYAN))
        for e in r["evidence"]:
            print("    -", Colors.c(e, Colors.WHITE))

    if r.get("exposures"):
        print(Colors.c("  Exposures:", Colors.RED))
        for e in r["exposures"]:
            print("    -", Colors.c(e, Colors.RED))

    if r.get("plugins"):
        print(Colors.c("  Plugins:", Colors.GREEN))
        for slug, d in r["plugins"].items():
            ver = d.get("version") or "?"
            print(f"    - {slug}  (version={ver})")

    if r.get("themes"):
        print(Colors.c("  Themes:", Colors.GREEN))
        for slug, d in r["themes"].items():
            ver = d.get("version") or "?"
            print(f"    - {slug}  (version={ver})")

    if r.get("vulns"):
        print(Colors.c("  Vulnerabilities:", Colors.YELLOW))
        for v in summarize_vulns(r["vulns"]):
            print("    -", Colors.c(v, Colors.YELLOW))

    print(Colors.c("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", Colors.CYAN))
# =========================================================
#  PART 7 — MAIN RUNNER / ORCHESTRATOR
# =========================================================

def scan_single_target(host, args, local_cve_map):
    """Scan a single domain/URL and return full result object."""
    result = {
        "host": host,
        "is_wordpress": False,
        "canonical": None,
        "version": None,
        "evidence": [],
        "exposures": [],
        "plugins": {},
        "themes": {},
        "vulns": []
    }

    # -----------------------------------------
    # 1) DETECT WORDPRESS
    # -----------------------------------------
    wp = detect_wordpress(host)
    if not wp["is_wp"]:
        return result  # not WP

    result["is_wordpress"] = True
    result["canonical"] = wp.get("canonical")
    result["version"] = wp.get("version")
    result["evidence"] = wp.get("evidence", [])

    canonical = result["canonical"]

    # -----------------------------------------
    # 2) EXPOSURE CHECKS
    # -----------------------------------------
    exposures = run_exposure_checks(canonical)
    result["exposures"] = exposures

    # -----------------------------------------
    # 3) PLUGIN/THEME ENUMERATION
    # -----------------------------------------
    enum_res = enumerate_plugins_and_themes(
        canonical,
        deep=args.deep_enum
    )
    result["plugins"] = enum_res["plugins"]
    result["themes"] = enum_res["themes"]

    # -----------------------------------------
    # 4) VULNERABILITY INTELLIGENCE
    # -----------------------------------------
    all_vulns = []

    # ---- WPVulnerability API ----
    if args.use_wpvuln:
        # core
        if result["version"]:
            vc = query_wpvuln_core(result["version"])
            if vc and vc.get("vulnerabilities"):
                all_vulns.extend(vc["vulnerabilities"])

        # plugins
        for slug in result["plugins"]:
            data = query_wpvuln_plugin(slug)
            if data and data.get("vulnerabilities"):
                all_vulns.extend(data["vulnerabilities"])

        # themes
        for slug in result["themes"]:
            data = query_wpvuln_theme(slug)
            if data and data.get("vulnerabilities"):
                all_vulns.extend(data["vulnerabilities"])

    # ---- WPScan API ----
    if args.use_wpscan and args.wpscan_api_key:
        key = args.wpscan_api_key

        # core
        if result["version"]:
            vc = query_wpscan_core(result["version"], key)
            if vc and "vulnerabilities" in vc:
                all_vulns.extend(vc["vulnerabilities"])

        # plugins
        for slug in result["plugins"]:
            data = query_wpscan_plugin(slug, key)
            if data and "vulnerabilities" in data:
                all_vulns.extend(data["vulnerabilities"])

        # themes
        for slug in result["themes"]:
            data = query_wpscan_theme(slug, key)
            if data and "vulnerabilities" in data:
                all_vulns.extend(data["vulnerabilities"])

    # ---- VulnCheck Public API ----
    if args.use_vulncheck:
        if result["version"]:
            vc = query_vulncheck_core(result["version"])
            if vc and vc.get("vulnerabilities"):
                all_vulns.extend(vc["vulnerabilities"])

        for slug in result["plugins"]:
            data = query_vulncheck_plugin(slug)
            if data and data.get("vulnerabilities"):
                all_vulns.extend(data["vulnerabilities"])

        for slug in result["themes"]:
            data = query_vulncheck_theme(slug)
            if data and data.get("vulnerabilities"):
                all_vulns.extend(data["vulnerabilities"])

    # ---- NVD API ----
    if args.use_nvd:
        keywords = []
        if result["version"]:
            keywords.append(f"wordpress {result['version']}")

        for slug in result["plugins"]:
            keywords.append(f"wordpress plugin {slug}")

        for slug in result["themes"]:
            keywords.append(f"wordpress theme {slug}")

        for kw in keywords:
            nvd_res = query_nvd(kw)
            if nvd_res:
                all_vulns.extend(nvd_res)

    # ---- Local CVE JSON ----
    if args.use_local_cve:
        if result["version"]:
            all_vulns.extend(lookup_local_cve(local_cve_map, result["version"]))

        for slug in result["plugins"]:
            all_vulns.extend(lookup_local_cve(local_cve_map, slug))

        for slug in result["themes"]:
            all_vulns.extend(lookup_local_cve(local_cve_map, slug))

    # -----------------------------------------
    # 5) MERGE + FINAL ASSIGN
    # -----------------------------------------
    result["vulns"] = merge_vulns(all_vulns)

    return result


# =========================================================
#  MAIN
# =========================================================

def main():
    ensure_cache()  # create cache folder

    parser = build_arg_parser()
    args = parser.parse_args()

    # Handle color output
    if args.no_color:
        Colors.disable()

    # ------------------------------------
    # Load input hosts
    # ------------------------------------
    hosts = []

    if args.crtsh:
        hosts = fetch_crtsh(args.crtsh)
        print(Colors.c(f"[i] Found {len(hosts)} hosts from crt.sh", Colors.BLUE))

        if args.list_only:
            for h in hosts:
                print(h)
            return

    if args.input:
        hosts.extend(load_from_file(args.input))

    # Deduplicate
    hosts = list(dict.fromkeys(hosts))

    if not hosts:
        print(Colors.c("[!] No hosts to scan.", Colors.RED))
        return

    # Enforce max hosts
    if len(hosts) > args.max_hosts:
        print(Colors.c(
            f"[i] Truncating list from {len(hosts)} to {args.max_hosts}",
            Colors.YELLOW
        ))
        hosts = hosts[:args.max_hosts]

    print(Colors.c(
        f"[i] Scanning {len(hosts)} hosts using {args.threads} threads...",
        Colors.CYAN
    ))

    # ------------------------------------
    # Load local CVE map if provided
    # ------------------------------------
    local_cve_map = {}
    if args.use_local_cve:
        local_cve_map = load_local_cve(args.use_local_cve)

    results = []

    # ------------------------------------
    # Thread pool
    # ------------------------------------
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        future_map = {
            pool.submit(scan_single_target, h, args, local_cve_map): h
            for h in hosts
        }
        for fut in concurrent.futures.as_completed(future_map):
            h = future_map[fut]
            try:
                res = fut.result()
                results.append(res)
                print_pretty_result(res)
            except Exception as e:
                print(Colors.c(f"[!] Error scanning {h}: {e}", Colors.RED))

    # ------------------------------------
    # Write outputs
    # ------------------------------------
    if args.output:
        write_csv(args.output, results)
    if args.txt:
        write_txt(args.txt, results)
    if args.json:
        write_json(args.json, results)


if __name__ == "__main__":
    main()
