# WordPress-Mega-Scanner
A powerful passive WordPress reconnaissance &amp; vulnerability intelligence scanner. Detect WordPress, enumerate plugins/themes, identify misconfigurations, and fetch up-to-date CVEs from WPVulnerability, WPScan, VulnCheck, NVD, and local mappings — all in a single modular Python tool.


## 🔥Features
🧩 WordPress Detection

* HTML + header fingerprinting
* Meta generator parsing
* WordPress version extraction
* Canonical URL discovery

## 🛡 Exposure & Misconfiguration Checks

Identifies dozens of common exposures:

* Directory listing detection
* Backup/config files exposure
* debug.log and error_log leaks
* .env, .git/HEAD, .svn/entries disclosure
* install.php and setup-config.php leftovers
* REST API user enumeration
* Readme/license version leaks

## 🔌 Plugin & Theme Enumeration

* Slug-based detection
* Lightweight mode (default)
* Deep mode (--deep-enum):
* Reads style.css, readme, changelog, plugin headers
* Extracts plugin/theme versions
* More accurate results


## 🧠 Vulnerability Intelligence (5 Engines)

Enable any combination:

* --use-wpvuln	 
* --use-wpscan	 
* --use-vulncheck	 
* --use-nvd	NVD    
* --use-local-cve  

All results merge into a unified vulnerability list.

## ⚙️ Input Options

* File input (-i file.txt)
* CRT.sh passive enumeration (--crtsh example.com)
* Host limiting (--max-hosts N)
* CRT.sh listing only (--list-only)

## 📤 Output Formats

* CSV (-o output.csv)
* TXT (-x output.txt)
* JSON (--json output.json)
* Color-coded console output



    


# 🔧 Installation

Requires Python 3.8+.

## Install dependencies:

```python3 -m pip install requests```

## Make script executable:

```chmod +x wp_mega_enum.py```

## Make script executable:

```chmod +x wp_mega_enum.py```



## 🕹 Usage Examples

### Basic scan:
```python3 wp_mega_enum.py -i subdomains.txt -o results.csv```

### Scan a domain via CRT.sh:
```python3 wp_mega_enum.py --crtsh example.com -o enum.csv```

### List CRT.sh results only:
```python3 wp_mega_enum.py --crtsh example.com --list-only```

### Enable all vulnerability engines:

```bash
python3 wp_mega_enum.py -i urls.txt \
  --use-wpvuln \
  --use-wpscan --wpscan-api-key YOUR_API_KEY \
  --use-vulncheck \
  --use-nvd \
  --use-local-cve cves.json \
  --deep-enum \
  -o results.csv --json results.json
```



### Disable colors:
```python3 wp_mega_enum.py --no-color -i urls.txt```

### 📁 Local CVE JSON Format

* Example cves.json:

```json
{
  "wordpress 6.5": [
    "CVE-2024-0001: Example vulnerability affecting WP 6.5"
  ],
  "elementor": [
    "CVE-2023-12345: Stored XSS in Elementor"
  ]
}
```


* Use with:

```python3 wp_mega_enum.py -i urls.txt --use-local-cve cves.json```

### 🧪 Example Console Output

```txt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TARGET: example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✔ WordPress detected
  Canonical URL: https://example.com
  Version: 6.5.2
  Exposures:
    - /wp-content/uploads/ -> Directory listing enabled
  Plugins:
    - elementor (version=3.18.1)
  Vulnerabilities:
    - CVE-2023-12345: Stored XSS...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```


## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing only.
Do NOT scan systems without explicit permission.

## ❤️ Credits

Built for penetration testers, red teamers, and bug bounty hunters who need:

* Deep WordPress reconnaissance

* Multisource vulnerability intelligence

* Clean, structured reporting

* Passive, safe scanning
