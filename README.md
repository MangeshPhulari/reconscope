# ReconScope v2

> Authorized endpoint and parameter enumeration for owned targets — inspired by [ParamSpider](https://github.com/devanshbatham/paramspider) and [hakrawler](https://github.com/hakluke/hakrawler).

**Use only on systems you own or have explicit written permission to assess.**

---

## Features

| Feature | Details |
|---|---|
| **Live crawler** | BFS crawl with concurrent fetches, HTML/JS/form parsing |
| **Wayback Machine mining** | Harvests historical URLs with parameters from `web.archive.org` (opt-in via `--wayback`) |
| **Deep JS extraction** | 12 regex patterns — `fetch()`, `axios`, `XMLHttpRequest`, `$.ajax`, `/api/`, `/v1/`, Next.js manifests |
| **FUZZ placeholder** | Replaces all query-param values with `FUZZ` (or any string) for direct piping to ffuf/wfuzz |
| **Proxy support** | Routes all requests through any HTTP/S proxy (e.g. Burp Suite) |
| **Extension filtering** | Skips images, fonts, CSS, media — keeps noise low |
| **User-Agent rotation** | Randomly picks from 10 realistic browser UA strings per request |
| **Rate limiting** | Configurable delay between requests |
| **Custom headers** | Inject arbitrary HTTP headers (e.g. `Authorization`) |
| **Rich terminal UI** | Coloured banner, live progress bar, summary table |
| **Multiple output formats** | `text`, `json`, `csv` |
| **Output modes** | stdout, single file (`--output-file`), or one file per target (`--output-dir`) |

---

## Installation

> Requires **Python ≥ 3.11**

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/MangeshPhulari/reconscope.git
cd reconscope

# 2. (Recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode (installs requests + rich automatically)
pip install -e .

# 4. Verify
reconscope --help
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/MangeshPhulari/reconscope.git
cd reconscope

# 2. (Recommended) Create a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install in editable mode (installs requests + rich automatically)
pip install -e .

# 4. Verify
reconscope --help
```

> **Windows note:** If you see a script execution policy error, run:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Install without a virtual environment (system-wide)

```bash
pip install git+https://github.com/MangeshPhulari/reconscope.git
```

---

## Usage

### Basic live crawl
```bash
reconscope example.com
```

### Wayback Machine mining only (no live crawl)
```bash
reconscope --wayback --no-crawl testphp.vulnweb.com
```

### Wayback + live crawl combined
```bash
reconscope --wayback example.com --max-depth 3 --output json
```

### Output with FUZZ placeholder (pipe to ffuf)
```bash
reconscope --wayback --no-crawl --placeholder FUZZ --params-only example.com | \
  ffuf -w - -u https://example.com/search?FUZZ=test
```

### Through Burp Suite proxy
```bash
reconscope example.com --proxy http://127.0.0.1:8080 --insecure
```

### Multiple targets from file
```bash
reconscope --input targets.txt --wayback --output json --output-dir results/
```

### Endpoints only (pipe-friendly)
```bash
reconscope example.com --endpoints-only --silent
```

### Parameters only
```bash
reconscope --wayback --no-crawl example.com --params-only --silent
```

---

## All Flags

```
positional arguments:
  targets               Target domains or URLs

optional arguments:
  -h, --help            show this help message and exit

  -i, --input FILE      File with one target per line

  --max-depth N         Maximum crawl depth (default: 2)
  --max-pages N         Maximum pages per target (default: 250)
  --concurrency N       Concurrent fetches (default: 8)
  --timeout SECS        Request timeout in seconds (default: 10)
  --delay SECS          Delay between requests (default: 0)
  --no-crawl            Skip live crawl; Wayback-only mode
  --allow-subdomains    Allow subdomains within scope
  --allow-external      Allow external hosts
  --insecure            Disable TLS verification
  --no-filter-extensions  Do not skip static assets

  -w, --wayback         Enable Wayback Machine parameter mining

  --proxy URL           Proxy URL (e.g. http://127.0.0.1:8080)
  -H, --header K:V      Extra request header (repeatable)
  --user-agent STRING   Override User-Agent

  -o, --output FORMAT   Output format: text | json | csv (default: text)
  --output-file FILE    Write output to a file
  --output-dir DIR      Save one file per target in directory
  -p, --placeholder STR Replace all param values with STR (default: FUZZ)
  --params-only         Print only parameter names
  --endpoints-only      Print only endpoint URLs
  -s, --silent          Suppress banner and progress
```

---

## Output Example

```
Target: testphp.vulnweb.com

Endpoints:
  https://testphp.vulnweb.com/artists.php  [html:a[href]]
  https://testphp.vulnweb.com/search.php?test=query  [html:form[GET]]
  https://testphp.vulnweb.com/userinfo.php  [js:deep]

Parameters:
  artist   [url-query]  (https://testphp.vulnweb.com/artists.php?artist=1)
  cat      [wayback]    (https://testphp.vulnweb.com/listproducts.php?cat=FUZZ)
  searchFor [html:form-field]  (https://testphp.vulnweb.com/search.php)

Wayback URLs:
  https://testphp.vulnweb.com/listproducts.php?cat=FUZZ
  https://testphp.vulnweb.com/artists.php?artist=FUZZ

Visited pages: 47
```

---

## Run Tests

```bash
cd Tool
python -m pytest tests/ -v
```

---

## Credits

Inspired by:
- [ParamSpider](https://github.com/devanshbatham/paramspider) — Wayback Machine URL mining concept
- [hakrawler](https://github.com/hakluke/hakrawler) — fast endpoint crawling philosophy

Built by **Mangesh Phulari**.
