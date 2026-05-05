# ReconScope

ReconScope is a small, authorized recon CLI for owned assets. It crawls a target domain or a list of domains, discovers endpoints from HTML, forms, scripts, robots.txt, and sitemaps, and extracts query parameters from discovered URLs and page markup.

## What it does

- Enumerates endpoints from links, forms, script references, inline JavaScript, robots.txt, and sitemap.xml.
- Extracts query parameters from URLs and form inputs.
- Restricts crawling to the supplied scope by default.
- Exports results as JSON, CSV, or plain text.

## Install

```bash
python -m pip install -e .
```

## Usage

```bash
reconscope example.com
reconscope example.com example.org --max-depth 2 --max-pages 500 --output json
reconscope --input targets.txt --allow-subdomains --output csv --output-file findings.csv
```

## Output

The tool reports three main sets:

- discovered endpoints
- discovered parameters
- visited pages

## Notes

Use only on systems you own or have explicit permission to assess.
