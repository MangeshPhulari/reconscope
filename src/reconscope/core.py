from __future__ import annotations

import csv
import json
import os
import random
import re
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_USER_AGENT = "ReconScope/2.0"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "curl/8.7.1",
]

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".webm",
    ".css", ".woff", ".woff2", ".eot", ".ttf", ".otf",
    ".zip", ".tar", ".gz", ".rar", ".7z",
}

# URL / parameter / JS-endpoint regexes
URL_RE = re.compile(r"(?P<url>(?:https?:)?//[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)")
PARAM_RE = re.compile(r"(?:[?&]|\b)([A-Za-z_][A-Za-z0-9_\-]{1,60})=")

# Deep JS patterns (fetch, axios, XHR, $.ajax, template literals, Next.js)
JS_PATTERNS = [
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""(?:open|send)\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`\s]+)['"`]""", re.DOTALL),
    re.compile(r"""url\s*:\s*['"`]([/][^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/api/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/v\d+/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/rest/[^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/graphql[^'"`\s]*)['"`]"""),
    re.compile(r"""href\s*=\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""action\s*=\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""(?:https?:)?//[A-Za-z0-9._-]+/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"""),
]

# API patterns & sensitive data regexes
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    "AWS Secret Key": re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Firebase Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "JWT Token": re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    "GitHub Token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
}

API_COMMON_PATHS = [
    "/api/v1", "/api/v2", "/api", "/rest/v1", "/rest/v2", "/v1", "/v2",
    "/swagger/v1/swagger.json", "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/docs", "/schema.graphql", "/v3", "/api/v3"
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    source: str


@dataclass(frozen=True)
class DiscoveredParameter:
    name: str
    source: str
    url: str | None = None


@dataclass(frozen=True)
class DiscoveredSecret:
    type: str
    value: str
    url: str


@dataclass
class PageRecord:
    url: str
    status_code: int | None
    content_type: str | None
    title: str | None
    source: str
    discovered_urls: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    parameters: set[str] = field(default_factory=set)
    secrets: list[DiscoveredSecret] = field(default_factory=list)


@dataclass
class ReconResult:
    target: str
    visited_pages: list[str] = field(default_factory=list)
    endpoints: dict[str, DiscoveredEndpoint] = field(default_factory=dict)
    parameters: dict[str, DiscoveredParameter] = field(default_factory=dict)
    pages: dict[str, PageRecord] = field(default_factory=dict)
    wayback_urls: list[str] = field(default_factory=list)
    secrets: list[DiscoveredSecret] = field(default_factory=list)

    def merge(self, other: "ReconResult") -> None:
        self.visited_pages.extend(p for p in other.visited_pages if p not in self.visited_pages)
        self.endpoints.update(other.endpoints)
        self.parameters.update(other.parameters)
        self.pages.update(other.pages)
        self.wayback_urls.extend(u for u in other.wayback_urls if u not in self.wayback_urls)
        self.secrets.extend(s for s in other.secrets if s not in self.secrets)


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------

class _HTMLDiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[tuple[str, str]] = set()
        self.scripts: set[str] = set()
        self.forms: set[tuple[str, str]] = set()
        self.text_chunks: list[str] = []
        self.title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value for key, value in attrs if value is not None}
        if tag == "a" and "href" in attr_map:
            self.links.add((attr_map["href"], "html:a[href]"))
        elif tag in {"link", "script", "img", "iframe", "source"}:
            candidate = attr_map.get("href") or attr_map.get("src") or attr_map.get("data-src")
            if candidate:
                self.links.add((candidate, f"html:{tag}"))
            if tag == "script" and "src" in attr_map:
                self.scripts.add(attr_map["src"])
        elif tag == "form":
            action = attr_map.get("action") or ""
            method = attr_map.get("method") or "GET"
            self.forms.add((action, method.upper()))
            if action:
                self.links.add((action, "html:form[action]"))
        elif tag in {"input", "select", "textarea"}:
            name = attr_map.get("name")
            if name:
                self.text_chunks.append(f"__PARAM__{name}")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = (self.title or "") + data.strip()
        if data.strip():
            self.text_chunks.append(data)


# ---------------------------------------------------------------------------
# Passive Source Miners (Wayback, OTX, CommonCrawl)
# ---------------------------------------------------------------------------

class BaseMiner:
    def __init__(
        self,
        placeholder: str = "FUZZ",
        proxies: dict[str, str] | None = None,
        timeout: float = 20.0,
        filter_extensions: bool = True,
    ) -> None:
        self.placeholder = placeholder
        self.proxies = proxies or {}
        self.timeout = timeout
        self.filter_extensions = filter_extensions

    def mine(self, domain: str) -> list[str]:
        raise NotImplementedError

    def _clean_urls(self, urls: list[str]) -> list[str]:
        seen: set[str] = set()
        cleaned: list[str] = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    continue
                ext = os.path.splitext(parsed.path)[1].lower()
                if self.filter_extensions and ext in SKIP_EXTENSIONS:
                    continue
                if not parsed.query:
                    continue
                # Replace all param values with placeholder
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                new_query = "&".join(f"{k}={self.placeholder}" for k, _ in pairs)
                clean = urlunparse(parsed._replace(query=new_query))
                if clean not in seen:
                    seen.add(clean)
                    cleaned.append(clean)
            except Exception:
                continue
        return cleaned

    def extract_parameters(self, urls: list[str], source_name: str) -> set[DiscoveredParameter]:
        params: set[DiscoveredParameter] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    params.add(DiscoveredParameter(name=key, source=source_name, url=url))
            except Exception:
                continue
        return params

class WaybackMiner(BaseMiner):
    """Query the Wayback Machine CDX API."""
    CDX_URL = "https://web.archive.org/cdx/search/cdx"

    def mine(self, domain: str) -> list[str]:
        # Use wildcard to find subdomains
        query_url = f"*.{domain}" if not domain.startswith("*.") else domain
        params = {
            "url": f"{query_url}/*",
            "output": "txt",
            "collapse": "urlkey",
            "fl": "original",
        }
        for attempt in range(3):  # 3 retries for 503/errors
            try:
                resp = requests.get(
                    self.CDX_URL,
                    params=params,
                    timeout=self.timeout,
                    proxies=self.proxies,
                )
                if resp.status_code == 503:
                    time.sleep(2 * (attempt + 1))
                    continue
                resp.raise_for_status()
                raw = [line.strip() for line in resp.text.splitlines() if line.strip()]
                return self._clean_urls(raw)
            except Exception:
                if attempt == 2: break
                time.sleep(1)
        return []

class OTXMiner(BaseMiner):
    """Query AlienVault OTX URL list."""
    API_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"

    def mine(self, domain: str) -> list[str]:
        url = self.API_URL.format(domain=domain)
        params = {"limit": 500, "page": 1}
        try:
            resp = requests.get(
                url,
                params=params,
                timeout=self.timeout,
                proxies=self.proxies,
            )
            resp.raise_for_status()
            data = resp.json()
            raw = [item["url"] for item in data.get("url_list", []) if "url" in item]
            return self._clean_urls(raw)
        except Exception:
            return []

class CommonCrawlMiner(BaseMiner):
    """Query Common Crawl index."""
    INDEX_URL = "https://index.commoncrawl.org/collinfo.json"

    def mine(self, domain: str) -> list[str]:
        try:
            # Get latest index
            resp = requests.get(self.INDEX_URL, timeout=self.timeout, proxies=self.proxies)
            resp.raise_for_status()
            latest_index = resp.json()[0]["cdx-api"]
            
            query_url = f"*.{domain}"
            params = {
                "url": query_url,
                "output": "json",
                "fl": "url",
            }
            resp = requests.get(latest_index, params=params, timeout=self.timeout, proxies=self.proxies)
            if resp.status_code != 200:
                return []
            
            raw = []
            for line in resp.text.splitlines():
                try:
                    item = json.loads(line)
                    if "url" in item:
                        raw.append(item["url"])
                except Exception:
                    continue
            return self._clean_urls(raw)
        except Exception:
            return []

class HackerTargetMiner(BaseMiner):
    """Query HackerTarget API for host links."""
    API_URL = "https://api.hackertarget.com/pagelinks/?q={domain}"

    def mine(self, domain: str) -> list[str]:
        url = self.API_URL.format(domain=domain)
        try:
            resp = requests.get(url, timeout=self.timeout, proxies=self.proxies)
            resp.raise_for_status()
            raw = [line.strip() for line in resp.text.splitlines() if line.strip() and "http" in line]
            return self._clean_urls(raw)
        except Exception:
            return []

class MultiSourceMiner:
    """Orchestrates multiple passive sources in parallel."""
    def __init__(self, **kwargs):
        self.miners = [
            WaybackMiner(**kwargs),
            OTXMiner(**kwargs),
            CommonCrawlMiner(**kwargs),
            HackerTargetMiner(**kwargs),
        ]

    def mine_all(self, domain: str) -> tuple[list[str], set[DiscoveredParameter]]:
        all_urls = set()
        all_params = set()
        
        import concurrent.futures as _futures
        with _futures.ThreadPoolExecutor(max_workers=len(self.miners)) as executor:
            future_to_miner = {executor.submit(m.mine, domain): m for m in self.miners}
            for future in _futures.as_completed(future_to_miner):
                miner = future_to_miner[future]
                source_name = miner.__class__.__name__.replace("Miner", "").lower()
                try:
                    urls = future.result()
                    all_urls.update(urls)
                    all_params.update(miner.extract_parameters(urls, source_name))
                except Exception:
                    continue
        
        return sorted(list(all_urls)), all_params


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class ReconScope:
    def __init__(
        self,
        *,
        max_depth: int = 2,
        max_pages: int = 250,
        concurrency: int = 8,
        timeout: float = 10.0,
        user_agent: str | None = None,
        rotate_ua: bool = True,
        allow_subdomains: bool = False,
        allow_external: bool = False,
        verify_ssl: bool = True,
        proxy: str | None = None,
        delay: float = 0.0,
        extra_headers: dict[str, str] | None = None,
        filter_extensions: bool = True,
        placeholder: str | None = None,
        progress_callback=None,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.user_agent = user_agent
        self.rotate_ua = rotate_ua
        self.allow_subdomains = allow_subdomains
        self.allow_external = allow_external
        self.verify_ssl = verify_ssl
        self.proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.delay = delay
        self.extra_headers = extra_headers or {}
        self.filter_extensions = filter_extensions
        self.placeholder = placeholder
        self.progress_callback = progress_callback  # called with (visited, max_pages)
        self._session = self._make_session()

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = self.verify_ssl
        if self.proxies:
            s.proxies.update(self.proxies)
        return s

    def _pick_ua(self) -> str:
        if self.user_agent:
            return self.user_agent
        if self.rotate_ua:
            return random.choice(USER_AGENTS)
        return DEFAULT_USER_AGENT

    def run(self, targets: Iterable[str]) -> ReconResult:
        aggregate = ReconResult(target=";".join(targets))
        for target in targets:
            aggregate.merge(self._run_single(target))
        return aggregate

    def _run_single(self, target: str) -> ReconResult:
        normalized = self._normalize_target(target)
        allowed_hosts = {normalized.netloc}
        result = ReconResult(target=target)
        queue: deque[tuple[str, int]] = deque([(urlunparse(normalized), 0)])
        seen: set[str] = set()

        while queue and len(result.visited_pages) < self.max_pages:
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < self.concurrency and len(result.visited_pages) + len(batch) < self.max_pages:
                current_url, depth = queue.popleft()
                if current_url in seen:
                    continue
                if not self._is_allowed(current_url, allowed_hosts):
                    continue
                seen.add(current_url)
                batch.append((current_url, depth))

            if not batch:
                continue

            import concurrent.futures as _futures
            with _futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                future_map = {
                    executor.submit(self._fetch_and_extract, url): (url, depth)
                    for url, depth in batch
                }
                for future in _futures.as_completed(future_map):
                    url, depth = future_map[future]
                    page, bundle = future.result()
                    result.visited_pages.append(url)
                    result.pages[url] = page
                    for endpoint in bundle.endpoints:
                        result.endpoints.setdefault(endpoint.url, endpoint)
                    for parameter in bundle.parameters:
                        key = f"{parameter.name}|{parameter.source}|{parameter.url or ''}"
                        result.parameters.setdefault(key, parameter)
                    if depth < self.max_depth:
                        for candidate in bundle.urls:
                            if candidate not in seen and self._is_allowed(candidate, allowed_hosts):
                                queue.append((candidate, depth + 1))

                    if self.progress_callback:
                        self.progress_callback(len(result.visited_pages), self.max_pages)

                    if self.delay > 0:
                        time.sleep(self.delay)

        return result

    @dataclass
    class _ExtractionBundle:
        urls: set[str] = field(default_factory=set)
        endpoints: set[DiscoveredEndpoint] = field(default_factory=set)
        parameters: set[DiscoveredParameter] = field(default_factory=set)

    def _fetch_and_extract(self, url: str) -> tuple[PageRecord, "_ExtractionBundle"]:
        page_data = self._fetch(url)
        bundle = self._ExtractionBundle()
        if not page_data:
            return PageRecord(url=url, status_code=None, content_type=None, title=None, source="fetch-failed"), bundle

        content = page_data["body"]
        content_type = page_data["content_type"]
        status_code = page_data["status_code"]
        title = None
        parser = _HTMLDiscoveryParser()

        if "html" in content_type or content.lstrip().startswith("<"):
            try:
                parser.feed(content)
            except Exception:
                pass
            title = parser.title
            for href, source in parser.links:
                resolved = self._resolve(url, href)
                if not self._skip_url(resolved):
                    bundle.urls.add(resolved)
                    bundle.endpoints.add(DiscoveredEndpoint(url=resolved, source=source))
            for script in parser.scripts:
                resolved = self._resolve(url, script)
                bundle.urls.add(resolved)
                bundle.endpoints.add(DiscoveredEndpoint(url=resolved, source="html:script[src]"))
            for action, method in parser.forms:
                if action:
                    resolved = self._resolve(url, action)
                    bundle.endpoints.add(DiscoveredEndpoint(url=resolved, source=f"html:form[{method}]"))
                    bundle.urls.add(resolved)
            for chunk in parser.text_chunks:
                if chunk.startswith("__PARAM__"):
                    bundle.parameters.add(DiscoveredParameter(name=chunk.removeprefix("__PARAM__"), source="html:form-field", url=url))

        # Deep JS extraction
        bundle.endpoints.update(self._deep_js_extract(content, url))
        bundle.urls.update(e.url for e in bundle.endpoints)
        bundle.parameters.update(self._extract_parameters_from_text(content, url))

        # Secret Scanning (V4)
        secrets = self._scan_secrets(content, url)
        
        # API Discovery (V4)
        if status_code == 200 and ("html" in content_type or url.endswith("/")):
            bundle.endpoints.update(self._discover_apis(url))

        # Apply placeholder to outgoing URLs if requested
        if self.placeholder:
            bundle.endpoints = {self._fuzz_endpoint(e) for e in bundle.endpoints}

        for endpoint in list(bundle.endpoints):
            bundle.urls.add(endpoint.url)

        page_record = PageRecord(
            url=url,
            status_code=status_code,
            content_type=content_type,
            title=title,
            source="html" if "html" in content_type else "text",
            discovered_urls=set(bundle.urls),
            endpoints={ep.url for ep in bundle.endpoints},
            parameters={p.name for p in bundle.parameters},
            secrets=secrets,
        )
        return page_record, bundle

    def _scan_secrets(self, text: str, url: str) -> list[DiscoveredSecret]:
        discovered = []
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                discovered.append(DiscoveredSecret(type=name, value=match.group(0), url=url))
        return discovered

    def _discover_apis(self, base_url: str) -> set[DiscoveredEndpoint]:
        endpoints = set()
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in API_COMMON_PATHS:
            target = urljoin(origin, path)
            endpoints.add(DiscoveredEndpoint(url=target, source="api:discovery"))
        return endpoints

    def _fetch(self, url: str) -> dict[str, str | int] | None:
        headers = {
            "User-Agent": self._pick_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            **self.extra_headers,
        }
        try:
            resp = self._session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            content_type = resp.headers.get("Content-Type", "text/html").split(";")[0].strip()
            charset = resp.apparent_encoding or "utf-8"
            body = resp.content.decode(charset, errors="replace")
            return {"body": body, "content_type": content_type, "status_code": resp.status_code}
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Deep JS endpoint extraction
    # ------------------------------------------------------------------

    def _deep_js_extract(self, text: str, base_url: str) -> set[DiscoveredEndpoint]:
        endpoints: set[DiscoveredEndpoint] = set()
        for pattern in JS_PATTERNS:
            for match in pattern.finditer(text):
                candidate = match.group(1) if match.lastindex else match.group(0)
                candidate = candidate.strip("'\"` \t\n\r")
                if not candidate or len(candidate) > 512:
                    continue
                resolved = self._resolve(base_url, candidate)
                if resolved.startswith("http"):
                    endpoints.add(DiscoveredEndpoint(url=resolved, source="js:deep"))
        return endpoints

    # ------------------------------------------------------------------
    # Parameter extraction
    # ------------------------------------------------------------------

    def _extract_parameters_from_text(self, text: str, base_url: str) -> set[DiscoveredParameter]:
        parameters: set[DiscoveredParameter] = set()
        for match in PARAM_RE.finditer(text):
            parameters.add(DiscoveredParameter(name=match.group(1), source="text", url=base_url))
        for match in URL_RE.finditer(text):
            candidate = self._resolve(base_url, match.group("url"))
            for key, _ in parse_qsl(urlparse(candidate).query, keep_blank_values=True):
                parameters.add(DiscoveredParameter(name=key, source="url-query", url=candidate))
        return parameters

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _resolve(self, base_url: str, candidate: str) -> str:
        try:
            return self._canonicalize(urlparse(urljoin(base_url, candidate)))
        except (ValueError, Exception):
            return ""

    def _normalize_target(self, target: str) -> urlparse:
        if "//" not in target:
            target = f"https://{target}"
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid target: {target}")
        return self._canonicalize_parsed(parsed)

    def _canonicalize(self, parsed) -> str:
        return urlunparse(self._canonicalize_parsed(parsed))

    def _canonicalize_parsed(self, parsed):
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return parsed._replace(scheme=scheme, netloc=netloc, path=path, fragment="")

    def _is_allowed(self, url: str, allowed_hosts: set[str]) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if not host:
            return False
        if self.allow_external:
            return True
        if host in allowed_hosts:
            return True
        if self.allow_subdomains:
            return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)
        return False

    def _skip_url(self, url: str) -> bool:
        if not self.filter_extensions:
            return False
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        return ext in SKIP_EXTENSIONS

    def _fuzz_endpoint(self, ep: DiscoveredEndpoint) -> DiscoveredEndpoint:
        parsed = urlparse(ep.url)
        if not parsed.query:
            return ep
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        new_query = "&".join(f"{k}={self.placeholder}" for k, _ in pairs)
        new_url = urlunparse(parsed._replace(query=new_query))
        return DiscoveredEndpoint(url=new_url, source=ep.source)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def export_json(self, result: ReconResult) -> str:
        payload = {
            "target": result.target,
            "visited_pages": result.visited_pages,
            "wayback_urls": result.wayback_urls,
            "endpoints": [ep.__dict__ for ep in result.endpoints.values()],
            "parameters": [p.__dict__ for p in result.parameters.values()],
            "secrets": [s.__dict__ for s in result.secrets],
            "pages": [
                {
                    "url": page.url,
                    "status_code": page.status_code,
                    "content_type": page.content_type,
                    "title": page.title,
                    "source": page.source,
                    "discovered_urls": sorted(page.discovered_urls),
                    "endpoints": sorted(page.endpoints),
                    "parameters": sorted(page.parameters),
                    "secrets": [s.__dict__ for s in page.secrets],
                }
                for page in result.pages.values()
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def export_csv(self, result: ReconResult) -> str:
        rows = [("type", "value", "source", "url")]
        rows.extend(("endpoint", ep.url, ep.source, "") for ep in result.endpoints.values())
        rows.extend(("parameter", p.name, p.source, p.url or "") for p in result.parameters.values())
        rows.extend(("wayback", url, "wayback", "") for url in result.wayback_urls)
        rows.extend(("secret", s.value, s.type, s.url) for s in result.secrets)
        buffer = _CSVBuffer()
        writer = csv.writer(buffer)
        for row in rows:
            writer.writerow(row)
        return buffer.getvalue()

    def export_text(self, result: ReconResult) -> str:
        lines = [f"Target: {result.target}", "", "Endpoints:"]
        for ep in sorted(result.endpoints.values(), key=lambda e: e.url):
            lines.append(f"  {ep.url}  [{ep.source}]")
        lines += ["", "Parameters:"]
        for p in sorted(result.parameters.values(), key=lambda x: x.name):
            suffix = f"  ({p.url})" if p.url else ""
            lines.append(f"  {p.name}  [{p.source}]{suffix}")
        if result.secrets:
            lines += ["", "Secrets Found:"]
            for s in result.secrets:
                lines.append(f"  [{s.type}] {s.value}  ({s.url})")
        if result.wayback_urls:
            lines += ["", "Passive URLs:"]
            for url in sorted(result.wayback_urls):
                lines.append(f"  {url}")
        lines += ["", f"Visited pages: {len(result.visited_pages)}"]
        return "\n".join(lines)

    def export_params_only(self, result: ReconResult) -> str:
        names = sorted({p.name for p in result.parameters.values()})
        return "\n".join(names)

    def export_endpoints_only(self, result: ReconResult) -> str:
        urls = sorted({ep.url for ep in result.endpoints.values()} | set(result.wayback_urls))
        return "\n".join(urls)

    def save_output_dir(self, result: ReconResult, out_dir: Path, fmt: str) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        domain = result.target.replace("https://", "").replace("http://", "").split("/")[0]
        fname = out_dir / f"{domain}.{fmt if fmt != 'text' else 'txt'}"
        if fmt == "json":
            content = self.export_json(result)
        elif fmt == "csv":
            content = self.export_csv(result)
        else:
            content = self.export_text(result)
        fname.write_text(content, encoding="utf-8")
        return fname


class _CSVBuffer:
    def __init__(self) -> None:
        self._chunks: list[str] = []

    def write(self, text: str) -> int:
        self._chunks.append(text)
        return len(text)

    def getvalue(self) -> str:
        return "".join(self._chunks)
