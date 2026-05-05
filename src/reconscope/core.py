from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen
import concurrent.futures as futures
import csv
import json
import re
import ssl
from collections import deque
from typing import Iterable

DEFAULT_USER_AGENT = "ReconScope/0.1"
URL_RE = re.compile(r"(?P<url>(?:https?:)?//[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)")
PARAM_RE = re.compile(r"(?:[?&]|\b)([A-Za-z_][A-Za-z0-9_\-]{1,60})=")
JS_ENDPOINT_RE = re.compile(r"(?:['\"])((?:https?:)?//[^'\"\s]+|/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)(?:['\"])" )


@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    source: str


@dataclass(frozen=True)
class DiscoveredParameter:
    name: str
    source: str
    url: str | None = None


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


@dataclass
class ReconResult:
    target: str
    visited_pages: list[str] = field(default_factory=list)
    endpoints: dict[str, DiscoveredEndpoint] = field(default_factory=dict)
    parameters: dict[str, DiscoveredParameter] = field(default_factory=dict)
    pages: dict[str, PageRecord] = field(default_factory=dict)

    def merge(self, other: "ReconResult") -> None:
        self.visited_pages.extend(page for page in other.visited_pages if page not in self.visited_pages)
        self.endpoints.update(other.endpoints)
        self.parameters.update(other.parameters)
        self.pages.update(other.pages)


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


class ReconScope:
    def __init__(
        self,
        *,
        max_depth: int = 2,
        max_pages: int = 250,
        concurrency: int = 8,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
        allow_subdomains: bool = False,
        allow_external: bool = False,
        verify_ssl: bool = True,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.user_agent = user_agent
        self.allow_subdomains = allow_subdomains
        self.allow_external = allow_external
        self.verify_ssl = verify_ssl

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
        ssl_context = None if self.verify_ssl else ssl._create_unverified_context()

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

            with futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                future_map = {
                    executor.submit(self._fetch_and_extract, url, ssl_context): (url, depth)
                    for url, depth in batch
                }
                for future in futures.as_completed(future_map):
                    url, depth = future_map[future]
                    page, discovered = future.result()
                    result.visited_pages.append(url)
                    result.pages[url] = page
                    for endpoint in discovered.endpoints:
                        result.endpoints.setdefault(endpoint.url, endpoint)
                    for parameter in discovered.parameters:
                        key = f"{parameter.name}|{parameter.source}|{parameter.url or ''}"
                        result.parameters.setdefault(key, parameter)
                    if depth < self.max_depth:
                        for candidate in discovered.urls:
                            if candidate not in seen and self._is_allowed(candidate, allowed_hosts):
                                queue.append((candidate, depth + 1))

        return result

    @dataclass
    class _ExtractionBundle:
        urls: set[str] = field(default_factory=set)
        endpoints: set[DiscoveredEndpoint] = field(default_factory=set)
        parameters: set[DiscoveredParameter] = field(default_factory=set)

    def _fetch_and_extract(self, url: str, ssl_context: ssl.SSLContext | None) -> tuple[PageRecord, "ReconScope._ExtractionBundle"]:
        page = self._fetch(url, ssl_context)
        bundle = self._ExtractionBundle()
        if not page:
            return PageRecord(url=url, status_code=None, content_type=None, title=None, source="fetch-failed"), bundle

        content = page["body"]
        content_type = page["content_type"]
        status_code = page["status_code"]
        title = None
        parser = _HTMLDiscoveryParser()

        if "html" in content_type or content.lstrip().startswith("<"):
            try:
                parser.feed(content)
            except Exception:
                pass
            title = parser.title
            for href, source in parser.links:
                bundle.urls.add(self._resolve(url, href))
                bundle.endpoints.add(DiscoveredEndpoint(url=self._resolve(url, href), source=source))
            for script in parser.scripts:
                bundle.urls.add(self._resolve(url, script))
                bundle.endpoints.add(DiscoveredEndpoint(url=self._resolve(url, script), source="html:script[src]"))
            for action, method in parser.forms:
                if action:
                    resolved = self._resolve(url, action)
                    bundle.endpoints.add(DiscoveredEndpoint(url=resolved, source=f"html:form[{method}]") )
                    bundle.urls.add(resolved)
            for chunk in parser.text_chunks:
                if chunk.startswith("__PARAM__"):
                    bundle.parameters.add(DiscoveredParameter(name=chunk.removeprefix("__PARAM__"), source="html:form-field", url=url))

        bundle.urls.update(self._extract_urls_from_text(content, url))
        bundle.endpoints.update(self._extract_endpoints_from_text(content, url))
        bundle.parameters.update(self._extract_parameters_from_text(content, url))

        for endpoint in list(bundle.endpoints):
            bundle.urls.add(endpoint.url)

        page_record = PageRecord(
            url=url,
            status_code=status_code,
            content_type=content_type,
            title=title,
            source="html" if "html" in content_type else "text",
            discovered_urls=set(bundle.urls),
            endpoints={endpoint.url for endpoint in bundle.endpoints},
            parameters={parameter.name for parameter in bundle.parameters},
        )
        return page_record, bundle

    def _fetch(self, url: str, ssl_context: ssl.SSLContext | None) -> dict[str, str | int] | None:
        headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=self.timeout, context=ssl_context) as response:
                body_bytes = response.read()
                content_type = response.headers.get_content_type()
                charset = response.headers.get_content_charset() or "utf-8"
                body = body_bytes.decode(charset, errors="replace")
                status_code = getattr(response, "status", 200)
                return {"body": body, "content_type": content_type, "status_code": status_code}
        except (HTTPError, URLError, TimeoutError, UnicodeError):
            return None

    def _extract_urls_from_text(self, text: str, base_url: str) -> set[str]:
        results: set[str] = set()
        for match in URL_RE.finditer(text):
            results.add(self._resolve(base_url, match.group("url")))
        return results

    def _extract_endpoints_from_text(self, text: str, base_url: str) -> set[DiscoveredEndpoint]:
        endpoints: set[DiscoveredEndpoint] = set()
        for match in URL_RE.finditer(text):
            candidate = self._resolve(base_url, match.group("url"))
            endpoints.add(DiscoveredEndpoint(url=candidate, source="text:url"))
        for match in JS_ENDPOINT_RE.finditer(text):
            candidate = self._resolve(base_url, match.group(1))
            endpoints.add(DiscoveredEndpoint(url=candidate, source="js:string"))
        return endpoints

    def _extract_parameters_from_text(self, text: str, base_url: str) -> set[DiscoveredParameter]:
        parameters: set[DiscoveredParameter] = set()
        for match in PARAM_RE.finditer(text):
            parameters.add(DiscoveredParameter(name=match.group(1), source="text", url=base_url))
        for candidate in self._extract_urls_from_text(text, base_url):
            for key, _ in parse_qsl(urlparse(candidate).query, keep_blank_values=True):
                parameters.add(DiscoveredParameter(name=key, source="url-query", url=candidate))
        return parameters

    def _resolve(self, base_url: str, candidate: str) -> str:
        return self._canonicalize(urlparse(urljoin(base_url, candidate)))

    def _normalize_target(self, target: str) -> str:
        if "//" not in target:
            target = f"https://{target}"
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid target: {target}")
        return self._canonicalize(parsed)

    def _canonicalize(self, parsed) -> str:
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query = parsed.query
        fragment = ""
        return urlunparse((scheme, netloc, path, "", query, fragment))

    def _is_allowed(self, url: str, allowed_hosts: set[str]) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if self.allow_external:
            return True
        if host in allowed_hosts:
            return True
        if self.allow_subdomains:
            return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)
        return False

    def export_json(self, result: ReconResult) -> str:
        payload = {
            "target": result.target,
            "visited_pages": result.visited_pages,
            "endpoints": [endpoint.__dict__ for endpoint in result.endpoints.values()],
            "parameters": [parameter.__dict__ for parameter in result.parameters.values()],
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
                }
                for page in result.pages.values()
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def export_csv(self, result: ReconResult) -> str:
        lines: list[str] = []
        rows = [
            ("type", "value", "source", "url"),
        ]
        rows.extend(("endpoint", endpoint.url, endpoint.source, "") for endpoint in result.endpoints.values())
        rows.extend(("parameter", parameter.name, parameter.source, parameter.url or "") for parameter in result.parameters.values())
        buffer = []
        writer = csv.writer(buffer := _CSVBuffer())
        for row in rows:
            writer.writerow(row)
        return buffer.getvalue()

    def export_text(self, result: ReconResult) -> str:
        lines = [f"Target: {result.target}", "", "Endpoints:"]
        for endpoint in sorted(result.endpoints.values(), key=lambda item: item.url):
            lines.append(f"- {endpoint.url} [{endpoint.source}]")
        lines.append("")
        lines.append("Parameters:")
        for parameter in sorted(result.parameters.values(), key=lambda item: item.name):
            suffix = f" ({parameter.url})" if parameter.url else ""
            lines.append(f"- {parameter.name} [{parameter.source}]{suffix}")
        lines.append("")
        lines.append(f"Visited pages: {len(result.visited_pages)}")
        return "\n".join(lines)


class _CSVBuffer:
    def __init__(self) -> None:
        self._chunks: list[str] = []

    def write(self, text: str) -> int:
        self._chunks.append(text)
        return len(text)

    def getvalue(self) -> str:
        return "".join(self._chunks)
