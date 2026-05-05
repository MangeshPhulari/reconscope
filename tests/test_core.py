"""Tests for ReconScope v2."""
from __future__ import annotations

from urllib.parse import urlparse

import pytest

from reconscope.core import ReconScope, WaybackMiner, DiscoveredParameter, SKIP_EXTENSIONS


# ---------------------------------------------------------------------------
# Existing tests (preserved)
# ---------------------------------------------------------------------------

def test_extracts_parameters_from_url_and_text() -> None:
    engine = ReconScope()
    text = "fetch('/api/users?id=1&token=abc'); const next = '/search?q=test';"
    params = engine._extract_parameters_from_text(text, "https://example.com/page")
    names = {item.name for item in params}
    assert "id" in names
    assert "token" in names
    assert "q" in names


def test_resolves_relative_urls() -> None:
    engine = ReconScope()
    assert engine._resolve("https://example.com/app/index.html", "/api/v1/users") == "https://example.com/api/v1/users"


def test_scope_blocks_external_hosts_by_default() -> None:
    engine = ReconScope()
    assert engine._is_allowed("https://evil.test/", {"example.com"}) is False
    assert engine._is_allowed("https://example.com/a", {"example.com"}) is True


# ---------------------------------------------------------------------------
# Extension filtering
# ---------------------------------------------------------------------------

def test_skip_url_filters_static_assets() -> None:
    engine = ReconScope(filter_extensions=True)
    assert engine._skip_url("https://example.com/logo.png") is True
    assert engine._skip_url("https://example.com/font.woff2") is True
    assert engine._skip_url("https://example.com/api/users") is False
    assert engine._skip_url("https://example.com/page.html") is False


def test_skip_url_disabled() -> None:
    engine = ReconScope(filter_extensions=False)
    assert engine._skip_url("https://example.com/logo.png") is False


def test_skip_extensions_set_contains_expected() -> None:
    for ext in (".jpg", ".png", ".gif", ".css", ".woff2", ".mp4", ".pdf"):
        assert ext in SKIP_EXTENSIONS


# ---------------------------------------------------------------------------
# FUZZ placeholder
# ---------------------------------------------------------------------------

def test_fuzz_endpoint_replaces_values() -> None:
    from reconscope.core import DiscoveredEndpoint
    engine = ReconScope(placeholder="FUZZ")
    ep = DiscoveredEndpoint(url="https://example.com/search?q=hello&page=2", source="test")
    fuzzed = engine._fuzz_endpoint(ep)
    assert "q=FUZZ" in fuzzed.url
    assert "page=FUZZ" in fuzzed.url
    assert "hello" not in fuzzed.url


def test_fuzz_endpoint_no_query_unchanged() -> None:
    from reconscope.core import DiscoveredEndpoint
    engine = ReconScope(placeholder="FUZZ")
    ep = DiscoveredEndpoint(url="https://example.com/api/users", source="test")
    assert engine._fuzz_endpoint(ep).url == ep.url


def test_custom_placeholder() -> None:
    from reconscope.core import DiscoveredEndpoint
    engine = ReconScope(placeholder="INJECT")
    ep = DiscoveredEndpoint(url="https://example.com/?id=1", source="test")
    fuzzed = engine._fuzz_endpoint(ep)
    assert "id=INJECT" in fuzzed.url


# ---------------------------------------------------------------------------
# Deep JS extraction
# ---------------------------------------------------------------------------

def test_deep_js_fetch_pattern() -> None:
    engine = ReconScope()
    js = """fetch('/api/users?id=1&role=admin')"""
    endpoints = engine._deep_js_extract(js, "https://example.com")
    urls = {ep.url for ep in endpoints}
    assert any("/api/users" in u for u in urls)


def test_deep_js_axios_pattern() -> None:
    engine = ReconScope()
    js = """axios.get('/api/data?token=abc')"""
    endpoints = engine._deep_js_extract(js, "https://example.com")
    urls = {ep.url for ep in endpoints}
    assert any("/api/data" in u for u in urls)


def test_deep_js_graphql_pattern() -> None:
    engine = ReconScope()
    js = """const url = '/graphql?query=test'"""
    endpoints = engine._deep_js_extract(js, "https://example.com")
    urls = {ep.url for ep in endpoints}
    assert any("/graphql" in u for u in urls)


def test_deep_js_source_label() -> None:
    engine = ReconScope()
    js = """fetch('/api/search')"""
    endpoints = engine._deep_js_extract(js, "https://example.com")
    sources = {ep.source for ep in endpoints}
    assert "js:deep" in sources


# ---------------------------------------------------------------------------
# WaybackMiner URL cleaning
# ---------------------------------------------------------------------------

def test_wayback_clean_urls_replaces_params_with_fuzz() -> None:
    miner = WaybackMiner(placeholder="FUZZ", filter_extensions=False)
    raw = [
        "https://example.com/search?q=hello&page=2",
        "https://example.com/api/users?id=123",
    ]
    cleaned = miner._clean_urls(raw)
    assert any("q=FUZZ" in u and "page=FUZZ" in u for u in cleaned)
    assert any("id=FUZZ" in u for u in cleaned)
    assert not any("hello" in u for u in cleaned)
    assert not any("123" in u for u in cleaned)


def test_wayback_clean_urls_skips_no_params() -> None:
    miner = WaybackMiner(filter_extensions=False)
    raw = ["https://example.com/about", "https://example.com/?id=1"]
    cleaned = miner._clean_urls(raw)
    assert all("?" in u for u in cleaned)


def test_wayback_clean_urls_filters_extensions() -> None:
    miner = WaybackMiner(filter_extensions=True)
    raw = [
        "https://example.com/logo.png?v=1",
        "https://example.com/search?q=test",
    ]
    cleaned = miner._clean_urls(raw)
    assert not any(".png" in u for u in cleaned)
    assert any("search" in u for u in cleaned)


def test_wayback_clean_urls_deduplicates() -> None:
    miner = WaybackMiner(filter_extensions=False)
    raw = [
        "https://example.com/?id=1",
        "https://example.com/?id=2",  # same param, different value → same after FUZZ
    ]
    cleaned = miner._clean_urls(raw)
    assert len(cleaned) == 1


def test_wayback_extract_parameters() -> None:
    miner = WaybackMiner()
    urls = [
        "https://example.com/search?q=FUZZ&lang=FUZZ",
        "https://example.com/api?token=FUZZ",
    ]
    params = miner.extract_parameters(urls)
    names = {p.name for p in params}
    assert "q" in names
    assert "lang" in names
    assert "token" in names
    for p in params:
        assert p.source == "wayback"


# ---------------------------------------------------------------------------
# CLI flag parsing (smoke tests)
# ---------------------------------------------------------------------------

def test_cli_parse_headers() -> None:
    from reconscope.cli import parse_headers
    result = parse_headers(["X-Custom: value1", "Authorization: Bearer token"])
    assert result["X-Custom"] == "value1"
    assert result["Authorization"] == "Bearer token"


def test_cli_parse_headers_none() -> None:
    from reconscope.cli import parse_headers
    assert parse_headers(None) == {}


def test_cli_load_targets_from_args(tmp_path) -> None:
    from reconscope.cli import load_targets, build_parser
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\ntestphp.vulnweb.com\n")
    parser = build_parser()
    args = parser.parse_args(["--input", str(target_file)])
    targets = load_targets(args)
    assert "example.com" in targets
    assert "testphp.vulnweb.com" in targets
