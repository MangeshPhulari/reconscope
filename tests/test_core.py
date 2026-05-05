from reconscope.core import ReconScope


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
