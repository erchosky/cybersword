"""Análisis de URLs: destino final, typosquatting y puntuación."""

import pytest

from modules import url_analyzer


@pytest.mark.parametrize(
    ("domain", "brand"),
    [("paypa1.com", "paypal"), ("secure.amaz0n.net", "amazon"), ("paypal-secure-login.com", "paypal"),
     ("dhl-tracking.info", "dhl")],
)
def test_typosquatting_detects_lookalikes(domain, brand):
    result = url_analyzer._check_typosquatting(domain)
    assert result["is_typosquat"]
    assert brand in {item["brand"] for item in result["similar_to"]}


@pytest.mark.parametrize("domain", ["paypal.com", "dhs.gov", "example.org", "chasebank-careers.com"])
def test_typosquatting_avoids_false_positives(domain):
    assert not url_analyzer._check_typosquatting(domain)["is_typosquat"]


def test_analysis_targets_the_final_destination(monkeypatch):
    seen = {}

    monkeypatch.setattr(url_analyzer, "_follow_redirects", lambda url: [url, "https://evil-login.example/verify"])
    for name in ("_whois_lookup", "_dns_lookup", "_ssl_check"):
        monkeypatch.setattr(url_analyzer, name, lambda domain, name=name: seen.setdefault(name, domain) and {})
    monkeypatch.setattr(url_analyzer, "_check_reputation", lambda url, domain: seen.setdefault("reputation", url) and {})
    monkeypatch.setattr(url_analyzer, "_detect_technologies", lambda url: {})
    monkeypatch.setattr(url_analyzer, "_check_security_headers", lambda url: {})
    monkeypatch.setattr(url_analyzer, "_display_results", lambda result: None)
    monkeypatch.setattr(url_analyzer, "log_analysis", lambda *args: None)

    result = url_analyzer.analyze_url("https://bit.ly/abc")
    assert result["is_shortened"] is True
    assert result["domain"] == "evil-login.example"
    assert seen["_whois_lookup"] == "evil-login.example"
    assert seen["reputation"] == "https://evil-login.example/verify"


def test_urlhaus_listed_url_raises_risk():
    score, details = url_analyzer._calculate_risk({"reputation": {"urlhaus": {"status": "ok"}}})
    assert score >= 40
    assert any("URLhaus" in detail for detail in details)


def test_new_domain_detection():
    assert url_analyzer._is_new_domain({"creation_date": "2001-01-01 00:00:00"}) is False
    assert url_analyzer._is_new_domain({"creation_date": ""}) is False
