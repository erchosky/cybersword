"""Emails y SMS: autenticación y marcas suplantadas."""

from email import policy
from email.parser import Parser

from modules import email_analyzer, sms_analyzer


def _message(headers: str) -> object:
    return Parser(policy=policy.default).parsestr(headers + "\n\nbody")


def test_received_spf_pass_is_recognised():
    msg = _message("From: a@example.com\nReceived-SPF: Pass (sender SPF authorized) client-ip=1.2.3.4")
    auth = email_analyzer._check_auth(msg)
    assert auth["spf"] == "PASS"
    assert auth["spf_pass"] is True


def test_authentication_results_still_parsed():
    msg = _message("From: a@example.com\nAuthentication-Results: mx.example.com; spf=fail; dkim=pass; dmarc=fail")
    auth = email_analyzer._check_auth(msg)
    assert (auth["spf"], auth["dkim"], auth["dmarc"]) == ("FAIL", "PASS", "FAIL")


def test_sms_ignores_brand_substrings(monkeypatch):
    monkeypatch.setattr(sms_analyzer, "log_analysis", lambda *args: None)
    result = sms_analyzer.analyze_sms("Shipping to our groups: pineapple and metal delivered, see syntax guide")
    assert result["impersonated_brands"] == []
    keywords = {item["keyword"] for item in result["phishing_keywords"]}
    assert not {"pin", "tax", "ups"} & keywords


def test_sms_detects_real_impersonation(monkeypatch):
    monkeypatch.setattr(sms_analyzer, "log_analysis", lambda *args: None)
    result = sms_analyzer.analyze_sms("Correos: tu paquete está retenido, paga en https://bit.ly/x")
    assert "Correos" in result["impersonated_brands"]
    assert result["urls"][0]["is_shortened"] is True
