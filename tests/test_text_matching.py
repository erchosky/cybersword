"""Coincidencias de palabras, marcas y acortadores (fuente habitual de falsos positivos)."""

import pytest

from utils.helpers import contains_pattern, contains_term, hostname_matches, is_url_shortener


@pytest.mark.parametrize(
    ("text", "term", "expected"),
    [
        ("Your ING account is blocked", "ing", True),
        ("Shipping update for your meeting", "ing", False),
        ("Join our groups today", "ups", False),
        ("Your UPS parcel is waiting", "ups", True),
        ("Thanks for your purchase", "chase", False),
        ("Chase alert: verify now", "chase", True),
        ("freedom of speech", "free", False),
        ("click here", "click here", True),
    ],
)
def test_contains_term_matches_whole_words(text, term, expected):
    assert contains_term(text, term) is expected


def test_contains_pattern_wraps_alternatives_as_whole_words():
    assert contains_pattern("tu banco la caixa", r"caixabank|la\s*caixa")
    assert not contains_pattern("metal detector", r"facebook|meta")


@pytest.mark.parametrize(
    ("host", "expected"),
    [("bit.ly", True), ("go.bit.ly", True), ("t.co", True), ("microsoft.com", False), ("wp.medium.com", False)],
)
def test_url_shortener_uses_exact_hostnames(host, expected):
    assert is_url_shortener(host) is expected


def test_hostname_matches_requires_label_boundary():
    assert hostname_matches("login.paypal.com", "paypal.com")
    assert not hostname_matches("paypal.com.evil.net", "paypal.com")
    assert not hostname_matches("notpaypal.com", "paypal.com")
