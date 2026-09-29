"""Escaneos activos: solo con autorización y sin falsos positivos por "soft 404"."""

import socket
import subprocess
import sys

import pytest

from modules import ip_analyzer, web_scanner
from tests.test_regressions import PROJECT_ROOT


class Response:
    def __init__(self, status=200, content=b"", headers=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {"Content-Type": "text/html"}


class Session:
    """Servidor falso: responde siempre lo mismo, como una SPA o un 404 personalizado."""

    def __init__(self, response_for):
        self.response_for = response_for

    def get(self, url, **kwargs):
        return self.response_for(url)


def _use_session(monkeypatch, session):
    monkeypatch.setattr(web_scanner, "make_session", lambda: session)
    monkeypatch.setattr(web_scanner, "_thread_session", lambda: session)


def test_sensitive_file_scan_ignores_soft_404(monkeypatch):
    page = b"<html>" + b"x" * 5000 + b"</html>"
    _use_session(monkeypatch, Session(lambda url: Response(200, page)))
    assert web_scanner.scan_sensitive_files("https://spa.example", paths=["/.env", "/.git/HEAD"]) == []


def test_soft_404_that_echoes_the_path_is_ignored(monkeypatch):
    def respond(url):
        return Response(200, f"<html>Page {url} not found</html>".encode() + b"x" * 3000)

    _use_session(monkeypatch, Session(respond))
    assert web_scanner.fuzz_directories("https://site.example", custom_wordlist=["admin", "backup"]) == []


def test_generic_redirect_to_login_is_ignored(monkeypatch):
    redirect = Response(302, b"", {"Location": "/login"})
    _use_session(monkeypatch, Session(lambda url: redirect))
    assert web_scanner.fuzz_directories("https://app.example", custom_wordlist=["admin"]) == []


def test_real_exposed_file_is_reported(monkeypatch):
    def respond(url):
        if url.endswith("/.env"):
            return Response(200, b"DB_PASSWORD=secret\n" * 10, {"Content-Type": "text/plain"})
        return Response(404, b"not found")

    _use_session(monkeypatch, Session(respond))
    found = web_scanner.scan_sensitive_files("https://leaky.example", paths=["/.env", "/robots.txt"])
    assert [item["path"] for item in found] == ["/.env"]
    assert found[0]["critical"] is True


def test_custom_wordlist_is_respected(monkeypatch):
    requested = []

    def respond(url):
        requested.append(url)
        return Response(404, b"not found")

    _use_session(monkeypatch, Session(respond))
    web_scanner.fuzz_directories("https://site.example", custom_wordlist=["only-this"])
    assert {url for url in requested if "nonexistent" not in url} == {"https://site.example/only-this"}


def test_ip_analysis_is_passive_by_default(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("port scan must not run without explicit consent")

    for name in ("_geolocate", "_check_reputation", "_check_threat_info"):
        monkeypatch.setattr(ip_analyzer, name, lambda ip: {})
    monkeypatch.setattr(ip_analyzer, "_reverse_dns", lambda ip: "")
    monkeypatch.setattr(ip_analyzer, "_port_scan", forbidden)
    monkeypatch.setattr(ip_analyzer, "_grab_banners", forbidden)
    monkeypatch.setattr(ip_analyzer, "log_analysis", lambda *args: None)

    result = ip_analyzer.analyze_ip("8.8.8.8")
    assert "open_ports" not in result
    assert result["port_scan"].startswith("not performed")


def test_port_scan_supports_ipv6():
    assert ip_analyzer._address_family("2001:db8::1") == socket.AF_INET6
    assert ip_analyzer._address_family("192.0.2.1") == socket.AF_INET


def test_scan_ports_flag_requires_ip():
    completed = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "cybersword.py"), "--scan-ports"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 2
    assert "--scan-ports requires --ip" in completed.stderr


@pytest.mark.parametrize("answer", [False])
def test_web_scanner_menu_requires_authorization(monkeypatch, answer):
    inputs = iter(["1", "https://target.example"])
    monkeypatch.setattr(web_scanner.console, "input", lambda *args, **kwargs: next(inputs))
    monkeypatch.setattr(web_scanner, "confirm_authorized", lambda action, target: answer)
    monkeypatch.setattr(web_scanner, "scan_web", lambda url: pytest.fail("scan ran without authorization"))
    web_scanner.run()
