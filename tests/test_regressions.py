import base64
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_quiet_sms_cli_emits_only_json():
    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "cybersword.py"),
            "--quiet",
            "--sms",
            "URGENTE: cuenta bloqueada https://example.com",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["risk_score"] > 0
    assert completed.stderr == ""


def test_html_export_escapes_untrusted_analysis_data(tmp_path):
    from utils.output import export_html

    output = tmp_path / "report.html"
    export_html(
        {"<key>": "<script>alert('x')</script>", "url": "javascript:alert(1)"},
        "<img src=x onerror=alert(1)>",
        output,
    )
    rendered = output.read_text(encoding="utf-8")
    assert "<script>alert" not in rendered
    assert "<img src=x" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "href='javascript:" not in rendered


def test_safe_get_never_retries_without_tls_verification(monkeypatch):
    from utils import helpers

    class FailingSession:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            raise requests.exceptions.SSLError("bad certificate")

    session = FailingSession()
    monkeypatch.setattr(helpers, "_config", {"settings": {"verify_tls": True}})
    assert helpers.safe_get("https://example.invalid", session=session) is None
    assert len(session.calls) == 1
    assert session.calls[0][1]["verify"] is True


def test_redirects_resolve_protocol_relative_locations(monkeypatch):
    from modules import url_analyzer

    class Response:
        def __init__(self, status_code, location=""):
            self.status_code = status_code
            self.headers = {"Location": location} if location else {}

    class Session:
        max_redirects = 10

        def __init__(self):
            self.responses = iter(
                [Response(302, "//redirect.example/path"), Response(200)]
            )

        def head(self, *args, **kwargs):
            return next(self.responses)

    monkeypatch.setattr(url_analyzer, "make_session", Session)
    assert url_analyzer._follow_redirects("https://start.example") == [
        "https://start.example",
        "https://redirect.example/path",
    ]


@pytest.mark.parametrize("mode", ["GCM", "CBC"])
def test_encryption_v2_round_trip_and_authentication(mode):
    from modules.crypto import aes_decrypt, aes_encrypt

    encrypted = aes_encrypt("contenido confidencial", "correct horse battery staple", mode)
    assert encrypted["version"] == 2
    assert aes_decrypt(encrypted["combined"], "correct horse battery staple", mode)[
        "plaintext"
    ] == "contenido confidencial"
    assert "error" in aes_decrypt(encrypted["combined"], "incorrect", mode)


def test_legacy_gcm_ciphertext_remains_decryptable():
    from Crypto.Cipher import AES
    from modules.crypto import aes_decrypt
    import hashlib

    passphrase = "legacy test phrase"
    key = hashlib.sha256(passphrase.encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(b"legacy data")
    combined = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    assert aes_decrypt(combined, passphrase, "GCM")["plaintext"] == "legacy data"


def test_fuzzer_executes_with_a_custom_wordlist(monkeypatch):
    from modules import web_scanner

    class Response:
        status_code = 404
        content = b"not found"
        headers = {"Content-Type": "text/plain"}

    class Session:
        def get(self, *args, **kwargs):
            return Response()

    session = Session()
    monkeypatch.setattr(web_scanner, "make_session", lambda: session)
    monkeypatch.setattr(web_scanner, "_thread_session", lambda: session)
    assert web_scanner.fuzz_directories(
        "https://example.invalid", custom_wordlist=["admin"]
    ) == []


def test_api_key_environment_variable_overrides_file(monkeypatch):
    from utils import helpers

    monkeypatch.setattr(helpers, "_config", {"api_keys": {"virustotal": "file-value"}})
    monkeypatch.setenv("CYBERSWORD_VIRUSTOTAL_API_KEY", "environment-value")
    assert helpers.get_api_key("virustotal") == "environment-value"


def test_python_magic_fallback_is_reachable(monkeypatch, tmp_path):
    from modules import file_analyzer

    class FakeMagic:
        @staticmethod
        def from_file(path, mime=False):
            return "text/plain" if mime else "ASCII text"

    sample = tmp_path / "sample.unknown"
    sample.write_text("plain text without a built-in magic signature", encoding="utf-8")
    monkeypatch.setattr(file_analyzer, "MAGIC_AVAILABLE", True)
    monkeypatch.setattr(file_analyzer, "magic", FakeMagic, raising=False)
    result = file_analyzer._identify_type(sample)
    assert result["type"] == "unknown"
    assert result["magic_lib"]
    assert result["mime"]


def test_session_report_escapes_targets_and_details(monkeypatch, tmp_path):
    from modules import reporter

    monkeypatch.setattr(
        reporter,
        "get_session_log",
        lambda: [
            {
                "timestamp": "2026-07-22T12:00:00",
                "module": "sms",
                "target": "<img src=x onerror=alert(1)>",
                "result": {"risk_score": 80, "message": "</pre><script>x</script>"},
            }
        ],
    )
    monkeypatch.setattr(reporter, "get_session_start", lambda: datetime(2026, 7, 22, 12))
    monkeypatch.setattr(
        reporter,
        "load_config",
        lambda: {"output": {"report_dir": str(tmp_path)}},
    )
    report_path = reporter.export_session_report()
    rendered = report_path.read_text(encoding="utf-8")
    assert "<img src=x" not in rendered
    assert "</pre><script>x</script>" not in rendered
    assert "&lt;img src=x" in rendered
