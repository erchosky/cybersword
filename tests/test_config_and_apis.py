"""Configuración, logs y adaptadores de API (sin red)."""

import requests

from utils import api_manager, helpers


def test_logs_are_not_persisted_unless_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(helpers, "_config", {"output": {"log_dir": str(tmp_path)}})
    helpers.log_analysis("sms", "target", {"risk_score": 1})
    assert list(tmp_path.iterdir()) == []

    monkeypatch.setattr(helpers, "_config", {"output": {"log_dir": str(tmp_path), "save_logs": True}})
    helpers.log_analysis("sms", "target", {"risk_score": 1})
    assert len(list(tmp_path.iterdir())) == 1


def test_empty_environment_variable_does_not_hide_file_key(monkeypatch):
    monkeypatch.setattr(helpers, "_config", {"api_keys": {"shodan": "from-file"}})
    monkeypatch.setenv("CYBERSWORD_SHODAN_API_KEY", "")
    assert helpers.get_api_key("shodan") == "from-file"


def test_explicit_timeout_wins_over_config(monkeypatch):
    seen = {}

    class Session:
        def get(self, url, **kwargs):
            seen.update(kwargs)
            raise requests.RequestException("offline")

    monkeypatch.setattr(helpers, "_config", {"settings": {"timeout": 30}})
    helpers.safe_get("https://example.invalid", timeout=3, session=Session())
    assert seen["timeout"] == 3
    helpers.safe_get("https://example.invalid", session=Session())
    assert seen["timeout"] == 30


def test_abusech_lookups_require_a_key_and_skip_the_network(monkeypatch):
    monkeypatch.setattr(api_manager, "make_session", lambda: (_ for _ in ()).throw(AssertionError("network used")))
    assert "error" in api_manager.urlhaus_check("https://example.com")
    assert "error" in api_manager.urlhaus_host("example.com")
    assert "error" in api_manager.malwarebazaar_hash("0" * 64)


def test_abusech_key_is_sent_as_auth_header(monkeypatch):
    sent = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"query_status": "no_results"}

    class Session:
        def post(self, url, **kwargs):
            sent.update(kwargs)
            return Response()

    monkeypatch.setenv("CYBERSWORD_ABUSECH_API_KEY", "abc123")
    monkeypatch.setattr(api_manager, "make_session", lambda: Session())
    api_manager.urlhaus_check("https://example.com")
    assert sent["headers"] == {"Auth-Key": "abc123"}


def test_rate_limit_returns_quickly_with_an_error(monkeypatch):
    class Response:
        status_code = 429

        def raise_for_status(self):
            raise requests.exceptions.HTTPError(response=self)

    class Session:
        def get(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(api_manager, "make_session", lambda: Session())
    def no_sleep(seconds):
        raise AssertionError("must not sleep")

    monkeypatch.setattr("time.sleep", no_sleep)
    result = api_manager._rl_get("abuseipdb", "https://example.invalid")
    assert "límite" in result["error"]
