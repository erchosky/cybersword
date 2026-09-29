"""Analizador de archivos y utilidades criptográficas."""

from modules import crypto, file_analyzer


def test_directories_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(file_analyzer, "log_analysis", lambda *args: None)
    assert file_analyzer.analyze_file(str(tmp_path)) == {}


def test_content_scan_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(file_analyzer, "MAX_SCAN_BYTES", 1024)
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"A" * 5000)
    data, truncated = file_analyzer._read_for_scan(sample)
    assert len(data) == 1024
    assert truncated is True


def test_iocs_are_extracted_from_bytes():
    iocs = file_analyzer._extract_iocs(b"connect to http://evil.example/p and 203.0.113.9")
    assert "http://evil.example/p" in iocs["urls"]
    assert "203.0.113.9" in iocs["ips"]


def test_generated_passwords_have_a_minimum_length():
    assert len(crypto.generate_password(0)["password"]) == 8
    assert len(crypto.generate_password(24)["password"]) == 24
