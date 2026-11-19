"""End-to-end tests for the SOC Alert Enrichment app.

VirusTotal and the response webhooks are mocked, so the suite runs fully
offline:  python -m pytest test_app.py
"""
import os
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent / "app.py")
DB = Path(__file__).parent / "soc_audit.db"

VT_PAYLOAD = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 40, "undetected": 20},
    "reputation": -5, "last_analysis_date": 1763500000}}}


class FakeResp:
    def __init__(self, status=200, payload=None, text="ok"):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture(autouse=True)
def mock_network(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        if url.endswith("/8.8.8.8") or "/files/" in url:
            return FakeResp(200, VT_PAYLOAD)
        return FakeResp(404, {})

    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResp(200, {}, "accepted")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(requests, "post", fake_post)
    if DB.exists():
        DB.unlink()
    yield
    if DB.exists():
        DB.unlink()


def boot():
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert not at.exception
    return at


def set_sidebar(at, label, value):
    for el in at.sidebar.text_input:
        if el.label == label:
            el.set_value(value)
            return
    raise AssertionError(f"sidebar input not found: {label}")


def set_main_input(at, label, value):
    for el in at.text_input:
        if el.label == label:
            el.set_value(value)
            return
    raise AssertionError(f"main input not found: {label}")


def click(at, label):
    for b in at.button:
        if b.label == label:
            b.click().run()
            return
    raise AssertionError(f"button not found: {label}")


def test_app_boots():
    boot()


def test_ip_enrichment_malicious():
    at = boot()
    set_sidebar(at, "VirusTotal API key", "test-key")
    set_main_input(at, "Suspicious IP address or file hash", "8.8.8.8")
    click(at, "Enrich indicator")
    result = at.session_state["last_result"]
    assert result["verdict"] == "MALICIOUS"
    assert result["malicious"] == 3
    assert result["total_engines"] == 64


def test_invalid_indicator_shows_error():
    at = boot()
    set_sidebar(at, "VirusTotal API key", "test-key")
    set_main_input(at, "Suspicious IP address or file hash", "not-an-indicator")
    click(at, "Enrich indicator")
    assert any("valid IPv4/IPv6" in e.value for e in at.error)


def test_missing_api_key_shows_error():
    at = boot()
    set_main_input(at, "Suspicious IP address or file hash", "8.8.8.8")
    click(at, "Enrich indicator")
    assert any("VirusTotal API key" in e.value for e in at.error)


def test_siem_sample_event():
    at = boot()
    set_sidebar(at, "VirusTotal API key", "test-key")
    click(at, "Process SIEM event")
    assert any("ALERT-2026-0001" in s.value for s in at.success)
