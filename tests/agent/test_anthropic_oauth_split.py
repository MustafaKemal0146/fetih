"""Unit tests for the split Anthropic OAuth helpers (issue #54).

These cover the pure, network-free pieces the desktop bridge drives:
building the authorize URL + PKCE material, and the guard rails on the code
exchange. The live token exchange itself hits Anthropic and is not tested here.
"""
from urllib.parse import parse_qs, urlparse

from agent import anthropic_adapter


def test_build_authorize_url_has_pkce_and_state():
    info = anthropic_adapter.build_fetih_oauth_authorize_url()
    assert set(info) >= {"authorize_url", "code_verifier", "state"}
    assert info["code_verifier"]
    assert info["state"]

    parsed = urlparse(info["authorize_url"])
    assert parsed.scheme == "https"
    assert parsed.netloc == "claude.ai"
    qs = parse_qs(parsed.query)
    assert qs["code_challenge_method"] == ["S256"]
    assert qs["response_type"] == ["code"]
    assert qs["state"] == [info["state"]]
    # The challenge is derived from the verifier, never the verifier itself.
    assert qs["code_challenge"][0] != info["code_verifier"]


def test_build_authorize_url_is_unique_per_call():
    a = anthropic_adapter.build_fetih_oauth_authorize_url()
    b = anthropic_adapter.build_fetih_oauth_authorize_url()
    assert a["state"] != b["state"]
    assert a["code_verifier"] != b["code_verifier"]


def test_exchange_rejects_empty_code():
    assert anthropic_adapter.exchange_fetih_oauth_code("", "verifier") is None
    assert anthropic_adapter.exchange_fetih_oauth_code("   ", "verifier") is None
    assert anthropic_adapter.exchange_fetih_oauth_code("#onlystate", "verifier") is None


def test_exchange_rejects_state_mismatch_without_network():
    # A mismatching embedded state must be rejected before any token request,
    # so this returns None without touching the network.
    result = anthropic_adapter.exchange_fetih_oauth_code(
        "somecode#attacker-state", "verifier", expected_state="real-state"
    )
    assert result is None
