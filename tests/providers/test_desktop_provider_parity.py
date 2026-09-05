"""The desktop shell and the CLI must agree on provider ids.

The Windows app used to carry a hand-maintained C# provider table. When an id
in that table drifted from ``fetih_cli.auth.PROVIDER_REGISTRY``, the setup
wizard completed happily and the user's first chat message died with
``AuthError: Unknown provider '<id>'`` — two screens telling two different
stories about the same install.

The structural fix is ``providers.catalog`` (the bridge serves the CLI's own
registry to the shell). These tests are the backstop: they fail the build if
an id ever reappears in the C# table that the Python resolver would reject.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVIDER_REGISTRY_CS = (
    REPO_ROOT / "apps" / "windows" / "Fetih.Desktop" / "Services" / "ProviderRegistry.cs"
)

#: Ids the C# catalog lists that the CLI resolves through a dedicated code
#: path rather than PROVIDER_REGISTRY. They still have to *resolve* — that is
#: what the parity test checks — they just aren't registry entries.
_NON_REGISTRY_IDS = {"openrouter", "custom"}


def _csharp_provider_ids() -> list[str]:
    """Every id declared in the C# fallback catalog (``new("<id>", …)``)."""
    if not PROVIDER_REGISTRY_CS.exists():  # pragma: no cover - desktop app absent
        pytest.skip(f"{PROVIDER_REGISTRY_CS} not present in this checkout")
    source = PROVIDER_REGISTRY_CS.read_text(encoding="utf-8")
    body = source.split("public static IReadOnlyList<ProviderEntry> All", 1)
    if len(body) != 2:  # pragma: no cover - shape changed
        pytest.fail("could not locate the ProviderRegistry.All catalog in the C# source")
    return re.findall(r'new\(\s*"([a-z0-9\-]+)"', body[1])


def test_csharp_catalog_is_not_empty():
    ids = _csharp_provider_ids()
    assert len(ids) > 20, f"only parsed {len(ids)} ids — the regex likely stopped matching"
    assert "groq" in ids


@pytest.mark.parametrize("provider_id", _csharp_provider_ids())
def test_every_desktop_provider_id_resolves_in_the_cli(provider_id):
    """A provider the wizard can offer must be one the runtime accepts."""
    from fetih_cli.auth import resolve_provider

    resolved = resolve_provider(provider_id)
    assert resolved, f"{provider_id} resolved to an empty provider"


def test_desktop_ids_are_registry_entries_or_deliberate_exceptions():
    from fetih_cli.auth import PROVIDER_REGISTRY

    missing = [
        pid
        for pid in _csharp_provider_ids()
        if pid not in PROVIDER_REGISTRY and pid not in _NON_REGISTRY_IDS
    ]
    assert not missing, (
        "these ids are offered by the desktop wizard but absent from "
        f"auth.PROVIDER_REGISTRY: {missing}"
    )


def test_groq_is_registered():
    """The original bug: every UI listed Groq, the resolver had never heard of it."""
    from fetih_cli.auth import PROVIDER_REGISTRY, resolve_provider

    assert "groq" in PROVIDER_REGISTRY
    assert resolve_provider("groq") == "groq"
    assert PROVIDER_REGISTRY["groq"].api_key_env_vars == ("GROQ_API_KEY",)


def test_groq_fallback_models_are_not_retired_ids():
    """A retired id in the offline seed turns setup's 'success' into a 404.

    Groq removed these; keeping them as the wizard's default meant the first
    message failed with ``model_not_found`` even though every other part of
    the install was correct.
    """
    from providers import get_provider_profile

    retired = {"llama-3.3-70b-versatile", "qwen/qwen3-32b", "moonshotai/kimi-k2-instruct"}
    profile = get_provider_profile("groq")
    assert profile is not None
    assert profile.fallback_models, "groq needs an offline seed list"
    assert not (set(profile.fallback_models) & retired)


def test_local_ollama_stays_local():
    """Choosing "run it on my machine" must not route prompts to a third party.

    ``ollama`` used to be an alias for the generic ``custom`` provider, whose
    default endpoint is OpenRouter. A user picking the local option to keep
    data on the box got the exact opposite, silently.
    """
    from fetih_cli.runtime_provider import resolve_runtime_provider

    runtime = resolve_runtime_provider(requested="ollama", target_model="llama3")
    assert runtime["provider"] == "ollama"
    assert "localhost" in runtime["base_url"] or "127.0.0.1" in runtime["base_url"]
    assert "openrouter" not in runtime["base_url"]


def test_ollama_cloud_is_still_remote():
    """The local fix must not drag the hosted service onto loopback with it."""
    from fetih_cli.runtime_provider import resolve_runtime_provider

    runtime = resolve_runtime_provider(requested="ollama-cloud", target_model="x")
    assert runtime["provider"] == "ollama-cloud"
    assert "ollama.com" in runtime["base_url"]


def test_unknown_provider_still_raises():
    """The guard rail itself must keep working — a typo must not fall back."""
    from fetih_cli.auth import AuthError, resolve_provider

    with pytest.raises(AuthError):
        resolve_provider("definitely-not-a-provider")
