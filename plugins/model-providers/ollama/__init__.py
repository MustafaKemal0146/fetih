"""Local Ollama provider profile.

Distinct from ``ollama-cloud``: this one talks to the daemon on this machine
over loopback, needs no credentials, and its catalog is whatever the user has
actually pulled — so it is fetched from the daemon rather than shipped as a
static list.

Before this profile existed, ``ollama`` was aliased to the generic ``custom``
provider, which falls back to the OpenRouter endpoint when no base URL is
configured. Choosing "run it locally" and then silently shipping the prompts
to a third party is the worst possible failure mode for the users who pick a
local model precisely so their data stays put.
"""

from providers import register_provider
from providers.base import ProviderProfile


class OllamaProfile(ProviderProfile):
    """Ollama's OpenAI-compatible surface, with a native-API model probe."""

    def fetch_models(self, *, api_key=None, timeout: float = 8.0):
        """List models the local daemon has downloaded.

        Ollama exposes ``/api/tags`` (native) alongside the OpenAI-compatible
        ``/v1/models``. Both work; ``/api/tags`` is used because it is the
        endpoint that is present even on builds where the compatibility layer
        is disabled. Returns ``None`` when the daemon is not running, which
        callers already treat as "fall back to the static list".
        """
        import json
        import urllib.request

        base = (self.base_url or "").rstrip("/")
        if base.endswith("/v1"):
            base = base[: -len("/v1")]
        if not base:
            return None

        try:
            req = urllib.request.Request(
                base + "/api/tags", headers={"User-Agent": "fetih-cli"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            return None

        names = []
        for item in (payload or {}).get("models") or []:
            name = item.get("name") or item.get("model") if isinstance(item, dict) else None
            if name:
                names.append(str(name))
        return names or None


ollama = OllamaProfile(
    name="ollama",
    aliases=("ollama-local", "ollama_local"),
    env_vars=("OLLAMA_LOCAL_API_KEY",),
    display_name="Ollama (yerel)",
    description="Ollama — bu makinede çalışan yerel model sunucusu",
    signup_url="https://ollama.com/download",
    base_url="http://localhost:11434/v1",
    # No hostname override: "localhost" identifies the machine, not the
    # provider (LM Studio and vLLM share it), so it must not become a
    # URL→provider mapping key. See agent/model_metadata.py.
    hostname="",
    # No static catalog on purpose: what exists is whatever `ollama pull`
    # put on this disk, and fetch_models() above is the only honest answer.
    fallback_models=(),
)

register_provider(ollama)
