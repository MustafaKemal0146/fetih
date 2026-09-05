"""Groq provider profile.

Groq was reachable through models.dev metadata (``fetih_cli/providers.py``)
but had no entry in ``fetih_cli/auth.PROVIDER_REGISTRY``, so the runtime
resolver rejected ``model.provider: groq`` with
``AuthError: Unknown provider 'groq'`` even though every UI listed it.

Registering the profile here is the single source of truth the auth registry,
the canonical provider list and the model picker all auto-extend from, so the
two registries can no longer disagree about whether Groq exists.

``fallback_models`` is only the offline seed — ``fetch_models()`` hits
``/openai/v1/models`` first and wins whenever the network is up. The seed is
kept to IDs verified against the live catalog, because a retired ID here
turns the very first chat turn into a Groq ``404 model_not_found``.
"""

from providers import register_provider
from providers.base import ProviderProfile

groq = ProviderProfile(
    name="groq",
    aliases=("groqcloud", "groq-cloud"),
    env_vars=("GROQ_API_KEY",),
    display_name="Groq",
    description="Groq (LPU inference — free tier available)",
    signup_url="https://console.groq.com/keys",
    # Tool-calling models only: the agent loop cannot drive a model that has
    # no ``tools`` support, so json-mode-only entries (compound, allam,
    # prompt-guard) and the audio/speech models are deliberately excluded.
    fallback_models=(
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "qwen/qwen3.8-27b",
        "qwen/qwen3.6-27b",
    ),
    base_url="https://api.groq.com/openai/v1",
    hostname="api.groq.com",
    default_max_tokens=8192,
)

register_provider(groq)
