"""
Subscription / managed-tool feature stub for FETIH.

FETIH does not ship the upstream "Nous Portal" subscription system —
it's a fork that runs entirely off direct API keys / OAuth. The module is
kept as a thin compatibility shim so existing callers (setup wizard,
status command, tools_config, agent prompt builder) continue to import
the same names without code changes.

Behaviour:
  - ``get_nous_subscription_features`` always returns a feature snapshot
    where ``subscribed`` is False and every feature has ``managed_by_nous=False``.
  - ``apply_nous_managed_defaults`` and ``apply_gateway_defaults`` are
    no-ops (return empty changeset).
  - ``get_gateway_eligible_tools`` returns three empty lists.
  - ``prompt_enable_tool_gateway`` returns ``set()`` without prompting.

Net effect: the setup wizard never advertises a "Nous subscription" /
"FETIH Portal" tier to the user, and every tool is driven by the user's
own credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional


@dataclass(frozen=True)
class NousFeatureState:
    key: str
    label: str
    included_by_default: bool = False
    available: bool = False
    active: bool = False
    managed_by_nous: bool = False
    direct_override: bool = False
    toolset_enabled: bool = False
    current_provider: str = ""
    explicit_configured: bool = False


@dataclass(frozen=True)
class NousSubscriptionFeatures:
    subscribed: bool = False
    nous_auth_present: bool = False
    provider_is_nous: bool = False
    features: Dict[str, NousFeatureState] = field(default_factory=dict)

    @property
    def web(self) -> NousFeatureState:
        return self.features["web"]

    @property
    def image_gen(self) -> NousFeatureState:
        return self.features["image_gen"]

    @property
    def tts(self) -> NousFeatureState:
        return self.features["tts"]

    @property
    def browser(self) -> NousFeatureState:
        return self.features["browser"]

    @property
    def modal(self) -> NousFeatureState:
        return self.features["modal"]

    def items(self) -> Iterable[NousFeatureState]:
        ordered = ("web", "image_gen", "tts", "browser", "modal")
        for key in ordered:
            yield self.features[key]


_FEATURE_LABELS = {
    "web": "Web Search & Extract",
    "image_gen": "Image Generation",
    "tts": "Text-to-Speech",
    "browser": "Browser Automation",
    "modal": "Sandbox Terminal",
}


def _empty_features() -> Dict[str, NousFeatureState]:
    return {
        key: NousFeatureState(key=key, label=label)
        for key, label in _FEATURE_LABELS.items()
    }


def get_nous_subscription_features(
    config: Optional[Dict[str, object]] = None,
) -> NousSubscriptionFeatures:
    """Return an "unsubscribed" feature snapshot.

    FETIH has no managed-tool subscription tier, so every feature is
    reported as not managed and not active. Callers can still read the
    dataclass fields safely.
    """
    return NousSubscriptionFeatures(features=_empty_features())


def apply_nous_managed_defaults(
    config: Dict[str, object],
    *,
    enabled_toolsets: Optional[Iterable[str]] = None,
) -> set:
    """No-op: FETIH never auto-applies managed-tool defaults."""
    return set()


def get_gateway_eligible_tools(
    config: Optional[Dict[str, object]] = None,
) -> tuple:
    """No-op: returns (unconfigured, has_direct, already_managed) all empty."""
    return [], [], []


def apply_gateway_defaults(
    config: Dict[str, object],
    tool_keys: list,
) -> set:
    """No-op: tool gateway is not used in FETIH."""
    return set()


def prompt_enable_tool_gateway(config: Dict[str, object]) -> set:
    """No-op: FETIH never prompts to enable the tool gateway."""
    return set()
