import importlib
import sys
import types
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from fetih_cli.auth import AuthError
from fetih_cli import main as fetih_main


# ---------------------------------------------------------------------------
# Module isolation: _import_cli() wipes tools.* / cli / run_agent from
# sys.modules so it can re-import cli fresh.  Without cleanup the wiped
# modules leak into subsequent tests on the same xdist worker, breaking
# mock patches that target "tools.file_tools._get_file_ops" etc.
# ---------------------------------------------------------------------------

def _reset_modules(prefixes: tuple[str, ...]):
    for name in list(sys.modules):
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            sys.modules.pop(name, None)


@pytest.fixture(autouse=True)
def _restore_cli_and_tool_modules():
    """Save and restore tools/cli/run_agent modules around every test."""
    prefixes = ("tools", "cli", "run_agent")
    original_modules = {
        name: module
        for name, module in sys.modules.items()
        if any(name == p or name.startswith(p + ".") for p in prefixes)
    }
    try:
        yield
    finally:
        _reset_modules(prefixes)
        sys.modules.update(original_modules)


def _install_prompt_toolkit_stubs():
    class _Dummy:
        def __init__(self, *args, **kwargs):
            pass

    class _Condition:
        def __init__(self, func):
            self.func = func

        def __bool__(self):
            return bool(self.func())

    class _ANSI(str):
        pass

    root = types.ModuleType("prompt_toolkit")
    history = types.ModuleType("prompt_toolkit.history")
    styles = types.ModuleType("prompt_toolkit.styles")
    patch_stdout = types.ModuleType("prompt_toolkit.patch_stdout")
    application = types.ModuleType("prompt_toolkit.application")
    layout = types.ModuleType("prompt_toolkit.layout")
    processors = types.ModuleType("prompt_toolkit.layout.processors")
    filters = types.ModuleType("prompt_toolkit.filters")
    dimension = types.ModuleType("prompt_toolkit.layout.dimension")
    menus = types.ModuleType("prompt_toolkit.layout.menus")
    widgets = types.ModuleType("prompt_toolkit.widgets")
    key_binding = types.ModuleType("prompt_toolkit.key_binding")
    completion = types.ModuleType("prompt_toolkit.completion")
    formatted_text = types.ModuleType("prompt_toolkit.formatted_text")

    history.FileHistory = _Dummy
    styles.Style = _Dummy
    patch_stdout.patch_stdout = lambda *args, **kwargs: nullcontext()
    application.Application = _Dummy
    layout.Layout = _Dummy
    layout.HSplit = _Dummy
    layout.Window = _Dummy
    layout.FormattedTextControl = _Dummy
    layout.ConditionalContainer = _Dummy
    processors.Processor = _Dummy
    processors.Transformation = _Dummy
    processors.PasswordProcessor = _Dummy
    processors.ConditionalProcessor = _Dummy
    filters.Condition = _Condition
    dimension.Dimension = _Dummy
    menus.CompletionsMenu = _Dummy
    widgets.TextArea = _Dummy
    key_binding.KeyBindings = _Dummy
    completion.Completer = _Dummy
    completion.Completion = _Dummy
    formatted_text.ANSI = _ANSI
    root.print_formatted_text = lambda *args, **kwargs: None

    sys.modules.setdefault("prompt_toolkit", root)
    sys.modules.setdefault("prompt_toolkit.history", history)
    sys.modules.setdefault("prompt_toolkit.styles", styles)
    sys.modules.setdefault("prompt_toolkit.patch_stdout", patch_stdout)
    sys.modules.setdefault("prompt_toolkit.application", application)
    sys.modules.setdefault("prompt_toolkit.layout", layout)
    sys.modules.setdefault("prompt_toolkit.layout.processors", processors)
    sys.modules.setdefault("prompt_toolkit.filters", filters)
    sys.modules.setdefault("prompt_toolkit.layout.dimension", dimension)
    sys.modules.setdefault("prompt_toolkit.layout.menus", menus)
    sys.modules.setdefault("prompt_toolkit.widgets", widgets)
    sys.modules.setdefault("prompt_toolkit.key_binding", key_binding)
    sys.modules.setdefault("prompt_toolkit.completion", completion)
    sys.modules.setdefault("prompt_toolkit.formatted_text", formatted_text)


def _import_cli():
    for name in list(sys.modules):
        if name == "cli" or name == "run_agent" or name == "tools" or name.startswith("tools."):
            sys.modules.pop(name, None)

    if "firecrawl" not in sys.modules:
        sys.modules["firecrawl"] = types.SimpleNamespace(Firecrawl=object)

    try:
        importlib.import_module("prompt_toolkit")
    except ModuleNotFoundError:
        _install_prompt_toolkit_stubs()
    return importlib.import_module("cli")


def test_fetih_cli_init_does_not_eagerly_resolve_runtime_provider(monkeypatch):
    cli = _import_cli()
    calls = {"count": 0}

    def _unexpected_runtime_resolve(**kwargs):
        calls["count"] += 1
        raise AssertionError("resolve_runtime_provider should not be called in FETIHCLI.__init__")

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _unexpected_runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))

    shell = cli.FETIHCLI(model="gpt-5", compact=True, max_turns=1)

    assert shell is not None
    assert calls["count"] == 0


def test_runtime_resolution_failure_is_not_sticky(monkeypatch):
    cli = _import_cli()
    calls = {"count": 0}

    def _runtime_resolve(**kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("temporary auth failure")
        return {
            "provider": "openrouter",
            "api_mode": "chat_completions",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "test-key",
            "source": "env/config",
        }

    class _DummyAgent:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))
    monkeypatch.setattr(cli, "AIAgent", _DummyAgent)

    shell = cli.FETIHCLI(model="gpt-5", compact=True, max_turns=1)

    assert shell._init_agent() is False
    assert shell._init_agent() is True
    assert calls["count"] == 2
    assert shell.agent is not None


def test_runtime_resolution_rebuilds_agent_on_routing_change(monkeypatch):
    cli = _import_cli()

    def _runtime_resolve(**kwargs):
        return {
            "provider": "openai-codex",
            "api_mode": "codex_responses",
            "base_url": "https://same-endpoint.example/v1",
            "api_key": "same-key",
            "source": "env/config",
        }

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))

    shell = cli.FETIHCLI(model="gpt-5", compact=True, max_turns=1)
    shell.provider = "openrouter"
    shell.api_mode = "chat_completions"
    shell.base_url = "https://same-endpoint.example/v1"
    shell.api_key = "same-key"
    shell.agent = object()

    assert shell._ensure_runtime_credentials() is True
    assert shell.agent is None
    assert shell.provider == "openai-codex"
    assert shell.api_mode == "codex_responses"


def test_cli_turn_routing_uses_primary_when_disabled(monkeypatch):
    cli = _import_cli()
    shell = cli.FETIHCLI(model="gpt-5", compact=True, max_turns=1)
    shell.provider = "openrouter"
    shell.api_mode = "chat_completions"
    shell.base_url = "https://openrouter.ai/api/v1"
    shell.api_key = "sk-primary"

    result = shell._resolve_turn_agent_config("what time is it in tokyo?")

    assert result["model"] == "gpt-5"
    assert result["runtime"]["provider"] == "openrouter"


def test_cli_prefers_config_provider_over_stale_env_override(monkeypatch):
    cli = _import_cli()

    monkeypatch.setenv("FETIH_INFERENCE_PROVIDER", "openrouter")
    config_copy = dict(cli.CLI_CONFIG)
    model_copy = dict(config_copy.get("model", {}))
    model_copy["provider"] = "custom"
    model_copy["base_url"] = "https://api.fireworks.ai/inference/v1"
    config_copy["model"] = model_copy
    monkeypatch.setattr(cli, "CLI_CONFIG", config_copy)

    shell = cli.FETIHCLI(model="fireworks/minimax-m2p5", compact=True, max_turns=1)

    assert shell.requested_provider == "custom"
def test_codex_provider_uses_config_model(monkeypatch):
    """Model comes from config.yaml, not LLM_MODEL env var.
    Config.yaml is the single source of truth to avoid multi-agent conflicts."""
    cli = _import_cli()

    # LLM_MODEL env var should be IGNORED (even if set)
    monkeypatch.setenv("LLM_MODEL", "should-be-ignored")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    # Set model via config
    monkeypatch.setitem(cli.CLI_CONFIG, "model", {
        "default": "gpt-5.2-codex",
        "provider": "openai-codex",
        "base_url": "https://chatgpt.com/backend-api/codex",
    })

    def _runtime_resolve(**kwargs):
        return {
            "provider": "openai-codex",
            "api_mode": "codex_responses",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "fake-codex-token",
            "source": "env/config",
        }

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))
    # Prevent live API call from overriding the config model
    monkeypatch.setattr(
        "fetih_cli.codex_models.get_codex_model_ids",
        lambda access_token=None: ["gpt-5.2-codex"],
    )

    shell = cli.FETIHCLI(compact=True, max_turns=1)

    assert shell._ensure_runtime_credentials() is True
    assert shell.provider == "openai-codex"
    # Model from config (may be normalized by codex provider logic)
    assert "codex" in shell.model.lower()
    # LLM_MODEL env var is NOT used
    assert shell.model != "should-be-ignored"


def test_codex_config_model_not_replaced_by_normalization(monkeypatch):
    """When the user sets model.default in config.yaml to a specific codex
    model, _normalize_model_for_provider must NOT replace it with the latest
    available model from the API.  Regression test for #1887."""
    cli = _import_cli()

    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    # User explicitly configured gpt-5.3-codex in config.yaml
    monkeypatch.setitem(cli.CLI_CONFIG, "model", {
        "default": "gpt-5.3-codex",
        "provider": "openai-codex",
        "base_url": "https://chatgpt.com/backend-api/codex",
    })

    def _runtime_resolve(**kwargs):
        return {
            "provider": "openai-codex",
            "api_mode": "codex_responses",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "fake-key",
            "source": "env/config",
        }

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))
    # API returns a DIFFERENT model than what the user configured
    monkeypatch.setattr(
        "fetih_cli.codex_models.get_codex_model_ids",
        lambda access_token=None: ["gpt-5.4", "gpt-5.3-codex"],
    )

    shell = cli.FETIHCLI(compact=True, max_turns=1)

    # Config model is NOT the global default — user made a deliberate choice
    assert shell._model_is_default is False
    assert shell._ensure_runtime_credentials() is True
    assert shell.provider == "openai-codex"
    # Model must stay as user configured, not replaced by gpt-5.4
    assert shell.model == "gpt-5.3-codex"


def test_codex_provider_preserves_explicit_codex_model(monkeypatch):
    """If the user explicitly passes a Codex-compatible model, it must be
    preserved even when the provider resolves to openai-codex."""
    cli = _import_cli()

    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    def _runtime_resolve(**kwargs):
        return {
            "provider": "openai-codex",
            "api_mode": "codex_responses",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "test-key",
            "source": "env/config",
        }

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))

    shell = cli.FETIHCLI(model="gpt-5.1-codex-mini", compact=True, max_turns=1)

    assert shell._model_is_default is False
    assert shell._ensure_runtime_credentials() is True
    assert shell.model == "gpt-5.1-codex-mini"


def test_codex_provider_strips_provider_prefix_from_model(monkeypatch):
    """openai/gpt-5.3-codex should become gpt-5.3-codex — the Codex
    Responses API does not accept provider-prefixed model slugs."""
    cli = _import_cli()

    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    def _runtime_resolve(**kwargs):
        return {
            "provider": "openai-codex",
            "api_mode": "codex_responses",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "test-key",
            "source": "env/config",
        }

    monkeypatch.setattr("fetih_cli.runtime_provider.resolve_runtime_provider", _runtime_resolve)
    monkeypatch.setattr("fetih_cli.runtime_provider.format_runtime_provider_error", lambda exc: str(exc))

    shell = cli.FETIHCLI(model="openai/gpt-5.3-codex", compact=True, max_turns=1)

    assert shell._ensure_runtime_credentials() is True
    assert shell.model == "gpt-5.3-codex"


def test_cmd_model_falls_back_to_auto_on_invalid_provider(monkeypatch, capsys):
    monkeypatch.setattr(
        "fetih_cli.config.load_config",
        lambda: {"model": {"default": "gpt-5", "provider": "invalid-provider"}},
    )
    monkeypatch.setattr("fetih_cli.config.save_config", lambda cfg: None)
    monkeypatch.setattr("fetih_cli.config.get_env_value", lambda key: "")
    monkeypatch.setattr("fetih_cli.config.save_env_value", lambda key, value: None)

    def _resolve_provider(requested, **kwargs):
        if requested == "invalid-provider":
            raise AuthError("Unknown provider 'invalid-provider'.", code="invalid_provider")
        return "openrouter"

    monkeypatch.setattr("fetih_cli.auth.resolve_provider", _resolve_provider)
    monkeypatch.setattr(fetih_main, "_prompt_provider_choice", lambda choices, **kwargs: len(choices) - 1)
    monkeypatch.setattr("sys.stdin", type("FakeTTY", (), {"isatty": lambda self: True})())

    fetih_main.cmd_model(SimpleNamespace())
    output = capsys.readouterr().out

    assert "Warning:" in output or "Uyarı:" in output
    assert ("falling back to auto provider detection" in output.lower() or
            "otomatik sağlayıcı tespitine geçiliyor" in output.lower())
    assert "No change." in output


def test_model_flow_custom_saves_verified_v1_base_url(monkeypatch, capsys):
    monkeypatch.setattr(
        "fetih_cli.config.get_env_value",
        lambda key: "" if key in {"OPENAI_BASE_URL", "OPENAI_API_KEY"} else "",
    )
    saved_env = {}
    monkeypatch.setattr("fetih_cli.config.save_env_value", lambda key, value: saved_env.__setitem__(key, value))
    monkeypatch.setattr("fetih_cli.auth._save_model_choice", lambda model: saved_env.__setitem__("MODEL", model))
    monkeypatch.setattr("fetih_cli.auth.deactivate_provider", lambda: None)
    monkeypatch.setattr("fetih_cli.main._save_custom_provider", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "fetih_cli.models.probe_api_models",
        lambda api_key, base_url: {
            "models": ["llm"],
            "probed_url": "http://localhost:8000/v1/models",
            "resolved_base_url": "http://localhost:8000/v1",
            "suggested_base_url": "http://localhost:8000/v1",
            "used_fallback": True,
        },
    )
    monkeypatch.setattr(
        "fetih_cli.config.load_config",
        lambda: {"model": {"default": "", "provider": "custom", "base_url": ""}},
    )
    monkeypatch.setattr("fetih_cli.config.save_config", lambda cfg: None)

    # After the probe detects a single model ("llm"), the flow asks
    # "Use this model? [Y/n]:" — confirm with Enter, then context length,
    # then display name. The api_mode prompt also runs before model selection.
    answers = iter(["http://localhost:8000", "local-key", "", "", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": next(answers))

    fetih_main._model_flow_custom({})
    output = capsys.readouterr().out

    assert "Saving the working base URL instead" in output
    assert "Detected model: llm" in output
    # OPENAI_BASE_URL is no longer saved to .env — config.yaml is authoritative
    assert "OPENAI_BASE_URL" not in saved_env
    assert saved_env["MODEL"] == "llm"


def test_model_flow_custom_persists_selected_api_mode(monkeypatch):
    saved_cfg = {"model": {"default": "", "provider": "custom", "base_url": ""}}
    captured_provider = {}

    monkeypatch.setattr(
        "fetih_cli.config.get_env_value",
        lambda key: "" if key in {"OPENAI_BASE_URL", "OPENAI_API_KEY"} else "",
    )
    monkeypatch.setattr("fetih_cli.auth._save_model_choice", lambda model: None)
    monkeypatch.setattr("fetih_cli.auth.deactivate_provider", lambda: None)
    monkeypatch.setattr(
        "fetih_cli.models.probe_api_models",
        lambda api_key, base_url: {
            "models": [],
            "probed_url": f"{base_url.rstrip('/')}/models",
            "resolved_base_url": None,
            "suggested_base_url": None,
            "used_fallback": False,
        },
    )
    monkeypatch.setattr("fetih_cli.config.load_config", lambda: saved_cfg)
    monkeypatch.setattr("fetih_cli.config.save_config", lambda cfg: saved_cfg.update(cfg))
    monkeypatch.setattr(
        "fetih_cli.main._save_custom_provider",
        lambda base_url, api_key="", model="", context_length=None, name=None, api_mode=None: captured_provider.update(
            {
                "base_url": base_url,
                "api_key": api_key,
                "model": model,
                "context_length": context_length,
                "name": name,
                "api_mode": api_mode,
            }
        ),
    )

    answers = iter(
        [
            "https://codex.example.com/v1",
            "3",
            "chosen-model",
            "",
            "",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": "test-key")

    fetih_main._model_flow_custom({"model": {"provider": "custom"}})

    assert saved_cfg["model"]["provider"] == "custom"
    assert saved_cfg["model"]["base_url"] == "https://codex.example.com/v1"
    assert saved_cfg["model"]["api_key"] == "test-key"
    assert saved_cfg["model"]["api_mode"] == "codex_responses"
    assert captured_provider["api_mode"] == "codex_responses"
def test_auto_provider_name_localhost():
    from fetih_cli.main import _auto_provider_name
    assert _auto_provider_name("http://localhost:11434/v1") == "Local (localhost:11434)"
    assert _auto_provider_name("http://127.0.0.1:1234/v1") == "Local (127.0.0.1:1234)"


def test_auto_provider_name_runpod():
    from fetih_cli.main import _auto_provider_name
    assert "RunPod" in _auto_provider_name("https://xyz.runpod.io/v1")


def test_auto_provider_name_remote():
    from fetih_cli.main import _auto_provider_name
    result = _auto_provider_name("https://api.together.xyz/v1")
    assert result == "Api.together.xyz"


def test_save_custom_provider_uses_provided_name(monkeypatch, tmp_path):
    """When a display name is passed, it should appear in the saved entry."""
    import yaml
    from fetih_cli.main import _save_custom_provider

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump({}))

    monkeypatch.setattr(
        "fetih_cli.config.load_config", lambda: yaml.safe_load(cfg_path.read_text()) or {},
    )
    saved = {}
    def _save(cfg):
        saved.update(cfg)
    monkeypatch.setattr("fetih_cli.config.save_config", _save)

    _save_custom_provider("http://localhost:11434/v1", name="Ollama")
    entries = saved.get("custom_providers", [])
    assert len(entries) == 1
    assert entries[0]["name"] == "Ollama"
