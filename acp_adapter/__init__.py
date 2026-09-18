"""ACP adapter package for FETIH.

Exposes the Agent Client Protocol surface (Zed, VS Code, JetBrains) on top of
the FETIH agent runtime.  The public entry point is
``acp_adapter.entry:main`` (also wired as the ``fetih-acp`` console script).

Submodules:
    entry         — CLI entry point (``fetih acp``), logging/env bootstrap
    server        — ``FETIHACPAgent`` implementing the ACP agent handlers
    session       — session lifecycle, persistence and cwd translation
    events        — streaming callbacks that turn agent signals into ACP updates
    permissions   — tool-approval permission requests driven by the client
    edit_approval — write_file/patch approval bridge used by model_tools
    tools         — tool kind mapping and tool-call content building
    auth          — provider detection and ACP auth-method advertisement
"""

__all__ = ["FETIH_VERSION"]

# Kept in sync with the ``version`` field in pyproject.toml; the registry
# manifest test asserts both match.
FETIH_VERSION = "1.1.0"
