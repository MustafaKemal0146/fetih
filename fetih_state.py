#!/usr/bin/env python3
"""
SQLite State Store for FETIH.

Provides persistent session storage with FTS5 full-text search, replacing
the per-session JSONL file approach. Stores session metadata, full message
history, and model configuration for CLI and gateway sessions.

Key design decisions:
- WAL mode for concurrent readers + one writer (gateway multi-platform)
- FTS5 virtual table for fast text search across all session messages
- Compression-triggered session splitting via parent_session_id chains
- Batch runner and RL trajectories are NOT stored here (separate systems)
- Session source tagging ('cli', 'telegram', 'discord', etc.) for filtering

This module is a thin backward-compatibility layer. The implementation was
split across:
  - fetih_state_common:      shared constants and WAL-fallback helpers
  - fetih_state_schema:      schema DDL, migrations, VACUUM/auto-prune
  - fetih_state_search:      FTS5/trigram/CJK message + session search
  - fetih_state_portability: rich session listing and export
  - fetih_state_registry:    Telegram DM topic bindings and handoff state
  - fetih_state_holders:     the SessionDB container class itself

Every name below is re-exported unchanged so existing
``from fetih_state import ...`` / ``import fetih_state`` call sites keep
working without modification.
"""

# `sqlite3` is imported directly (rather than only transitively via the
# submodules below) so ``unittest.mock.patch("fetih_state.sqlite3.connect",
# ...)`` keeps resolving — the attribute must exist on this module's own
# namespace. It's the same module object sqlite3.connect is patched on
# everywhere else, so behavior is unaffected either way.
import sqlite3  # noqa: F401  (re-exported for back-compat / patch targets)

from fetih_state_common import (  # noqa: F401  (re-exported for back-compat)
    DEFAULT_DB_PATH,
    T,
    _last_init_error_lock,
    _log_wal_fallback_once,
    _set_last_init_error,
    _wal_fallback_warned_lock,
    _wal_fallback_warned_paths,
    _WAL_INCOMPAT_MARKERS,
    apply_wal_with_fallback,
    format_session_db_unavailable,
    get_last_init_error,
    logger,
)
from fetih_state_schema import (  # noqa: F401  (re-exported for back-compat)
    FTS_SQL,
    FTS_TRIGRAM_SQL,
    SCHEMA_SQL,
    SCHEMA_VERSION,
    SessionSchemaMixin,
)
from fetih_state_search import SessionSearchMixin  # noqa: F401  (re-exported for back-compat)
from fetih_state_portability import SessionPortabilityMixin  # noqa: F401  (re-exported for back-compat)
from fetih_state_registry import SessionRegistryMixin  # noqa: F401  (re-exported for back-compat)
from fetih_state_holders import SessionDB  # noqa: F401  (re-exported for back-compat)
