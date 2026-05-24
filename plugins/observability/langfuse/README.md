# Langfuse Observability Plugin

This plugin ships bundled with FETIH but is **opt-in** — it only loads when
you explicitly enable it.

## Enable

```bash
pip install langfuse
fetih plugins enable observability/langfuse
```

Or check the box in the interactive `fetih plugins` UI.

## Required credentials

Set these in `~/.fetih/.env`:

```bash
FETIH_LANGFUSE_PUBLIC_KEY=pk-lf-...
FETIH_LANGFUSE_SECRET_KEY=sk-lf-...
FETIH_LANGFUSE_BASE_URL=https://cloud.langfuse.com   # or your self-hosted URL
```

Without the SDK or credentials the hooks no-op silently — the plugin fails
open.

## Verify

```bash
fetih plugins list                 # observability/langfuse should show "enabled"
fetih chat -q "hello"              # then check Langfuse for a "FETIH turn" trace
```

## Optional tuning

```bash
FETIH_LANGFUSE_ENV=production       # environment tag
FETIH_LANGFUSE_RELEASE=v1.0.0       # release tag
FETIH_LANGFUSE_SAMPLE_RATE=0.5      # sample 50% of traces
FETIH_LANGFUSE_MAX_CHARS=12000      # max chars per field (default: 12000)
FETIH_LANGFUSE_DEBUG=true           # verbose plugin logging
```

## Disable

```bash
fetih plugins disable observability/langfuse
```
