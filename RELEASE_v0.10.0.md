# FETIH v0.10.0 (v2026.4.16)

**Release Date:** April 16, 2026

> The Tool Gateway release — paid FETIH Portal subscribers can now use web search, image generation, text-to-speech, and browser automation through their existing subscription with zero additional API keys.

---

## ✨ Highlights

- **Nous Tool Gateway** — Paid [FETIH Portal](https://github.com/MustafaKemal0146/fetih) subscribers now get automatic access to **web search** (Firecrawl), **image generation** (FAL / FLUX 2 Pro), **text-to-speech** (OpenAI TTS), and **browser automation** (Browser Use) through their existing subscription. No separate API keys needed — just run `fetih model`, select FETIH Portal, and pick which tools to enable. Per-tool opt-in via `use_gateway` config, full integration with `fetih tools` and `fetih status`, and the runtime correctly prefers the gateway even when direct API keys exist. Replaces the old hidden `FETIH_ENABLE_NOUS_MANAGED_TOOLS` env var with clean subscription-based detection. ([#11206](https://github.com/MustafaKemal0146/fetih/pull/11206), based on work by @jquesnelle; docs: [#11208](https://github.com/MustafaKemal0146/fetih/pull/11208))

---

## 🐛 Bug Fixes & Improvements

This release includes 180+ commits with numerous bug fixes, platform improvements, and reliability enhancements across the agent core, gateway, CLI, and tool system. Full details will be published in the v0.11.0 changelog.

---

## 👥 Contributors

- **@jquesnelle** (emozilla) — Original Tool Gateway implementation ([#10799](https://github.com/MustafaKemal0146/fetih/pull/10799)), salvaged and shipped in this release

---

**Full Changelog**: [v2026.4.13...v2026.4.16](https://github.com/MustafaKemal0146/fetih/compare/v2026.4.13...v2026.4.16)
