## 3.0.0a5

- Moved all English static, shield, MCP, sandbox, memory, and supply-chain assets into `languages/en`.
- Confirmed Arabic static and runtime assets are owned by `languages/ar`.
- Reduced `rules/registry.py` to a language-pack compiler and compatibility adapter.
- Added migration tests proving both built-in packs own their complete rule assets.

# Changelog

## 3.0.0a2

- Added a central typed rule engine (`PatternRule`, `RuleHit`, `RuleSet`).
- Moved generic scanner, Shield, and MCP signatures into one registry.
- Updated Shield and MCP Guard to use shared rule evaluation and scoring.
- Added channel-aware rule evaluation and immutable named rule sets.
- Added dedicated registry and engine regression tests.
- Preserved all existing finding IDs, severities, thresholds, and CLI behavior.

## 3.0.0a1

- Reorganized the project into an installable `src/` package.
- Added a unified `pi-audit` CLI.
- Preserved legacy `scripts/` commands and import paths.
- Moved documentation and tests into dedicated directories.
- Added packaging, test, lint, and type-check configuration.
- No detection-rule behavior intentionally changed.

## 3.0.0a3

- Added canonical `Finding` and `Location` models for scanner, shield, and MCP guard results.
- Added unified `ScorePolicy`, `ScoreSummary`, and `calculate_score()` APIs.
- Added exact-finding deduplication and confidence-aware scoring support.
- Preserved historical static severity weights and runtime ALLOW/WARN/BLOCK thresholds.
- Added structured findings to Shield and MCP result objects while retaining legacy text findings.
- Added `scan_findings()` for typed static-audit results.
- Added schema-versioned structured findings and scoring metadata to JSON reports.
- Increased the test suite from 74 to 81 tests.

## 3.0.0a4

- Added a public Language Pack API and registry.
- Migrated Arabic normalization and rule assets into `languages/ar`.
- Added the built-in English pack and mixed-language auto-detection.
- Preserved legacy `language_rules` and `normalization` import paths.

## 3.0.0a6
- Added built-in Russian language pack with Cyrillic normalization.
- Added Russian direct/indirect injection, extraction, authority, refusal, exfiltration, MCP, memory, and supply-chain rules.
- Added multilingual runtime scanning for all registered non-English language packs.
- Preserved native Russian text while retaining Cyrillic homoglyph detection for English payloads.

## 3.0.0a7

- Added bounded recursive deobfuscation for URL percent encoding, HTML entities,
  Unicode escapes, ROT13, Base32, Base85, reversed text, Base64, and hex.
- Added maximum depth, decoded-size, and candidate-count limits.
- Integrated decoded-content analysis with all installed language packs.
- Added regression and false-positive tests for Shield and MCP Guard.

## 3.0.0a8

- Added bounded `SessionRiskState` for multi-turn prompt-injection correlation.
- Detects instruction fragments reconstructed across separate user turns.
- Added decayed session scoring, TTL expiry, maximum retained turns, and per-session isolation.
- Added safe state serialization that re-analyzes stored messages when restored.
- Added `pi-audit session` CLI for one-message-per-line conversation analysis.
