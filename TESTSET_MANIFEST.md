# Test-Set Collection Manifest

Committed **before any test-set scanning**, per commitment 7 of
[PREREGISTRATION.md](PREREGISTRATION.md) (registered 2026-08-02; the frozen
scanner is v2.3.2, `scripts/pi_scan.py` sha256
`93dc6ef7e288806a7930fde5cc7962f9e58012c40ed6b6847adc762d8df8e377`).

Collected: 2026-08-03. Retrieved after registration, committed before scanning.

## Sources

All public GitHub repositories collecting AI-agent system prompts or skill
files, carrying an OSI license; none is one of the three development sources
or a fork of them.

| source id | repository | commit SHA | retrieved | license | files kept |
|---|---|---|---|---|---|
| copilot | github/awesome-copilot | `336af71f1b7d2e6e15a8a986ba79ca031a40549b` | 2026-08-03 | MIT | 824 |
| subagents | wshobson/agents | `c4b82b0ad771190355eb8e204b1329732a18449a` | 2026-08-03 | MIT | 183 |
| gpt-prompts | LouisShark/chatgpt_system_prompt | `37a95e8a062d78424546e5acfbe0f95b3de79e2a` | 2026-08-03 | MIT | 1386 |
| prompt-library | 0xeb/TheBigPromptLibrary | `655667d2dd43bad65f189ec49d8606bf3e8d967e` | 2026-08-03 | MIT | 98 |

**Total: 2,491 files.**

## Eligibility (uniform across all sources)

A file is included if and only if it matches one convention:

- **C1** basename is `SKILL.md`
- **C2** name ends `.agent.md`, `.instructions.md`, or `.prompt.md`
- **C3** name ends `.mdc`
- **C4** its top-level directory is `prompt`, `prompts`, `system-prompts`,
  `system_prompts`, or `gpts` (case-insensitive) and it ends `.md`/`.txt`

Uniform exclusions: any path component `.github` or `docs`; repository-meta
files (`README*`, `LICENSE*`, `CONTRIBUTING*`, `CHANGELOG*`, `SECURITY*`,
`CODEOWNERS`, `SUPPORT*`, `TOC.md`, `GETTING_STARTED*`, root `AGENTS.md` /
`CLAUDE.md` / `GEMINI.md`); files under 200 characters; exact sha256
duplicates.

## Integrity checks at collection

- Exact-hash duplicates removed within the test set: **41**
  (subagents 3, gpt-prompts 26, prompt-library 12)
- Overlap with the 502 development files (by sha256): **0** — the dev/test
  split is clean
- **Census, not a sample**: every eligible file was taken, so the registered
  sampling seed (20260803) was not invoked
- Machine-readable manifest: `manifest-test.jsonl` (2,491 rows, one per file,
  with `source_repo`, `repo_sha`, `source_path`, `retrieved`, `license_note`,
  `sha256`, `bytes`, `chars`), sha256:
  `8b3068b167776032b4ab4d68e721e0c1364949760aee1871463ef646cca7b316`

## What happens next

This manifest is committed first. Only then is the frozen scanner
(v2.3.2) run against the 2,491 files — exactly once. Any defect discovered
from these files is documented as a limitation, not fixed before publication
(commitment 2).
