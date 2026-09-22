# Study Pre-Registration — Agent Prompt Security Scan

**Registered: 2026-08-02, before any test-set collection or scanning.**

## Frozen scanner version

- Repository HEAD at registration: `b1b80fb724cf30694a7e174ae593cba16cdcb3a6`
- `scripts/pi_scan.py` sha256: `93dc6ef7e288806a7930fde5cc7962f9e58012c40ed6b6847adc762d8df8e377`
- Version label: v2.3.2 (91 tests passing at freeze)

## Design commitments (registered in advance)

1. **Dev/test split.** The 502 files collected 2026-08-02 are the
   *development set*: both scanner fixes (PI-SECRET placeholder suppression,
   PI-TOOLS app-description suppression) were discovered from them. Their
   numbers are published as diagnostics, explicitly labeled
   "development set (tuning-informed)" — disclosed, not hidden — and never
   presented as results. The *test set* is collected after this registration
   and scanned exactly once with the frozen version.
2. **Freeze rule.** Any defect discovered from test-set files is documented
   as a limitation and NOT fixed before publication. Fixing it would
   re-open tuning on the data being measured.
3. **Single-rater declaration.** Initial labeling is by a single rater
   involved in the tool's design; this is stated as a limitation. An
   independent blind labeling of 30 test-set files (rater sees files without
   scanner output) is completed before publication — not after — and the
   agreement rate is published alongside the precision estimate.
4. **Confidence intervals.** Every percentage carries its Wilson interval;
   no point-only claims.
5. **Per-source reporting.** Sources are not equivalent (leaked prompts,
   published prompts, coding-rule collections). Every figure is reported
   split by source, with a "what each source represents" note.
6. **Privacy.** Published outputs are aggregate-only: no repository names,
   no file names, no "worst offender" lists. Any file containing a
   live-looking credential enters the RESPONSIBLE_DISCLOSURE path and is
   excluded from publication.
7. **Test-set collection.** Sources and criteria are fixed at registration:
   public GitHub repositories that collect AI-agent system prompts or skill
   files, found by topic/keyword search, carrying an OSI license, excluding
   the three development sources and their forks. Sampling uses seed
   20260803. The collection manifest (repository names, commit SHAs, file
   hashes) is committed to this repository *before* the scan runs, and is
   retained for reproducibility.

*This file is committed before the test set exists, so the boundaries
cannot have been drawn after seeing results.*
