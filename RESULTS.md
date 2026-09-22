# RESULTS — Prompt-Injection Posture of Public Agent-Configuration Corpora

**A pre-registered, single-scan study.** Date: 2026-08-03.
Scanner: `scripts/pi_scan.py` v2.3.2, frozen at sha256
`93dc6ef7e288806a7930fde5cc7962f9e58012c40ed6b6847adc762d8df8e377`.

This file reports results. Companion documents: `PREREGISTRATION.md`
(registered before any test data existed), `TESTSET_MANIFEST.md` (data sealed
before any results existed), `VALIDATION.md` (including the score-floor
calibration), `verify_testset.py` (end-to-end reproduction).

---

## 1. Chain of custody

1. **Pre-registration** committed before the test set existed
   (`PREREGISTRATION.md`, including scanner fingerprint and sampling seed
   `20260803`).
2. **Test-set manifest** committed before the scan ran
   (`TESTSET_MANIFEST.md`; manifest sha256
   `8b3068b167776032b4ab4d68e721e0c1364949760aee1871463ef646cca7b316`).
3. **One frozen scan**, run exactly once over the sealed corpus. Results file
   sha256 `8afce45bbc5d70c27866320642312ff0c1077bf0a4dcd952709f6518ced7bf63`.
4. **Independent reproduction** on a second machine: `ALL CHECKS PASSED`
   (scanner hash, corpus hash-set, and all headline values reproduced).

The scanner was not modified at any point after registration. Every analysis
below is derived from the single registered scan; no re-scanning occurred.

## 2. Test set

2,491 files from four public MIT-licensed GitHub sources, pinned by commit SHA
(sources, SHAs, inclusion conventions C1–C4, and integrity checks are in
`TESTSET_MANIFEST.md`): gpt-prompts 1,386 · copilot 824 · subagents 183 ·
prompt-library 98. Minimum length 200 chars; 41 duplicates removed; zero
overlap with the development set.

## 3. Primary result — declared controls, not scores

The pre-registered primary metric is the **mean number of declared controls
out of six** (hierarchy, non-disclosure, role guard, delimiters, refusal
behavior, output limits), because the absolute risk score has a structural
floor (§5) and measures *declared* controls, not actual safety.

**Corpus headline: 66.7% of files [64.8, 68.5] declare zero of the six
controls.** Corpus mean: **0.41 of 6 (6.9%)**.

| Per-rule declaration (corpus, n=2,491) | declared |
|---|---|
| Non-disclosure of the prompt itself | 16.8% |
| Output scope/format limits | 9.6% |
| Instruction hierarchy | 6.4% |
| Refusal behavior on rule-breaking | 4.9% |
| Delimiters for untrusted input | 3.0% |
| Role guard (scope or identity-claim stability) | 0.8% |

| Source | n | mean of 6 | zero declared | SEVERELY EXPOSED (≥70) |
|---|---|---|---|---|
| prompt-library | 98 | 0.82 (14%) | 45.9% | 61.2% |
| gpt-prompts | 1,386 | 0.49 (8%) | 60.9% | 37.5% |
| copilot | 824 | 0.30 (5%) | 74.5% | 76.6% |
| subagents | 183 | 0.14 (2%) | 86.9% | 82.5% |

No corpus source reaches a mean of one declared control out of six.

## 4. Risk-score distribution (secondary, calibration-adjusted)

Scores: mean 73.2, median 71, min 27, max 100.
Verdict bands: **SEVERELY EXPOSED (≥70): 54.7% [52.7, 56.6]** · HIGH RISK
(40–69): 44.9% · MODERATE (15–39): 0.4% · **HARDENED (<15): 0 files**.

These bands are valid for the tool's intended single-target audit. Across a
corpus they must be read against the calibration in §5: a median of 71 sits
only **8 points above the structural floor of 63** — the corpus signal is the
distance from the floor, not the absolute band.

## 5. Calibration — the score floor (measured, documented)

Measured directly on the frozen scanner (full probe table in
`VALIDATION.md`): the empty file, a neutral sentence, and an ordinary
coding-rules paragraph all score **63/100**, because six absence rules
(18+18+8+8+8+3) fire on *any* text lacking explicit declarations. A prompt
declaring all six controls in recognized phrasing scores 11 (HARDENED).

Consequence: the score quantifies **declared controls in recognized
phrasing**, not actual safety. This is a documented property of the tool,
preserved under the freeze — and the reason §3, not §4, is the headline.

## 6. Internal consistency check (involved rater — declared limitation)

A stratified-proportional 30-file sample (seed `20260803`: gpt-prompts 17,
copilot 10, subagents 2, prompt-library 1) was labeled on five declaration
questions (plus file kind) by a rater who **participated in the study
design**. This is an internal consistency check, **not** an independent
accuracy measurement (see §8).

Agreement with the scanner: **135/150 cells (90.0%)** —
q1 hierarchy 29/30 · q2 role guard 28/30 · q3 delimiters 29/30 ·
q4 refusal 29/30 · **q5 output limits 20/30**.

All 12 disagreements point one way: the scanner claims a control is absent
where the rater found it declared — the scanner is **systematically
conservative** (overstates risk, never understates it in this sample). Two
specific pattern gaps were identified and are documented, not fixed (freeze):

- **PI-NO-OUTPUTLIM misses a category, not a phrasing**: structural output
  mandates ("You MUST produce following this exact structure", word budgets,
  fixed templates) — constraints on *form*, arguably stronger than topic
  limits. 10 of 30 sample files.
- **PI-NO-ROLEGUARD misses scope-binding phrasing**: "Only answer questions
  related to X" declares a role boundary without authority-claim language.
  2 of 30 sample files.

## 7. Impact estimates (involved-rater-based — not arbitrated)

Propagating the §6 disagreement rates to the corpus (Wilson 95%, n=30):

| Quantity | scanner-measured | corrected estimate |
|---|---|---|
| Output limits declared | 9.6% | ~44% [30, 62] |
| Role guard declared | 0.8% | ~7% [3, 22] |
| Mean controls of 6 | 0.41 (6.9%) | ~0.83 (13.8%) [0.64, 1.15] |
| Zero controls declared | 66.7% | ~39% [26, 51] |

These corrections rest on the involved rater's reading (structural mandates
count as output limits) and are **not independently arbitrated** (§8). They
bound the direction of the scanner's error: reality declares *more* than the
scan reports.

## 8. Deviation from pre-registration — disclosed

`PREREGISTRATION.md` item 3 requires independent blind labeling, by a rater
who neither participated in design nor saw scanner output, **completed before
publication**.

**What happened.** The recruited independent rater received the blind pack
(30 content-only files, worksheet, Arabic instructions v1.2) and withdrew,
stating principled non-participation. Zero cells were filled. No replacement
rater meeting the criteria (independent · no design involvement · no exposure
to scanner output · reads technical English) was available.

**Decision.** Publish with the deviation disclosed rather than (a) labeling by
a design participant under an independence label, or (b) abandoning the
study. Binding consequences, applied throughout this report: no
scanner-vs-human figure is presented as independently validated; §6 is
labeled internal consistency only; §7 is labeled non-arbitrated.

**Related event, documented as evidence the pre-set controls work.** Before
the withdrawal, a first draft of the rater instructions (v1.1) was rejected
by a pre-set review condition: its explanation of the role-guard question had
been written from the scanner rule's own definition (authority-spoofing)
instead of the frozen worksheet concept (scope restriction). Had it shipped,
the blind rater would have been steered toward the scanner on exactly the
question where scanner misses were suspected. v1.2 corrected this; the full
version log is retained in the study record.

## 9. Limitations

1. **Single, involved rater.** All human-judgment figures (§6, §7) come from
   one rater who participated in design. See §8.
2. **Declaration ≠ safety.** The scanner measures explicit declarations in
   recognized phrasing; a file can declare controls and be unsafe, or be
   careful and undeclared.
3. **Structural floor.** Absolute corpus bands overstate risk; §5.
4. **Two documented pattern gaps** (structural output mandates; scope-binding
   phrasing) — left unfixed under the freeze; both err toward overstating
   risk.
5. **Corpus scope.** Four public English-dominant GitHub sources; findings
   describe these corpora, not all deployed agents.
6. **Small consistency sample** (n=30) — wide intervals in §7 by design.
7. **Development-set figures** (§11) are tuning-informed diagnostics, not
   evidence of generalization on their own.

## 10. Freeze compliance and disclosed corrections

- Scanner sha256 `93dc6ef7…` unchanged since registration; no rule, weight,
  or pattern was edited after the test set existed.
- The display/aggregation script initially used inverted band labels
  (risk-score semantics read backwards). **Numbers were never affected**; the
  labels were corrected before publication and the event is disclosed here.
- The reproduction script normalizes CRLF line endings before hashing (one
  file in the corpus contains CRLFs). Scan numbers were never affected.

## 11. Development-set diagnostics (tuning-informed — disclosed)

The 502-file development set used to tune v2.3.2, restated with correct risk
semantics and the §5 calibration caveat: mean 73.1, median 71; SEVERELY
EXPOSED 55.6%; zero-declared 65.1%; mean-of-6 0.67. These numbers informed
rule design and are diagnostics, not findings. Their closeness to the sealed
test set (73.2 / 54.7% / 66.7% / 0.41) indicates the frozen scanner behaves
stably on unseen data; it does not validate the rules' definitions.

## 12. Reproduction

`verify_testset.py` downloads the four sources by pinned commit SHA, rebuilds
the corpus, verifies the hash set against `manifest-test.jsonl` (set
equality; per-source counts), fetches the frozen scanner, re-scans, and
checks the headline values (2,491 files · mean 73.2 · median 71 · severe
1,362 · hardened 0). Reproduced end-to-end on two independent machines.

## 13. Ethics

All publication is aggregate-only: no per-file scores, no "worst offender"
lists, no repository names attached to individual findings. Twelve potential
secret findings were triaged; none contained live credentials (didactic
examples and training-lab material). The responsible-disclosure path was not
triggered. All four sources are MIT-licensed; collection respected public
access only.

---

*Study conducted 2026-08-01 → 2026-08-03. Scanner frozen throughout.
Deviations and corrections disclosed in §8 and §10.*
