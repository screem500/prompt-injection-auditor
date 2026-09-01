# Changelog

## v2.6.1 — 2026-09-02

### Fixed — five findings from the pre-tag review of v2.6.0

A second-pass review of the v2.6.0 candidate probed the rules with realistic
text instead of the claimed benchmark numbers. Five findings reproduced
exactly as reported and are fixed here; the sixth (operational) is addressed
by new permanent gates below. v2.6.0 was never tagged — the fixes land in
the same first public 2.6.x release.

1. **PI-TOOLS / PI-NO-CONFIRM-GATE: destructive detection required only a
   verb.** `(delete|remove|drop|truncate) ` fired on refactoring vocabulary —
   "remove unused imports and dead code" reported a destructive capability
   and fed PI-NO-CONFIRM-GATE a High. The pattern now requires a
   consequential object (files, records, tables, accounts, data, ...) within
   two words: "delete records in the CRM" fires; "remove unused imports"
   does not. File deletion without a gate ("delete temporary build files")
   still fires **by design** — the OpenClaw anchor was exactly unattended
   file deletion. The Arabic table is untouched.
2. **mcp_guard: the "safe" wrapped form carried raw terminal controls.**
   `guard_tool_response()` built `sanitized` from the raw input, so an
   OSC 52 clipboard-write sequence passed into the wrapped output
   byte-for-byte while scoring ran on the normalized form. The sanitized
   form is now built from the neutralized text (ESC → visible ␛, other
   controls → �, tag block decoded to visible ASCII); JSON inputs are
   rebuilt value-by-value so the sanitized form stays parseable.
3. **pi_shield rewrote visible user text.** Homoglyph folding — a scoring
   aid — leaked into the model-bound output: "Привет" arrived as "Пpивeт",
   ZWNJ stripping broke Persian shaping, ZWJ stripping broke emoji
   sequences. The shield now keeps two views: `normalize()` (aggressive,
   scoring-only) and the new `sanitize_output()` (faithful — controls
   neutralized, tag block decoded into the open, hidden characters
   stripped, visible text untouched). Homoglyph attacks still block;
   Cyrillic, Persian script and 👨‍👩‍👧 pass intact.
4. **PI-UNICODE-OBFUSCATION fired on ordinary typography.** Presence-alone
   detection flagged ❤️ (variation selector), 👨‍👩‍👧 (ZWJ), Persian
   می‌خواهم (ZWNJ) and Arabic text carrying RLM. The check is now
   context-aware: joiners and direction marks are legitimate between
   shaping-script letters (Arabic, Hebrew, Syriac, ...) and after emoji
   bases, and stay suspicious everywhere else — a ZWJ inside a Latin
   keyword ("ig‍nore") still fires, as do ZWSP, bidi overrides and the
   whole tag block.
5. **`\bDAN\b` matched case-insensitively — "Hi, I'm Dan" scored 35
   (WARN).** DAN ("Do Anything Now") is an all-caps acronym; the pattern is
   now case-sensitive, with a guard that keeps the jailbreak family
   single-counted — exactly as when DAN was an alternative inside the
   case-insensitive tuple, never stacked.

### Added — the review's operational finding becomes permanent gates

- **`check_redactions.py`** (new): the pre-commit sweep `check_rule_docs.py`
  always referenced but the repo never shipped. Fails on private home-
  directory path literals, personal email addresses, and
  live-looking credentials — judged by the scanner's own PI-SECRET engine —
  outside documented fixture locations. Allowlist entries are per
  (file, check) with written justification. Wired into CI.
- **CI release gate** (`.github/workflows/tests.yml`): a new `gate` job runs
  what RELEASING.md step 3 always demanded — the redaction sweep, hardened
  corpus `--expect-clean`, and a vulnerable-corpus separation floor
  (mean ≥ 43.3). A gate that only exists locally is a suggestion.
- **Test-count drift check** (`tests/test_docs_sync.py` check 4): the
  CHANGELOG's newest stated test count must equal the number of test
  methods actually collected from `tests/`. Release notes quote the count
  from the run output, never from memory (step 7).

### Fixed — second review round

A follow-up review re-tested every fix above and probed the surrounding
code. All seven of its points reproduced and are fixed here.

6. **PI-NO-CONFIRM-GATE: publish/deploy fired on workflow descriptions.**
   "Our CI pipeline deploys to production on every merge" reported a
   consequential capability. The extra pattern now requires agent voice in
   the match window ("you", "the agent/assistant", "your job/role/task") —
   findings are about what the prompt tells the agent to do, not about what
   a document describes.
7. **Destructive pairing lost recall to punctuation.** The two-word window
   rejected "delete, archive, or forward messages" (comma) and "remove the
   customer's account" (apostrophe). Intermediates now tolerate commas and
   apostrophes and allow up to three words.
8. **PI-UNICODE-OBFUSCATION: two context classes still fired.** RLM after
   punctuation on an Arabic line is line-level layout — legitimate whenever
   the line contains shaping-script characters. Variation selectors after
   digits or symbols (1️⃣, ™️) are emoji typography — suspicious only when
   glued to a Latin/Cyrillic/Greek letter.
9. **Fullwidth delimiter forgeries passed the wrappers.** ＜/user_data＞
   (U+FF1C/U+FF1E) was detected by the scanner's fullwidth rule but the
   pi_shield/mcp_guard escape regexes matched only ASCII brackets, so the
   forgery rode into the wrapped output. Both wrappers now count and
   neutralize fullwidth forms identically.
10. **mcp_guard: the neutralization note fired on every clean JSON, and
    bare OSC 52 scored zero.** Re-serialization made `sanitized != text`
    unconditionally true for JSON input; the note now compares per-value
    and fires only on real change. OSC 52 clipboard-write sequences now
    score +30 on raw text (WARN) matching the scanner's PI-ANSI-INJECT
    stance; SGR color sequences stay weightless on purpose — captured
    build logs legitimately carry them.
- **CI gate compared against the wrong number.** The gate job floored the
  vulnerable-corpus mean at 43.3 — the *separation* value, not the mean —
  silently guaranteeing only 40.3 of separation. The job now computes both
  means and gates `separation ≥ 43.3` directly.
- **VALIDATION.md's historical table was read as current.** The v2.2-era
  table (separation 40.6) now carries an explicit current-measurement note
  (v2.6.1: hardened 3.0, vulnerable 46.3, separation 43.3, 180 tests) so a
  skimming reader cannot mix the two.
- **`scripts/finish_verify.py` removed.** A personal build-verification
  helper that was never meant to ship; nothing references it. Documented
  here so the deletion is on record.

### Fixed — third review round (cross-suite run)

The follow-up review cross-ran both test suites on both trees. Five of its
seven second-round points were equivalent between the implementations; four
gaps reproduced on this tree and are fixed here.

11. **Fullwidth tag NAMES defeated the wrappers.** Bracket-only
    neutralization covered ＜/＞ but not a tag whose name is fullwidth —
    ＜／ｕｓｅｒ＿ｄａｔａ＞ was detected by the scanner yet reached the wrapped
    output intact (mcp_guard: ALLOW 0). Both wrappers now detect the tag on
    a length-preserving NFKC fold of the input and neutralize the bracket
    characters in place — covering every codepoint NFKC folds to a single
    '<'/'>' (fullwidth forms, U+2329/U+232A via 〈〉), while mathematical
    ⟨⟩ — which NFKC does not fold — stays untouched.
12. **mcp_guard: dangerous terminal sequences scored zero.** SGR 8
    (conceal — the exact "invisible to the reviewer, readable to the model"
    primitive PI-ANSI-INJECT describes), OSC 8 hyperlinks, REP repeat
    floods and DCS all passed at ALLOW 0. Each now scores +60 (BLOCK) on
    raw text. SGR colors stay weightless by design — captured build logs
    legitimately carry them; conceal is not a color.
13. **Agent voice crossed sentences.** "You are a release assistant. Our
    CI pipeline deploys to production on every green build." — the
    .cursorrules shape — fired High because the 140-character require
    window reached back to the "You" opener. The agent-voice requirement
    is now evaluated on the sentence holding the match, and CI/workflow
    vocabulary (CI/CD, pipeline, pull/merge request, workflow) suppresses
    the publish/deploy pattern outright.
14. **ALM (U+061C) still fired on Arabic lines.** It now gets the same
    line-level treatment as LRM/RLM — with a correction found while
    testing: ALM sits inside the Arabic block, so the mark itself must be
    excluded when judging the line's script, or every ALM would read as
    "legitimate".

### Fixed — recall follow-ups (fourth pass, pre-tag)

15. **Publish/deploy accepted no object.** "You may deploy to production"
    fired, but "deploy the app / changes to production" and "push the
    release branch to main" did not. The pattern now allows up to three
    intermediate words (dots included, for "e.g." and version numbers).
16. **A period inside "1.2"/"e.g." split the gating sentence.** The
    agent-voice requirement lost its "You" opener and the finding went
    quiet. A period now ends a sentence only before whitespace or the
    line edge. Precision is untouched: third-person and CI/workflow
    phrasings stay quiet.

### Benchmark (method unchanged, VALIDATION.md)

Hardened corpus: 8 files, zero defect findings, mean 3.0 unchanged.
Vulnerable corpus: 13 files, mean 46.3 unchanged — no corpus file carries
the constructs the fixes touch, and v13's "delete records" still pairs.
Separation 43.3 unchanged.

### External corpus (garak in-the-wild, 650 prompts, SHA-256 c072aa09…)

Re-measured on the fixed shield: BLOCK 102 (15.7%) unchanged; WARN 134 →
128 (19.7%); ALLOW 414 → 420 (64.6%); noticed 36.3% → 35.4%; mean score
25.1 → 24.8. The entire movement is six payloads that scored WARN 35
solely for mentioning a person named Dan ("Dan Carlin", "Dan and Anna",
"a person named Dan") — the false-positive class fix 5 removes. Per
RELEASING.md step 4 the dip is recorded with its reason rather than
blocking the tag: those six were detected for the wrong reason.
VALIDATION.md's external section carries the new numbers.

### Tests

60 new cases in `tests/test_fp_regression.py` across four review rounds
(25 + 14 + 14 + 7: agent-voice gate and sentence scoping, destructive
tolerance, unicode context at character and line level, fullwidth
delimiters and tag names, mcp_guard notes / OSC 52 / dangerous ANSI, ALM,
deploy-object recall) and one doc-sync check (test count). 140 → 201
tests, all green on the CI matrix.

## v2.6.0 — 2026-08-28 (release candidate; superseded by v2.6.1 before tagging)

### Added — PI-NO-CONFIRM-GATE (rule 18): consequential actions with no confirmation gate

A prompt that grants send / delete / pay / publish / deploy and never states a
confirmation, staging, or stop rule now yields a High finding, Critical when
the same prompt ingests untrusted content (the EchoLeak shape with the last
gate removed). Consequential capabilities reuse the labels PI-TOOLS already
detects — bilingual, negation-aware, app-context-aware — so the two rules
never disagree about what the prompt declares; publish/deploy phrasing is
matched by a dedicated pattern so PI-TOOLS behavior is untouched. A stated
gate in English or Arabic suppresses the finding
(ARABIC_CONFIRM_GATE_PATTERNS, 6 normalized patterns).

Anchors: OpenClaw inbox-deletion incident (2026-02-23, OWASP GenAI Exploit
Round-up Q1 2026 — no CVE, only a missing gate); out-of-band defense
literature (CaMeL arXiv 2503.18813; adaptive-attack results, Nasr et al.
arXiv 2510.09023); Five Eyes joint guidance on agentic AI (May 2026).
Documentation: rule-inventory row, checklist #30, attack-patterns-2026 §6,
taxonomy-mapping row, SKILL.md severity guide.

### Added — CI, documentation drift guard, bilingual documentation policy

- `.github/workflows/tests.yml`: full suite on every push/PR — Linux and
  Windows, Python 3.8/3.10/3.12 — plus two CLI smoke tests (valid-JSON
  output; CR-bearing file handled, guarding the v2.5.1 fix).
- `tests/test_docs_sync.py`: wires `check_rule_docs.py` into the unittest
  suite and adds two checks — every `references/<name>.ar.md` twin covers
  exactly the rule IDs of its English base, and every file `SKILL.md` names
  exists in the repository.
- Bilingual policy: English documents gain Arabic twins; first twin is the
  2026 landscape research note (`references/attack-landscape-2026-08.md` and
  `.ar.md`). Twins may differ in wording, never in coverage — enforced by
  test.
- `RELEASING.md` (English + Arabic): the additive-only policy and the
  9-step release gate this entry followed.

### Benchmark (method unchanged, VALIDATION.md)

Hardened corpus: 8 files, zero defect findings before and after — the new
rule fires nowhere on it. Vulnerable corpus grew 12 → 13 files
(`v13_no_confirm_gate.txt`, the new rule's target file, scores 44). Corpus
movement, per the additive policy: `v03_echoleak.txt` 51 → 86 — it declares
send + web fetch with no gate, so PI-NO-CONFIRM-GATE fires Critical there by
design. Vulnerable mean 43.6 → 46.3; hardened mean 3.0 unchanged;
hardened/vulnerable separation 40.6 → 43.3.

### Tests

14 new cases in `tests/test_confirm_gate.py` (positive EN/AR, Critical under
ingestion, gate suppression EN/AR, negated capability, app-description
context, publish/deploy) and 4 doc-sync checks in `tests/test_docs_sync.py`.
122 → 140 tests, all green on the CI matrix.

## v2.5.2 — 2026-08-08

### Fixed — pi_shield was blind to Unicode tag-block smuggling (ASCII smuggling)

A community question on the v2.5 announcement — does PI-ANSI-INJECT catch
U+E0000 tag characters? — exposed a real gap. The scanner was already
covered: PI-UNICODE-OBFUSCATION flags the entire tag block because it is
Unicode category Cf and the rule covers the whole class. But pi_shield's
Layer 1 stripped only an explicit zero-width/bidi list, so a payload
written entirely in invisible tag characters passed the shield
ALLOW 0/100 — decoded by no one on the way in, still read by the model.

`normalize()` now decodes the printable tag range (U+E0020–U+E007E) back to
ASCII — Layer-3 scoring then sees the payload ("ignore all previous
instructions" smuggled in tags scores 95/100 → BLOCK) — drops the block's
non-printable tags, and strips every remaining category-Cf format
character, superseding the explicit list with the full class and matching
the scanner's coverage. Benign tag text passes through as visible ASCII.

Scanner and rules untouched: 17 rule IDs, no corpus movement.

### Tests

7 new tag-smuggling tests in `tests/test_shield.py` (122 total): tag decode,
non-printable drop, BLOCK on smuggled injection, benign pass-through, no
tag residue in sanitized output, zero-width regression, Arabic-text no-op.

## v2.5.1 — 2026-08-03

### Fixed — PI-ANSI-INJECT was blind to carriage returns through the CLI

Python's universal-newline file reading translates `\r` to `\n` before
`scan()` ever sees the text, so v2.5.0 flagged stray-CR overwrites when the
scanner was used as a library but silently missed them through the actual
command line — the primary usage. `pi_scan` and `pi_shield` now read files
with `newline=""` and reconfigure stdin the same way. Guarded by a CLI-level
regression test that writes a real `\r` file and drives the real entry point
via subprocess (115 tests). Found while preparing the feature's demo —
exactly the kind of gap a demo run exists to catch.

## v2.5.0 — 2026-08-03

New rule **PI-ANSI-INJECT** (17 rule IDs) plus a matching `pi_shield`
sanitization layer — the scanner's first rule that detects a live attack
*artifact* rather than a missing control. ANSI escape sequences render one
view to a human reviewer and another to the terminal/model pipeline, which
makes them a prompt-injection carrier of their own: the conceal attribute
hides instructions from reviewers while the model still reads the raw bytes,
carriage returns overwrite displayed lines, OSC 52 writes to the user's
clipboard (supported by Windows Terminal), and REP sequences hang the
terminal. Demonstrated in the wild through MCP tool descriptions (Trail of
Bits, 2025) and long-standing terminal CVEs (WinRAR CVE-2024-33899, Git
CVE-2024-52005, kubectl CVE-2021-25743).

### Added — PI-ANSI-INJECT (tiered)

- **High** — raw ESC byte (0x1B) or C1 control (U+0080–U+009F, accepted as
  CSI/OSC/DCS by VTE-based terminals, kitty, WezTerm), or a stray carriage
  return (line-overwrite). Known dangerous sequences are named in the
  finding: OSC 52 clipboard write, OSC 8 disguised hyperlink, conceal
  attribute, REP repeat-bomb, device control strings.
- **Medium** — escape sequences written out as text (`\x1b[`, `\033[`,
  `ESC[`), which is how an article *about* the attack looks; documentation
  must not be punished like a live payload.
- CRLF files stay clean by construction: line splitting for this rule keeps
  `\r` visible and forgives exactly one trailing CR per line.

### Added — pi_shield terminal-control neutralization (Layer 1)

`normalize()` now replaces ESC with a visible placeholder, drops C1 and
remaining C0/DEL controls, normalizes CRLF, and turns stray carriage returns
visible — only tab and newline survive, matching terminal-security guidance
and Trail of Bits' PrintGuard approach (keep the artifact visible, never
silent-strip it).

### Tests

16 new tests in `tests/test_ansi_injection.py` (114 total): raw ESC/C1/CR
payloads fire High, each named sequence is recognized, textual documentation
stays Medium, CRLF files are not flagged, and the shield leaves no ESC/C1
byte in sanitized output.

### Corpus census (same 2,491-file study corpus)

Zero files contain raw ESC bytes, C1 controls, or stray carriage returns —
the new rule fires on nothing in the corpus (no false positives, no score
movement). That fits the threat model: ANSI injection arrives through
*fetched* content (articles, tool output, MCP descriptions), which is the
surface `pi_shield` sanitizes, not through stored system prompts.

## v2.4.0 — 2026-08-03

First release after the published pre-registered study (`RESULTS.md`). The
study froze v2.3.2 and documented two recognition gaps as limitations; this
release closes them. The study's numbers remain pinned to v2.3.2 — nothing
here retroactively changes `RESULTS.md`.

### Improved — PI-NO-OUTPUTLIM (structural mandates)

v2.3.2 recognized only topic-scope limits ("only answer about X") and missed
a whole category: constraints on **form**. Added recognition for:

- mandatory structure/format/template ("You MUST produce … following this
  exact structure", "Output format:", "Reply Template …")
- format mandates with a preposition ("respond in JSON", "write … in
  well-formatted Markdown") — tool/URL contexts like `output=json` and
  "write a JSON file" are deliberately excluded
- length budgets ("Word Budget", "under 2 pages", "max 3 paragraphs")
- Arabic counterparts for all of the above

### Improved — PI-NO-ROLEGUARD (scope-binding)

v2.3.2 recognized only authority-spoof guards ("claiming to be the developer
grants no privileges") and missed **scope-binding** role boundaries. Added:

- "Only answer questions related to …" / "only respond to …"
- refusing/avoiding responses outside the scope ("avoids all responses
  outside the scope of …")
- out-of-scope questions are declined/refused
- staying within the role's boundaries; "your role is limited to …"
- Arabic counterparts for all of the above

### Corpus delta (same 2,491-file study corpus, v2.3.2 → v2.4.0)

- OUTPUTLIM recognized as declared: 9.6% → 21.1% (−287 absence findings)
- ROLEGUARD recognized as declared: 0.8% → 2.1% (−32 absence findings)
- mean declared controls of 6: 0.41 → 0.54
- zero-declared files: 66.7% → 59.3%

The remaining distance to the study's involved-rater estimate (RESULTS.md §7)
is the documented residual: weak, subtle, or non-English declarations (e.g.,
Chinese-language prompts remain unsupported).

### Tests

98 tests (was 91): new English and Arabic regression cases derived from the
study's labeled evidence, including the `template <URL>` false-recognition
guard. `check_rule_docs.py` passes; all 16 rule IDs unchanged.

### Performance

New patterns are single-bounded-span by construction (a multi-span candidate
set caused catastrophic backtracking on an 85 KB reference file during
development — caught, rewritten, and verified: 85 KB file scans in < 0.5 s).
