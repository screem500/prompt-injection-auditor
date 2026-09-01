"""Documentation drift guard.

Three checks, all text-based so they do not depend on how rules are
implemented inside the scanner:

1. Every PI-* rule ID mentioned in the scanner sources appears in
   references/rule-inventory.md, and every ID in the inventory appears in
   the sources. A new rule cannot ship undocumented; a removed rule cannot
   linger in the docs.

2. Every Arabic twin document (references/<name>.ar.md) has an English base
   (references/<name>.md) and both mention the same set of rule IDs. That is
   the bilingual standard: twins may differ in wording, never in coverage.

3. Every .py or .md file that SKILL.md names in backticks exists somewhere in
   the repository. SKILL.md is what the agent reads; a stale file name there
   is a broken instruction.

4. The CHANGELOG's newest stated test count equals the number of test
   methods actually collected from tests/. Release notes quote the count
   from the run output, never from memory (RELEASING.md step 7).

If a check fails, the message lists the exact IDs or files, so the fix is
either a doc edit or an addition to ALLOWLIST below (for tokens that look
like rule IDs but are not, e.g. an example in a comment).

حارس انجراف التوثيق.

ثلاثة فحوصات نصية لا تعتمد على طريقة تنفيذ القواعد داخل الفاحص:

1. كل معرّف قاعدة PI-* مذكور في مصادر الفاحص يظهر في references/rule-inventory.md،
   وكل معرّف في الجرد يظهر في المصادر. لا تُنشر قاعدة بلا توثيق، ولا تبقى قاعدة
   محذوفة في التوثيق.

2. كل ملف عربي توأم (references/<name>.ar.md) له أصل إنجليزي (references/<name>.md)
   ويذكر الاثنان نفس مجموعة معرّفات القواعد. هذا هو معيار ثنائية اللغة: يجوز أن
   يختلف التوأمان في الصياغة، لا في التغطية.

3. كل ملف .py أو .md يذكره SKILL.md بين علامتي backtick موجود فعلاً في المستودع.
   SKILL.md هو ما يقرؤه الوكيل، واسم ملف قديم فيه يعني تعليمة مكسورة.

4. أحدث عدد اختبارات مذكور في CHANGELOG.md يساوي عدد دوال الاختبار المجمّعة
   فعلياً من tests/. ملاحظات الإصدار تقتبس العدد من مخرجات التشغيل، لا من
   الذاكرة (RELEASING.md الخطوة 7).

عند فشل فحص تُدرج الرسالة المعرّفات أو الملفات بالضبط، فيكون الإصلاح إما تعديل
توثيق أو إضافة إلى ALLOWLIST أدناه (لرموز تشبه معرّفات القواعد وليست كذلك).
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
REFERENCES = os.path.join(ROOT, "references")
INVENTORY = os.path.join(REFERENCES, "rule-inventory.md")
SKILL = os.path.join(ROOT, "SKILL.md")

# Files whose PI-* tokens define or emit rules. Add to this tuple when a new
# module starts emitting findings.
RULE_SOURCES = ("pi_scan.py", "language_rules.py")

# A rule ID: PI- followed by upper-case words joined by hyphens.
RULE_ID = re.compile(r"\bPI-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\b")

# Tokens that match RULE_ID but are not rules (examples, placeholders).
ALLOWLIST = set()


def _read(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()


def _ids_in(text):
    return set(RULE_ID.findall(text)) - ALLOWLIST


def _walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "__pycache__"]
        for name in filenames:
            yield os.path.join(dirpath, name)


class TestRuleInventorySync(unittest.TestCase):
    """Check 1: delegate to the repository's own checker, check_rule_docs.py.

    That script already verifies code <-> rule-inventory parity, checklist
    references, and stated rule counts. Wiring it in here puts it on the CI
    path instead of duplicating its logic.
    """

    def test_check_rule_docs_passes(self):
        import subprocess
        import sys
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "check_rule_docs.py")],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            "check_rule_docs.py failed:\n" + proc.stdout + proc.stderr,
        )


class TestBilingualTwins(unittest.TestCase):
    """Check 2: every <name>.ar.md has a <name>.md base with the same rule IDs."""

    def _twins(self):
        if not os.path.isdir(REFERENCES):
            return []
        return sorted(f for f in os.listdir(REFERENCES) if f.endswith(".ar.md"))

    def test_every_arabic_twin_has_an_english_base(self):
        orphans = []
        for twin in self._twins():
            base = twin[: -len(".ar.md")] + ".md"
            if not os.path.exists(os.path.join(REFERENCES, base)):
                orphans.append(twin)
        self.assertFalse(orphans, "Arabic twins without an English base: %s" % orphans)

    def test_twins_cover_the_same_rule_ids(self):
        drift = []
        for twin in self._twins():
            base = twin[: -len(".ar.md")] + ".md"
            base_path = os.path.join(REFERENCES, base)
            if not os.path.exists(base_path):
                continue  # reported by the previous test
            base_ids = _ids_in(_read(base_path))
            twin_ids = _ids_in(_read(os.path.join(REFERENCES, twin)))
            if base_ids != twin_ids:
                drift.append(
                    "%s: only in English %s, only in Arabic %s"
                    % (base, sorted(base_ids - twin_ids), sorted(twin_ids - base_ids))
                )
        self.assertFalse(drift, "bilingual twins disagree on rule coverage:\n" + "\n".join(drift))


class TestChangelogTestCount(unittest.TestCase):
    """Check 4: the CHANGELOG's newest stated test count is the real one.

    Release notes quote the test count "from the actual test run output, not
    from memory" (RELEASING.md step 7). This enforces it: the first
    "N -> M tests" (or bare "M tests") claim in CHANGELOG.md — the newest
    entry, since the file prepends — must equal the number of test methods
    actually collected from tests/test_*.py. A stale number fails the suite.
    """

    ARROW_CLAIM = re.compile(r"(\d+)\s*(?:→|->)\s*(\d+)\s+tests\b")
    BARE_CLAIM = re.compile(r"\b(\d+)\s+tests\b")
    TEST_METHOD = re.compile(r"^\s+def\s+(test_\w+)", re.M)

    def _actual_count(self):
        tests_dir = os.path.join(ROOT, "tests")
        total = 0
        for name in sorted(os.listdir(tests_dir)):
            if name.startswith("test_") and name.endswith(".py"):
                total += len(self.TEST_METHOD.findall(
                    _read(os.path.join(tests_dir, name))))
        return total

    def test_changelog_test_count_is_current(self):
        changelog = _read(os.path.join(ROOT, "CHANGELOG.md"))
        arrow = self.ARROW_CLAIM.search(changelog)
        claimed = int(arrow.group(2)) if arrow else None
        if claimed is None:
            bare = self.BARE_CLAIM.search(changelog)
            claimed = int(bare.group(1)) if bare else None
        self.assertIsNotNone(
            claimed, "CHANGELOG.md states no test count; RELEASING.md step 7 requires one")
        actual = self._actual_count()
        self.assertEqual(
            claimed, actual,
            "CHANGELOG.md claims %s tests but tests/ collects %s — "
            "update the newest entry from the actual run output" % (claimed, actual))


class TestSkillFileReferences(unittest.TestCase):
    """Check 3: files named in SKILL.md exist somewhere in the repository."""

    NAME_IN_BACKTICKS = re.compile(r"`([A-Za-z0-9_./\-]+\.(?:py|md))`")

    # File names SKILL.md mentions as audit *targets* the user brings, not as
    # files of this repository. Extend when the skill text adds new examples.
    EXAMPLE_TARGETS = {"AGENTS.md", "CLAUDE.md", "MEMORY.md", "SOUL.md"}

    def test_referenced_files_exist(self):
        self.assertTrue(os.path.exists(SKILL), "SKILL.md is missing")
        names = set(self.NAME_IN_BACKTICKS.findall(_read(SKILL))) - self.EXAMPLE_TARGETS
        present = set()
        for path in _walk_files(ROOT):
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            present.add(rel)
            present.add(os.path.basename(rel))
        missing = sorted(n for n in names if n not in present)
        self.assertFalse(missing, "SKILL.md names files that do not exist: %s" % missing)


if __name__ == "__main__":
    unittest.main()
