Release gate for prompt-injection-auditor

This file defines what "ready to publish" means. Nothing is tagged until every step below passes. The same list applies to a patch release and to a major one; the only difference is how many rows change in the CHANGELOG.


The additive rule

Existing behavior is never removed or renamed. Concretely:

A rule ID, once released, is permanent. To retire a rule, mark it deprecated in references/rule-inventory.md and keep the ID reserved; the scanner may stop emitting it, the ID never gets reused.

Existing tests are never deleted. They may be extended or joined by new ones.

Scores of files already in the benchmark corpus do not change between releases unless the CHANGELOG names the rule that moved them and why.

Default behavior and existing CLI flags stay as they are. New behavior lives behind new flags, new rule IDs, new files, or new sections.

Every document that exists in English keeps existing. Arabic is added as a twin file (references/<name>.ar.md) or as an Arabic entry next to the English one, never as a replacement.


The gate

Step 1. Continuous integration is green on the full matrix (Linux and Windows, Python 3.8 to 3.12) as defined in .github/workflows/tests.yml. Local runs do not count.

Step 2. tests/test_docs_sync.py passes: rule-inventory.md lists exactly the rule IDs the scanner emits, every Arabic twin covers the same rule IDs as its English base, and SKILL.md names only files that exist.

Step 3. The precision benchmark documented in VALIDATION.md is re-run. Zero false positives on the hardened corpus, and a hardened-versus-vulnerable separation not lower than the previous release. Both numbers go into the CHANGELOG entry.

Step 4. External recall is re-run and recorded: garak payloads for pi_shield and mcp_guard; snyk-labs/toxicskills-goof for the skill linter once it exists. A recall number lower than the previous release blocks the tag unless the CHANGELOG explains the trade-off.

Step 5. Every new rule ships complete: an entry in rule-inventory.md with an English and an Arabic description; Arabic detection patterns in language_rules.py; at least one positive test (the rule fires) and one negative test (a benign look-alike does not); a row in taxonomy-mapping.md (CrowdStrike IM/PT plus OWASP LLM, ASI, AST or MCP identifiers where they apply); a matching item in defense-checklist.md; and an anchor (CVE, advisory, paper, or incident report) whose link resolves today.

Step 6. Documentation moves with the code: CHANGELOG.md entry dated with the tag date; the README "New in" section describes the new version; the SKILL.md resources list names the files that exist now with their current locations; the version string appears in exactly one place in the code.

Step 7. Release notes quote the rule count and the test count from the actual test run output, not from memory.

Step 8. CVE anchors are checked one by one. Each links to an advisory. When two identifiers exist for one issue, both are listed with a note.

Step 9. Tag. If anything is found after tagging, bump the patch version and go back to Step 1; tags are never moved or deleted.


بوابة الإصدار لمشروع prompt-injection-auditor

يحدد هذا الملف معنى "جاهز للنشر". لا يُوضع وسم إصدار قبل اجتياز كل خطوة أدناه. القائمة نفسها تنطبق على إصدار ترقيعي وعلى إصدار رئيسي؛ الفرق الوحيد هو عدد السطور التي تتغير في CHANGELOG.


قاعدة الإضافة فقط

لا يُحذف سلوك قائم ولا يُعاد تسميته. وبشكل ملموس:

معرّف القاعدة، بمجرد إصداره، دائم. لسحب قاعدة من الخدمة تُعلَّم على أنها مهجورة في references/rule-inventory.md ويبقى المعرّف محجوزاً؛ يجوز أن يتوقف الفاحص عن إصدارها، ولا يُعاد استخدام المعرّف أبداً.

الاختبارات القائمة لا تُحذف. يجوز توسيعها أو إضافة اختبارات جديدة إلى جانبها.

درجات الملفات الموجودة أصلاً في مجموعة القياس لا تتغير بين إصدارين إلا إذا سمّى CHANGELOG القاعدة التي حركتها والسبب.

السلوك الافتراضي وخيارات سطر الأوامر القائمة تبقى كما هي. السلوك الجديد يوضع خلف خيارات جديدة أو معرّفات قواعد جديدة أو ملفات جديدة أو أقسام جديدة.

كل وثيقة موجودة بالإنجليزية تبقى موجودة. تُضاف العربية كملف توأم (references/<name>.ar.md) أو كمدخل عربي بجانب المدخل الإنجليزي، ولا تحل محله أبداً.


البوابة

الخطوة 1. التكامل المستمر أخضر على المصفوفة الكاملة (لينكس وويندوز، بايثون 3.8 إلى 3.12) كما هي معرّفة في .github/workflows/tests.yml. التشغيل المحلي لا يُحتسب.

الخطوة 2. اجتياز tests/test_docs_sync.py: يذكر rule-inventory.md بالضبط معرّفات القواعد التي يصدرها الفاحص، وكل توأم عربي يغطي نفس معرّفات القواعد التي يغطيها أصله الإنجليزي، ولا يذكر SKILL.md إلا ملفات موجودة.

الخطوة 3. إعادة تشغيل قياس الدقة الموثق في VALIDATION.md. صفر إيجابيات كاذبة على مجموعة الأوامر المحصّنة، وفصل بين المحصّن والمعرّض لا يقل عن الإصدار السابق. الرقمان يُسجلان في مدخل CHANGELOG.

الخطوة 4. إعادة تشغيل قياس الاستدعاء الخارجي وتسجيله: حمولات garak لكل من pi_shield و mcp_guard؛ وعينات snyk-labs/toxicskills-goof لفاحص المهارات عند وجوده. رقم استدعاء أقل من الإصدار السابق يمنع الوسم ما لم يشرح CHANGELOG المقايضة.

الخطوة 5. كل قاعدة جديدة تُشحن مكتملة: مدخل في rule-inventory.md بوصف إنجليزي وآخر عربي؛ أنماط كشف عربية في language_rules.py؛ اختبار إيجابي واحد على الأقل (القاعدة تُطلق) واختبار سلبي واحد (شبيه حميد لا يُطلقها)؛ سطر في taxonomy-mapping.md (تصنيف CrowdStrike IM/PT مع معرّفات OWASP من LLM و ASI و AST و MCP حيث تنطبق)؛ بند مقابل في defense-checklist.md؛ ومرسى (CVE أو تنبيه أمني أو ورقة أو تقرير حادثة) يعمل رابطه اليوم.

الخطوة 6. التوثيق يتحرك مع الكود: مدخل CHANGELOG.md مؤرخ بتاريخ الوسم؛ قسم "New in" في README يصف الإصدار الجديد؛ قائمة الموارد في SKILL.md تسمّي الملفات الموجودة الآن بمواقعها الحالية؛ سلسلة رقم الإصدار تظهر في موضع واحد فقط في الكود.

الخطوة 7. ملاحظات الإصدار تقتبس عدد القواعد وعدد الاختبارات من مخرجات التشغيل الفعلي، لا من الذاكرة.

الخطوة 8. مراسي CVE تُفحص واحداً واحداً. كل منها يرتبط بتنبيه أمني. وعند وجود معرّفين لمشكلة واحدة يُذكر الاثنان مع ملاحظة.

الخطوة 9. الوسم. إذا ظهر أي شيء بعد الوسم، يُرفع رقم الإصدار الترقيعي ويُعاد من الخطوة 1؛ الوسوم لا تُنقل ولا تُحذف أبداً.
