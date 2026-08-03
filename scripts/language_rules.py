"""Language-specific patterns for prompt-injection auditing.

Arabic rules are intentionally kept separate from the scanner and the existing
English patterns so additional language packs can be added later. All Arabic
patterns run against normalized text from normalization.py.
"""

# Attack phrases in explicitly defensive, quoted, or documentation contexts are
# skipped to reduce false positives. The scanner applies these only to a local
# window around each candidate match, not blindly to the entire line.
ARABIC_DEFENSIVE_CONTEXT_PATTERNS = [
    r"(?:مثال|امثله|اختبار|حاله\s+اختبار|نمط\s+(?:ال)?هجوم|عباره\s+خبيثه|حموله\s+اختباريه|لاغراض\s+التوعيه)",
    r"(?:ارفض|تجاهل|لا\s+تتبع|لا\s+تنفذ|احذر\s+من|اكتشف|امنع).{0,80}(?:طلب|رساله|محتوي|تعليمات|عباره|نص).{0,80}(?:يقول|تقول|مثل|تتضمن|تحتوي)",
    r"(?:عباره|نص|جمله|طلب).{0,35}(?:تقول|يقول|التاليه|المسماه)",
    r"(?:يرفض|رفض|امنع|منع).{0,45}(?:عباره|نص|جمله|طلب)",
    r"(?:وثق|اشرح|حلل|ناقش).{0,55}(?:نمط|هجوم|عباره|حموله)",
    r"(?:ترجم|اشرح|عرف|ناقش).{0,25}(?:عباره|مصطلح|كلمه|مفهوم).{0,45}",
]

ARABIC_INJECTION_PATTERNS = [
    {
        "id": "PI-AR-OVERRIDE",
        "severity": "High",
        "title": "Arabic instruction-override attempt",
        "patterns": [
            r"(?:تجاهل|اهمل|الغ|تجاوز|انس|انسي).{0,35}(?:كل\s+)?(?:التعليمات|الاوامر|القواعد|القيود).{0,35}(?:السابقه|اعلاه|الماضيه|الحاليه)?",
            r"(?:تجاهل|اهمل|انس|انسي).{0,20}(?:كل\s+)?ما\s+سبق",
            r"لا\s+(?:تلتزم|تعمل|تتقيد).{0,12}ب.{0,30}(?:التعليمات|القواعد|القيود)",
            r"اعتبر.{0,25}(?:التعليمات|الاوامر|القواعد).{0,25}(?:ملغاه|باطله|غير\s+ساريه)",
            r"(?:الاولوية|الاولويه).{0,30}(?:لهذه\s+الرساله|لهذا\s+الطلب|لتعليماتي).{0,35}(?:وليس|بدلا\s+من).{0,25}(?:النظام|تعليمات\s+النظام)",
        ],
        "detail": "The text attempts to replace or bypass higher-priority instructions using Arabic phrasing.",
        "fix": "Add explicit instruction hierarchy and treat user/retrieved content as data, never commands. (Checklist #1, #5, #14)",
    },
    {
        "id": "PI-AR-EXTRACT",
        "severity": "High",
        "title": "Arabic system-prompt extraction attempt",
        "patterns": [
            r"(?<![\u0600-\u06FF])(?:[وف]\s*)?(?:اعطني|ارني|اكشف|اظهر|اطبع|اعرض|كرر|اكتب|لخص|ترجم|رمز|حول|شفر).{0,55}(?:موجه\s+النظام|الموجه\s+النظامي|تعليمات\s+النظام|التعليمات\s+الداخليه|التعليمات\s+السريه|تعليماتك\s+الاولي|اعداداتك|قواعدك\s+السريه|التعليمات\s+التي\s+سبقت|ما\s+قيل\s+لك\s+قبل)",
            r"ما\s+(?:هي|هو).{0,35}(?:تعليماتك\s+الداخليه|تعليمات\s+النظام|نص\s+موجه\s+النظام|موجهك\s+النظامي)",
            r"(?:اذكر|عدد).{0,30}(?:كل|جميع).{0,20}(?:القواعد|التعليمات).{0,30}(?:المخفيه|الداخليه|التي\s+تعمل\s+بها)",
        ],
        "detail": "The text asks the agent to disclose, transform, or enumerate protected instructions.",
        "fix": "Add a non-disclosure rule covering verbatim, paraphrased, translated, and encoded disclosure. (Checklist #2)",
    },
    {
        "id": "PI-AR-ROLE",
        "severity": "Medium",
        "title": "Arabic authority-spoofing attempt",
        "patterns": [
            r"(?:انا|نحن).{0,25}(?:المطور|المبرمج|مدير\s+النظام|المسؤول|الادمن|مالك\s+النظام).{0,45}(?:لدي|لدينا|امنحني|اسمح\s+لي|صلاحيات|تفويض|نفذ|اكشف|اعرض|تجاوز)",
            r"بصفتي.{0,25}(?:المطور|المسؤول|مدير\s+النظام).{0,45}(?:نفذ|اكشف|اعرض|تجاوز|امنحني)",
            r"(?:رساله|توجيه|امر).{0,20}من.{0,20}(?:المطور|المسؤول|مدير\s+النظام|الادمن).{0,45}(?:نفذ|اكشف|اعرض|تجاوز)",
        ],
        "detail": "A user-supplied identity claim is being used to request elevated privileges.",
        "fix": "State that identity claims in user content grant no privileges. (Checklist #3)",
    },
    {
        "id": "PI-AR-REFUSAL-SUPPRESS",
        "severity": "High",
        "title": "Arabic refusal-suppression attempt",
        "patterns": [
            r"(?:لا\s+ترفض|ممنوع\s+ان\s+ترفض|لا\s+يمكنك\s+الرفض|لا\s+يحق\s+لك\s+الرفض|يجب\s+ان\s+تستجيب|(?:اجب|استجب)\s+دون\s+رفض|نفذ\s+دون\s+اعتراض|لا\s+تعتذر|لا\s+تذكر\s+السياسات|لا\s+تطبق\s+القيود|لا\s+تقل\s+لا\s+(?:استطيع|يمكنني))",
        ],
        "detail": "The text attempts to disable refusal or policy-enforcement behavior.",
        "fix": "Keep refusal behavior controlled by system policy and define a predictable refusal response. (Checklist #7)",
    },
    {
        "id": "PI-AR-EXFIL",
        "severity": "High",
        "title": "Arabic data-exfiltration instruction",
        "patterns": [
            r"(?<![\u0600-\u06FF])(?:[وف]\s*)?(?:ارسل|انقل|سرب|شارك|ارفع).{0,55}(?:ال)?(?:بيانات|معلومات|اسرار|مفاتيح|محتوي|ملفات).{0,70}(?:الي|عبر|علي).{0,45}(?:رابط|بريد|ويبهوك|خادم|موقع|عنوان|https?://|[\w.+-]+@[\w.-]+\.[a-z]{2,})",
            r"ضمن.{0,30}(?:البيانات|الاسرار|المفاتيح).{0,40}(?:رابط|صوره\s+ماركداون|عنوان\s+url|https?://)",
        ],
        "detail": "The text directs sensitive data to an outbound channel.",
        "fix": "Apply egress filtering, least privilege, and human confirmation for outbound actions. (Checklist #9, #10, #11, #12)",
    },
    {
        "id": "PI-AR-INDIRECT",
        "severity": "High",
        "title": "Arabic instruction targeting an agent through retrieved content",
        "patterns": [
            r"(?:يا\s+(?:ايها\s+)?(?:المساعد|الوكيل|النموذج)|الي\s+(?:المساعد|الوكيل|النموذج)).{0,100}(?:الذي\s+يقرا|عند\s+قراءه|بعد\s+قراءه|نفذ|اتبع|طبق)",
            r"هذه\s+التعليمات.{0,45}(?:للمساعد|للوكيل|للنموذج).{0,60}(?:نفذ|اتبع|طبق)",
            r"(?:عند|بعد)\s+قراءه.{0,30}(?:الملف|المستند|النص|الصفحه|البريد|الرساله).{0,65}(?:نفذ|اتبع|طبق|ارسل|اكشف)",
            r"(?:تعليمات|رساله)\s+(?:الي|موجهه\s+الي).{0,20}(?:المساعد|الوكيل|النموذج).{0,60}(?:نفذ|اتبع|طبق|تجاهل)",
        ],
        "detail": "Retrieved Arabic content appears to contain instructions addressed to the consuming agent.",
        "fix": "Delimit retrieved content and mark it as inert data before model ingestion. (Checklist #5, #14, #18)",
    },
]

ARABIC_HIERARCHY_PATTERNS = [
    r"تعليمات\s+النظام.{0,35}(?:لها\s+الاولويه|تعلو|تسبق|اعلي\s+اولويه)",
    r"لا\s+(?:تتبع|تنفذ|تطع).{0,45}تعليمات.{0,35}(?:المستخدم|المحتوي|المستند|الاداه|المصدر\s+الخارجي)",
    r"(?:المحتوي|النص|البيانات).{0,35}(?:بيانات|معلومات).{0,20}وليست?\s+تعليمات",
    # any subject, not only "تعليمات النظام"
    r"(?:هذه\s+)?(?:التعليمات|القواعد|الاعدادات|التهيئه|السياسه).{0,30}(?:تعلو|تسبق|تتقدم|لها\s+الاولويه|اعلي\s+اولويه)",
    r"(?:ترتيب|تسلسل)\s+(?:الصلاحيات|الاولويات|القواعد)",
    r"تعلو\s+علي\s+(?:اي|كل|جميع)",
]

ARABIC_NONDISCLOSURE_PATTERNS = [
    r"لا\s+(?:تكشف|تفصح|تشارك|تعرض|تطبع|تكرر|تلخص|تترجم|ترمز).{0,50}(?:التعليمات|موجه\s+النظام|الاعدادات|القواعد\s+الداخليه)",
    r"يجب\s+عدم.{0,25}(?:كشف|افشاء|عرض|طباعه|ترجمه|ترميز).{0,45}(?:التعليمات|الموجه|الاعدادات)",
]

ARABIC_ROLE_CLAIM_PATTERNS = [
    r"ادعاء.{0,25}(?:المطور|المسؤول|مدير\s+النظام|المالك).{0,35}لا\s+(?:يمنح|يعطي).{0,20}صلاحيات",
    r"(?:الصلاحيات|التفويض).{0,35}(?:تاتي|تصدر).{0,25}(?:فقط|حصرا).{0,20}(?:النظام|دور\s+النظام)",
    # "claiming X does not grant anything", in any order
    r"ادعاء.{0,45}لا\s+(?:يمنح|يعطي|يمنحه|يعطيه|يكسبه)",
    r"لا\s+(?:يمنح|يعطي|يمنحه|يعطيه).{0,30}(?:اي\s+)?صلاحي",
    r"(?:ادعاء|زعم).{0,30}(?:الادوار|الدور|الهويه|الصفه)",
    r"(?:الادوار|الهويه|الصفه)\s+المدعاه",
    # v2.4.0: scope-binding (role boundary declarations), matching English set
    r"(?:[اأإ]جب|استجب|[اأإ]رد|ساعد)\s+فقط\s+(?:عن|علي|على|ضمن|في)",
    r"(?:ارفض|تجنب|امتنع).{0,30}(?:الطلبات|الاسئله|المواضيع|الردود)?.{0,25}(?:خارج|خارج\s+عن).{0,15}(?:النطاق|الدور|الموضوع|الصلاحيه)",
    r"(?:الزم|التزم|ابق|البقاء|اعمل).{0,20}(?:ضمن|داخل).{0,15}(?:نطاق|دور|حدود)",
    r"(?:الاسي.{0,2}ه|الطلبات|المواضيع).{0,20}خارج.{0,15}(?:النطاق|الدور).{0,25}(?:ترفض|يرفض|تتجاهل)",
]

ARABIC_OUTPUT_CONSTRAINT_PATTERNS = [
    r"(?:اجب|استجب|ساعد).{0,15}فقط.{0,40}(?:ضمن|في).{0,20}(?:النطاق|الموضوع|المهام)",
    r"التزم.{0,25}(?:بالنطاق|بالموضوع|بالمهام\s+المسموحه)",
    r"ارفض.{0,30}(?:الطلبات|الاسئله).{0,25}(?:خارج|غير\s+المتعلقه).{0,15}النطاق",
    # "answer only about X" with any object, and "nothing else"
    r"(?:[اأإ]جب|استجب|[اأإ]رد)\s+فقط",
    r"فقط\s+(?:عن|على|علي)\s+(?:[اأ]سئل[هة]|الاسئله|الأسئلة|طلبات)",
    r"(?:لا\s+شيء|لا\s+شي)\s+(?:غير\s+ذلك|اخر)",
    r"ما\s+عداها\s+(?:ارفض|يرفض)",
    # v2.4.0: structural mandates (form constraints), matching the English set
    r"(?:التنسيق|الصيغه|البنيه|القالب)\s+(?:الزامي|الزاميه|التالي|التاليه|المحدد|المحدده)",
    r"(?:التزم|الزام|يجب).{0,25}(?:بالقالب|بالبنيه|بالتنسيق|بصيغه)",
    r"(?:خرج|اخرج|اكتب|انتج|[اأ]رد|[اأ]جب).{0,30}(?:بصيغه|بتنسيق|بشكل)\s+(?:json|جدول|ماركداون|نصي|محدد)",
    r"(?:كلمه|كلمات|فقره|فقرات|سطر|اسطر|حرف|احرف).{0,20}(?:حد\s+اقصي|كحد\s+اقصي|فقط|بحد)",
]

ARABIC_UNTRUSTED_CONTENT_PATTERNS = [
    r"<(?:retrieved|untrusted|external|user|document|kb|data|context)[_-]?(?:data|content|input)?>",
    r"(?:افصل|ضع|لف).{0,35}(?:المحتوي|البيانات|النص).{0,30}(?:وسوم|فواصل|علامات)",
    r"(?:المحتوي|البيانات)\s+المسترجعه.{0,35}(?:بيانات|معلومات).{0,20}وليست?\s+تعليمات",
    # describing the boundary rather than naming a tag
    r"(?:داخل|بين|ضمن)\s+(?:الوسوم|الفواصل|العلامات|المحددات)",
    r"(?:نص|محتوي|بيانات)\s+خامل",
    r"يعامل\s+ك(?:نص|بيانات)\s+خامل",
]

ARABIC_REFUSAL_PATTERNS = [
    r"(?:ارفض|سارفض|يجب\s+رفض).{0,35}(?:محاولات|طلبات|تعليمات).{0,25}(?:الحقن|التجاوز|استخراج\s+الموجه)",
    r"(?:لا\s+استطيع|لا\s+يمكنني).{0,30}(?:تنفيذ|مساعدتك|الاستجابه)",
    # the prompt describing refusal behaviour
    r"ارفض.{0,40}(?:بعباره|بجمله|بصيغه)\s+(?:ثابته|محدده|موحده)",
    r"(?:عباره|جمله|صيغه)\s+رفض\s+(?:ثابته|محدده|موحده)",
    r"ارفض\s+ما\s+(?:عداها|عدا\s+ذلك)",
]

ARABIC_TOOL_RISK_KEYWORDS = [
    (r"(?:ارسل|ارسال).{0,20}(?:بريد|رساله|رسائل|sms)", "Outbound messaging capability (Arabic)"),
    (r"(?:نفذ|تنفيذ|شغل|تشغيل).{0,25}(?:كود|شفره|اوامر|امر|سكريبت|صدفه)", "Code/command execution capability (Arabic)"),
    (r"(?:احذف|حذف|ازل|ازاله).{0,20}(?:ملف|سجل|بيانات|حساب|جدول)", "Destructive action capability (Arabic)"),
    (r"(?:(?:اشتر|شراء|ادفع|دفع).{0,25}(?:مال|مبلغ|دفعه|فاتوره|اشتراك|منتج)|(?:حول|تحويل).{0,20}(?:مال|مبلغ|رصيد|حواله))", "Financial action capability (Arabic)"),
    (r"(?:طلب\s+http|استدعاء\s+(?:api|واجهه)|تصفح|ويبهوك|جلب\s+رابط)", "Network/egress capability (Arabic)"),
    (r"(?:اقرا|قراءه|اصل|الوصول|استرجع).{0,35}(?:ملف|مستند|بريد|درايف|قاعده\s+بيانات)", "Sensitive data access (Arabic)"),
]

ARABIC_INGEST_KEYWORDS = [
    r"(?:اجلب|جلب|اقرا|قراءه|لخص|تلخيص|اكشط|استخراج).{0,45}(?:صفحه\s+ويب|موقع|رابط|الانترنت|الويب)",
    r"(?:البريد|صندوق\s+الوارد|الرسائل).{0,30}(?:المستلمه|الوارد|من\s+المستخدمين)",
    r"(?:ملف|مستند|ملفات|مستندات).{0,20}(?:مرفوعه|مرفقه|يرفعها\s+المستخدم)",
    r"(?:rag|قاعده\s+المعرفه|قاعده\s+متجهات|بحث\s+متجهي|استرجاع)",
]

# --- 2026 agent-runtime families -------------------------------------------
# Arabic triggers for the MCP/sandbox/memory/supply-chain rules in pi_scan.
# Written for normalized Arabic text (diacritics/tatweel removed, ة -> ه,
# hamzated alef -> ا). Sandbox gate/workdir terms stay English-only in
# pi_scan: those phrases appear in English even inside Arabic prompts.

ARABIC_AUTOLOAD_PATTERNS = [
    r"(?:ملف|ملفات)\s*(?:الـ)?(?:إعداد|اعداد|تهيئه|تهيئة|تكوين)",
    r"(?:تحميل|قراءه|قراءة|تطبيق)\s*(?:تلقائي|تلقائيا|أوتوماتيكي)",
    r"(?:عند|لدى)\s*(?:فتح|تحميل|بدء)\s*(?:المستودع|المشروع|مساحه العمل|مساحة العمل)",
    r"(?:يقرأ|يقرا|تقرأ|تقرا|يحمل|تحمل)[^\n]{0,40}(?:جذر\s*)?(?:المستودع|المشروع|مساحه العمل|مساحة العمل)",
]

ARABIC_MCP_PRESENT_PATTERNS = [
    r"(?:\bmcp\b|بروتوكول\s+سياق\s+النموذج|خادم\s+(?:ال)?ادوات|خوادم\s+(?:ال)?ادوات)",
]

ARABIC_MCP_MUTABLE_PATTERNS = [
    r"(?:اضف|اضافه|اضافت|سجل|تسجيل|ثبت|تثبيت|اربط|ربط|اتصل|وصل).{0,25}(?:خادم|خوادم).{0,15}(?:ال)?(?:ادوات|mcp)",
]

ARABIC_MEMORY_PATTERNS = [
    r"(?:ذاكره\s+(?:دائمه|طويله(?:\s+الاجل|\s+المدي)?)|مخزن\s+(?:ال)?ذاكره|يتذكر\s+عبر\s+الجلسات|(?:يحفظ|حفظ)\s+.{0,15}في\s+(?:ال)?ذاكره)",
]

ARABIC_MEMORY_GUARD_PATTERNS = [
    r"(?:سلامه\s+(?:ال)?ذاكره|مصدر\s+(?:ال)?ذاكره|مراجعه\s+قبل\s+(?:ال)?(?:كتابه|تخزين).{0,15}ذاكره|(?:ال)?ذاكره\s+(?:بيانات|معلومات).{0,20}وليست?\s+تعليمات)",
]

ARABIC_SUPPLY_CHAIN_FETCH_PATTERNS = [
    r"(?:ثبت|تثبيت|نزل|تنزيل|اجلب|جلب|استنسخ).{0,25}(?:حزمه|الحزمه|مكتبه|المكتبه|مستودع|المستودع|تبعيه|تبعيات)",
]
