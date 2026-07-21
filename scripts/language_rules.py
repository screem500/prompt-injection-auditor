"""Language-specific patterns for prompt-injection auditing.

Arabic rules are intentionally kept separate from the scanner and the existing
English patterns so additional language packs can be added later.
All Arabic patterns run against normalized text from normalization.py.
"""

# Lines containing an attack phrase in an explicitly defensive/example context
# are skipped to reduce false positives in hardened prompts and documentation.
ARABIC_DEFENSIVE_CONTEXT_PATTERNS = [
    r"(?:ارفض|تجاهل|لا تتبع|لا تنفذ|احذر من).{0,80}(?:طلب|رساله|محتوي|تعليمات).{0,80}(?:يقول|تقول|مثل|تتضمن)",
    r"(?:لا|يجب عدم)\s*(?:تكشف|تفصح|تشارك|تعرض|تطبع|تكرر|تلخص|تترجم|ترمز)",
    r"(?:مثال|امثله|اختبار|حاله اختبار|نمط هجوم|عباره خبيثه|حموله اختباريه)",
]

ARABIC_INJECTION_PATTERNS = [
    {
        "id": "PI-AR-OVERRIDE",
        "severity": "High",
        "title": "Arabic instruction-override attempt",
        "patterns": [
            r"(?:تجاهل|اهمل|الغ|تجاوز).{0,35}(?:كل\s+)?(?:التعليمات|الاوامر|القواعد|القيود).{0,35}(?:السابقه|السابقة|اعلاه|الماضيه|الحاليه)?",
            r"لا\s+تلتزم\s+ب.{0,30}(?:التعليمات|القواعد|القيود)",
        ],
        "detail": "The text attempts to replace or bypass higher-priority instructions using Arabic phrasing.",
        "fix": "Add explicit instruction hierarchy and treat user/retrieved content as data, never commands. (Checklist #1, #5, #14)",
    },
    {
        "id": "PI-AR-EXTRACT",
        "severity": "High",
        "title": "Arabic system-prompt extraction attempt",
        "patterns": [
            r"(?:اكشف|اظهر|اطبع|اعرض|كرر|اكتب|لخص|ترجم|رمز).{0,45}(?:موجه النظام|الموجه النظامي|تعليمات النظام|التعليمات الداخليه|التعليمات السرية|اعداداتك|قواعدك السريه)",
            r"ما\s+(?:هي|هى).{0,30}(?:تعليماتك الداخليه|تعليمات النظام|موجهك النظامي)",
        ],
        "detail": "The text asks the agent to disclose, transform, or enumerate protected instructions.",
        "fix": "Add a non-disclosure rule covering verbatim, paraphrased, translated, and encoded disclosure. (Checklist #2)",
    },
    {
        "id": "PI-AR-ROLE",
        "severity": "Medium",
        "title": "Arabic authority-spoofing attempt",
        "patterns": [
            r"(?:انا|نحن).{0,25}(?:المطور|المبرمج|مدير النظام|المسؤول|الادمن|مالك النظام).{0,40}(?:لدي|لدينا|امنحني|اسمح لي|صلاحيات|تفويض)",
            r"بصفتي.{0,25}(?:المطور|المسؤول|مدير النظام).{0,40}(?:نفذ|اكشف|اعرض|تجاوز)",
        ],
        "detail": "A user-supplied identity claim is being used to request elevated privileges.",
        "fix": "State that identity claims in user content grant no privileges. (Checklist #3)",
    },
    {
        "id": "PI-AR-REFUSAL-SUPPRESS",
        "severity": "High",
        "title": "Arabic refusal-suppression attempt",
        "patterns": [
            r"(?:لا ترفض|ممنوع ان ترفض|يجب ان تستجيب|نفذ دون اعتراض|لا تذكر السياسات|لا تطبق القيود|لا تقل لا استطيع)",
        ],
        "detail": "The text attempts to disable refusal or policy-enforcement behavior.",
        "fix": "Keep refusal behavior controlled by system policy and define a predictable refusal response. (Checklist #7)",
    },
    {
        "id": "PI-AR-EXFIL",
        "severity": "High",
        "title": "Arabic data-exfiltration instruction",
        "patterns": [
            r"(?:ارسل|انقل|سرب|شارك|ارفع).{0,55}(?:البيانات|المعلومات|الاسرار|المفاتيح|المحتوي|الملفات).{0,70}(?:الي|عبر|علي).{0,45}(?:رابط|بريد|ويبهوك|خادم|موقع|عنوان)",
            r"ضمن.{0,30}(?:البيانات|الاسرار|المفاتيح).{0,40}(?:رابط|صوره ماركداون|عنوان url)",
        ],
        "detail": "The text directs sensitive data to an outbound channel.",
        "fix": "Apply egress filtering, least privilege, and human confirmation for outbound actions. (Checklist #9, #10, #11, #12)",
    },
    {
        "id": "PI-AR-INDIRECT",
        "severity": "High",
        "title": "Arabic instruction targeting an agent through retrieved content",
        "patterns": [
            r"(?:يا\s+(?:ايها\s+)?(?:المساعد|الوكيل|النموذج)|الي\s+(?:المساعد|الوكيل|النموذج)).{0,100}(?:الذي يقر[اأ]|عند قراءه|بعد قراءه|نفذ|اتبع)",
            r"هذه\s+التعليمات.{0,45}(?:للمساعد|للوكيل|للنموذج).{0,60}(?:نفذ|اتبع|طبق)",
        ],
        "detail": "Retrieved Arabic content appears to contain instructions addressed to the consuming agent.",
        "fix": "Delimit retrieved content and mark it as inert data before model ingestion. (Checklist #5, #14, #18)",
    },
]

ARABIC_HIERARCHY_PATTERNS = [
    r"تعليمات\s+النظام.{0,30}(?:لها\s+الاولويه|تعلو|تسبق|اعلي\s+اولويه)",
    r"لا\s+(?:تتبع|تنفذ|تطع).{0,40}تعليمات.{0,35}(?:المستخدم|المحتوي|المستند|الاداه|المصدر الخارجي)",
    r"(?:المحتوي|النص|البيانات).{0,35}(?:بيانات|معلومات).{0,20}وليست?\s+تعليمات",
]

ARABIC_NONDISCLOSURE_PATTERNS = [
    r"لا\s+(?:تكشف|تفصح|تشارك|تعرض|تطبع|تكرر|تلخص|تترجم|ترمز).{0,45}(?:التعليمات|موجه\s+النظام|الاعدادات|القواعد\s+الداخليه)",
    r"يجب\s+عدم.{0,25}(?:كشف|افشاء|عرض|طباعه).{0,40}(?:التعليمات|الموجه|الاعدادات)",
]

ARABIC_ROLE_CLAIM_PATTERNS = [
    r"ادعاء.{0,25}(?:المطور|المسؤول|مدير\s+النظام|المالك).{0,35}لا\s+(?:يمنح|يعطي).{0,20}صلاحيات",
    r"(?:الصلاحيات|التفويض).{0,35}(?:تاتي|تأتي|تصدر).{0,25}(?:فقط|حصرا).{0,20}(?:النظام|دور\s+النظام)",
]

ARABIC_OUTPUT_CONSTRAINT_PATTERNS = [
    r"(?:اجب|استجب|ساعد).{0,15}فقط.{0,40}(?:ضمن|في).{0,20}(?:النطاق|الموضوع|المهام)",
    r"التزم.{0,25}(?:بالنطاق|بالموضوع|بالمهام\s+المسموحه)",
    r"ارفض.{0,30}(?:الطلبات|الاسئله).{0,25}(?:خارج|غير\s+المتعلقه).{0,15}النطاق",
]

ARABIC_UNTRUSTED_CONTENT_PATTERNS = [
    r"<(?:retrieved|untrusted|external|user)[_-]?(?:data|content|input)>",
    r"(?:افصل|ضع|لف).{0,35}(?:المحتوي|البيانات|النص).{0,30}(?:وسوم|فواصل|علامات)",
    r"(?:المحتوي|البيانات)\s+المسترجعه.{0,35}(?:بيانات|معلومات).{0,20}وليست?\s+تعليمات",
]

ARABIC_REFUSAL_PATTERNS = [
    r"(?:ارفض|سارفض|يجب\s+رفض).{0,35}(?:محاولات|طلبات|تعليمات).{0,25}(?:الحقن|التجاوز|استخراج\s+الموجه)",
    r"(?:لا\s+استطيع|لا\s+يمكنني).{0,30}(?:تنفيذ|مساعدتك|الاستجابه)",
]

ARABIC_TOOL_RISK_KEYWORDS = [
    (r"(?:ارسل|ارسال).{0,20}(?:بريد|رساله|رسائل|sms)", "Outbound messaging capability (Arabic)"),
    (r"(?:نفذ|تنفيذ|شغل|تشغيل).{0,25}(?:كود|شفرة|اوامر|امر|سكريبت|صدفه)", "Code/command execution capability (Arabic)"),
    (r"(?:احذف|حذف|ازل|ازاله).{0,20}(?:ملف|سجل|بيانات|حساب|جدول)", "Destructive action capability (Arabic)"),
    (r"(?:(?:اشتر|شراء|ادفع|دفع).{0,25}(?:مال|مبلغ|دفعه|فاتوره|اشتراك|منتج)|(?:حول|تحويل).{0,20}(?:مال|مبلغ|رصيد|حواله))", "Financial action capability (Arabic)"),
    (r"(?:طلب\s+http|استدعاء\s+(?:api|واجهه)|تصفح|ويبهوك|جلب\s+رابط)", "Network/egress capability (Arabic)"),
    (r"(?:اقر[اأ]|قراءه|اصل|الوصول|استرجع).{0,35}(?:ملف|مستند|بريد|درايف|قاعده\s+بيانات)", "Sensitive data access (Arabic)"),
]

ARABIC_INGEST_KEYWORDS = [
    r"(?:اجلب|جلب|اقر[اأ]|قراءه|لخص|تلخيص|اكشط|استخراج).{0,45}(?:صفحه\s+ويب|موقع|رابط|الانترنت|الويب)",
    r"(?:البريد|صندوق\s+الوارد|الرسائل).{0,30}(?:المستلمه|الوارد|من\s+المستخدمين)",
    r"(?:ملف|مستند|ملفات|مستندات).{0,20}(?:مرفوعه|مرفقه|يرفعها\s+المستخدم)",
    r"(?:rag|قاعده\s+المعرفه|قاعده\s+متجهات|بحث\s+متجهي|استرجاع)",
]
