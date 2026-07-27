"""English prompt-injection and runtime rule assets."""

SECRET_PATTERNS = [
    (r"sk-(proj-|svcacct-|admin-)?[a-zA-Z0-9_\-]{20,}", "OpenAI-style API key"),
    (r"sk-ant-[a-zA-Z0-9\-]{20,}", "Anthropic-style API key"),
    (r"ghp_[a-zA-Z0-9]{30,}", "GitHub personal access token"),
    (r"AIza[0-9A-Za-z\-_]{30,}", "Google API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key"),
    (r"(?i)(api[\s_-]?key|secret|token|password)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+.]{16,}", "Hardcoded credential-like value"),
]

HIERARCHY_PATTERNS = [
    r"system instructions? (outrank|override|take precedence|have priority)",
    r"never (follow|obey|execute) instructions? (from|in|within) (user|retrieved|external|tool)",
    r"(user|retrieved|external) content is data",
    r"treat .{0,40} as data[, ] not (as )?instructions?",
    r"highest priority",
]

NONDISCLOSURE_PATTERNS = [
    r"never (reveal|disclose|share|repeat|output|print|show|paraphrase|summarize|translate|encode)",
    r"do not (reveal|disclose|share|repeat|output|print)",
    r"must not (reveal|disclose|share|repeat|output|print)",
    r"keep .{0,30}(instructions?|prompt|configuration) .{0,20}(secret|confidential|private)",
]

ROLE_CLAIM_PATTERNS = [
    r"(claiming|claims?) to be (a |an |the )?(developer|admin|creator|owner)",
    r"no (extra |additional )?privileges",
    r"authorization comes only from",
    r"ignore (role|identity) claims?",
]

OUTPUT_CONSTRAINT_PATTERNS = [
    r"only (answer|respond|discuss|help with)",
    r"(refuse|decline) (to )?(discuss|answer|engage)",
    r"stay (on topic|within scope|focused)",
    r"if asked (about|to) .{0,40}(unrelated|outside|off[- ]topic)",
]

UNTRUSTED_CONTENT_PATTERNS = [
    r"<(retrieved|untrusted|external|user)[_-]?(data|content|input)>",
    r"delimit",
    r"wrapped in (xml |html )?tags",
    r"spotlighting",
    r"datamarking",
]

REFUSAL_PATTERNS = [
    r"(i'?m sorry|i cannot|i can'?t|i must decline|i'?m unable)",
    r"respond with .{0,30}(refus|declin)",
]

LEAK_PRONE_PATTERNS = [
    (r"(?i)when asked about your (instructions|prompt|rules).{0,60}(share|explain|describe|list)", "Meta-disclosure invitation"),
    (r"(?i)your (instructions|system prompt) (are|is)[:]", "Prompt self-reference that aids extraction"),
    (r"(?i)you (may|can) (share|reveal|disclose) your (instructions|prompt)", "Explicit permission to leak"),
    (r"(?i)(always|never refuse to) (comply|answer|obey)", "Unconditional compliance clause"),
    (r"(?i)you have (no|zero) (restrictions|limitations|guidelines)", "Unrestricted persona statement"),
]

TOOL_RISK_KEYWORDS = [
    (r"(?i)send (an? )?(email|message|sms)", "Outbound messaging capability"),
    (r"(?i)(execute|run) (code|commands?|scripts?|shell)", "Code/command execution capability"),
    (r"(?i)(delete|remove|drop|truncate) ", "Destructive action capability"),
    (r"(?i)(purchase|pay|transfer|wire|checkout)", "Financial action capability"),
    (r"(?i)(http[s]? request|api call|fetch|browse|webhook)", "Network/egress capability"),
    (r"(?i)(read|access|retrieve) .{0,30}(file|document|email|drive|database)", "Sensitive data access"),
]

INGEST_KEYWORDS = [
    r"(?i)(retrieve|fetch|read|summarize|ingest|scrape).{0,40}(web ?page|url|website|internet)",
    r"(?i)(email|inbox|message)s? (you receive|from users|retrieved)",
    r"(?i)uploaded (file|document)s?",
    r"(?i)(rag|knowledge base|vector (store|database)|retrieval)",
]

EXEC_TOOL_PATTERN = r"(?i)(\bbash\b|\bshell\b|\bterminal\b|subprocess|os\.system|code interpreter|python tool|powershell|command execution)"

MCP_PRESENT_PATTERN = r"(?i)(\bmcp\b|model context protocol|tool[- ]server)"

MCP_MUTABLE_PATTERN = r"(?i)(add|register|install|configure|connect|attach) .{0,20}(mcp|tool[- ]server|connector)"

MCP_UNSAFE_PATTERN = r"(?i)(stdio|serializ\w*|deserializ\w*|pickle|command string|spawn|child process)"

SANDBOX_GATE_PATTERN = r"(?i)(allow[- ]?list|whitelist|auto[- ]?approv\w*|pre[- ]?approved|safe commands?|trusted commands?|deny[- ]?list|blocklist|forbidden commands?|dangerous commands?)"

SANDBOX_BYPASS_AWARE_PATTERN = r"(?i)(obfuscat\w*|normali[sz]\w*|canonicali[sz]\w*|shell built[- ]?ins?|argument injection|quote stripping)"

SANDBOX_WORKDIR_PATTERN = r"(?i)(working directory|project root|environment variables?)"

MEMORY_PATTERN = r"(?i)(long[- ]?term memory|persistent memory|memory store|remembers? across sessions|saves? to memory|memory bank)"

MEMORY_GUARD_PATTERN = r"(?i)(memory integrity|signed memory|memory provenance|review\w*.{0,25}before.{0,25}(writing|storing).{0,20}memory|memory is data)"

SUPPLY_CHAIN_FETCH_PATTERN = r"(?i)(npm install|pip install|npx |yarn add|go get|cargo add|git clone|clone the repo|download the package|fetch the package|add (a |the )?dependency)"

SUPPLY_CHAIN_MODEL_NAMED_PATTERN = r"(?i)(the (real|official|correct) (package|library|repo|module)|whatever package (fits|is needed)|install the right (package|library)|packages? (you|the model|the agent) (think|believe|decide|deem)|any (package|library|dependency) (you |it )?(need|require)|(?:packages?|librar(?:y|ies)|dependenc(?:y|ies))[a-z ,]{0,20}(?:as|if) needed|determine which (package|library))"

SHIELD_PATTERN_TUPLES = [
    (r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\b", 60, "instruction override"),
    (r"\bdisregard\b|\boverride\b.{0,20}\b(instructions?|rules?|guidelines?)\b", 35, "instruction override"),
    (r"\byou are now\b|\bact as\b|\bpretend (to be|you are|you're)\b|\broleplay\b", 25, "persona hijack"),
    (r"\b(system|developer|admin)\s*(mode|message|update|override|directive)\b", 30, "fake system message"),
    (r"\b(repeat|print|reveal|show|output|display|leak)\b.{0,50}\b(system prompt|instructions?|config(uration)?)\b", 35, "prompt extraction"),
    (r"\bwhat were you told\b|\byour (initial |original )?(instructions|rules|prompt)\b", 20, "extraction probe"),
    (r"\b(translate|encode|base64|rot13|hex)\b.{0,40}\b(instructions?|prompt|rules)\b", 30, "output laundering"),
    (r"\bi am (the )?(developer|admin|creator|owner|an? openai)\b", 25, "authority spoofing"),
    (r"\bno (restrictions|guidelines|rules)\b|\bjailbreak\b|\bDAN\b", 35, "jailbreak attempt"),
    (r"\bnew (directive|instruction|rule)s?\s*[:=]", 25, "directive injection"),
]

MCP_PATTERN_TUPLES = [
    # Model special tokens — legitimate inside chat templates, NEVER inside
    # tool DATA. Any occurrence means someone is trying to forge the transcript.
    (r"<\|(?:im_start|im_end|endoftext|system|assistant|user)\|?>", 60, "model special-token injection"),
    (r"<<\s*/?\s*SYS\s*>>|\[\s*/?\s*INST\s*\]", 60, "model special-token injection"),
    (r"</?(?:system|assistant)\s*>", 60, "role-tag injection"),
    # <s>/</s> are real BOS/EOS tokens (Llama, Mistral). Kept at warn weight:
    # NLP corpus data can carry them legitimately, but inside tool data they
    # usually mean transcript forgery.
    (r"</?s>", 30, "BOS/EOS token smuggling"),
    (r"^\s*#{1,4}\s*(?:system|instructions?)\s*$", 30, "fake markdown system header"),

    # Fake consent — a tool result cannot know what the user approved. Injected
    # "yes, proceed" lines are the classic human-in-the-loop bypass.
    (r"\b(?:the\s+)?(?:user|human|operator)\s+(?:has\s+)?(?:approved|confirmed|consented|agreed|said\s+yes)\b", 50, "fake user consent"),
    (r"\b(?:approval|confirmation|consent)\s*[:=]\s*(?:yes|true|granted)\b", 50, "fake user consent"),
    (r"\byes\b[^\n]{0,20}\b(?:proceed|go\s+ahead|continue\s+with)\b", 25, "fake user consent"),

    # Pushing the agent toward a dangerous follow-up action.
    (r"\bproceed\b[^\n]{0,40}\b(?:delet|send|transfer|execut|run|drop|wipe|email|message|post|upload)", 25, "dangerous-action endorsement"),

    # Tool-call manipulation — steering the agent to invoke other tools.
    (r"\b(?:call|invoke|execute|use|run)\s+(?:the\s+)?[\w-]{0,30}\s*(?:tool|function)\b", 25, "tool-call manipulation"),
    (r"\b(?:tool_call|function_call)\b|\"name\"\s*:\s*\"(?:send_|delete_|transfer_|exec)", 30, "tool-call manipulation"),

    # Exfiltration channels — markdown images/links whose URL query string can
    # carry stolen data to an attacker host (the EchoLeak pattern).
    (r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?=&]", 60, "markdown exfiltration channel"),
    (r"https?://[^\s)\]]*(?:webhook\.site|requestbin|hookbin|ngrok|canarytokens|burpcollaborator|oastify|interact\.sh|pipedream)", 60, "known exfiltration endpoint"),

    # Hidden instruction channels.
    (r"<!--[^>]*(?:ignore|instruction|system|prompt|secret|password|token|previous)[^>]*-->", 35, "hidden instruction in HTML comment"),

    # Context poisoning — trying to persist attacker text into future turns.
    (r"\b(?:remember|store|save|add)\b[^\n]{0,40}\b(?:to\s+(?:your\s+)?(?:context|memory|system\s+prompt)|for\s+later)\b", 30, "context poisoning"),
]

LANGUAGE_SEVERITY_WEIGHT = {"Critical": 60, "High": 60, "Medium": 25, "Low": 10}

