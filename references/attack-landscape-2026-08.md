Prompt Injection Auditor: 2026 threat and defense landscape (research note)

Compiled: 2026-08-26
Purpose: map what changed in 2026 against the current rule set (17 rule IDs as of v2.5.2) and turn it into a prioritized backlog. Every entry names its source. Primary sources are marked P, secondary reporting S. Numbers are as published by the cited source and were not independently reproduced. Verify each anchor before shipping a rule that depends on it.

Status of this note: research input, not a specification. Rule names below are proposals.


SECTION 1. FIVE SHIFTS THAT DEFINE 2026

Shift 1. Indirect prompt injection is operational, not academic.

Google reported that the share of crawled pages carrying malicious indirect injection grew about 32 percent in relative terms between November 2025 and February 2026, with static sites and blogs favored (S, via CSA research note, May 2026). Unit 42 mapped 22 payload-delivery techniques in active use; Forcepoint documented ten distinct payloads across separate domains (S, same note). GrafanaGhost (Noma Security, disclosed April 7, 2026) is the fully documented chain of the quarter: hidden instructions in an external resource made Grafana's AI companion render an external image whose URL carried enterprise data to the attacker (P, OWASP Q1 2026 Exploit Round-up). This is the EchoLeak class again, one year later, in a different product.

Consequence for this repo: the markdown-image and external-render exfiltration rules are the right bet. Keep them, and add the combination "renders external images or markdown while ingesting untrusted content" as an explicit finding even when no tool sends data out; the rendering path is the channel.

Shift 2. Agent skills became the supply chain.

Timeline (P, OWASP Agentic Skills Top 10 project page and its incident timeline through July 2026; S where noted): Anthropic's Agent Skills specification opened on December 18, 2025 (S). ClawHavoc ran January 27 to 29, 2026: 341 malicious skills on ClawHub in three days, 335 of them delivering the AMOS stealer from a single C2 address; the final tally reached 1,184 skills across 12 publisher accounts (Antiy CERT). The skills wrote instructions into MEMORY.md and SOUL.md for session-persistent backdooring. Snyk ToxicSkills (February 5, 2026) scanned 3,984 skills from ClawHub and skills.sh: 36.82 percent had at least one flaw, 13.4 percent a critical one, 76 confirmed malicious payloads. Snyk separately documented 280 plus skills leaking API keys and PII through over-permissioned manifests, and on February 11 argued that pattern-matching skill scanners miss most critical threats because those rely on natural-language instruction manipulation rather than code signatures. Trail of Bits (June 3, 2026) bypassed every public skill scanner it tested in under an hour, using payload padding that forces truncation, logic hidden in binary or archive formats, and prompt-injecting the scanner's own LLM judge. Air Security (June 22 to 24, 2026) shipped a researcher-built malicious skill to over 26,000 agents while every scanner cleared it, with the payload served from an attacker-controlled external documentation URL; a follow-up scan of 142,836 live skills found 17,822 (12.4 percent, 6.7 million installs) resting on at least one untrusted external instruction source. SkillJacking (July 2, 2026): 925 skills serving about 134,000 agents sit on instantly hijackable dependencies (deleted GitHub accounts, unregistered packages, expired domains, freed cloud-app slots); the researchers took over the most popular video-generation skill on skills.sh by re-registering its deleted owner account.

OWASP published the Agentic Skills Top 10 (AST10) v1 in 2026: AST01 Malicious Skills, AST02 Supply Chain Compromise, AST03 Over-Privileged Skills, AST04 Insecure Metadata, AST05 Untrusted External Instructions, AST06 Weak Isolation, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance, AST10 Cross-Platform Reuse. The same project proposes a Universal Skill Format whose defaults are worth copying as lint checks: deny_write on SOUL.md, MEMORY.md and AGENTS.md; network as a domain allowlist rather than a boolean; an explicit shell flag; a risk tier; a content hash and signature.

Consequence for this repo: the roadmap item "skill-file linter mode" is now the most timely feature in the project. It has a published taxonomy to map to (AST01 to AST10), a public malicious corpus to measure recall on (snyk-labs/toxicskills-goof), and a published list of evasions it must survive (Trail of Bits). It also has competitors: Cisco's skill-scanner, mcp-scan's --skills mode, ClawHub's VirusTotal plus LLM guard, and the academic SkillSieve (arXiv 2604.06550). None of them advertise Arabic coverage.

Shift 3. The MCP tool layer has its own OWASP list.

OWASP MCP Top 10 (beta; next release planned for October 2026) codifies MCP01:2025 Token Mismanagement and Secret Exposure and MCP03:2025 Tool Poisoning, the latter with three sub-techniques: rug pulls (a tool changes its description after approval), schema poisoning (instruction-bearing or misleading interface definitions), and tool shadowing (a fake or duplicate tool intercepts calls meant for a trusted one) (P, OWASP project page; S, Cycode and CSA summaries). Prevalence reported in 2026: roughly 5.5 percent of 1,899 public servers showed tool poisoning (Hasan et al., 2025, S); 36.7 percent of 7,000 plus servers were SSRF-vulnerable (BlueRock, 2026). mcp-scan by Invariant Labs is the de facto configuration scanner.

Consequence for this repo: mcp_guard already scans tool definitions and responses for injection; the missing dimension is time. A rug pull is invisible to a single scan. Description pinning (hash the tool definition at approval, alert on change) is a deterministic, zero-dependency feature that maps directly to MCP03 and is exactly the kind of out-of-band control Shift 5 favors.

Shift 4. Incidents are architectural, and mostly have no CVE.

OWASP's Q1 2026 Exploit Round-up (P, April 14, 2026) documents eight incidents from January 1 to April 11; exactly one carries a CVE (CVE-2025-59528, Flowise CustomMCP remote code execution, actively exploited from April 7 with 12,000 to 15,000 instances exposed). The rest are misconfiguration, excessive agency, supply chain, or prompt injection: an OpenClaw agent deleting an inbox and ignoring stop commands (February 23); a Meta internal agent's advice widening data access for two hours (March); Vertex AI "Double Agent" privilege inheritance through a managed service account (Unit 42, March 31); the Claude Code source-map leak that became a malware lure within hours (March 31 onward); the Mercor breach tied to malicious LiteLLM versions (March 31); GrafanaGhost (April 7). OWASP maps them to the Top 10 for Agentic Applications 2026: ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.

Consequence for this repo: CVE anchors are good but insufficient. Each rule should also carry an ASI, AST, or MCP identifier, because that is the vocabulary security teams now use to triage findings. taxonomy-mapping.md should gain these columns next to the CrowdStrike IM/PT mapping.

Shift 5. Defense research reached a verdict on in-band detection.

Nasr et al. (arXiv 2510.09023; authors from OpenAI, Anthropic and Google DeepMind) tested twelve published jailbreak and prompt-injection defenses under adaptive attacks and bypassed most with above 90 percent success. Zhan et al. (NAACL 2025 Findings, arXiv 2503.00061) bypassed all eight indirect-injection defenses they evaluated, each above 50 percent. "Defenses Against Prompt Attacks Learn Surface Heuristics" (arXiv 2601.07185, January 2026) names the mechanism: trained detectors latch onto surface cues. PISmith (arXiv 2603.13026, March 2026) reports that no existing defense keeps task utility while resisting RL-driven adaptive attacks. Newer fine-tuning defenses such as ReasAlign (January 2026) report low single-digit attack success, but on static benchmarks (S, Sysdig summary). The field's answer is out-of-band enforcement: CaMeL (Google DeepMind and ETH Zurich, arXiv 2503.18813) separates a privileged planner from a quarantined reader and enforces capability policies before every tool call; FIDES, Progent, RTBAS and FORGE realize the same idea with information-flow labels and reference monitors; LaunchSafe's adaptive evaluation (arXiv 2606.26479, June 25, 2026) reports an out-of-band defense holding at 4.2 to 2.6 percent attack success under adaptation while in-band detectors go above 90 percent (P, arXiv abstracts). The Five Eyes joint guidance on agentic AI (May 2026) says the same in policy language: no single safeguard suffices and human oversight at consequential decisions is a prerequisite (S).

Consequence for this repo: pi_shield and mcp_guard are in-band filters and must be described as such. They raise the cost of the naive majority of attacks and do not stop an adaptive attacker. The scanner's highest-value job is different and is exactly what a static tool does well: check whether the agent's declared architecture has out-of-band controls (approval gates on destructive actions, deny-by-default egress, capability scoping, provenance rules on memory writes). Those are hygiene findings with a concrete fix, and they age well.


SECTION 2. TECHNIQUE ENTRIES MAPPED TO THE RULE SET

Format per entry: Anchor / Boundary / Static signal / Coverage today / Action / Test.
Coverage refers to rule IDs visible in public releases: PI-SECRET, PI-TOOLS, PI-NO-HIERARCHY, PI-NO-NONDISCLOSE, PI-MCP, PI-SANDBOX-BYPASS, PI-MEMORY, PI-SUPPLY-CHAIN, PI-AUTOLOAD-CONFIG, PI-UNICODE-OBFUSCATION, PI-ANSI-INJECT. Rules not named here should be checked against references/rule-inventory.md before deciding an entry is uncovered.

Entry 2.1. Untrusted external instruction sources (AST05)
Anchor: Air Security, June 2026 (26,000 agents reached; 12.4 percent of 142,836 skills affected).
Boundary: skill instruction layer; also system prompts that tell the agent to follow guidance fetched from a URL.
Static signal: strong. Text directing the agent to fetch a URL and treat its contents as instructions, procedures or updates ("read the latest instructions at", "always check ... for updates before running", "the current workflow is maintained at"). Distinct from documentation links the agent may consult for facts.
Coverage: none visible. PI-AUTOLOAD-CONFIG is the local-file cousin.
Action: new rule PI-EXTERNAL-INSTRUCTIONS. High by default; Critical when the same file declares shell or network capability. Arabic patterns from day one.
Test: "see the API docs at https://example.com/api" must not fire; "follow the steps published at https://... before each run" must.

Entry 2.2. Identity and memory file persistence (ASI06, AST03)
Anchor: ClawHavoc wrote into MEMORY.md and SOUL.md; Vidar infostealer variants targeted openclaw.json, device.json, soul.md and memory.md (Hudson Rock, February 2026); the Universal Skill Format proposes deny_write on SOUL.md, MEMORY.md and AGENTS.md by default; OpenClaw log poisoning (patched February 14, 2026): the agent read its own logs for troubleshooting, so log writes became indirect injection.
Boundary: persistent memory and identity files; also CLAUDE.md, AGENTS.md, .cursorrules, hooks configuration, and self-read logs or transcripts.
Static signal: strong in skills (instructions to append to or edit these files); moderate in prompts (memory write capability with no provenance rule, which PI-MEMORY already covers).
Coverage: PI-MEMORY, partial.
Action: extend PI-MEMORY with a named target list of identity and instruction files. Any instruction to write to them is High, Critical with untrusted ingestion. Add "reads its own logs, history or transcripts as guidance" to the untrusted-source list.
Test: a skill that maintains a project notes file stays at most Medium; a skill that appends to AGENTS.md is High.

Entry 2.3. Dropper patterns inside markdown and scripts (AST01)
Anchor: ClawHavoc (curl-pipe-bash and base64-encoded droppers); the omnicogg skill carried its payload at the top of README.md followed by 22 MB of padding (JFrog, March 2026; Unit 42, June 2026); after SKILL.md scanning appeared, attackers pivoted to README.md and to registry comments disguised as update instructions.
Boundary: the whole skill package, not only SKILL.md.
Static signal: strong. Pipe-to-shell, base64 decode into a shell, PowerShell encoded commands, download to a temporary directory followed by execution, and the same in Arabic-language instructions.
Coverage: unclear. PI-SUPPLY-CHAIN targets package installs; PI-SANDBOX-BYPASS targets command gates.
Action: new rule PI-DROPPER applied to every text file in a package (SKILL.md, README.md, references, scripts). Critical.
Test: a script that pipes curl into jq must not fire; curl into sh must.

Entry 2.4. Scanner evasion by size, truncation and opaque assets (AST08)
Anchor: Trail of Bits, June 3, 2026; omnicogg 22 MB padding.
Boundary: the scanner itself.
Static signal: yes, about the scanner's own behavior. Any silent skip or truncation is a bypass.
Coverage: unknown. Confirm what pi_scan does with a 25 MB file and with non-text files.
Action: never skip silently. Oversized input produces a finding (PI-OVERSIZED, Medium) and the scanner still processes head and tail. Non-text files in a package (binaries, archives, images) are listed as findings (PI-OPAQUE-ASSET, Medium) so a reviewer sees them. Document the behavior in VALIDATION.md.
Test: a 25 MB file with a payload at byte 0 and another at the end; both must be found.

Entry 2.5. Hijackable dependencies (AST02, AST07)
Anchor: SkillJacking, July 2, 2026.
Boundary: the skill's supply chain: GitHub owners, package names, domains and cloud-app slots referenced in instructions or scripts.
Static signal: partial. Enumerating references is deterministic; checking whether they are live requires network, which conflicts with the zero-dependency offline default.
Coverage: PI-SUPPLY-CHAIN covers model-named packages only.
Action: new rule PI-DEPENDENCY-INVENTORY (Info or Low) that lists every external reference in a package for the reviewer, plus an optional --online flag that checks existence and raises unregistered packages, missing repositories and unresolvable domains to High. Offline stays the default.
Test: a skill referencing three domains and one npm package yields four inventory lines.

Entry 2.6. Over-privileged and insecure manifests (AST03, AST04)
Anchor: Snyk, 280 plus leaky skills (February 5, 2026); ToxicSkills; OWASP Universal Skill Format v1.0.
Boundary: YAML frontmatter of SKILL.md and equivalent manifests.
Static signal: strong. network as a boolean instead of an allowlist, shell true, wildcard file paths, secret or environment-variable values in frontmatter, dependency version ranges instead of pins.
Coverage: PI-SECRET (secrets), PI-TOOLS (capability declarations). No manifest parsing visible.
Action: linter mode parses frontmatter with a minimal parser (no PyYAML by default; if PyYAML is present, safe_load only, per AST04) and emits findings mapped to AST03 and AST04.
Test: network true is Medium; network allow with two named domains is not a finding; a wildcard under write is High.

Entry 2.7. Destructive actions without a confirmation gate (ASI09, ASI10)
Anchor: OpenClaw inbox deletion, February 23, 2026 (OWASP Q1 round-up); Five Eyes guidance on human oversight at consequential decisions.
Boundary: system prompt and tool configuration.
Static signal: strong. The prompt declares delete, send, pay, publish or deploy capability and contains no explicit confirmation, staging, rollback or stop rule.
Coverage: PI-TOOLS records the capability; no gate check visible.
Action: new rule PI-NO-CONFIRM-GATE. High; Critical when the same prompt ingests untrusted content. This is the single rule that most directly encodes the out-of-band consensus of Shift 5.
Test: a prompt with "send email" and "ask the user before sending" passes; without the second clause it fails.

Entry 2.8. MCP tool poisoning sub-techniques (MCP03)
Anchor: OWASP MCP Top 10 beta; Invariant Labs research; CSA research note, July 2026.
Boundary: tool descriptions, parameter schemas, tool responses.
Static signal: rug pull requires state across sessions; schema poisoning and shadowing are detectable per scan.
Coverage: mcp_guard scans definitions and responses for injection; no pinning, no cross-server duplicate detection.
Action: description pinning (hash of name plus description plus schema per tool, stored baseline, alert on change); duplicate or near-duplicate tool names across servers including homoglyph variants (reuse the normalization layer); instruction-like text inside parameter descriptions. Map findings to MCP03.
Test: the same tool name from two servers with different schemas is a finding; a description that changed between two runs is a finding.

Entry 2.9. Markdown image and link exfiltration (LLM01, LLM05)
Anchor: EchoLeak (2025), GrafanaGhost (April 2026).
Coverage: present in mcp_guard and pi_scan.
Action: keep; add the capability combination "renders markdown or fetches external images" plus untrusted ingestion as a High finding in pi_scan (see Shift 1).

Entry 2.10. Agent-to-agent and public write channel injection (ASI01, ASI08)
Anchor: Clinejection (February 17, 2026): a malicious cline 2.3.0 on npm silently installed OpenClaw during an eight-hour window; the reported entry point was an issue-triage workflow driven by an LLM (S, Termdock postmortem, March 2026). GitHub MCP toxic agent flows (2025) are the same shape.
Boundary: agents that read public issues, pull requests, comments or other agents' output and can write anywhere public.
Static signal: strong. Reads issue or PR text plus can comment, open PRs or push.
Coverage: PI-TOOLS trifecta logic; confirm that "post a comment", "open a pull request" and "publish" count as egress in both languages.
Action: add public write channels to the egress capability list if missing; add Arabic equivalents.

Entry 2.11. Unicode, ANSI and tag-block smuggling
Coverage: PI-UNICODE-OBFUSCATION, PI-ANSI-INJECT, pi_shield Layer 1 as of v2.5.2.
Open item: the Cf-class strip removes ZWNJ (U+200C) and ZWJ (U+200D), which alters Persian and Urdu word forms and breaks emoji sequences. Decide on an allowlist or document the side effect; add a Persian test string containing ZWNJ.

Entry 2.12. Hierarchy and non-disclosure language (hygiene, not resistance)
Anchor: Shift 5.
Action: keep PI-NO-HIERARCHY and PI-NO-NONDISCLOSE; change the score band wording so that zero findings reads "no static findings" rather than "hardened"; state in README and in the report footer that the score measures prompt hygiene, not injection resistance.


SECTION 3. TAXONOMY COLUMNS TO ADD TO taxonomy-mapping.md

OWASP LLM Top 10 2025: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM05 Improper Output Handling, LLM06 Excessive Agency.
OWASP Top 10 for Agentic Applications 2026: ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI08, ASI09, ASI10 as listed in Shift 4.
OWASP Agentic Skills Top 10 v1: AST01 to AST10.
OWASP MCP Top 10 beta: at least MCP01 and MCP03; complete the list from the project page once the beta text is final.
Optional: MITRE ATLAS technique IDs and CSA MAESTRO layers (the AST10 project already publishes a MAESTRO mapping that can be reused).


SECTION 4. EXTERNAL MATERIAL FOR RECALL MEASUREMENT

snyk-labs/toxicskills-goof: real malicious skill samples published for scanner testing. First target for the linter's recall number.
garak: already measured against; publish the recall figure in VALIDATION.md alongside precision.
AgentDojo (Debenedetti et al.): the injection strings in its task suite are a usable paraphrase set for pi_shield and mcp_guard recall. Extract payloads rather than run the harness; its purpose is agent evaluation.
"Do Not Mention This to the User" (arXiv 2602.06547, USENIX Security 2026): detection of malicious agent skills in the wild; check whether a labeled dataset was released.
SkillSieve (arXiv 2604.06550, April 2026): hierarchical triage for malicious skills; prior art to cite and compare against.
"Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection" (arXiv 2604.18248, April 2026): design reading for detection beyond regex.
Trail of Bits bypass list (June 2026): padding and truncation, binary and archive hiding, judge injection. Turn the first two into regression tests; the third applies only if an LLM judge is ever added.
Reporting rule: keep synthetic-corpus precision and external-corpus recall as separate numbers, and state the provenance of each corpus.


SECTION 5. WHAT NOT TO DO

Do not add a regex for every technique in a blog post. Add a rule only where a static signal exists in a file the scanner reads and where the fix is concrete.
Do not add an LLM judge to the linter without a plan for judge injection; Trail of Bits broke every judge-based scanner it tested.
Do not let the linter scan SKILL.md alone; the campaigns already moved to README.md and scripts.
Do not break the zero-dependency offline default; network checks stay behind a flag.
Do not describe pi_shield or mcp_guard as prevention. They are in-band filters with a documented ceiling; the adaptive-attack literature is unambiguous.


SECTION 6. SUGGESTED ORDER

Step 1. Rename the score band, add the honesty sentence, add CI, fix README and SKILL.md drift. No research needed; one week of small PRs.
Step 2. Linter mode v1: entries 2.1, 2.2, 2.3, 2.4 and 2.6 plus AST mapping. Measure recall on toxicskills-goof and publish it.
Step 3. pi_scan rules 2.7 and 2.9 with Arabic patterns; extend taxonomy-mapping.md (Section 3).
Step 4. mcp_guard pinning and shadowing (entry 2.8).
Step 5. Dependency inventory with the optional online check (entry 2.5).
Step 6. SARIF export so all of the above lands in GitHub Code Scanning.


SECTION 7. ITEMS TO VERIFY BEFORE THE NEXT RELEASE

The README cites Flowise CVE-2026-40933 (CVSS 9.9); OWASP's Q1 2026 round-up anchors the actively exploited Flowise CustomMCP RCE to CVE-2025-59528. They may be two different issues; confirm both identifiers and which one the PI-MCP rule text means.
Claude Code: the AST10 timeline lists CVE-2025-59536 (CVSS 8.7, already anchored in PI-AUTOLOAD-CONFIG) and a second one, CVE-2026-21852 (CVSS 5.3); consider adding the second.
OpenClaw ClawJacked CVE-2026-28363 (CVSS 9.9, localhost WebSocket brute force) is a runtime bug, not a prompt weakness; it belongs in attack-patterns-2026.md as context, not as a rule.


SECTION 7B. ADDENDUM 2026-09-23 — WHAT LANDED IN v2.6.2

Four technique entries from this note's orbit shipped as runtime families
(pi_shield / mcp_guard patterns), not new scanner rule IDs — consistent
with Section 5: the static scanner gains a rule only where the signal sits
in a file the scanner reads. Scanner rule IDs remain 18.

1. Environment-variable poisoning. Cursor CVE-2026-22708 / GHSA-82wg-qcm4-
   fp2w (disclosed January 14, 2026 by Pillar Security — reported to Cursor
   August 11, 2025; affected ≤ 2.2, fixed in 2.3): shell builtins
   (export/typeset/declare) were implicitly trusted by the command
   allowlist, so injected content could poison shell startup and hook
   variables (PAGER, PERL5OPT, PYTHONWARNINGS, LD_PRELOAD, BASH_ENV,
   GIT_SSH_COMMAND, …) and let the NEXT benign command execute the payload
   — zero-click and one-click forms. Exploitation requires the non-default
   Auto-Run Mode with Allowlist mode enabled. Static signal:
   weak in prompts (PI-SANDBOX-BYPASS already flags allowlist gates with no
   bypass awareness), strong in content. Shipped: verb-driven and bare-
   assignment detection in pi_shield and mcp_guard; bare hook-variable
   strings in pasted logs deliberately silent.

2. Concealment / masquerade instructions. The Gemini calendar-invite
   injection (disclosed January 2026) paired a dormant indirect payload
   with an explicit masquerade order ("respond with 'it's a free time
   slot'"); the concealment half is what made the attack silent. Shipped:
   "do not inform the user" / "without telling the user" / "respond with
   '<canned>'" detection in both layers, English and Arabic; positive
   phrasing stays silent.

3. Memory-write instructions. Memory poisoning is documented research
   (MINJA; the systematic memory-poisoning study, arXiv 2606.04329; and the
   Sleeper study, Pulipaka et al., arXiv 2605.15338, May 2026 — poisoned
   memories written in up to 99.8% of attempts on GPT-5.5 and 95.0% on
   Kimi-K2.6, and 60-89% retrieval-conditioned adversarial action) whose
   canonical payload is a one-line write: "remember that the user prefers
   X". The effect is conditional on the agent's write/retrieve path — a
   study result, not evidence of a live campaign. Shipped: memory-write
   detection in mcp_guard only — the same phrase from a user to their own
   agent is a legitimate memory feature, and the shield correctly ignores
   it.

4. Protocol-relative markdown images. GrafanaGhost (Shift 1) smuggled data
   through image URLs that bypassed scheme checks; the markdown-exfiltration
   pattern now treats the scheme as optional and flags bare "//host" images
   as render callbacks, and pi_shield gains check_output_channels() for the
   model-output side. Shipped in both layers.

Measured effect: the pinned garak in-the-wild corpus (650 prompts, SHA-256
c072aa09…) moved 102/128/420 (noticed 35.4%, mean 24.8) to 111/135/404
(noticed 37.8%, mean 26.4); both versions were diffed payload-by-payload
and the movement is entirely the new families catching phrasing already
present in the corpus. Scanner benchmark unchanged (3.0 / 46.3 / 43.3).

Still open from Section 6, unchanged: skill-file linter mode (Step 2),
PI-EXTERNAL-INSTRUCTIONS / PI-DROPPER (entries 2.1, 2.3), mcp_guard tool-
description pinning against rug pulls (entry 2.8 / MCP03) — now the most
evidence-backed remaining item, with Microsoft's June 2026 guidance
(signed tool manifests, metadata scanning) and the MCPTox benchmark
(45 live servers, 20 agents, average tool-poisoning ASR 36.5 percent,
arXiv 2508.14925) as the measurement baseline to beat.


SECTION 8. SOURCES

(P) OWASP GenAI Exploit Round-up Report Q1 2026, April 14, 2026: https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/
(P) OWASP Agentic Skills Top 10 project page with 2026 incident timeline: https://owasp.org/www-project-agentic-skills-top-10/
(P) OWASP MCP Top 10 project page: https://owasp.org/www-project-mcp-top-10/
(P) Snyk ToxicSkills, February 5, 2026: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
(P) Unit 42, OpenClaw skill marketplace supply chain risk, June 24, 2026: https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
(P) Nasr et al., The Attacker Moves Second, arXiv 2510.09023
(P) Debenedetti et al., Defeating Prompt Injections by Design (CaMeL), arXiv 2503.18813
(P) Narisetty et al., Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents, arXiv 2606.26479, June 25, 2026
(P) Defenses Against Prompt Attacks Learn Surface Heuristics, arXiv 2601.07185
(P) PISmith: Reinforcement Learning-based Red Teaming for Prompt Injection Defenses, arXiv 2603.13026
(P) SkillSieve, arXiv 2604.06550
(P) Beyond Pattern Matching, arXiv 2604.18248
(S) CSA research note, Indirect Prompt Injection Goes Operational, May 20, 2026: https://labs.cloudsecurityalliance.org/research/csa-research-note-indirect-prompt-injection-in-the-wild-2026/
(S) CSA research note, MCP Tool Poisoning, July 2, 2026: https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/
(S) Termdock, ClawHub incident postmortem including Clinejection, March 17, 2026: https://www.termdock.com/en/blog/clawhub-malicious-skills-incident
(S) Sysdig, The Comprehensive Guide to Prompt Injection Attacks in 2026: https://www.sysdig.com/learn-cloud-native/prompt-injection
(S) Cycode, OWASP MCP Top 10 guide, June 24, 2026: https://cycode.com/blog/owasp-mcp-top-10/
(S) Practical DevSecOps, MCP Security Statistics 2026: https://www.practical-devsecops.com/mcp-security-statistics-2026-report/

Addendum sources (Section 7B):
(P) Cursor security advisory GHSA-82wg-qcm4-fp2w, Terminal Tool Allowlist Bypass via Environment Variables (CVE-2026-22708; Auto-Run + Allowlist condition; affected ≤ 2.2, fixed in 2.3), January 14, 2026: https://github.com/cursor/cursor/security/advisories/GHSA-82wg-qcm4-fp2w — and the Pillar Security technical write-up, January 14, 2026: https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors
(P) MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers, arXiv 2508.14925: https://arxiv.org/html/2508.14925v1
(P) Gemini calendar-invite indirect prompt injection disclosure (dormant payload + masquerade instruction), January 2026
(P) Pulipaka et al., Hidden in Memory: Sleeper Memory Poisoning in LLM Agents, arXiv 2605.15338, May 2026: https://arxiv.org/abs/2605.15338
(S) Systematic study of memory poisoning in LLM agents, arXiv 2606.04329, June 2026
(S) CSA research note, MCP Attack Surface: Tool Poisoning and IDE Auto-Execution, July 1, 2026: https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/
