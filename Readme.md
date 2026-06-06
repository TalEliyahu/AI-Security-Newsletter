# AI Security Newsletter - May 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AI Security community on Twitter](https://x.com/AISecHub) and [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our new project, [Awesome AI Security](https://www.awesomeaisecurity.com/).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - *Innovate and Invest with Confidence, Lead with Assurance.*

<p>
  <a href="https://innovguard.com">
    <img src="assets/innovguard-sponsor.png" alt="InnovGuard" width="360">
  </a>
</p>

---

# 🔍 Insights

📌 [SymJack: the approval prompt is lying to you. A symlink-hijack RCE in six AI coding agents](https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/)

SymJack turns a harmless-looking file copy into a configuration overwrite for coding agents, showing how unresolved symlinks can make an approval dialog display a benign-looking action while the operating system follows a link into agent configuration.

📌 [When prompts become shells: RCE vulnerabilities in AI agent frameworks](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)

Microsoft shows prompt-injection-to-RCE paths in Semantic Kernel where untrusted model-shaped text reaches tool-backed filters, plugin execution, and file-write behavior, turning agent framework glue code into host-side action.

📌 [Beyond source code: The files AI coding agents trust - and attackers exploit](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access)

The attack surface around coding agents now includes instruction files, runtime settings, IDE extensions, and project automation, not just application source code. Agent-facing configuration becomes executable influence when it can steer tool use, permissions, or repository automation.

📌 [Copirate 365 at DEF CON: Plundering in the Depths of Microsoft Copilot](https://embracethered.com/blog/posts/2026/defcon-talk-copirate-365/)

Johann Rehberger walks through Copilot data-exfiltration paths, delayed tool invocation, and the uneven security contracts between AI widgets and their host applications, with emphasis on host controls such as audit logs, containment, and runtime-enforced feature allowlists.

📌 [Configuring Codex Securely Across Every Platform and Use Case](https://www.promptarmor.com/resources/configuring-codex-securely-across-every-platform-and-use-case)

PromptArmor maps Codex risk to concrete AI coding-agent controls: workspace app permissions, MCP server restrictions, action approvals, managed configuration, telemetry, role-based feature access, authorization, monitoring, and configuration management.

📌 [Comment and Control: How One Prompt Injection Hit Claude Code, Gemini CLI, and Copilot Agent](https://repello.ai/blog/comment-and-control-claude-code-gemini-copilot-prompt-injection)

The writeup turns the Comment and Control disclosure into an engineering checklist for CI-connected AI coding agents, where untrusted GitHub content reaches agent actions through PR titles, issue comments, workflow triggers, credential access, and CI secrets.

📌 [The Personal AI Control Plane: How to Govern Your Agents Before They Govern Your Workflow](https://notquiterandom.com/2026/05/11/the-personal-ai-control-plane-how-to-govern-your-agents-before-they-govern-your-workflow/)

The post turns personal and small-team AI-agent sprawl into a concrete control-plane problem: inventory, permissions, memory, logging, review, revocation, and unmanaged delegated authority across assistants, automations, copilots, and plugins.

📌 [Vibe coding and agentic engineering are getting closer than I’d like](https://simonwillison.net/2026/May/6/vibe-coding-and-agentic-engineering/)

Simon Willison names a quiet failure mode in AI-assisted engineering: coding agents can produce convincing repositories, tests, and documentation faster than reviewers can establish provenance, runtime evidence, scoped permissions, and operational trust.

📌 [Evaluating MCP Servers for Security (2026)](https://futureagi.com/blog/evaluating-mcp-servers-security-2026/)

The MCP evaluation guidance focuses on tool-description injection, result tampering, sandbox escape, and cross-tenant isolation, treating MCP servers as privileged plugins before they receive real data or production access.

📌 [Intel Deep Dive: TeamPCP/Shai-Hulud 3.0 AI-Targeted Tradecraft](https://www.dataminr.com/resources/cyber-intel-deep-dive-teampcp-shai-hulud-3-0/)

Dataminr ties the May Shai-Hulud activity to AI-targeted tradecraft, including Claude Code persistence hooks, package supply-chain abuse, and prompt-injection content designed to interfere with analysis. The campaign connects developer credentials, agent-accessible repositories, and AI-assisted development pipelines.

📌 [The 12-Message Prompt Injection Pattern: Why Single-Turn Defenses Are Dead](https://austa.ai/articles/multi-turn-prompt-injection-pattern-2026/)

Austa documents a multi-turn prompt-injection pattern that avoids obvious jailbreak language and accumulates influence across conversation state, memory, retrieved content, tool results, and delayed authorization.

📌 [AI Agent Prompt Injection Is Now an Execution Boundary](https://openclawai.io/blog/ai-agent-prompt-injection-execution-boundary)

The article makes a clear distinction between text manipulation and execution risk. Once an agent can write files, call APIs, or run code, prompt injection becomes a question of privilege separation and tool authorization rather than only instruction hierarchy.

📌 [Why Policy in Amazon Bedrock AgentCore chose Cedar for securing agentic workflows](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)

The writeup makes agent authorization concrete by moving policy decisions outside the model and into Cedar-based checks where action, resource, user, and context are evaluated before an operation is allowed.

📌 [Prompt injection defenses that survive 2026](https://www.tmls.nyc/insights/field-notes/prompt-injection-defenses-that-survive-2026)

The defense model assumes that prompt injection controls can fail and pushes mitigation into the tool boundary: allowlisted recipients, scoped database access, constrained side effects, authorization checks, and clear blast-radius decisions.

📌 [When prompt injection turns an AI agent framework into host-level code execution](https://www.cantina.security/blog/prompt-injection-host-code-execution-ai-agents)

Cantina’s note is short and concrete: framework behavior around file writes, execution, and sensitive tools determines whether prompt injection remains a content issue or becomes host compromise.

---

# 🧰 Tools & Resources

🧰 **[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)** - Claude Code skill bundle for authorized vulnerability research, with prompts for exploit validation, attack-path notes, mitigation checks, and disclosure-oriented testing of AI coding-agent behavior. ⭐️1,260

🧰 **[AiSOC](https://github.com/beenuar/AiSOC)** - Self-hostable AI SOC workflow that records agent prompts, tool calls, rationale, detection steps, authorization context, and replayable investigations for security operations teams. ⭐️1,049

🧰 **[forkd](https://github.com/deeplethe/forkd)** - KVM microVM sandbox runtime for AI agents that need isolated execution, filesystem containment, network boundaries, and credential separation instead of broad host access. ⭐️906

🧰 **[audit](https://github.com/evilsocket/audit)** - Multi-stage vulnerability-discovery agent for authorized review workflows where evidence, triage, and exploitability need to be separated. ⭐️544

🧰 **[OpenHack](https://github.com/hadriansecurity/OpenHack)** - File-based whitebox security-review workspace for AI-assisted vulnerability triage, attack-path review, threat-model checkpoints, mitigation tracking, and human approval points. ⭐️512

🧰 **[speca](https://github.com/NyxFoundation/speca)** - Specification-to-checklist agentic auditing framework for turning system requirements into reviewable security checks, threat-model tasks, authorization tests, and mitigation validation. ⭐️419

🧰 **[promptbeat](https://github.com/tophant-ai/promptbeat)** - Red-teaming toolkit for LLM safety and prompt-injection evaluation runs, including attack-path testing, bypass measurement, mitigation comparison, and detection-oriented reporting. ⭐️378

🧰 **[codex-redteam-mode](https://github.com/chAng-L19/codex-redteam-mode)** - Red-team reasoning mode for Codex-style AI coding-agent workflows, with prompts for adversarial review, abuse-case testing, prompt-injection checks, and threat modeling. ⭐️251

🧰 **[AdStrike](https://github.com/capture0x/AdStrike)** - AI-assisted Active Directory red-team framework for authorized recon, vulnerability discovery, attack-path mapping, credential-risk review, and operator-guided testing. ⭐️197

🧰 **[OpenOSINT](https://github.com/OpenOSINT/OpenOSINT)** - OSINT agent with MCP server and CLI support for authorized security research, evidence collection, credential-risk review, investigation workflows, and tool-boundary testing. ⭐️193

🧰 **[Adrian](https://github.com/secureagentics/Adrian)** - Runtime monitoring and control layer for AI agents, focused on visibility, authorization decisions, unsafe tool actions, and behavioral detection. ⭐️112

🧰 **[promptzero](https://github.com/openbashok/promptzero)** - Transparent Claude API proxy that anonymizes sensitive data before it leaves the local environment, reducing credential exposure and privacy leakage in AI-assisted workflows. ⭐️39

🧰 **[redlyne](https://github.com/redlyne-ai/redlyne)** - VS Code-oriented security tool for detecting, triaging, and patching vulnerabilities in AI-generated Python code, with review flow around exploitability, mitigation, and deployment risk. ⭐️37

🧰 **[skill-scanner-agent](https://github.com/HuTa0kj/skill-scanner-agent)** - Scanner for agent skill packages that checks risky instructions, prompt-injection behavior, unsafe permissions, tool authorization, and security-relevant behavior before use. ⭐️32

🧰 **[bughunter-ai](https://github.com/h4ckologic/bughunter-ai)** - Autonomous bug-bounty framework that wires Claude Code, Burp MCP, credential vaulting, attack-path discovery, vulnerability validation, and mitigation notes for authorized testing. ⭐️22

🧰 **[PROMPTPurify](https://github.com/securelayer7/PROMPTPurify)** - Prompt-injection guardrail project for filtering hostile user or tool-output content, evaluating bypass behavior, and adding detection before unsafe agent tool invocation. ⭐️17

---

# 📄 Reports

📘 **[Summary Analysis of Responses to the Request for Information Regarding Security Considerations for AI Agents](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)**

NIST summarizes CAISI RFI responses on agent security, including threat categories, authorization gaps, tool-use risks, mitigation needs, and adaptation points for applying existing cybersecurity practices to autonomous systems.

📘 **[Careful Adoption of Agentic AI Services](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/)**

The Five Eyes guidance defines an AI agent adoption baseline around low-risk use cases, strict privilege controls, continuous monitoring, tool-access threat modeling, containment, sandboxing, and reversibility.

📘 **[Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf?ver=bmgiSbNQLP6Z_GiWtRt6bg%3D%3D)**

NSA's guidance treats MCP as an AI automation trust-boundary problem, covering authorization, context handling, tool invocation, logging, deployment hardening, and operational controls for production agent workflows.

📘 **[Detecting Offensive Cyber Agents: A Detection-in-Depth Approach](https://www.iaps.ai/research/detecting-offensive-cyber-agents)**

IAPS frames autonomous cyber agents as a detection problem for defenders, proposing agent identifiers, agent honeypots, AI-assisted alert triage, an agentic security alert standard, and coordination mechanisms for disrupting offensive agent activity.

📘 **[Software Bill of Materials for AI - Minimum Elements](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html)**

The G7/CISA/BSI guidance defines minimum AI SBOM elements across models, datasets, software dependencies, services, hardware, deployment context, security control metadata, dependency exposure, and artifact validation.

📘 **[AIUC-1 Crosswalks - OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/aiuc-1-crosswalks-owasp-top-10-for-agentic-applications/)**

OWASP maps AI usage categories to the Agentic Applications Top 10 across tool misuse, goal hijacking, memory poisoning, excessive agency, identity abuse, supply-chain exposure, monitoring gaps, and runtime containment.

📘 **[AI Security Maturity Model](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model)**

CSA's AISMM defines a maturity model for operational AI security programs, with control objectives across governance, identity, monitoring, model security, application security, data security, supply chain, and incident response.

📘 **[Empowering Defenders: AI for Cybersecurity](https://www.weforum.org/publications/empowering-defenders-ai-for-cybersecurity/)**

The World Economic Forum white paper focuses on AI use inside cybersecurity operations, including detection support, alert triage, monitoring, human oversight, pilot validation, governance, and where agentic AI can change defender workflows without removing accountability from security teams.

📘 **[Shai-Hulud/Megalodon: A Two-Wave AI Developer Supply Chain Attack](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-megalodon-supply-chain-cascade/)**

CSA connects package-registry compromise and CI/CD backdooring to AI developer workflows, including persistence in coding tools, credential theft, malicious automation, and supply-chain trust failures in agent-enabled engineering environments.

📘 **[Sub-4-Hour Weaponization of Agentic AI Frameworks](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentic-framework-rapid-exploitation-20260/)**

CSA uses PraisonAI exploitation timing to frame exposed AI agent frameworks around authentication, network segmentation, vulnerability monitoring, exploit detection, and patch processes measured in hours rather than ordinary application release cycles.

📘 **[The Non-Human Identity Governance Vacuum](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nonhuman-identity-agentic-ai-governance-v1-cs/)**

The paper treats AI agent credentials as a non-human identity security problem, with emphasis on ownership, lifecycle, permission review, authorization boundaries, credential rotation, detection, and runtime behavior for autonomous systems.

---

# 🚨 CVEs

🛡️ [CVE-2026-41497](https://nvd.nist.gov/vuln/detail/CVE-2026-41497) - Critical 9.8 · PraisonAI MCP command handling. PraisonAI MCP command parsing can allow arbitrary executables through `parse_mcp_command`, placing command execution directly on the MCP trust boundary for agent orchestration.

🛡️ [CVE-2026-7301](https://nvd.nist.gov/vuln/detail/CVE-2026-7301) - Critical 9.8 · SGLang multimodal scheduler ROUTER socket. SGLang exposed a ROUTER socket path where unsafe `pickle.loads` handling could become RCE inside model-serving worker control planes.

🛡️ [CVE-2026-7304](https://nvd.nist.gov/vuln/detail/CVE-2026-7304) - Critical 9.8 · SGLang custom logit processor. SGLang custom logit processor loading used unsafe deserialization when the feature was enabled, turning an inference extension hook into a code execution boundary.

🛡️ [CVE-2026-31239](https://nvd.nist.gov/vuln/detail/CVE-2026-31239) - Critical 9.8 · Mamba model loading. The Mamba model framework used unsafe `torch.load()` behavior when loading Hugging Face models, making model artifacts a code execution input in the AI supply chain.

🛡️ [CVE-2026-44336](https://nvd.nist.gov/vuln/detail/CVE-2026-44336) - Critical 9.4 · PraisonAI default tool path handling. PraisonAI default tools allowed path traversal and arbitrary file write, with possible code execution through Python path behavior in agent runtime paths.

🛡️ [CVE-2026-42208](https://nvd.nist.gov/vuln/detail/CVE-2026-42208) - Critical 9.3 · LiteLLM proxy API key checks. LiteLLM proxy API key validation exposed SQL injection risk that could affect stored credentials and authorization state in an LLM gateway database.

🛡️ [CVE-2026-7302](https://nvd.nist.gov/vuln/detail/CVE-2026-7302) - Critical 9.1 · SGLang file write path handling. SGLang path traversal could allow arbitrary file writes, giving exposed model-serving APIs a path toward host compromise.

🛡️ [CVE-2026-5817](https://nvd.nist.gov/vuln/detail/CVE-2026-5817) - High 8.8 · Docker Model Runner / vLLM Metal remote model code loading. Docker Model Runner used `trust_remote_code=True` without sandboxing for vLLM Metal on macOS, letting malicious OCI model content cross from model supply chain into local code execution.

🛡️ [CVE-2026-45672](https://nvd.nist.gov/vuln/detail/CVE-2026-45672) - High 8.8 · Open WebUI code execution endpoint. Open WebUI allowed code execution through a utility endpoint even when code execution was configured off, exposing a gap between application settings and reachable routes.

🛡️ [CVE-2026-42271](https://nvd.nist.gov/vuln/detail/CVE-2026-42271) - High 8.7 · LiteLLM MCP REST test endpoints. LiteLLM MCP test endpoints could spawn supplied stdio commands for authenticated users without sufficient role checks, exposing command execution through an MCP administration path.

🛡️ [CVE-2026-47101](https://nvd.nist.gov/vuln/detail/CVE-2026-47101) - High 8.7 · LiteLLM API key route authorization. LiteLLM API key routes allowed privilege escalation, putting downstream providers, stored credentials, users, and tenant data at risk through model-gateway key management.

🛡️ [CVE-2026-47102](https://nvd.nist.gov/vuln/detail/CVE-2026-47102) - High 8.7 · LiteLLM user role self-update. LiteLLM role-management logic allowed users to escalate privileges through self-update behavior in identity mutation endpoints for an LLM gateway.

🛡️ [CVE-2026-44338](https://nvd.nist.gov/vuln/detail/CVE-2026-44338) - High 7.3 · PraisonAI legacy API authentication bypass. PraisonAI shipped a legacy Flask API server with authentication disabled by default, exposing agent enumeration and workflow-triggering endpoints when reachable; public scanning reportedly started within hours of advisory publication.

---

# 📅 Upcoming Conferences

## June 2026

📅 [38th Annual FIRST Conference (FIRSTCON26)](https://www.first.org/conference/2026/) - June 14-19, 2026 · Denver, CO, USA · Organizer: FIRST

📅 [SiMLA 2026 - Security in Machine Learning and its Applications](https://simlaacns.github.io/) - June 22-25, 2026 · Stony Brook, NY, USA · Organizer: SiMLA / ACNS

## August 2026

📅 [Black Hat USA 2026 - AI Summit](https://blackhat.com/us-26/ai-summit.html) - August 4, 2026 · Las Vegas, NV, USA · Organizer: Black Hat

📅 [IEEE CSR GenXSec 2026 - Generative and eXplainable AI for Security in Networking](https://www.ieee-csr.org/csr-genxsec/) - August 3-5, 2026 · Lisbon, Portugal · Organizer: IEEE CSR

## October 2026

📅 [CAMLIS 2026 - Conference on Applied Machine Learning in Information Security](https://www.camlis.org/) - October 21-23, 2026 · Arlington, VA, USA · Organizer: CAMLIS

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · Austin, TX, USA · Organizer: IEEE

## November 2026

📅 [19th ACM Workshop on Artificial Intelligence and Security (AISec 2026)](https://aisec.cc/) - November 15-19, 2026 · The Hague, Netherlands · Organizer: ACM AISec
---

# 📚 Research

📖 **GenAI-Driven Threat Detection with Microsoft Security Copilot**

The paper introduces the Dynamic Threat Detection Agent, an always-on adaptive agent inside Microsoft Security Copilot that investigates Microsoft Defender incidents, builds activity timelines, generates attack-specific hypotheses, validates outputs with schema and grounding constraints, and creates explainable detections. The paper reports deployment across tens of thousands of Defender customers as a production-scale defensive AI-security example. [arXiv](https://arxiv.org/abs/2605.20896)

📖 **Beyond Zero: Enterprise Security for the AI Era**

The paper argues that application-level zero trust is not enough for autonomous AI agents and high-velocity enterprise data access. It moves authorization closer to each operation, with per-resource and per-method decisions, action-level trust boundaries, and machine-speed access checks for both humans and agents. [arXiv](https://arxiv.org/abs/2605.22985)

📖 **LACUNA: Safe Agents as Recursive Program Holes**

The paper treats unsafe agent behavior as a program-composition problem, where execution holes require scoped authority, typed boundaries, authorization checks, and sandbox limits before an agent fills them with action. [arXiv](https://arxiv.org/abs/2605.28617)

📖 **MIRAGE: Context-Aware Prompt Injection against Mobile GUI Agents via User-Generated Content**

Mobile GUI agents inherit risk from user-generated content because screenshots, app text, and interface state can become indirect prompt-injection inputs when agents browse feeds, reviews, comments, or chat surfaces. [arXiv](https://arxiv.org/abs/2605.28116)

📖 **Aligning Provenance with Authorization: A Dual-Graph Defense for LLM Agents**

The control idea is to bind what an agent is allowed to do to where information came from. Provenance and authorization become two linked graphs for modeling, mitigating, and auditing untrusted content that tries to authorize privileged tool use. [arXiv](https://arxiv.org/abs/2605.26497)

📖 **AgentSecBench: Measuring Prompt Injection, Privacy Leakage, and Tool-Use Integrity in LLM Agents**

AgentSecBench gives evaluators a way to test whether agents preserve tool-use integrity and privacy under prompt injection, replacing one-off jailbreak demos with repeatable evidence for agent security review. [arXiv](https://arxiv.org/abs/2605.26269)

📖 **How Agentic AI Coding Assistants Become the Attacker's Shell**

For AI coding assistants, the shell is the danger line: repository text, tool calls, terminal access, and developer approvals can combine into code execution through agent permissions, workspace trust, sandboxing, credential exposure, and command-execution controls. [arXiv](https://arxiv.org/abs/2605.25871)

📖 **IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization**

IterInject models indirect prompt injection as an optimization loop rather than a single clever payload, testing whether defenses survive attacker iteration across tool outputs and retrieved content. [arXiv](https://arxiv.org/abs/2605.24659)

📖 **Poisoning the Watchtower: Prompt Injection Attacks Against LLM-Augmented Security Operations Through Adversarial Log Content**

Security copilots that summarize logs can be attacked through the logs themselves, making SOC data an untrusted input once an LLM is part of triage, detection, alert enrichment, or investigation workflows. [arXiv](https://arxiv.org/abs/2605.24421)

📖 **Heartbeat-Bound Hierarchical Credentials: Cryptographic Revocation for AI Agent Swarms**

The paper focuses on revocation for multi-agent systems where subordinate agents receive bounded credentials that expire and can be revoked cryptographically, with authorization and credential lifecycle handled outside prompt instruction. [arXiv](https://arxiv.org/abs/2605.20704)

📖 **Overeager Coding Agents: Measuring Out-of-Scope Actions on Benign Tasks**

Benign tasks can still produce unsafe behavior when AI coding agents edit files, call tools, or change state outside the requested scope. The paper measures overreach, authorization failures, unsafe tool invocation, sandbox escapes, and mitigation gaps without relying on malicious prompts. [arXiv](https://arxiv.org/abs/2605.18583)

📖 **An Empirical Study of Privacy Leakage Chains via Prompt Injection in Black-Box Chatbot Environments**

Privacy leakage becomes a chain when injected instructions steer retrieval, memory, and response behavior across turns. The paper is relevant to teams testing black-box assistants where source code and system prompts are unavailable. [arXiv](https://arxiv.org/abs/2605.18133)

📖 **LivePI: More Realistic Benchmarking of Agents Against Indirect Prompt Injection**

LivePI pushes prompt-injection testing closer to deployed agents by using live interaction paths instead of static prompt suites. That helps practitioners see which controls survive real tool use and changing web content. [arXiv](https://arxiv.org/abs/2605.17986)

📖 **ESLD: A Latent-Space Architecture for Faster, Stronger Prompt-Injection Defense**

The defense moves prompt-injection detection into latent-space signals rather than relying only on surface text, targeting encoded, indirect, and paraphrased instruction attacks before they trigger tool invocation, data leakage, policy bypass, or unsafe agent action. [arXiv](https://arxiv.org/abs/2605.18918)

📖 **Remembering More, Risking More: Longitudinal Safety Risks in Memory-Equipped LLM Agents**

Persistent memory changes the threat model because poisoned or sensitive context can survive across sessions. The paper gives teams a reason to segment memory, label provenance, audit carry-forward data, detect poisoning, and mitigate privacy leakage in memory-equipped agents. [arXiv](https://arxiv.org/abs/2605.17830)

📖 **AI Agents May Always Fall for Prompt Injections**

The paper argues that prompt injection remains structurally hard for AI agents that must process untrusted content and follow instructions, framing tools, data flow, authorization, sandboxing, detection, and permissions as controls outside the model itself. [arXiv](https://arxiv.org/abs/2605.17634)

📖 **ASPI: Seeking Ambiguity Clarification Amplifies Prompt Injection Vulnerability in LLM Agents**

Clarification turns out to be an attack state: when an agent asks for more information, it may expose a new path for injected content to shape the next tool action. The evaluation surface includes ambiguous tasks, authorization checks, detection, and mitigation, not only fully specified prompts. [arXiv](https://arxiv.org/abs/2605.17324)

📖 **Unsafe by Flow: Uncovering Bidirectional Data-Flow Risks in MCP Ecosystem**

The paper focuses on bidirectional data flow in MCP systems: what tools receive from agents, what agents accept back from tools, and how data leakage, confused-deputy behavior, tool-result tampering, and authorization failure emerge at the agent-tool boundary. [arXiv](https://arxiv.org/abs/2605.07836)

📖 **Adversarial Machine Learning: A 20-Year Survey of Attacks, Defenses, and Standards**

This survey organizes two decades of adversarial ML work across attacks, defenses, evaluation methods, standards, model security testing, robustness, lifecycle risk, deployment controls, and AI assurance. [McGill publication page](https://dmas.lab.mcgill.ca/fung/publicationsByType.htm)

---

# 💬 Practitioner Discussions

💬 [Linus Torvalds says AI-powered bug hunters have made Linux security mailing list almost entirely unmanageable](https://www.reddit.com/r/cybersecurity/comments/1tgibc2/linus_torvalds_says_aipowered_bug_hunters_have/)

r/cybersecurity · Reddit score 1,670 · 135 comments

The thread surfaces a real maintainer problem: AI-assisted vulnerability reports can increase volume and detail without improving exploitability, reproduction quality, or triage capacity.

💬 [VP Requested Full API Access to the ERP for Claude Integration](https://www.reddit.com/r/sysadmin/comments/1tdymin/vp_requested_full_api_access_to_the_erp_for/)

r/sysadmin · Reddit score 859 · 287 comments

The thread captures the access-control problem in plain operational terms: business pressure can push agents toward broad credentials before security has defined scope, approval, logging, revocation, authorization, and monitoring.

💬 [LinkedIn user hides AI prompt injection in bio to force recruitment spam to be sent in Olde English prose](https://www.reddit.com/r/cybersecurity/comments/1tgl37m/linkedin_user_hides_ai_prompt_injection_in_bio_to/)

r/cybersecurity · Reddit score 541 · 25 comments

The example is playful, but the mechanism is serious: scraped profile text becomes untrusted instructions for downstream recruiting, sales, and enrichment automation.

💬 [Anyone Can Silently Steal Your Files from your Claude AI chat - Live Demo](https://www.reddit.com/r/cybersecurity/comments/1tnixwn/anyone_can_silently_steal_your_files_from_your/)

r/cybersecurity · Reddit score 416 · 68 comments

The conversation focuses on agent data access and what users assume a chat interface can reach across desktop agents, browser agents, connected-file assistants, credentials, authorization boundaries, and file access.

💬 [Interview for AI security engineer position at a Fortune 500 company](https://www.reddit.com/r/cybersecurity/comments/1tdjhjf/interview_for_ai_security_engineer_position_at_a/)

r/cybersecurity · Reddit score 406 · 86 comments

The thread shows what practitioners expect from an AI security role: AppSec foundations, model behavior, prompt injection, threat modeling, vulnerability review, authorization, governance, detection, and practical controls around AI-enabled products.

---

# 🎥 Videos

1️⃣ [AppSec Security: The SDLC in the age of agentic](https://www.youtube.com/watch?v=9sEbUpS4eTY) - Jon McCoy at NDC Security 2026

2️⃣ [Securing Code in the Age of AI](https://www.youtube.com/watch?v=nKKNrgGuU8M) - Simona Toader at NDC Security 2026

3️⃣ [AI Agents and Jupyter Notebooks for Security Data Analysis](https://www.youtube.com/watch?v=VJPWZGhQe4A) - Roberto Rodriguez at NDC Security 2026

4️⃣ [MCP Security: Keep Your AI Agents from Spilling the Tea](https://www.youtube.com/watch?v=Myg3A-AVjyo) - Manfred Bjorlin and Awar Abdulkarim at NDC Security 2026

5️⃣ [The Most Dangerous Intern is an LLM: Abusing AI Agents Through Text](https://www.youtube.com/watch?v=hm0PxdJuWl4) - BSides Budapest 2026

6️⃣ [Security for AI Agents Using an Ensemble of Fine-tuned Models](https://www.youtube.com/watch?v=BEvFbJQCXDs) - Lidan Hazout and Bar Kaduri at BSidesSF 2026

7️⃣ [Your AI Agent Has Production Access: Now What?](https://www.youtube.com/watch?v=-3p2F5HWdSY) - Jack at BSidesSF 2026

8️⃣ [How We Red-Teamed Our Own AI Agent: Lessons from the Field](https://www.youtube.com/watch?v=6sYpcbpsxrc) - Josiah Peedikayil and HS at BSidesSF 2026

9️⃣ [Pwning and Defending AI Agent Code Interpreters](https://www.youtube.com/watch?v=Fdrm2tLVAwc) - Kinnaird McQuade at BSidesSF 2026

🔟 [MCPwned: Hacking MCP Servers with One Skeleton Key](https://www.youtube.com/watch?v=4_Om7f_2dro) - Jonathan Leitschuh at BSidesSF 2026

1️⃣1️⃣ [Prompt, Commit, Repeat: Security at Scale When 1,000 Devs Use AI Agents](https://www.youtube.com/watch?v=s8whRBI5Inc) - Balachandra Shanabhag at BSidesSF 2026

---

# 🤝 Let's Connect

If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
