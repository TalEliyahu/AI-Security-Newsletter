# AI Security Newsletter - May 2026

A monthly technical digest for AI security practitioners, researchers, builders, and security leaders tracking how AI systems fail, get attacked, and can be defended. This issue covers technical AI security research, vulnerability analysis, exploit chains, agent/tool abuse, AI malware, CVEs, newly created tools, non-vendor reports, upcoming events, practitioner discussions, and cybersecurity conference talks.

<p>
  <a href="https://innovguard.com">
    <img src="assets/innovguard-sponsor.png" alt="InnovGuard" width="360">
  </a>
</p>

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month’s issue is especially focused on coding-agent security, prompt injection as an execution boundary, MCP/tool abuse, AI developer supply-chain risk, and agent identity governance.

---

# 🔍 Insights

📌 [SymJack: the approval prompt is lying to you. A symlink-hijack RCE in six AI coding agents](https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/)

SymJack turns a harmless-looking file copy into a configuration overwrite for coding agents. The useful lesson is that approval dialogs must resolve symlinks and show the real write target, because a model can approve a benign-looking action while the operating system follows a link into agent configuration.

For defenders, the exploit path is a trust-boundary failure between model approval text and filesystem behavior. Mitigations should include symlink-aware path checks, sandboxed workspaces, authorization on configuration writes, and detection for agent config changes.

📌 [When prompts become shells: RCE vulnerabilities in AI agent frameworks](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)

Microsoft shows how prompt injection crossed into code execution in Semantic Kernel when untrusted text reached tool-backed filters and file-write behavior. For agent builders, the boundary is no longer the prompt alone - it is every framework path that can turn model-shaped input into host-side action.

The concrete risk is RCE through framework glue code: filters, tool calls, file writes, and plugin execution paths need threat modeling, sandbox isolation, authorization checks, and regression tests for hostile content.

📌 [Beyond source code: The files AI coding agents trust - and attackers exploit](https://cloud.google.com/blog/topics/threat-intelligence/beyond-source-code-the-files-ai-coding-agents-trust-and-attackers-exploit)

The attack surface around coding agents now includes instruction files, runtime settings, IDE extensions, and project automation, not just application source code. AppSec teams should treat agent-facing configuration as executable influence and scan it for intent, privilege changes, and hidden instructions.

That makes repository metadata part of the supply chain. Useful controls include detection for poisoned instructions, credential exposure checks, extension allowlists, sandboxed agent execution, and authorization review before automation changes run.

📌 [Copirate 365 at DEF CON: Plundering in the Depths of Microsoft Copilot](https://embracethered.com/blog/posts/2026/defcon-talk-copirate-365/)

Johann Rehberger walks through Copilot data-exfiltration paths, delayed tool invocation, and the uneven security contracts between AI widgets and their host applications. The practical takeaway is still sharp: audit logs, containment, and runtime-enforced feature allowlists matter more than trusting the assistant to self-police.

The failure mode is a trust-boundary break between untrusted content, assistant memory, and privileged Microsoft 365 actions. Teams should model exfiltration, require authorization for side effects, and add detection around unusual Copilot tool use.

📌 [Configuring Codex Securely Across Every Platform and Use Case](https://www.promptarmor.com/resources/configuring-codex-securely-across-every-platform-and-use-case)

PromptArmor maps Codex risk to concrete AI coding-agent controls: workspace app permissions, MCP server restrictions, action approvals, managed configuration, telemetry, and role-based feature access. The value is operational because it treats coding-agent security as authorization, monitoring, and configuration management, not just model behavior.

The checklist is strongest when used as a deployment threat model: restrict tool permissions, sandbox untrusted repositories, monitor command execution, detect policy bypass, and review credentials before agents can touch production workflows.

📌 [Comment and Control: One Prompt Injection Pattern Hijacked Claude Code, Gemini CLI, and GitHub Copilot Agent](https://getburnrate.io/blog)

The writeup turns the Comment and Control disclosure into an engineering checklist for CI-connected AI coding agents. The important pattern is prompt injection through untrusted GitHub content reaching agent actions through PR titles, issue comments, workflow triggers, credential access, and CI secrets.

The defensive line is the repository trust boundary. Treat comments, issues, and pull requests as hostile input, require authorization before tool invocation, isolate CI credentials, and add detection for agent actions triggered by external text.

📌 [AI agents are the new insider threat](https://www.reversinglabs.com/blog/ai-agents-new-insider-threat)

This piece frames agents as digital workers with credentials, expected behavior, and abnormal activity patterns. For defenders, that shifts monitoring from application logs alone to agent behavior analytics: what the agent accessed, what it usually does, and when it starts acting outside its role.

The practical model is non-human identity monitoring: credential scope, authorization drift, data access, tool invocation, and anomaly detection need to be reviewed the same way teams review privileged service accounts.

📌 [Vibe coding and agentic engineering are getting closer than I’d like](https://simonwillison.net/2026/May/6/vibe-coding-and-agentic-engineering/)

Simon Willison names a quiet failure mode in AI-assisted engineering: coding agents can produce convincing repositories, tests, and documentation faster than reviewers can establish trust. The security angle is review calibration - teams need provenance, runtime evidence, scoped permissions, and operational checks before treating agent-generated code as safe.

This is not an exploit writeup, but it gives security teams a useful threat model for agentic development: sandbox generated changes, verify tests independently, track provenance, and require authorization before agent-written code reaches deployment.

📌 [Evaluating MCP Servers for Security (2026)](https://futureagi.com/blog/evaluating-mcp-servers-security-2026/)

The MCP evaluation guidance focuses on tool-description injection, result tampering, sandbox escape, and cross-tenant isolation. The practical control point is evaluation before integration: MCP servers should be tested like privileged plugins, not accepted as neutral connectors.

Security review should cover MCP trust boundaries, authorization, credential handling, malicious tool output, and detection for unexpected tool invocation. That makes the guidance useful before an MCP server receives real data or production access.

📌 [Intel Deep Dive: TeamPCP/Shai-Hulud 3.0 AI-Targeted Tradecraft](https://www.dataminr.com/resources/cyber-intel-deep-dive-teampcp-shai-hulud-3-0/)

Dataminr ties the May Shai-Hulud activity to AI-targeted tradecraft, including Claude Code persistence hooks, package supply-chain abuse, and prompt-injection content designed to interfere with analysis. That makes the campaign relevant to teams securing AI-assisted development pipelines, developer credentials, and agent-accessible repositories.

The defender takeaway is supply-chain monitoring around AI developer tooling: watch for credential theft, malicious package behavior, persistence in agent configuration, and abuse paths that turn coding assistants into privileged execution points.

📌 [The 12-Message Prompt Injection Pattern: Why Single-Turn Defenses Are Dead](https://austa.ai/articles/multi-turn-prompt-injection-pattern-2026/)

Austa describes a multi-turn prompt-injection pattern that avoids obvious jailbreak language and accumulates influence over a conversation. The defensive point is that single-turn filters miss slow-burn attacks, so agent systems need stateful detection and tool-boundary controls.

Teams evaluating agents should test attack paths across memory, retrieved content, tool results, and delayed authorization. Mitigations need conversation-state monitoring, sandboxed tools, and policy checks at each side-effect boundary.

📌 [AI Agent Prompt Injection Is Now an Execution Boundary](https://openclawai.io/blog/ai-agent-prompt-injection-execution-boundary)

The article makes a clear distinction between text manipulation and execution risk. Once an agent can write files, call APIs, or run code, prompt injection becomes a question of privilege separation and tool authorization rather than only instruction hierarchy.

That moves mitigation into engineering controls: isolate execution, restrict credentials, log tool calls, detect unusual side effects, and require explicit authorization when untrusted content influences privileged action.

📌 [Prompt Injection in 2026: 7 Attack Patterns We See](https://cybersecify.com/blog/prompt-injection-2026-attack-patterns/)

The taxonomy separates prompt injection by entry point and persistence: direct input, retrieved content, RAG poisoning, tool chains, multi-turn manipulation, cross-agent transfer, and multimodal content. It gives red teams a useful checklist for coverage rather than treating prompt injection as one generic bug.

The value is practical coverage: each pattern maps to a different trust boundary, detection point, mitigation strategy, and abuse path that testers can add to agent and LLM application evaluations.

📌 [Prompt injection defenses that survive 2026](https://www.tmls.nyc/insights/field-notes/prompt-injection-defenses-that-survive-2026)

The defense model assumes that prompt injection defenses can fail and pushes mitigation into the tool boundary: allowlisted recipients, scoped database access, constrained side effects, authorization checks, and clear blast-radius decisions. That is the right framing for production AI agents that will eventually read hostile content.

It is useful because it separates detection from containment. Even if an injected instruction reaches the model, sandboxing, privilege limits, data-flow controls, and audit logs can keep the attack path from turning into unauthorized access.

📌 [When prompt injection turns an AI agent framework into host-level code execution](https://www.cantina.security/blog/prompt-injection-host-code-execution-ai-agents)

Cantina’s note is short, but the security point is concrete: framework behavior around file writes, execution, and sensitive tools determines whether prompt injection remains a content issue or becomes host compromise. That is the line AI product teams need to threat model.

The control lesson is to test framework defaults as code-execution surfaces: sandbox file writes, require authorization for command execution, isolate credentials, and add detection for tool calls influenced by untrusted content.

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

NIST summarizes CAISI RFI responses on agent security, including threat categories, authorization gaps, tool-use risks, mitigation needs, and where existing cybersecurity practices need adaptation for autonomous systems.

📘 **[Careful Adoption of Agentic AI Services](https://www.cyber.gov.au/sites/default/files/2026-05/careful_adoption_of_agentic_ai_services.pdf)**

The Five Eyes guidance gives security teams a practical AI agent adoption baseline: start with low-risk use cases, enforce strict privilege controls, monitor continuously, threat model tool access, and design deployments for containment, sandboxing, and reversibility.

📘 **[Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf?ver=bmgiSbNQLP6Z_GiWtRt6bg%3D%3D)**

NSA's guidance treats MCP as an AI automation trust-boundary problem, covering authorization, context handling, tool invocation, logging, deployment hardening, and operational controls for production agent workflows.

📘 **[Detecting Offensive Cyber Agents: A Detection-in-Depth Approach](https://www.iaps.ai/research/detecting-offensive-cyber-agents)**

IAPS frames autonomous cyber agents as a detection problem for defenders, proposing agent identifiers, agent honeypots, AI-assisted alert triage, an agentic security alert standard, and coordination mechanisms for disrupting offensive agent activity.

📘 **[Software Bill of Materials for AI - Minimum Elements](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html)**

The G7/CISA/BSI guidance defines minimum AI SBOM elements across models, datasets, software dependencies, services, hardware, deployment context, and security control metadata. Security teams can use that inventory for AI supply-chain review, threat modeling, vulnerability response, mitigation planning, dependency exposure analysis, and artifact validation.

📘 **[AIUC-1 Crosswalks - OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/aiuc-1-crosswalks-owasp-top-10-for-agentic-applications/)**

OWASP maps AI usage categories to the Agentic Applications Top 10, giving AppSec teams a control checklist for agent risks such as tool misuse, goal hijacking, memory poisoning, excessive agency, identity abuse, supply-chain exposure, monitoring gaps, and runtime containment.

📘 **[AI Security Maturity Model](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model)**

CSA's AISMM gives security leaders a maturity model for operational AI security programs, with control objectives across governance, identity, monitoring, model security, application security, data security, supply chain, and incident response.

📘 **[Empowering Defenders: AI for Cybersecurity](https://www.weforum.org/publications/empowering-defenders-ai-for-cybersecurity/)**

The World Economic Forum white paper focuses on AI use inside cybersecurity operations, including detection support, alert triage, monitoring, human oversight, pilot validation, governance, and where agentic AI can change defender workflows without removing accountability from security teams.

📘 **[Shai-Hulud/Megalodon: A Two-Wave AI Developer Supply Chain Attack](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-megalodon-supply-chain-cascade/)**

CSA connects package-registry compromise and CI/CD backdooring to AI developer workflows, including persistence in coding tools, credential theft, malicious automation, and supply-chain trust failures that matter to agent-enabled engineering teams.

📘 **[Sub-4-Hour Weaponization of Agentic AI Frameworks](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentic-framework-rapid-exploitation-20260/)**

CSA uses PraisonAI exploitation timing to argue that exposed AI agent frameworks need authentication, network segmentation, vulnerability monitoring, exploit detection, and patch processes measured in hours rather than ordinary application release cycles.

📘 **[The Non-Human Identity Governance Vacuum](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nonhuman-identity-agentic-ai-governance-v1-cs/)**

The paper treats AI agent credentials as a non-human identity security problem, with emphasis on ownership, lifecycle, permission review, authorization boundaries, credential rotation, detection, and runtime behavior for autonomous systems.

---

# 🚨 CVEs

🛡️ [CVE-2026-41497](https://nvd.nist.gov/vuln/detail/CVE-2026-41497) - Critical 9.8 · PraisonAI MCP command handling. PraisonAI MCP command parsing can allow arbitrary executables through `parse_mcp_command`. For teams running AI agent orchestration, the RCE risk sits at an MCP trust boundary and needs sandboxing, authentication, authorization checks, and detection for unexpected command execution.

🛡️ [CVE-2026-7301](https://nvd.nist.gov/vuln/detail/CVE-2026-7301) - Critical 9.8 · SGLang multimodal scheduler ROUTER socket. SGLang exposed a ROUTER socket path where unsafe `pickle.loads` handling could become RCE. Model-serving infrastructure needs network isolation, scheduler authorization, exploit detection, and sandboxing around worker control planes.

🛡️ [CVE-2026-7304](https://nvd.nist.gov/vuln/detail/CVE-2026-7304) - Critical 9.8 · SGLang custom logit processor. SGLang custom logit processor loading used unsafe deserialization when the feature was enabled. Treat AI model-serving extension hooks as code execution boundaries that need sandboxing, authorization, vulnerability tests, and mitigation before exposure.

🛡️ [CVE-2026-31239](https://nvd.nist.gov/vuln/detail/CVE-2026-31239) - Critical 9.8 · Mamba model loading. The Mamba model framework used unsafe `torch.load()` behavior when loading Hugging Face models. This is an AI model supply-chain vulnerability where model artifacts become code execution inputs, so mitigation should include trusted sources, sandboxing, and artifact validation.

🛡️ [CVE-2026-44336](https://nvd.nist.gov/vuln/detail/CVE-2026-44336) - Critical 9.4 · PraisonAI default tool path handling. PraisonAI default tools allowed path traversal and arbitrary file write, with possible code execution through Python path behavior. Agent runtimes need filesystem allowlists, sandboxed tool paths, authorization, and detection for unexpected writes.

🛡️ [CVE-2026-42208](https://nvd.nist.gov/vuln/detail/CVE-2026-42208) - Critical 9.3 · LiteLLM proxy API key checks. LiteLLM proxy API key validation exposed SQL injection risk that could affect stored credentials and authorization state. LLM gateway databases should be treated as sensitive control planes with injection tests, monitoring, and mitigation.

🛡️ [CVE-2026-7302](https://nvd.nist.gov/vuln/detail/CVE-2026-7302) - Critical 9.1 · SGLang file write path handling. SGLang path traversal could allow arbitrary file writes. For AI model-serving and inference services, the attack path can move from exposed APIs to host compromise, so filesystem sandboxing, authorization, and write detection matter.

🛡️ [CVE-2026-5817](https://nvd.nist.gov/vuln/detail/CVE-2026-5817) - High 8.8 · Docker Model Runner / vLLM Metal remote model code loading. Docker Model Runner used `trust_remote_code=True` without sandboxing for vLLM Metal on macOS. Malicious OCI model content can cross from model supply chain into local code execution, so model-source authorization and sandboxing matter.

🛡️ [CVE-2026-45672](https://nvd.nist.gov/vuln/detail/CVE-2026-45672) - High 8.8 · Open WebUI code execution endpoint. Open WebUI allowed code execution through a utility endpoint even when code execution was configured off. AI app settings need negative tests, authorization checks, route monitoring, and mitigation showing disabled capabilities stay unreachable.

🛡️ [CVE-2026-42271](https://nvd.nist.gov/vuln/detail/CVE-2026-42271) - High 8.7 · LiteLLM MCP REST test endpoints. LiteLLM MCP test endpoints could spawn supplied stdio commands for authenticated users without sufficient role checks. MCP administration paths need strict authorization, role separation, command-execution monitoring, and sandboxing.

🛡️ [CVE-2026-47101](https://nvd.nist.gov/vuln/detail/CVE-2026-47101) - High 8.7 · LiteLLM API key route authorization. LiteLLM API key routes allowed privilege escalation. In model gateways, key-management bugs can expose downstream providers, credentials, users, and tenant data, so authorization tests and detection around key routes are required.

🛡️ [CVE-2026-47102](https://nvd.nist.gov/vuln/detail/CVE-2026-47102) - High 8.7 · LiteLLM user role self-update. LiteLLM role-management logic allowed users to escalate privileges through self-update behavior. Agent and gateway control planes need authorization tests, privilege-change monitoring, and mitigation around identity mutation endpoints.

🛡️ [CVE-2026-44338](https://nvd.nist.gov/vuln/detail/CVE-2026-44338) - High 7.3 · PraisonAI legacy API authentication bypass. PraisonAI shipped a legacy Flask API server with authentication disabled by default, exposing agent enumeration and workflow-triggering endpoints when reachable. The security value is the exploitation timing: public scanning reportedly started within hours of advisory publication, which makes exposed agent orchestration services an urgent inventory and patch target.

---

# 📅 Upcoming Conferences

## June 2026

📅 [38th Annual FIRST Conference (FIRSTCON26)](https://www.first.org/conference/2026/) - June 14-19, 2026 · Denver, CO, USA · Organizer: FIRST

Incident response, vulnerability disclosure, exploit coordination, and security operations matter for AI systems once agents, model gateways, and model-serving services become part of production infrastructure.

📅 [SiMLA 2026 - Security in Machine Learning and its Applications](https://simlaacns.github.io/) - June 22-25, 2026 · Stony Brook, NY, USA · Organizer: SiMLA / ACNS

Focused venue for machine-learning security, adversarial ML, model robustness, privacy leakage, poisoning, benchmark design, and practical evaluation methods that AI security teams can reuse.

## August 2026

📅 [IEEE CSR GenXSec 2026 - Generative and eXplainable AI for Security in Networking](https://www.ieee-csr.org/csr-genxsec/) - August 3-5, 2026 · Lisbon, Portugal · Organizer: IEEE CSR

Track for generative AI in network security, including detection, explainability, threat modeling, mitigation, and operational use of AI systems in defensive environments.

## October 2026

📅 [CAMLIS 2026 - Conference on Applied Machine Learning in Information Security](https://www.camlis.org/) - October 21-23, 2026 · Arlington, VA, USA · Organizer: CAMLIS

Applied ML security venue for defenders and researchers working on model behavior, detection, adversarial testing, vulnerability analysis, benchmark design, and security analytics.
---

# 📚 Research

📖 **LACUNA: Safe Agents as Recursive Program Holes**

For AI agent security teams, the paper treats unsafe agent behavior as a program-composition problem: execution holes need scoped authority, typed boundaries, authorization checks, and sandbox limits before an agent fills them with action. [arXiv](https://arxiv.org/abs/2605.28617)

📖 **MIRAGE: Context-Aware Prompt Injection against Mobile GUI Agents via User-Generated Content**

Mobile GUI agents inherit risk from user-generated content because screenshots, app text, and interface state can become indirect prompt-injection inputs. The paper is useful for testing visual-agent trust boundaries, attack paths, detection, and mitigation when agents browse feeds, reviews, comments, or chat surfaces. [arXiv](https://arxiv.org/abs/2605.28116)

📖 **Aligning Provenance with Authorization: A Dual-Graph Defense for LLM Agents**

The control idea is to bind what an agent is allowed to do to where information came from. Provenance and authorization become two linked graphs, giving defenders a threat model, mitigation path, and audit structure for preventing untrusted content from authorizing privileged tool use. [arXiv](https://arxiv.org/abs/2605.26497)

📖 **AgentSecBench: Measuring Prompt Injection, Privacy Leakage, and Tool-Use Integrity in LLM Agents**

AgentSecBench gives evaluators a way to test whether agents preserve tool-use integrity and privacy under prompt injection. That matters for buyers and builders who need repeatable evidence rather than one-off jailbreak demos. [arXiv](https://arxiv.org/abs/2605.26269)

📖 **How Agentic AI Coding Assistants Become the Attacker's Shell**

For AI coding assistants, the shell is the danger line: repository text, tool calls, terminal access, and developer approvals can combine into code execution. The paper gives AppSec teams another lens for reviewing agent permissions, workspace trust, sandboxing, credential exposure, and command-execution controls in developer environments. [arXiv](https://arxiv.org/abs/2605.25871)

📖 **IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization**

IterInject models indirect prompt injection as an optimization loop rather than a single clever payload. Red teams can use that framing to test whether defenses survive attacker iteration across tool outputs and retrieved content. [arXiv](https://arxiv.org/abs/2605.24659)

📖 **Poisoning the Watchtower: Prompt Injection Attacks Against LLM-Augmented Security Operations Through Adversarial Log Content**

Security copilots that summarize logs can be attacked through the logs themselves. The paper is a reminder that SOC data is not automatically trusted input once an LLM is part of triage, detection, alert enrichment, or investigation workflows. [arXiv](https://arxiv.org/abs/2605.24421)

📖 **Heartbeat-Bound Hierarchical Credentials: Cryptographic Revocation for AI Agent Swarms**

The paper focuses on revocation for multi-agent systems where subordinate agents need bounded credentials. The useful idea is that agent authority should expire and be revoked cryptographically, with authorization, credential lifecycle, monitoring, and mitigation handled outside prompt instruction. [arXiv](https://arxiv.org/abs/2605.20704)

📖 **Overeager Coding Agents: Measuring Out-of-Scope Actions on Benign Tasks**

Benign tasks can still produce unsafe behavior when AI coding agents edit files, call tools, or change state outside the requested scope. The paper gives reviewers an evaluation method for measuring overreach, authorization failures, unsafe tool invocation, sandbox escapes, and mitigation gaps without relying on malicious prompts. [arXiv](https://arxiv.org/abs/2605.18583)

📖 **An Empirical Study of Privacy Leakage Chains via Prompt Injection in Black-Box Chatbot Environments**

Privacy leakage becomes a chain when injected instructions steer retrieval, memory, and response behavior across turns. The paper is relevant to teams testing black-box assistants where source code and system prompts are unavailable. [arXiv](https://arxiv.org/abs/2605.18133)

📖 **LivePI: More Realistic Benchmarking of Agents Against Indirect Prompt Injection**

LivePI pushes prompt-injection testing closer to deployed agents by using live interaction paths instead of static prompt suites. That helps practitioners see which controls survive real tool use and changing web content. [arXiv](https://arxiv.org/abs/2605.17986)

📖 **ESLD: A Latent-Space Architecture for Faster, Stronger Prompt-Injection Defense**

The defense moves prompt-injection detection into latent-space signals rather than relying only on surface text. It is worth tracking because production filters need to catch encoded, indirect, and paraphrased instruction attacks before they trigger tool invocation, data leakage, policy bypass, or unsafe agent action. [arXiv](https://arxiv.org/abs/2605.18918)

📖 **Remembering More, Risking More: Longitudinal Safety Risks in Memory-Equipped LLM Agents**

Persistent memory changes the threat model because poisoned or sensitive context can survive across sessions. The paper gives teams a reason to segment memory, label provenance, audit carry-forward data, detect poisoning, and mitigate privacy leakage in memory-equipped agents. [arXiv](https://arxiv.org/abs/2605.17830)

📖 **AI Agents May Always Fall for Prompt Injections**

The paper argues that prompt injection remains structurally hard for AI agents that must process untrusted content and follow instructions. The practical implication is to design external controls for tools, data flow, authorization, sandboxing, detection, and permissions rather than waiting for a purely model-level fix. [arXiv](https://arxiv.org/abs/2605.17634)

📖 **ASPI: Seeking Ambiguity Clarification Amplifies Prompt Injection Vulnerability in LLM Agents**

Clarification turns out to be an attack state: when an agent asks for more information, it may expose a new path for injected content to shape the next tool action. Agent evaluations should include ambiguous tasks, authorization checks, detection, and mitigation, not only fully specified prompts. [arXiv](https://arxiv.org/abs/2605.17324)

📖 **Unsafe by Flow: Uncovering Bidirectional Data-Flow Risks in MCP Ecosystem**

For MCP security, the paper focuses on bidirectional data flow: what tools receive from agents and what agents accept back from tools. The useful threat model is data leakage, confused-deputy behavior, tool-result tampering, authorization failure, and mitigation at the agent-tool boundary. [arXiv](https://arxiv.org/abs/2605.07836)

📖 **Adversarial Machine Learning: A 20-Year Survey of Attacks, Defenses, and Standards**

This survey organizes two decades of adversarial ML work across attacks, defenses, evaluation methods, and standards. It is useful as a reference point for teams aligning model security testing with robustness, model lifecycle risk, deployment controls, and AI assurance work. [McGill publication page](https://dmas.lab.mcgill.ca/fung/publicationsByType.htm)

---

# 💬 Practitioner Discussions

💬 [Linus Torvalds says AI-powered bug hunters have made Linux security mailing list almost entirely unmanageable](https://www.reddit.com/r/cybersecurity/comments/1tgibc2/linus_torvalds_says_aipowered_bug_hunters_have/)

The thread surfaces a real maintainer problem: AI-assisted vulnerability reports can increase volume and detail without improving exploitability, reproduction quality, or triage capacity. Security teams adopting AI bug-finding need validation gates, duplicate detection, evidence standards, and mitigation notes before sending findings upstream.

💬 [VP Requested Full API Access to the ERP for Claude Integration](https://www.reddit.com/r/sysadmin/comments/1tdymin/vp_requested_full_api_access_to_the_erp_for/)

The thread captures the access-control problem in plain operational terms: business pressure can push agents toward broad credentials before security has defined scope, approval, logging, revocation, authorization, and monitoring.

💬 [LinkedIn user hides AI prompt injection in bio to force recruitment spam to be sent in Olde English prose](https://www.reddit.com/r/cybersecurity/comments/1tgl37m/linkedin_user_hides_ai_prompt_injection_in_bio_to/)

The example is playful, but the mechanism is serious: scraped profile text becomes untrusted instructions for downstream automation. Recruiting, sales, and enrichment agents need trust-boundary checks, prompt-injection detection, sandboxed actions, and authorization before external profile data influences tool use.

💬 [Anyone Can Silently Steal Your Files from your Claude AI chat - Live Demo](https://www.reddit.com/r/cybersecurity/comments/1tnixwn/anyone_can_silently_steal_your_files_from_your/)

The conversation focuses on agent data access and what users assume a chat interface can reach. It is useful for threat modeling desktop agents, browser agents, connected-file assistants, credential boundaries, authorization checks, and monitoring for unusual file access.

💬 [Interview for AI security engineer position at a Fortune 500 company](https://www.reddit.com/r/cybersecurity/comments/1tdjhjf/interview_for_ai_security_engineer_position_at_a/)

The thread shows what practitioners expect from an AI security role: AppSec foundations, model behavior, prompt injection, threat modeling, vulnerability review, authorization, governance, detection, and practical controls around AI-enabled products.

---

# 🎥 Videos

1️⃣ [AppSec Security: The SDLC in the age of agentic](https://www.youtube.com/watch?v=9sEbUpS4eTY) - Jon McCoy at NDC Security 2026

Why watch: maps agentic coding into the SDLC, where AppSec needs threat modeling, vulnerability review, authorization gates, detection, and runtime controls for AI-generated changes.

2️⃣ [Securing Code in the Age of AI](https://www.youtube.com/watch?v=nKKNrgGuU8M) - Simona Toader at NDC Security 2026

Why watch: useful for teams adjusting secure code review, vulnerability triage, threat modeling, prompt-injection review, sandboxing, and developer workflows around AI coding agents.

3️⃣ [AI Agents and Jupyter Notebooks for Security Data Analysis](https://www.youtube.com/watch?v=VJPWZGhQe4A) - Roberto Rodriguez at NDC Security 2026

Why watch: shows how notebook-based AI agents can support security data analysis while still requiring authorization around data access, credential exposure, notebook sandboxing, code execution, and tool execution.

4️⃣ [MCP Security: Keep Your AI Agents from Spilling the Tea](https://www.youtube.com/watch?v=Myg3A-AVjyo) - Manfred Bjorlin and Awar Abdulkarim at NDC Security 2026

Why watch: focuses on MCP security boundaries, tool invocation risk, authorization checks, sandboxing, agent data leakage, and practical controls for tool-connected AI assistants.

5️⃣ [The Most Dangerous Intern is an LLM: Abusing AI Agents Through Text](https://www.youtube.com/watch?v=hm0PxdJuWl4) - BSides Budapest 2026

Why watch: frames untrusted text as an abuse channel for AI agents, with practical implications for trust boundaries, tool authorization, sandboxing, detection, and mitigation.

6️⃣ [Security for AI Agents Using an Ensemble of Fine-tuned Models](https://www.youtube.com/watch?v=BEvFbJQCXDs) - Lidan Hazout and Bar Kaduri at BSidesSF 2026

Why watch: covers a defensive architecture for agent security that uses multiple tuned models to detect policy bypass, unsafe tool invocation, abuse paths, and risky behavior instead of trusting one guardrail.

7️⃣ [Your AI Agent Has Production Access: Now What?](https://www.youtube.com/watch?v=-3p2F5HWdSY) - Jack at BSidesSF 2026

Why watch: directly addresses the deployment problem: agents with production permissions need identity, authorization, credential controls, monitoring, detection, and rollback plans.

8️⃣ [How We Red-Teamed Our Own AI Agent: Lessons from the Field](https://www.youtube.com/watch?v=6sYpcbpsxrc) - Josiah Peedikayil and HS at BSidesSF 2026

Why watch: gives red-team lessons from testing an AI agent, including attack paths, bypass findings, mitigation gaps, detection ideas, and defensive findings teams can adapt to their own systems.

9️⃣ [Pwning and Defending AI Agent Code Interpreters](https://www.youtube.com/watch?v=Fdrm2tLVAwc) - Kinnaird McQuade at BSidesSF 2026

Why watch: code interpreters turn model output into execution, so the talk is relevant for sandboxing, file access, exploit containment, authorization, credential exposure, and mitigation.

🔟 [MCPwned: Hacking MCP Servers with One Skeleton Key](https://www.youtube.com/watch?v=4_Om7f_2dro) - Jonathan Leitschuh at BSidesSF 2026

Why watch: focuses on MCP server exploitation and shared-key failure modes that can break trust between agents and tools, with lessons for authorization, credential isolation, detection, and mitigation.

1️⃣1️⃣ [Prompt, Commit, Repeat: Security at Scale When 1,000 Devs Use AI Agents](https://www.youtube.com/watch?v=s8whRBI5Inc) - Balachandra Shanabhag at BSidesSF 2026

Why watch: useful for organizations rolling out AI coding agents at scale, where secure defaults, vulnerability review, authorization, sandboxing, detection, and developer guardrails need to hold across many teams.

---

# 🤝 Let's Connect

If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
