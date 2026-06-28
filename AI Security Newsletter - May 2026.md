# AI Security Newsletter - May 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://www.awesomeaisecurity.com/).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

<p align="center">
  <a href="https://innovguard.com">
    <img src="assets/innovguard-sponsor.png" alt="InnovGuard" width="360">
  </a>
</p>

---

# 🔍 Insights

📌 [SymJack: the approval prompt is lying to you. A symlink-hijack RCE in six AI coding agents](https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/)

SymJack turns a harmless-looking file copy into a configuration overwrite for coding agents. The useful lesson is that approval dialogs must resolve symlinks and show the real write target, because a model can approve a benign-looking action while the operating system follows a link into agent configuration.

📌 [When prompts become shells: RCE vulnerabilities in AI agent frameworks](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)

Microsoft shows how prompt injection crossed into code execution in Semantic Kernel when untrusted text reached tool-backed filters and file-write behavior. The failure sits at the framework boundary where model-shaped input can become host-side action through filters, tool calls, file writes, and plugin execution paths.

📌 [Beyond source code: The files AI coding agents trust - and attackers exploit](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access)

The attack surface around coding agents now includes instruction files, runtime settings, IDE extensions, and project automation, not just application source code. These files become executable influence when agents trust local context, credentials, and build automation during development.

📌 [Copirate 365 at DEF CON: Plundering in the Depths of Microsoft Copilot](https://embracethered.com/blog/posts/2026/defcon-talk-copirate-365/)

Johann Rehberger walks through Copilot data-exfiltration paths, delayed tool invocation, and the uneven security contracts between AI widgets and their host applications. The practical takeaway is still sharp: audit logs, containment, and runtime-enforced feature allowlists matter more than trusting the assistant to self-police.

📌 [Configuring Codex Securely Across Every Platform and Use Case](https://www.promptarmor.com/resources/configuring-codex-securely-across-every-platform-and-use-case)

PromptArmor maps Codex risk to concrete AI coding-agent controls: workspace app permissions, MCP server restrictions, action approvals, managed configuration, telemetry, and role-based feature access. The value is operational because it treats coding-agent security as authorization, monitoring, and configuration management, not just model behavior.

📌 [Comment and Control: How One Prompt Injection Hit Claude Code, Gemini CLI, and Copilot Agent](https://repello.ai/blog/comment-and-control-claude-code-gemini-copilot-prompt-injection)

The writeup turns the Comment and Control disclosure into an engineering checklist for CI-connected AI coding agents. The important pattern is prompt injection through untrusted GitHub content reaching agent actions through PR titles, issue comments, workflow triggers, credential access, and CI secrets.

📌 [AI agents are the new insider threat](https://www.reversinglabs.com/blog/ai-agents-new-insider-threat)

This piece frames agents as digital workers with credentials, expected behavior, and abnormal activity patterns. The security model shifts from application logs alone to agent behavior analytics: what the agent accessed, what it usually does, and when it starts acting outside its role.

📌 [Vibe coding and agentic engineering are getting closer than I’d like](https://simonwillison.net/2026/May/6/vibe-coding-and-agentic-engineering/)

Simon Willison names a quiet failure mode in AI-assisted engineering: coding agents can produce convincing repositories, tests, and documentation faster than reviewers can establish trust. The security angle is review calibration - teams need provenance, runtime evidence, scoped permissions, and operational checks before treating agent-generated code as safe.

📌 [Evaluating MCP Servers for Security (2026)](https://futureagi.com/blog/evaluating-mcp-servers-security-2026/)

The MCP evaluation guidance focuses on tool-description injection, result tampering, sandbox escape, and cross-tenant isolation. The practical control point is evaluation before integration: MCP servers should be tested like privileged plugins, not accepted as neutral connectors.

📌 [Intel Deep Dive: TeamPCP/Shai-Hulud 3.0 AI-Targeted Tradecraft](https://www.dataminr.com/resources/cyber-intel-deep-dive-teampcp-shai-hulud-3-0/)

Dataminr ties the May Shai-Hulud activity to AI-targeted tradecraft, including Claude Code persistence hooks, package supply-chain abuse, and prompt-injection content designed to interfere with analysis. The campaign puts pressure on controls around developer credentials, malicious package behavior, persistence in agent configuration, and agent-accessible repositories.

📌 [The 12-Message Prompt Injection Pattern: Why Single-Turn Defenses Are Dead](https://austa.ai/articles/multi-turn-prompt-injection-pattern-2026/)

Austa describes a multi-turn prompt-injection pattern that avoids obvious jailbreak language and accumulates influence over a conversation. The defensive point is that single-turn filters miss slow-burn attacks, so agent systems need stateful detection and tool-boundary controls.

📌 [AI Agent Prompt Injection Is Now an Execution Boundary](https://openclawai.io/blog/ai-agent-prompt-injection-execution-boundary)

The article makes a clear distinction between text manipulation and execution risk. Once an agent can write files, call APIs, or run code, prompt injection becomes a question of privilege separation and tool authorization rather than only instruction hierarchy.

📌 [Prompt Injection in 2026: 7 Attack Patterns We See](https://cybersecify.com/blog/prompt-injection-2026-attack-patterns/)

The taxonomy separates prompt injection by entry point and persistence: direct input, retrieved content, RAG poisoning, tool chains, multi-turn manipulation, cross-agent transfer, and multimodal content. It gives red teams a useful checklist for coverage rather than treating prompt injection as one generic bug.

📌 [Prompt injection defenses that survive 2026](https://www.tmls.nyc/insights/field-notes/prompt-injection-defenses-that-survive-2026)

The defense model assumes that prompt injection defenses can fail and pushes mitigation into the tool boundary: allowlisted recipients, scoped database access, constrained side effects, authorization checks, and clear blast-radius decisions. That is the right framing for production AI agents that will eventually read hostile content.

📌 [When prompt injection turns an AI agent framework into host-level code execution](https://www.cantina.security/blog/prompt-injection-host-code-execution-ai-agents)

Cantina’s note is short, but the security point is concrete: framework behavior around file writes, execution, and sensitive tools determines whether prompt injection remains a content issue or becomes host-level code execution. That is the line AI product teams need to threat model.

📌 [Why Policy in Amazon Bedrock AgentCore chose Cedar for securing agentic workflows](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)

AWS describes how Bedrock AgentCore uses Cedar-backed policy checks around agent actions, resources, users, and context. The useful security pattern is moving authorization out of model instruction-following and into deterministic runtime enforcement for tool use and side effects.

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

🧰 **[OpenOSINT](https://github.com/OpenOSINT/OpenOSINT)** - OSINT agent with MCP server and CLI support for authorized security research, evidence collection, credential-risk review, investigation workflows, detection notes, and tool-boundary testing. ⭐️193

🧰 **[Adrian](https://github.com/secureagentics/Adrian)** - Runtime monitoring and control layer for AI agents, focused on visibility, authorization decisions, unsafe tool actions, and behavioral detection. ⭐️112

🧰 **[promptzero](https://github.com/openbashok/promptzero)** - Transparent Claude API proxy that anonymizes sensitive data before it leaves the local environment, reducing credential exposure and privacy leakage in AI-assisted workflows. ⭐️39

🧰 **[redlyne](https://github.com/redlyne-ai/redlyne)** - VS Code-oriented security tool for detecting, triaging, and patching vulnerabilities in AI-generated Python code, with review flow around exploitability, mitigation, and deployment risk. ⭐️37

🧰 **[skill-scanner-agent](https://github.com/HuTa0kj/skill-scanner-agent)** - Scanner for agent skill packages that checks risky instructions, prompt-injection behavior, unsafe permissions, tool authorization, detection signals, and mitigation notes before use. ⭐️32

🧰 **[bughunter-ai](https://github.com/h4ckologic/bughunter-ai)** - Autonomous bug-bounty framework that wires Claude Code, Burp MCP, credential vaulting, attack-path discovery, vulnerability validation, and mitigation notes for authorized testing. ⭐️22

🧰 **[PROMPTPurify](https://github.com/securelayer7/PROMPTPurify)** - Prompt-injection guardrail project for filtering hostile user or tool-output content, evaluating bypass behavior, and adding detection before unsafe agent tool invocation. ⭐️17

---

# 📄 Reports

📘 **[Summary Analysis of Responses to the Request for Information Regarding Security Considerations for AI Agents](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)**

NIST summarizes CAISI RFI responses on agent security, including threat categories, authorization gaps, tool-use risks, mitigation needs, and where existing cybersecurity practices need adaptation for autonomous systems.

📘 **[Careful Adoption of Agentic AI Services](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/)**

The Five Eyes guidance gives security teams a practical AI agent adoption baseline: start with low-risk use cases, enforce strict privilege controls, monitor continuously, threat model tool access, and design deployments for containment, sandboxing, and reversibility.

📘 **[Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf?ver=bmgiSbNQLP6Z_GiWtRt6bg%3D%3D)**

NSA’s MCP guidance turns the month’s agent-security theme into concrete design review areas: access control, context serialization, approval workflows, token/session handling, audit logs, denial-of-service paths, and real MCP exploitation patterns.

📘 **[Detecting Offensive Cyber Agents: A Detection-in-Depth Approach](https://www.iaps.ai/research/detecting-offensive-cyber-agents)**

IAPS frames offensive cyber agents as systems that can plan, call tools, and adapt across attack stages. The report is useful for defenders because it maps detection points across planning, execution, infrastructure use, and tool behavior instead of treating AI-enabled attacks as ordinary automation.

📘 **[Software Bill of Materials for AI - Minimum Elements](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html)**

BSI and public-sector partners define minimum AI SBOM elements for models, datasets, components, licenses, provenance, and security-relevant dependencies. The guidance matters for teams trying to make AI supply-chain reviews auditable instead of relying on informal model or package inventories.

📘 **[AIUC-1 Crosswalks - OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/aiuc-1-crosswalks-owasp-top-10-for-agentic-applications/)**

OWASP maps AI user/control weaknesses to the Top 10 for Agentic Applications. The crosswalk helps security teams connect agent risks such as tool misuse, excessive agency, authorization gaps, and untrusted content to a review framework they can use in assessments.

📘 **[Shai-Hulud/Megalodon: A Two-Wave AI Developer Supply Chain Attack](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-megalodon-supply-chain-cascade/)**

CSA connects package-registry compromise and CI/CD backdooring to AI developer workflows, including persistence in coding tools, credential theft, malicious automation, and supply-chain trust failures that matter to agent-enabled engineering teams.

📘 **[Sub-4-Hour Weaponization of Agentic AI Frameworks](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentic-framework-rapid-exploitation-20260/)**

CSA uses PraisonAI exploitation timing to argue that exposed AI agent frameworks need authentication, network segmentation, vulnerability monitoring, exploit detection, and patch processes measured in hours rather than ordinary application release cycles.

📘 **[The Non-Human Identity Governance Vacuum](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nonhuman-identity-agentic-ai-governance-v1-cs/)**

The paper treats AI agent credentials as a non-human identity security problem, with emphasis on ownership, lifecycle, permission review, authorization boundaries, credential rotation, detection, and runtime behavior for autonomous systems.

📘 **[AI Security Maturity Model](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model)**

CSA's maturity model gives teams a control framework for AI security program development, including governance, risk management, model/application controls, monitoring, and operational readiness. It is most useful as a baseline for comparing internal AI security practices against repeatable maturity levels.

📘 **[Empowering Defenders: AI for Cybersecurity](https://www.weforum.org/publications/empowering-defenders-ai-for-cybersecurity/)**

The World Economic Forum report looks at where AI can help defenders in security operations, detection, response, and workforce scaling. The security value is in the operating model: teams still need trustworthy data pipelines, human oversight, evaluation, and controls around AI-assisted defensive workflows.

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

📅 [SiMLA 2026 - Security in Machine Learning and its Applications](https://simlaacns.github.io/) - June 22-25, 2026 · Stony Brook, NY, USA · Organizer: SiMLA / ACNS

## August 2026

📅 [IEEE CSR GenXSec 2026 - Generative and eXplainable AI for Security in Networking](https://www.ieee-csr.org/csr-genxsec/) - August 3-5, 2026 · Lisbon, Portugal · Organizer: IEEE CSR

📅 [Black Hat USA 2026 - AI Summit](https://blackhat.com/us-26/ai-summit.html) - August 4, 2026 · Las Vegas, NV, USA · Organizer: Black Hat

## October 2026

📅 [CAMLIS 2026 - Conference on Applied Machine Learning in Information Security](https://www.camlis.org/) - October 21-23, 2026 · Arlington, VA, USA · Organizer: CAMLIS

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · Austin, TX, USA · Organizer: IEEE

## November 2026

📅 [19th ACM Workshop on Artificial Intelligence and Security (AISec 2026)](https://aisec.cc/) - November 15-19, 2026 · The Hague, Netherlands · Organizer: ACM AISec

---

# 📚 Research

📖 **GenAI-Driven Threat Detection with Microsoft Security Copilot**

The paper introduces the Dynamic Threat Detection Agent, an always-on adaptive agent inside Microsoft Security Copilot that investigates Microsoft Defender incidents, builds activity timelines, generates attack-specific hypotheses, validates outputs with schema and grounding constraints, and creates explainable detections. [arXiv](https://arxiv.org/abs/2605.20896)

📖 **Beyond Zero: Enterprise Security for the AI Era**

The paper argues that application-level zero trust is not enough for autonomous AI agents and high-velocity enterprise data access. Its security model moves authorization closer to each operation, with per-resource and per-method decisions, action-level trust boundaries, and machine-speed access checks for both humans and agents. [arXiv](https://arxiv.org/abs/2605.22985)

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

The defense moves prompt-injection detection into latent-space signals rather than relying only on surface text. It is worth tracking because production filters need to catch encoded, indirect, and paraphrased instruction attacks before they trigger tool invocation, policy bypass, or unsafe agent action. [arXiv](https://arxiv.org/abs/2605.18918)

📖 **Remembering More, Risking More: Longitudinal Safety Risks in Memory-Equipped LLM Agents**

Persistent memory changes the threat model because poisoned or sensitive context can survive across sessions. The paper gives teams a reason to segment memory, label provenance, audit carry-forward data, detect poisoning, and mitigate privacy leakage in memory-equipped agents. [arXiv](https://arxiv.org/abs/2605.17830)

📖 **AI Agents May Always Fall for Prompt Injections**

The paper argues that prompt injection remains structurally hard for AI agents that must process untrusted content and follow instructions. The practical implication is to design external controls for tools, data flow, authorization, sandboxing, detection, and permissions rather than waiting for a purely model-level fix. [arXiv](https://arxiv.org/abs/2605.17634)

📖 **ASPI: Seeking Ambiguity Clarification Amplifies Prompt Injection Vulnerability in LLM Agents**

Clarification turns out to be an attack state: when an agent asks for more information, it may expose a new path for injected content to shape the next tool action. Agent evaluations should include ambiguous tasks, authorization checks, detection, and mitigation, not only fully specified prompts. [arXiv](https://arxiv.org/abs/2605.17324)

📖 **Unsafe by Flow: Uncovering Bidirectional Data-Flow Risks in MCP Ecosystem**

For MCP security, the paper focuses on bidirectional data flow: what tools receive from agents and what agents accept back from tools. The useful threat model is cross-boundary data exposure, confused-deputy behavior, tool-result tampering, authorization failure, and mitigation at the agent-tool boundary. [arXiv](https://arxiv.org/abs/2605.07836)

---

# 💬 Practitioner Discussions

💬 [Linus Torvalds says AI-powered bug hunters have made Linux security mailing list almost entirely unmanageable](https://www.reddit.com/r/cybersecurity/comments/1tgibc2/linus_torvalds_says_aipowered_bug_hunters_have/)

The thread surfaces a real maintainer problem: AI-assisted vulnerability reports can increase volume and detail without improving exploitability, reproduction quality, or triage capacity. Security teams adopting AI bug-finding need validation gates, duplicate detection, evidence standards, and mitigation notes before sending findings upstream.

💬 [VP Requested Full API Access to the ERP for Claude Integration](https://www.reddit.com/r/sysadmin/comments/1tdymin/vp_requested_full_api_access_to_the_erp_for/)

The thread captures the access-control problem in plain operational terms: business pressure can push agents toward broad credentials before security has defined scope, approval, logging, revocation, authorization, threat modeling, and monitoring.

💬 [LinkedIn user hides AI prompt injection in bio to force recruitment spam to be sent in Olde English prose](https://www.reddit.com/r/cybersecurity/comments/1tgl37m/linkedin_user_hides_ai_prompt_injection_in_bio_to/)

The example is playful, but the mechanism is serious: scraped profile text becomes untrusted instructions for downstream automation. Recruiting, sales, and enrichment agents need trust-boundary checks, instruction-injection detection, sandboxed actions, and authorization before external profile data influences tool use.

💬 [Anyone Can Silently Steal Your Files from your Claude AI chat - Live Demo](https://www.reddit.com/r/cybersecurity/comments/1tnixwn/anyone_can_silently_steal_your_files_from_your/)

The conversation focuses on agent data access and what users assume a chat interface can reach. It is useful for threat modeling desktop agents, browser agents, connected-file assistants, credential boundaries, authorization checks, and monitoring for unusual file access.

💬 [Interview for AI security engineer position at a Fortune 500 company](https://www.reddit.com/r/cybersecurity/comments/1tdjhjf/interview_for_ai_security_engineer_position_at_a/)

The thread shows what practitioners expect from an AI security role: AppSec foundations, model behavior, agent abuse, threat modeling, vulnerability review, authorization, governance, detection, and practical controls around AI-enabled products.

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
