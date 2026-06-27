# AI Security Newsletter - June 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://www.awesomeaisecurity.com/).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - *Innovate and Invest with Confidence, Lead with Assurance.*

<p>
  <a href="https://innovguard.com">
    <img src="assets/innovguard-sponsor.png" alt="InnovGuard" width="360">
  </a>
</p>

---

# 🔍 Insights

📌 [Updating our taxonomy: Failure modes in agentic AI systems](https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/)
Microsoft expands its agentic-AI failure-mode taxonomy from red-team work, giving security teams a cleaner way to reason about tool misuse, excessive agency, memory contamination, identity boundaries, and human-override gaps in deployed agent systems.

📌 [Miasma Worm hits Microsoft again: Azure Functions Action and 72 other repositories disabled after supply chain attack targeting AI coding agents](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents)
StepSecurity documents a supply-chain campaign aimed at AI coding-agent workflows and GitHub repositories, with the defensive focus on dependency trust, action provenance, repository write paths, and agent-visible credentials in CI/CD environments.

📌 [Codex CLI RCE: Prompt injection mitigations](https://cymulate.com/blog/codex-cli-rce-prompt-injection-mitigations/)
Cymulate walks through prompt-injection risk in command-line coding agents, where untrusted text can steer file writes or tool execution unless sandboxing, approval boundaries, and command constraints are enforced outside the model.

📌 [The smart TV in your living room is a node in the AI-scraping economy](https://blog.includesecurity.com/2026/06/the-smart-tv-in-your-livingroom-is-a-node-in-the-aiscraping-economy/)
Include Security traces how consumer-device telemetry can become part of broader AI data collection pipelines, making the security question less about one device and more about opaque data flows, user consent, and downstream model-facing enrichment.

📌 [Prompt injection and agent runtime security](https://www.tmls.nyc/research/prompt-injection-agent-security)
TMLS frames prompt injection as a runtime security problem for agents, where the practical boundary sits around tool calls, retrieved content, permissions, logging, and side effects rather than prompt wording alone.

📌 [MCP prompt injection surface: securing agents in 2026](https://www.keepmyprompts.com/en/blog/mcp-prompt-injection-surface-secure-agents-2026)
KeepMyPrompts maps MCP prompt-injection exposure across tool descriptions, server responses, and agent decisions, which is useful for teams reviewing MCP servers before they connect them to production data or privileged actions.

📌 [Agentjacking: MCP Injection Hijacks AI Coding Agents](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentjacking-mcp-sentry-injection-20260612/)
Cloud Security Alliance summarizes the Sentry-to-MCP "agentjacking" pattern, where externally controlled telemetry or issue content becomes trusted context for coding agents. The useful defensive frame is to treat observability, bug-report, and integration data as untrusted agent input, not as neutral development metadata.

📌 [Five Eyes warns AI is enabling malicious cyber activity](https://www.nsa.gov/Press-Room/News-Highlights/Tag/280930/artifical-intelligence/)
Five Eyes cyber agencies warn that adversaries are using AI to improve reconnaissance, phishing, malware adaptation, and vulnerability discovery. The defensive signal is that AI-assisted attack activity is now a mainstream intelligence concern, not a niche application-security topic.

📌 [Breaking LiteLLM: From Low-Privilege User to Admin and RCE](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)
Obsidian documents a chained LiteLLM privilege-escalation and RCE path, showing how low-privilege access to an AI gateway can become administrative control. For defenders, the case argues for separating gateway administration, model-provider secrets, MCP testing functions, and runtime agent permissions.

📌 [NIST Mathematical Proof Supports Transition to a Continuous-Monitor-and-Update Security Model for AI Systems](https://www.nist.gov/news-events/news/2026/06/nist-mathematical-proof-supports-transition-continuous-monitor-and-update)
NIST highlights why fixed AI guardrails cannot be treated as complete protection against adaptive prompts. The practical security takeaway is to pair guardrails with continuous evaluation, runtime containment, monitoring, and update loops instead of treating a static rule set as a durable control boundary.

📌 [Prompt injection still drives most agentic AI security failures in new OWASP report](https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/)
Help Net Security pulls out the key operational shift in OWASP's latest agentic-security report: prompt injection has moved from theoretical concern to documented incidents, advisories, and breach patterns. The pressure is now on engineering teams to secure tool use, identity, memory, and approvals around agents.

📌 [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
OWASP's agentic application list gives teams a concrete control vocabulary for excessive agency, tool misuse, context poisoning, authorization failures, memory risk, and agent supply-chain exposure. It is useful as a review checklist for agent features before they receive production credentials or write access.

📌 [Security Considerations for Model Context Protocol Implementations in AI Agent Systems](https://datatracker.ietf.org/doc/html/draft-mohiuddin-mcp-security-considerations-00)
This IETF Internet-Draft frames MCP security at the protocol and implementation layer, including transport, authentication, authorization, tool exposure, and data-flow concerns. It helps security reviewers separate MCP as a protocol from the specific trust decisions made by each server, client, and agent host.

📌 [The AI Agent Lethal Trifecta](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-lethal-trifecta-capability-securi/)
CSA Labs applies the "lethal trifecta" lens to agent deployments: access to private data, exposure to untrusted content, and the ability to trigger external side effects. That framing is useful because most serious agent failures appear when all three are present in one workflow.

📌 [LLM Agents as Offensive Post-Exploitation Tools](https://labs.cloudsecurityalliance.org/research/)
Cloud Security Alliance's June research archive includes work on LLM agents as post-exploitation tools, shifting the AI-security discussion from jailbreak demos to attacker operations after initial access. The defensive focus becomes containment, telemetry, credential scoping, and detecting agent-driven lateral movement.

---

# 🧰 Tools & Resources

🧰 **[prompt-gate](https://github.com/ShieldNet-360/prompt-gate)** - Local DLP and DNS-layer control for blocking unauthorized AI tools and inspecting outbound prompts for secrets or sensitive data before they leave the endpoint. ⭐️28

🧰 **[claude-ai-cyber-security-skills](https://github.com/0xGhostCAT/claude-ai-cyber-security-skills)** - Claude Code skill collection for security workflows, including offensive testing, defensive analysis, and tool-assisted investigation patterns. ⭐️17

🧰 **[talos](https://github.com/ory/talos)** - API-key and capability-token service for humans, services, and AI agents that need scoped machine-to-machine authorization. ⭐️14

🧰 **[Awesome-AI-Redteam](https://github.com/Threekiii/Awesome-AI-Redteam)** - Curated AI red-team knowledge base for prompt injection, jailbreaks, agent security, evaluation methods, and defensive references. ⭐️6

🧰 **[MCPAudit](https://github.com/MCP-Audit/MCPAudit)** - Offensive scanner for MCP servers that looks for exposed tools, unsafe configuration, and attack paths in agent integration surfaces. ⭐️6

🧰 **[delego](https://github.com/Delego-Dev/delego)** - Policy and audit layer for agent actions, designed to constrain delegated operations before autonomous systems reach sensitive workflows. ⭐️6

🧰 **[skillguard](https://github.com/mannanj/skillguard)** - Scanner for Claude Code skills that checks skill files for malicious commands, suspicious scripts, and unsafe execution patterns. ⭐️6

🧰 **[LLM-SafeRoute](https://github.com/lowoodz/LLM-SafeRoute)** - Local LLM API router with policy checks for data leakage, provider routing, and operational controls around model requests. ⭐️5

🧰 **[guardian-runtime](https://github.com/ashp15205/guardian-runtime)** - Runtime guardrail service for LLM applications that tracks prompt risk, data exposure, and token-cost behavior during inference calls. ⭐️5

🧰 **[claude-code-docker-container-demo](https://github.com/deancourse/claude-code-docker-container-demo)** - Docker and devcontainer template for running Claude Code inside a constrained development environment instead of a broad local workstation context. ⭐️4

🧰 **[redactr](https://github.com/vicsantiagobr/redactr)** - Client-side secret and PII scrubber for text sent to AI tools, pastebins, or other external services. ⭐️4

🧰 **[csreview](https://github.com/decksoftware/csreview)** - Local development-time review helper for checking AI-assisted code against security expectations before changes reach deployment workflows. ⭐️3

---

# 📄 Reports

📘 **[State of Agentic AI Security and Governance 2.01](https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance/)**

OWASP's June update turns agentic-AI security into a governance and engineering map, covering autonomous workflows, agent risk categories, controls, and the practical gap between early threat models and production incidents.

📘 **[Summary Analysis of Responses to the Request for Information Regarding Security Considerations for AI Agents](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)**

NIST summarizes CAISI RFI responses on AI-agent security, including authorization, tool-use risk, evaluation practices, mitigation needs, and the government support organizations want for secure agent adoption.

📘 **[Security Considerations for Model Context Protocol Implementations in AI Agent Systems](https://datatracker.ietf.org/doc/draft-mohiuddin-mcp-security-considerations/)**

The IETF draft gives implementers a protocol-level checklist for MCP security, including transport choices, authentication, authorization, tool descriptions, server trust, and deployment controls for agent systems.

📘 **[2026 State of Modern Application & AI Security](https://cloudsecurityalliance.org/artifacts/2026-state-of-modern-application-and-ai-security)**

Cloud Security Alliance examines how compressed exploitation timelines and AI-assisted vulnerability discovery change application-security priorities, with emphasis on runtime visibility, exploitability validation, and mitigation speed.

📘 **[Model Context Protocol: Security Design Considerations for AI-Driven Automation](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)**

NSA and international partners publish MCP security design guidance for AI-driven automation, covering authentication, authorization, server trust, transport controls, tool exposure, and monitoring for agent ecosystems moving from experiments into production.

---

# 🛡️ CVEs

🛡️ [CVE-2026-42074: OpenClaude sandbox disable flag exposes host execution](https://nvd.nist.gov/vuln/detail/CVE-2026-42074)
Critical 9.8. OpenClaude exposes a dangerous sandbox-disable path in a coding-agent CLI, making local agent execution boundaries dependent on configuration that can turn model-steered workflows into host-level command execution risk.

🛡️ [CVE-2026-25879: Langroid SQLChatAgent executes LLM-produced SQL](https://nvd.nist.gov/vuln/detail/CVE-2026-25879)
Critical 9.8. Langroid's SQLChatAgent can execute SQL generated by an LLM, putting database trust boundaries, query validation, and agent-mediated data access under direct security review.

🛡️ [CVE-2026-47117: OpenMed model-loading path allows code execution](https://nvd.nist.gov/vuln/detail/CVE-2026-47117)
Critical 9.8. OpenMed's privacy-filter model loading path can execute attacker-controlled model artifacts, reinforcing that model files and checkpoints need supply-chain controls before being loaded into sensitive systems.

🛡️ [CVE-2026-5241: Hugging Face Transformers LightGlue model loading RCE](https://nvd.nist.gov/vuln/detail/CVE-2026-5241)
Critical 9.6. Transformers' LightGlue loading path can turn model repository content into executable behavior, a model supply-chain issue for teams pulling artifacts from external model hubs.

🛡️ [CVE-2026-32625: LibreChat MCP environment resolution exposes secrets](https://nvd.nist.gov/vuln/detail/CVE-2026-32625)
Critical 9.6. LibreChat's MCP environment-variable handling can expose sensitive values through agent tool configuration, making MCP server setup, variable expansion, and secret scoping part of the security boundary.

🛡️ [CVE-2026-44211: Cline WebSocket hijack affects autonomous coding agent sessions](https://nvd.nist.gov/vuln/detail/CVE-2026-44211)
Critical 9.6. Cline's autonomous coding-agent control channel can be abused through cross-origin WebSocket behavior, putting browser trust, local agent ports, and session authorization in scope for agent runtime hardening.

🛡️ [CVE-2026-49121: AI Tensor Engine for ROCm message queue RCE](https://nvd.nist.gov/vuln/detail/CVE-2026-49121)
High 8.1. AITER's MessageQueue path can allow code execution in AI infrastructure, affecting teams that depend on ROCm acceleration for model training, inference, or benchmark workloads.


🛡️ [CVE-2026-38950: ESA AnomalyMatch checkpoint loading code execution](https://nvd.nist.gov/vuln/detail/CVE-2026-38950)
High 7.8. ESA AnomalyMatch can execute code during model checkpoint loading, another reminder that anomaly-detection pipelines still inherit unsafe deserialization and artifact-trust risks.

🛡️ [CVE-2026-4035: MLflow AI Gateway environment-variable exposure](https://nvd.nist.gov/vuln/detail/CVE-2026-4035)
High 7.7. MLflow AI Gateway can expose environment variables through gateway behavior, which matters for teams using ML platforms as the routing layer between applications, models, and service credentials.

---

# 📅 Upcoming Conferences

## August 2026

📅 [IEEE CSR GenXSec 2026](https://www.ieee-csr.org/csr-genxsec/) - August 3-5, 2026 · Lisbon, Portugal · Organizer: IEEE CSR

📅 [Black Hat USA 2026 - AI Summit](https://blackhat.com/us-26/ai-summit.html) - August 4, 2026 · Las Vegas, NV, USA · Organizer: Black Hat

## October 2026

📅 [CAMLIS 2026](https://www.camlis.org/) - October 21-23, 2026 · Arlington, VA, USA · Organizer: CAMLIS

📅 [GAISS 2026](https://gaiss.info/) - October 28-30, 2026 · Austin, TX, USA · Organizer: IEEE

## November 2026

📅 [ACM AISec 2026](https://aisec.cc/) - November 15-19, 2026 · The Hague, Netherlands · Organizer: ACM AISec

---

# 📚 Research

📖 **Will the Agent Recuse Itself? Measuring LLM-Agent Compliance with In-Band Access-Deny Signals**

Tests whether agents honor access-deny signals that appear inside the task context, a useful benchmark for teams relying on agents to stop when authorization changes are expressed through content rather than a hard external policy gate. [arXiv](https://arxiv.org/abs/2606.06460)

📖 **WebMCP Tool Surface Poisoning: Runtime Manipulation Attacks on LLM Agents**

Studies runtime manipulation of MCP tool surfaces, showing how attacker-controlled descriptions or tool state can alter agent behavior after integration rather than only during static server review. [arXiv](https://arxiv.org/abs/2606.06387)

📖 **Membrane: A Self-Evolving Contrastive Safety Memory for LLM Agent Defense**

Proposes a safety-memory layer for LLM agents that compares risky and benign behavior over time, giving defenders a way to treat memory as a monitored control surface instead of passive context. [arXiv](https://arxiv.org/abs/2606.05743)

📖 **GuardNet: Ensemble Strategies of Shallow Neural Networks for Robust Prompt Injection and Jailbreak Detection**

Evaluates lightweight ensemble detectors for prompt injection and jailbreak attempts, focusing on detection behavior that can run near application traffic rather than only inside offline model evaluation. [arXiv](https://arxiv.org/abs/2606.05566)

📖 **A Taxonomy of Runtime Faults in Model Context Protocol Servers**

Builds a fault taxonomy for MCP servers, giving AppSec teams a vocabulary for unsafe tool exposure, protocol handling, validation failures, and runtime behaviors that can affect agent trust boundaries. [arXiv](https://arxiv.org/abs/2606.05339)

📖 **From Agent Traces to Trust: Evidence Tracing and Execution Provenance in LLM Agents**

Focuses on provenance for agent execution traces, which matters when security reviewers need to reconstruct what an agent saw, which tools it invoked, and where an unsafe action entered the workflow. [arXiv](https://arxiv.org/abs/2606.04990)

📖 **Description-Code Inconsistency in Real-world MCP Servers: Measurement, Detection, and Security Implications**

Measures mismatch between MCP tool descriptions and implementation behavior, a practical issue because agents often decide whether to trust or invoke tools based on descriptions that may not match code. [arXiv](https://arxiv.org/abs/2606.04769)

📖 **What If Prompt Injection Never Left? Exploring Cross-Session Stored Prompt Injection in Agentic Systems**

Examines stored prompt injection across sessions, where malicious instructions persist in memory or saved state and reappear later when the agent regains tool access. [arXiv](https://arxiv.org/abs/2606.04425)

📖 **From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents**

Analyzes memory poisoning in agents that convert external content into trusted future context, making memory write policy, provenance, and cleanup part of the security model. [arXiv](https://arxiv.org/abs/2606.04329)

📖 **Caught in the Act(ivation): Toward Pre-Output and Multi-Turn Detection of Credential Exfiltration by LLM Agents**

Looks at credential-exfiltration detection before final output and across multiple turns, which is relevant for agents that can gather secrets gradually through tool use, memory, or intermediate reasoning steps. [arXiv](https://arxiv.org/abs/2606.04141)

---

# 💬 Practitioner Discussions

---

# 🎥 Videos

1️⃣ [RCE in LLM Coding Agents: Lessons from Newly Disclosed Claude Code Vulnerabilities](https://www.youtube.com/watch?v=vo8kqlkjpWg)
Cloud Native San Francisco session on coding-agent RCE lessons, useful for teams reviewing how prompt injection, local tools, and developer environments can combine into host-side execution risk.

2️⃣ [The Future of Secure Enterprise AI: Building Reliable Agents with MCP](https://www.youtube.com/watch?v=-EJJLb7eRKo)
Xpand Conference talk on MCP-based enterprise agent design, with practical emphasis on reliable agent infrastructure, data exposure, and security controls around connected tools.

3️⃣ [CNAS 2026 National Security Conference: Setting the Rules for AI Warfare](https://www.youtube.com/watch?v=8MDyUeumV2c)
CNAS session on AI warfare norms and national-security policy, relevant for security teams tracking how AI-enabled cyber operations are moving into public-sector doctrine and governance.

4️⃣ [HitchHacker's Guide to Building Secure Agents](https://www.youtube.com/watch?v=eRaay8rBU_I)
NDC Conferences talk on secure agent construction, covering the engineering risks that appear when agents receive tools, credentials, state, and autonomy inside real software systems.

5️⃣ [Attacking AI Systems](https://www.youtube.com/watch?v=5PNr7VSv-Ss)
CodeValue session on attacking AI systems, useful as a practitioner-oriented walkthrough of how AI features expand application threat models beyond ordinary prompt and API handling.

---

# 🤝 Let's Connect

If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
