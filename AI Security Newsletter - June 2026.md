# AI Security Newsletter - June 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://www.awesomeaisecurity.com/).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - *Innovate and Invest with Confidence, Lead with Assurance.*

<p align="center">
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

📌 [The sorry state of skill distribution](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/)
Trail of Bits researchers bypassed ClawHub, Cisco skill-scanner, and skills.sh checks with skill packages that used truncation, archive indirection, bytecode poisoning, and prompt-injection framing, showing why public agent-skill marketplaces need curation and provenance controls rather than scanner trust alone.

📌 [Codex CLI RCE: Prompt injection mitigations](https://cymulate.com/blog/codex-cli-rce-prompt-injection-mitigations/)
Cymulate walks through prompt-injection risk in command-line coding agents, where untrusted text can steer file writes or tool execution unless sandboxing, approval boundaries, and command constraints are enforced outside the model.

📌 [Agentjacking: MCP Injection Hijacks AI Coding Agents](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentjacking-mcp-sentry-injection-20260612/)
Cloud Security Alliance summarizes the Sentry-to-MCP "agentjacking" pattern, where externally controlled telemetry or issue content becomes trusted context for coding agents. The useful defensive frame is to treat observability, bug-report, and integration data as untrusted agent input, not as neutral development metadata.

📌 [SearchLeak: How We Turned M365 Copilot Into a One-Click Data Exfiltration Weapon](https://www.varonis.com/blog/searchleak)
Varonis describes a Microsoft 365 Copilot Enterprise attack chain that combines parameter-to-prompt injection, HTML rendering behavior, and search-path abuse to leak sensitive M365 data through a single-click workflow.

📌 [AutoJack: How a single page can RCE the host running your AI agent](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/)
Microsoft shows how a malicious webpage viewed by an AI browsing agent can reach a local AutoGen Studio service and trigger host process execution through unsafe localhost trust and agent action handling.

📌 [Mastra npm Supply Chain Attack: 140+ Packages Backdoored via easy-day-js Typosquat](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)
StepSecurity reports a compromise of Mastra's npm ecosystem through a typosquatted dependency with an obfuscated postinstall dropper, affecting agent, RAG, MCP, and workflow packages used in AI application stacks.

📌 [Breaking LiteLLM: From Low-Privilege User to Admin and RCE](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)
Obsidian documents a chained LiteLLM privilege-escalation and RCE path, showing how low-privilege access to an AI gateway can become administrative control over provider secrets, proxy policy, and runtime agent functions.

📌 [Amazon Q Vulnerability: Compromise via MCP Auto-Execution](https://www.wiz.io/blog/amazon-q-vulnerability)
Wiz analyzes an Amazon Q VS Code extension issue where workspace-trusted MCP configuration in a cloned repository could auto-load attacker-controlled behavior and expose developer execution paths and cloud credentials.

📌 [macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/)
SentinelOne documents a Rust backdoor that plants prompt-injection content for analysts and AI-assisted tooling, shifting the attack from sandbox escape to manipulation of the human and model reviewing the malware.

📌 [Computer-Use and TOCTOU: What You Click Is Not What You Get!](https://embracethered.com/blog/posts/2026/toctou-agent-what-you-click-is-not-what-you-get/)
Johann Rehberger demonstrates a computer-use agent race condition where the screen changes after the model observes it but before the click lands, turning a benign-looking interaction into an Outlook send action and making pre-action pixel or state revalidation a core control.

📌 [The vibe coding spectrum approach to AI-assisted software development](https://www.ncsc.gov.uk/blogs/the-vibe-coding-spectrum-approach-to-ai-assisted-software-development)
The UK NCSC frames AI-assisted coding as a risk spectrum, separating low-risk prototypes from generated code that touches authentication, authorization, sensitive data, safety-critical behavior, or critical infrastructure.

📌 [Prompt Injection and Agent Runtime Security: A Practical Threat Model](https://www.tmls.nyc/research/prompt-injection-agent-security)
TMLS frames prompt injection as a runtime security problem, mapping attacks through tool mediation, memory stores, outbound channels, and human approval gaps. The practical takeaway is to move controls into capability brokers, sandboxed execution, allow-lists, and audit paths instead of treating prompt text as the security boundary.

📌 [What happened after 2,000 people tried to hack my AI assistant](https://www.fernandoi.cl/posts/hackmyclaw/)
Fernando Irarrázaval reports an OpenClaw email-agent prompt-injection challenge with more than 6,000 attempts and no successful secret leak, while surfacing practical deployment issues around agent memory contamination, batch context, API cost, account suspension, and model choice.

---

# 🧰 Tools & Resources

🧰 **[AgentStalker](https://github.com/Gach0ng/AgentStalker)** - Agent vulnerability benchmark and analysis toolkit with taint tracking, AST analysis, code auditing, and sandbox reproduction for agentic attack paths. ⭐️115

🧰 **[darknet-mcp-server](https://github.com/badchars/darknet-mcp-server)** - MCP server that exposes breach, ransomware, malware, exploit, stealer-log, and threat-intelligence tools to AI agents for controlled security research workflows. ⭐️67

🧰 **[mcp-trust-plane](https://github.com/abluva-research/mcp-trust-plane)** - Composable data-security and guardrail plane for Model Context Protocol providers, focused on policy controls around MCP-connected tools and data. ⭐️60

🧰 **[prompt-gate](https://github.com/ShieldNet-360/prompt-gate)** - Local DLP and DNS-layer control for blocking unauthorized AI tools and inspecting outbound prompts for secrets or sensitive data before they leave the endpoint. ⭐️28

🧰 **[claude-ai-cyber-security-skills](https://github.com/0xGhostCAT/claude-ai-cyber-security-skills)** - Claude Code skill collection for security workflows, including offensive testing, defensive analysis, and tool-assisted investigation patterns. ⭐️17

🧰 **[talos](https://github.com/ory/talos)** - API-key and capability-token service for humans, services, and AI agents that need scoped machine-to-machine authorization. ⭐️14

🧰 **[SkillsGuard](https://github.com/Teycir/SkillsGuard)** - Static scanner for malicious or unsafe AI-agent skill packages, SKILL.md files, and bundled scripts. ⭐️13

🧰 **[tamga](https://github.com/yatuk/tamga)** - Self-hosted LLM security proxy for PII redaction, prompt-injection defense, and compliance controls around model traffic. ⭐️11

🧰 **[llm-sec-range](https://github.com/gatsby-sec/llm-sec-range)** - LLM attack and defense range covering prompt-injection CTFs, OWASP LLM Top 10, vulnerable agents, and local model targets. ⭐️9

🧰 **[aka-claude-tools](https://github.com/alsoknownassecurity/aka-claude-tools)** - Claude Code hardening utilities for clean context, isolated profiles, locked credentials, guarded egress, and safer local defaults. ⭐️9

🧰 **[agent-jackstop](https://github.com/tenet-security/agent-jackstop)** - Hardening layer for Cursor and Claude Code against prompt injection through untrusted tool output, also described as agentjacking. ⭐️8

🧰 **[LLM-Safety-platform](https://github.com/RII6/LLM-Safety-platform)** - AI red-teaming platform for LLM vulnerability assessment, prompt injection, obfuscation attacks, and sampling-stability analysis. ⭐️6

---

# 📄 Reports

📘 **[State of Agentic AI Security and Governance 2.01](https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance/)**

OWASP's June update turns agentic-AI security into a governance and engineering map, covering autonomous workflows, agent risk categories, controls, and the practical gap between early threat models and production incidents.

📘 **[AI Controls Matrix v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)**

Cloud Security Alliance publishes 247 AI control objectives across 18 security domains, with mappings to assurance and compliance frameworks such as ISO 42001, ISO 27001, BSI AIC4, and EU AI Act-oriented governance.

📘 **[AICMv1.1 Implementation Guidelines for Cloud Service Providers](https://cloudsecurityalliance.org/artifacts/aicmv1-1-implementation-guidelines-for-cloud-service-providers-csp)**

CSA turns the AI Controls Matrix into cloud-provider implementation guidance across audit planning, remediation, vulnerability management, partner oversight, threat detection, and AI-specific assurance practices.

📘 **[The AI shift in cyber risk: why leaders must act now](https://www.ncsc.gov.uk/news/the-ai-shift-in-cyber-risk-why-leaders-must-act-now)**

The UK NCSC and Five Eyes partners warn that AI is reducing attacker barriers and compressing the vulnerability-to-exploitation window, while mapping the risk shift to secure-by-design defaults, exposure reduction, patch speed, strong authentication, incident readiness, and defensive AI use.

📘 **[Model Context Protocol: Security Design Considerations for AI-Driven Automation](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)**

NSA and international partners publish MCP security design guidance for AI-driven automation, covering authentication, authorization, server trust, transport controls, tool exposure, and monitoring for agent ecosystems moving from experiments into production.

---

# 🛡️ CVEs

🛡️ [CVE-2026-49257: mcp-pinot exposes unauthenticated MCP tool invocation](https://nvd.nist.gov/vuln/detail/CVE-2026-49257)
Critical 10.0. mcp-pinot can bind an HTTP MCP server to 0.0.0.0 with OAuth disabled by default, exposing SQL, schema, and table mutation tools through server-side Apache Pinot credentials.

🛡️ [CVE-2026-54309: n8n MCP Browser transport accepts unauthenticated tool calls](https://nvd.nist.gov/vuln/detail/CVE-2026-54309)
Critical 10.0. n8n's MCP Browser HTTP transport can accept session initialization and tool calls without authentication, exposing browser-control automation to reachable clients.

🛡️ [CVE-2026-56274: Flowise Custom MCP Server command injection](https://nvd.nist.gov/vuln/detail/CVE-2026-56274)
Critical 9.9. Flowise Custom MCP Server command flag handling and file-access restrictions can be bypassed for OS command injection inside an LLM workflow platform.

🛡️ [CVE-2026-55255: Langflow flow execution IDOR](https://nvd.nist.gov/vuln/detail/CVE-2026-55255)
Critical 9.9. Langflow's responses API can let an authenticated attacker execute another user's flow by supplying a victim flow ID, breaking tenant isolation for AI workflow execution.

🛡️ [CVE-2026-50548: Cursor agent terminal sandbox escape](https://nvd.nist.gov/vuln/detail/CVE-2026-50548)
Critical 9.8. Cursor's agent terminal sandbox can be bypassed by modifying working-directory parameters, allowing agent-driven terminal actions outside the intended workspace boundary.

🛡️ [CVE-2026-50549: Cursor agent file-write sandbox escape](https://nvd.nist.gov/vuln/detail/CVE-2026-50549)
Critical 9.8. Cursor's file-write sandbox can fall back incorrectly after canonicalization failure, creating a path for agent file writes outside the intended project boundary.

🛡️ [CVE-2026-49468: LiteLLM proxy host-header authorization bypass](https://nvd.nist.gov/vuln/detail/CVE-2026-49468)
Critical 9.8. LiteLLM proxy host-header parsing can allow unauthenticated access to protected management routes under specific deployment conditions, risking gateway controls and provider secrets.

🛡️ [CVE-2026-7664: IBM Langflow Streamable MCP authorization bypass](https://nvd.nist.gov/vuln/detail/CVE-2026-7664)
Critical 9.8. IBM Langflow's Streamable MCP transport can expose protected MCP resources and operations to unauthenticated attackers in affected open source releases.

🛡️ [CVE-2026-55743: OpenHuman desktop agent shell allowlist bypass](https://nvd.nist.gov/vuln/detail/CVE-2026-55743)
Critical 9.6. OpenHuman's desktop-agent shell allowlist can be bypassed through find execution flags and environment tricks, turning indirect prompt-injection paths into host command execution.

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

📖 **AgentRedBench: Dynamic Redteaming and Integration-Aware Defense for LLM Agents over SaaS Integrations**

Benchmarks indirect prompt injection against tool-use agents connected to SaaS integrations such as Gmail, Salesforce, and Jira, making the attack surface closer to production agent workflows than chat-only prompt-injection tests. [arXiv](https://arxiv.org/abs/2606.02240)

📖 **SkillGuard: A Permission Framework for Agent Skills**

Treats third-party agent skills as permissioned software artifacts, mapping what a skill can inject into agent context to what it can cause the agent to do at runtime. [arXiv](https://arxiv.org/abs/2606.03024)

📖 **Description-Code Inconsistency in Real-world MCP Servers: Measurement, Detection, and Security Implications**

Measures 19,200 description-code pairs from 2,214 MCP servers and finds that tool descriptions often diverge from actual implementation behavior, creating a blind spot for agents that choose tools based on natural-language descriptions. [arXiv](https://arxiv.org/abs/2606.04769)

📖 **GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines**

Shows how AI agents embedded in CI/CD and pull-request workflows can ingest attacker-controlled repository content while holding elevated permissions, turning prompt injection into a software supply-chain risk. [arXiv](https://arxiv.org/abs/2606.09935)

📖 **Toward Secure LLM Agents: Threat Surfaces, Attacks, Defenses, and Evaluation**

Synthesizes 247 papers into a systems-oriented map of agent security, centering information flow, delegated authority, persistent state, tool-mediated control-flow hijacking, and the weakness of non-compositional defenses. [arXiv](https://arxiv.org/abs/2606.10749)

📖 **Same-Origin Policy for Agentic Browsers**

Shows that agentic browsers can become automated cross-origin data-flow channels, then proposes SOPGuard to enforce browser-origin boundaries while preserving task utility. [arXiv](https://arxiv.org/abs/2606.14027)

📖 **Benign in Isolation, Harmful in Composition: Security Risks in Agent Skill Ecosystems**

Introduces Skill Composition Risk, where individually benign skills become harmful when their outputs, trust signals, authorization cues, or side effects influence later tool calls in a shared agent context. [arXiv](https://arxiv.org/abs/2606.15242)

📖 **SafeClawBench: Separating Semantic, Audit-Evidence, and Sandbox Harm in Tool-Using LLM Agents**

Introduces a staged benchmark for tool-using agent security across direct and indirect prompt injection, tool-return injection, memory poisoning, memory extraction, and unsafe inference, separating model agreement from audit-visible and sandbox-observed harm. [arXiv](https://arxiv.org/abs/2606.18356)

📖 **"What Happens Locally, Leaks Globally": Detecting Privacy Leakage Risks in MCP Servers**

Frames MCP leakage as a protocol-induced privacy problem where credentials, API keys, or PII cross the local-to-LLM boundary through returned values, logs, or tool-handler errors. [arXiv](https://arxiv.org/abs/2606.21338)

📖 **ShareLock: A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP**

Introduces a multi-tool MCP poisoning attack where malicious instructions are split across benign-looking tool descriptions and reconstructed only after a trigger, reducing detectability compared with single-tool poisoning. [arXiv](https://arxiv.org/abs/2606.27027)

---

# 💬 Practitioner Discussions

💬 [Clean GitHub repo tricks AI coding agents into running malware](https://www.reddit.com/r/cybersecurity/comments/1uh4c7u/clean_github_repo_tricks_ai_coding_agents_into/)
r/cybersecurity · Reddit score 183 · 19 comments
Practitioners treated the thread as a coding-agent trust-boundary case: repository prompts, config files, setup scripts, and tool-output context can become execution influence before a reviewer sees a conventional malicious payload.

💬 [macOS Gaslight Backdoor Weaponizes Prompt Injection Against Security Analysts](https://www.reddit.com/r/cybersecurity/comments/1uedcrf/macos_gaslight_backdoor_weaponizes_prompt/)
r/cybersecurity · Reddit score 202 · 11 comments
The discussion framed prompt injection as malware-analysis workflow abuse: malicious samples can plant instructions for analysts and their AI tooling, so the review environment, analyst notes, and model context become part of the attack surface.

💬 [Rolling out Copilot - How worried should i be about Indirect Prompt Injection?](https://www.reddit.com/r/cybersecurity/comments/1uaxq9e/rolling_out_copilot_how_worried_should_i_be_about/)
r/cybersecurity · Reddit score 48 · 31 comments
Security teams compared Copilot rollout controls for indirect prompt injection, focusing on untrusted documents and email, inherited user permissions, overshared data, connector scope, and whether least privilege alone is enough for retrieval-augmented assistants.

💬 [How are teams handling MCP tool surface exposure?](https://www.reddit.com/r/cybersecurity/comments/1u6z2sx/how_are_teams_handling_mcp_tool_surface_exposure/)
r/cybersecurity · Reddit score 13 · 19 comments
The thread focused on MCP as a tool-exposure boundary: teams debated server reachability, tool-description trust, approval gates, per-tool authorization, and whether agent tool access should be modeled closer to API access or local code execution.

💬 [Is anyone's security policy actually ready for AI agents, or are we all just pretending?](https://www.reddit.com/r/cybersecurity/comments/1u3w3o3/is_anyones_security_policy_actually_ready_for_ai/)
r/cybersecurity · Reddit score 47 · 73 comments
Practitioners mapped AI agents to governance gaps in existing policy: who owns automated actions, what requires human approval, how delegated permissions are logged, and how incident response changes when a workflow operator is partly automated.

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

6️⃣ [BlueHat 2026: From trusted agents to adversaries: Securing agentic AI in the age of prompt injection](https://www.youtube.com/watch?v=-sZ0kfoe9HU)
BlueHat 2026 talk on how trusted agent workflows become adversarial when tool outputs, retrieved content, and delegated actions cross trust boundaries.

7️⃣ [Breaching LLM-Powered Applications: Overcoming Security and Privacy Challenges](https://www.youtube.com/watch?v=lTlOUU5roVs)
Spring I/O session by Brian Vermeer covering practical attack paths against LLM-powered applications, including prompt injection, privacy leakage, application integration risk, and architectural mitigations.

8️⃣ [ContinuumCon 2026 - Hunting Prompt Injection](https://www.youtube.com/watch?v=dk5wpovUdQ0)
ContinuumCon talk by Mackenzie Jackson on finding, testing, and reasoning about prompt-injection behavior in AI systems as an operational security problem.

9️⃣ [Securing AI Agents with MCP and Zero Trust Identity](https://www.youtube.com/watch?v=y9w38zo6Dsk)
DZone Events session on securing MCP-connected agents with zero-trust identity concepts, scoped access, tool authorization, and safer delegated workflows.

🔟 [Practical MCP Security in Action](https://www.youtube.com/watch?v=Wh-2chCEfYA)
Bulgarian Java User Group technical session by Willem Jan Glerum on MCP security tradeoffs, server and tool exposure, configuration risk, and controls for agent integrations.

---

# 🤝 Let's Connect

If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
