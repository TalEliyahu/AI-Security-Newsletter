# AI Security Newsletter - March 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month's issue is especially focused on agentic AI security, AI-assisted vulnerability discovery, prompt injection, MCP/tool abuse, and runtime controls.

---

# 🔍 Insights

📌 [Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)  
Unit 42 documents an observed web-based indirect prompt injection pattern where an agent processes attacker-controlled page content as operational instruction. The useful takeaway is not just "prompt injection exists"; it is that browser-connected agents need content trust boundaries, tool-use policy, and runtime monitoring before they browse untrusted sites with useful permissions.

📌 [Codex Security: now in research preview](https://openai.com/index/codex-security-now-in-research-preview/)  
OpenAI introduced Codex Security, an application security agent that builds project context, creates editable threat models, validates findings where possible, and proposes patches. It matters because AI-assisted vulnerability discovery is shifting from standalone scanning toward agentic workflows that reason over architecture, exploitability, and remediation.

📌 [Partnering with Mozilla to improve Firefox's security](https://www.anthropic.com/news/mozilla-firefox-security?id=2631)  
Anthropic describes a Mozilla collaboration where Claude Opus 4.6 found Firefox vulnerabilities that were triaged and fixed through Mozilla's normal process. The practical signal for defenders is that maintainers will need processes for AI-generated vulnerability reports, including validation, duplicate handling, patch review, and exploitability assessment.

📌 [AI as tradecraft: How threat actors operationalize AI](https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/)  
Microsoft Threat Intelligence maps how threat actors use AI across phishing, persona building, infrastructure research, malware iteration, discovery, persistence, and exfiltration planning. The post is useful because it separates AI as an accelerator from fully autonomous attack execution and gives defenders concrete behaviors to hunt.

📌 [Cisco Secure AI Factory with NVIDIA makes AI easier to deploy and secure, anywhere organizations need it](https://investor.cisco.com/files/doc_news/Cisco-Secure-AI-Factory-with-NVIDIA-Makes-AI-Easier-to-Deploy-and-Secure-Anywhere-Organizations-Need-It-2026.pdf)  
Cisco and NVIDIA expanded their Secure AI Factory architecture with security controls for distributed AI infrastructure and agent execution. The security angle is the move toward policy enforcement near AI workloads, including BlueField DPU enforcement, Cisco AI Defense, and guardrails for agent and tool actions.

📌 [Observability for AI Systems: Strengthening visibility for proactive risk detection](https://www.microsoft.com/en-us/security/blog/2026/03/18/observability-ai-systems-strengthening-visibility-proactive-risk-detection/)  
Microsoft argues that AI system observability has to cover model behavior, prompts, grounding data, agent actions, and operational context, not just infrastructure metrics. This is a strong reminder that logging for AI needs to preserve the right evidence for abuse investigation without turning every prompt into uncontrolled sensitive data.

📌 [HackerOne launches agentic prompt injection testing as AI vulnerabilities surge 540%](https://www.hackerone.com/press-release/hackerone-launches-agentic-prompt-injection-testing-ai-vulnerabilities-surge-540)  
HackerOne launched agentic prompt injection testing, pointing to rising AI vulnerability submissions on its platform. Even though this is a product announcement, it is a useful market signal: bug bounty and testing programs are starting to treat prompt injection and agent misuse as testable vulnerability classes rather than generic AI risk.

📌 [Secure Homegrown AI Agents with Falcon AIDR and NVIDIA NeMo Guardrails](https://www.crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/)  
CrowdStrike shows how Falcon AIDR can be integrated with NVIDIA NeMo Guardrails to inspect agent inputs and outputs, block prompt injection attempts, redact sensitive data, and apply policy decisions at runtime. The security relevance is the action layer: production agents need controls around what they read, write, and call, not only safer model prompts.

📌 [Secure agentic AI end-to-end](https://www.microsoft.com/en-us/security/blog/2026/03/20/secure-agentic-ai-end-to-end/)  
Microsoft lays out an agent security stack spanning agent inventory, identity, data controls, prompt-injection protection, and security operations. It is a practical reference for teams moving from "AI app security" to full agent lifecycle governance across identities, tools, data, and SOC workflows.

📌 [Cursor Security: How to Secure AI-Generated Code in 2026](https://www.endorlabs.com/learn/cursor-security)  
Endor Labs maps Cursor-related risks such as prompt injection in project context, malicious dependencies, hidden rules files, token leaks, and unreviewed auto-run execution. The article is useful for engineering security teams because it turns coding-assistant risk into concrete controls: workspace trust, dependency checks, egress filtering, secrets scanning, and mandatory review.

📌 [7.2% of MCP Servers Have Security Vulnerabilities - What We Found Scanning 1,899 Servers](https://prompttools.co/blog/mcp-server-security-study-2026)  
ClawGuard reports results from MCP server scanning and highlights credential exposure, tool poisoning, and audit gaps. Treat the exact vendor numbers as source-specific, but the pattern is important: MCP security review has to inspect tool metadata, auth posture, path handling, and hidden instructions before an agent is connected.

📌 [How SentinelOne's AI EDR autonomously discovered and stopped Anthropic's Claude from executing a zero day supply chain attack, globally](https://www.sentinelone.com/blog/how-sentinelones-ai-edr-autonomously-discovered-and-stopped-anthropics-claude-from-executing-a-zero-day-supply-chain-attack-globally/)  
SentinelOne describes a supply-chain scenario involving agentic coding workflows, malicious packages, and endpoint/runtime intervention. The high-impact claims should be read as SentinelOne's account, but the defensive lesson is sound: AI coding agents execute in developer environments where package installation, shell execution, and secrets access need runtime controls.

📌 [How Charlotte AI AgentWorks Fuels Security's Agentic Ecosystem](https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/)  
CrowdStrike explains its agent-building approach for security operations. The practical value is seeing how SOC agents are being packaged around defined tasks and data sources, which also clarifies where governance, permissions, telemetry, and human review need to sit before autonomous remediation scales.

📌 [Addressing the OWASP Top 10 Risks in Agentic AI with Microsoft Copilot Studio](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/)  
Microsoft maps OWASP's Agentic AI Top 10 to concrete agent platform controls, including goal hijack, tool misuse, identity abuse, memory/context poisoning, and cascading failures. This is useful because it connects the taxonomy to implementation decisions security teams can actually audit.

📌 [Establishing Runtime Security for Agentic AI](https://www.ibm.com/think/insights/agentic-ai-runtime-security)  
IBM focuses on runtime security for agents that can call tools, handle credentials, and perform multi-step work. The key point is that agent security cannot stop at pre-deployment testing; teams need live policy enforcement, monitoring, and response paths for tool calls and delegated actions.

---

# 🧰 Tools & Resources

🧰 **[onecli](https://github.com/onecli/onecli)** - Open-source credential vault designed to give AI agents service access without exposing raw keys directly to the agent runtime. ⭐️2.2k

🧰 **[zerobox](https://github.com/afshinm/zerobox)** - Lightweight process sandboxing for commands, with file, network, and credential controls useful for constraining coding-agent execution. ⭐️599

🧰 **[api-relay-audit](https://github.com/toby-bridges/api-relay-audit)** - Audit tool for third-party AI API relay/proxy services, checking for hidden prompt injection, prompt leakage, instruction override, and context truncation. ⭐️442

🧰 **[hol-guard](https://github.com/hashgraph-online/hol-guard)** - AI developer-agent protection tool for Codex, Claude Code, Cursor, Gemini, OpenCode, plugins, skills, MCP servers, and agent harnesses. ⭐️319

🧰 **[agentseal](https://github.com/getagentseal/agentseal)** - Toolkit for scanning local agent skills and MCP configs, monitoring for supply-chain issues, testing prompt-injection resistance, and auditing MCP servers. ⭐️257

🧰 **[claudit-sec](https://github.com/HarmonicSecurity/claudit-sec)** - macOS audit tool for Claude Desktop and Claude Code environments, covering MCP servers, extensions, plugins, connectors, scheduled tasks, and permissions. ⭐️247

🧰 **[clawshield-public](https://github.com/SleuthCo/clawshield-public)** - Agent security proxy with prompt-injection, PII, secrets, policy, audit, firewall, and monitoring components for agent traffic. ⭐️130

🧰 **[AgentGuard](https://github.com/numbergroup/AgentGuard)** - AI agent security framework focused on prompt injection, command injection, Unicode bypass handling, and defensive checks around agent workflows. ⭐️100

🧰 **[shellward](https://github.com/jnMetaCode/shellward)** - AI agent security middleware and MCP server with DLP flow controls, prompt-injection detection, and integration hooks for agent frameworks. ⭐️93

🧰 **[agentsid-scanner](https://github.com/AgentsID-dev/agentsid-scanner)** - MCP server security scanner that grades authentication, permissions, injection risk, and tool safety. ⭐️23

🧰 **[GRITS](https://github.com/X-Scale-AI/GRITS)** - Open-source framework for scoring, hardening, and governing AI agents with zero-trust-oriented controls. ⭐️11

🧰 **[agent-security-playbook](https://github.com/cmaenner/agent-security-playbook)** - OWASP-grounded procedures for prompt-injection testing, AI agent audits, and LLM risk assessment. ⭐️5

---

# 📄 Reports

📘 **[HiddenLayer 2026 AI Threat Landscape Report](https://www.prnewswire.com/news-releases/hiddenlayer-releases-the-2026-ai-threat-landscape-report-spotlighting-the-rise-of-agentic-ai-and-the-expanding-attack-surface-of-autonomous-systems-302716687.html)**  
HiddenLayer's March report focuses on agentic AI, AI supply-chain exposure, shadow AI, breach visibility gaps, and unclear ownership of AI security controls.

📘 **[Rapid7 2026 Global Threat Landscape Report](https://www.rapid7.com/research/report/global-threat-landscape-report-2026/)**  
Rapid7's report is broader cybersecurity, but it is relevant here because it calls out AI as an attacker force multiplier and connects shrinking exploitation timelines to the need for faster exposure management and response.

📘 **[AI Cooperation Trajectories: Adversaries and Geostrategic Competitors](https://cetas.turing.ac.uk/publications/ai-cooperation-trajectories-adversaries-and-geostrategic-competitors)**  
CETaS examines hostile AI cooperation among adversaries and geostrategic competitors, with implications for national security, AI-enabled cyber operations, and domestic resilience.

📘 **[Image-Based Prompt Injection: Hijacking Multimodal LLMs Through Visually Embedded Adversarial Instructions](https://labs.cloudsecurityalliance.org/research/csa-research-note-image-prompt-injection-multimodal-llm-2026/)**  
Cloud Security Alliance's research note summarizes visual prompt-injection attack classes, multimodal threat scenarios, and defense-in-depth patterns for vision-capable AI systems.

📘 **[Securing OpenClaw in the Enterprise: A Zero Trust Approach to Agentic AI Hardening](https://labs.cloudsecurityalliance.org/research/enterprise-openclaw-zero-trust-hardening-guide-v1/)**  
Cloud Security Alliance maps OpenClaw and similar agentic platforms to zero-trust controls, agent identity, MCP/tool governance, sandboxing, supply-chain review, and operational hardening.

---

# 📅 Upcoming Conferences

## April 2026

📅 [DiCyFor & AI Security Summit - Kuala Lumpur](https://www.dicyfor.com/kualalumpur2026) - April 15, 2026 · The Pullman Hotel KLCC, Kuala Lumpur, Malaysia · Organizer: DiCyFor

📅 [SANS AI Cybersecurity Summit 2026](https://www.sans.org/ai-cybersecurity-summit-2026) - April 20-21, 2026 · Arlington, VA, USA & Live Online · Organizer: SANS Institute

📅 [AI Security Summit at Black Hat Asia 2026](https://blackhat.com/asia-26/ai-security-summit.html) - April 22, 2026 · Marina Bay Sands, Singapore · Organizer: Black Hat

## May 2026

📅 [AI Security Summit 2026](https://events.lynx.co/AI-Security-Summit/) - May 13, 2026 · Check Point HQ, Tel Aviv, Israel · Organizer: Lynx Events

## August 2026

📅 [The AI Summit at Black Hat USA 2026](https://blackhat.com/us-26/ai-summit.html) - August 4, 2026 · Mandalay Bay, Las Vegas, NV, USA · Organizer: Black Hat

## October 2026

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · University of Texas at Austin, Austin, TX, USA · Organizer: IEEE

---

# 📚 Research

📖 **Architecting Secure AI Agents: Perspectives on System-Level Defenses Against Indirect Prompt Injection Attacks**  
Chong Xiang, Drew Zagieboylo, Shaona Ghosh, Sanjay Kariyappa, Kai Greshake, Hanshen Xiao, Chaowei Xiao, G. Edward Suh. [arXiv](https://arxiv.org/abs/2603.30016)

📖 **Adversarial Prompt Injection Attack on Multimodal Large Language Models**  
Meiwen Ding, Song Xia, Chenqi Kong, Xudong Jiang. [arXiv](https://arxiv.org/abs/2603.29418)

📖 **Crossing the NL/PL Divide: Information Flow Analysis Across the NL/PL Boundary in LLM-Integrated Code**  
Zihao Xu, Xiao Cheng, Ruijie Meng, Yuekang Li. [arXiv](https://arxiv.org/abs/2603.28345)

📖 **Evaluating Privilege Usage of Agents with Real-World Tools**  
Quan Zhang, Lianhang Fu, Lvsi Lian, Gwihwan Go, Yujue Wang, Chijin Zhou, Yu Jiang, Geguang Pu. [arXiv](https://arxiv.org/abs/2603.28166)

📖 **Kill-Chain Canaries: Stage-Level Tracking of Prompt Injection Across Attack Surfaces and Model Safety Tiers**  
Haochuan Kevin Wang, Zechen Zhang. [arXiv](https://arxiv.org/abs/2603.28013)

📖 **"Elementary, My Dear Watson." Detecting Malicious Skills via Neuro-Symbolic Reasoning across Heterogeneous Artifacts**  
Shenao Wang, Junjie He, Yanjie Zhao, Yayi Wang, Kan Yu, Haoyu Wang. [arXiv](https://arxiv.org/abs/2603.27204)

📖 **The System Prompt Is the Attack Surface: How LLM Agent Configuration Shapes Security and Creates Exploitable Vulnerabilities**  
Ron Litvak. [arXiv](https://arxiv.org/abs/2603.25056)

📖 **Claudini: Autoresearch Discovers State-of-the-Art Adversarial Attack Algorithms for LLMs**  
Alexander Panfilov, Peter Romov, Igor Shilov, Yves-Alexandre de Montjoye, Jonas Geiping, Maksym Andriushchenko. [arXiv](https://arxiv.org/abs/2603.24511)

📖 **Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning**  
Charoes Huang, Xin Huang, Ngoc Phu Tran, Amin Milani Fard. [arXiv](https://arxiv.org/abs/2603.22489)

📖 **Are AI-assisted Development Tools Immune to Prompt Injection?**  
Charoes Huang, Xin Huang, Amin Milani Fard. [arXiv](https://arxiv.org/abs/2603.21642)

📖 **How Vulnerable Are AI Agents to Indirect Prompt Injections? Insights from a Large-Scale Public Competition**  
Mateusz Dziemian, Maxwell Lin, Xiaohan Fu, Micha Nowak, Nick Winter, Eliot Jones, Andy Zou, Lama Ahmad, Kamalika Chaudhuri, Sahana Chennabasappa, Xander Davies, Lauren Deason, Benjamin L. Edelman, Tanner Emek, Ivan Evtimov, Jim Gust, Maia Hamin, Kat He, Klaudia Krawiecka, Riccardo Patana, Neil Perry, Troy Peterson, Xiangyu Qi, Javier Rando, Zifan Wang, Zihan Wang, Spencer Whitman, Eric Winsor, Arman Zharmagambetov, Matt Fredrikson, Zico Kolter. [arXiv](https://arxiv.org/abs/2603.15714)

---

# 🎥 Videos

1️⃣ [The Emerging AI SOC Market Explained | Analyst Chat 291](https://www.youtube.com/watch?v=9ou_61F-H4A) - KuppingerCole Analysts

2️⃣ [Agentic Runtime Security Explained: Securing Non-Human Identities](https://www.youtube.com/watch?v=HtnlUosO3XA) - IBM Technology

3️⃣ [How to Build an AI SOC Analyst in 8 Minutes](https://www.youtube.com/watch?v=xWPsmQq3Le8) - Blake White

4️⃣ [What is Agentic Security Runtime? Securing AI Agents](https://www.youtube.com/watch?v=NH0plIdqDMk) - IBM Technology

5️⃣ [Securing AI Agents: Identity & Access Management with Entra Agent ID and OAuth 2.1](https://www.youtube.com/watch?v=B3J8er4xDWU) - Joe Tan

6️⃣ [Stop buying AI security tools until you watch this](https://www.youtube.com/watch?v=tFSb2lSgqwA) - David Bombal

7️⃣ [Beyond the Hype: Measuring Cyber Readiness in the Age of AI - Gibb Witham](https://www.youtube.com/watch?v=AU77gxn1lVo) - CyberRisk TV

8️⃣ [OWASP Agentic Top 10 Risks You Must Know in 2026](https://www.youtube.com/watch?v=JRYHmsPUgmk) - Kratikal Tech Ltd.

9️⃣ [AI Red Teaming: Advanced Adversary Simulation | Cybersecurity 2026](https://www.youtube.com/watch?v=TDJ4aOi3P2A) - Shield Spectrum

🔟 [Claude Hacked Firefox and Found 100+ Security Bugs](https://www.youtube.com/watch?v=8btR9Qy-Zl8) - OVERRIDE

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
