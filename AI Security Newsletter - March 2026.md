# AI Security Newsletter - March 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month's issue is focused on technical AI security research, vulnerability analysis, exploit chains, agent/tool abuse, AI malware, and concrete defensive engineering lessons. Product announcements, vendor partnerships, vendor reports, short videos, tutorials, and non-conference videos were excluded.

---

# 🔍 Insights

📌 [Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)  
Unit 42 documents observed indirect prompt injection against web-connected AI agents, including hidden or manipulated website content that agents process as instructions. The important lesson is architectural: browser agents need provenance, content trust boundaries, tool-use limits, and runtime monitoring before they ingest arbitrary web pages.

📌 [AI as tradecraft: How threat actors operationalize AI](https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/)  
Microsoft Threat Intelligence maps how threat actors are using AI for phishing, persona building, infrastructure research, malware iteration, discovery, persistence, and exfiltration planning. It is useful because it keeps the threat model grounded in observed operator workflows rather than vague claims about fully autonomous attacks.

📌 [Detecting and analyzing prompt abuse in AI tools](https://www.microsoft.com/en-us/security/blog/2026/03/12/detecting-analyzing-prompt-abuse-in-ai-tools/)  
Microsoft Incident Response turns prompt abuse into an investigation workflow: discover AI apps, collect logs, identify hidden instructions, inspect suspicious file requests, and connect prompt events to incident response. The defensive value is practical telemetry design for production AI systems.

📌 [Claudy Day: Chaining Prompt Injection and Data Exfiltration in Claude.ai](https://www.oasis.security/blog/claude-ai-prompt-injection-data-exfiltration-vulnerability)  
Oasis describes a Claude.ai attack chain combining invisible prompt injection, data exfiltration through the Anthropic Files API, and an open redirect delivery path. The finding shows why AI assistants need strict handling for pre-filled prompts, file APIs, conversation history access, and externally supplied links.

📌 [MS-Agent does not properly sanitize commands sent to its shell tool, allowing for RCE](https://www.kb.cert.org/vuls/id/431821)  
CERT/CC published CVE-2026-2256 for command injection in ModelScope's MS-Agent framework through unsanitized prompt-derived input passed to a shell tool. This is a clean example of why agent tools cannot rely on regex denylists when prompts, retrieved documents, or external content can influence command construction.

📌 [Claude Code has a Workspace Trust Dialog Bypass via Repo-Controlled Settings File](https://github.com/advisories/GHSA-mmgp-wc2j-qcv7)  
GitHub Advisory Database tracks CVE-2026-33068, where Claude Code resolved repository-controlled settings before showing the workspace trust dialog. The bug matters beyond one tool because it shows that trust prompts fail if untrusted repository state can influence permission mode before the trust decision is made.

📌 [Snowflake Cortex AI Escapes Sandbox and Executes Malware](https://www.promptarmor.com/resources/snowflake-ai-escapes-sandbox-and-executes-malware)  
PromptArmor details an indirect prompt injection chain against Snowflake Cortex Code CLI that bypassed human approval, used shell process substitution to evade command validation, and disabled the sandbox for execution. The case is a concrete warning that subagents, shell parsing, and sandbox override flags need deterministic enforcement outside the model.

📌 [Invisible Threats: Source Code Exfiltration in Google Antigravity](https://www.firetail.ai/blog/invisible-threats-source-code-exfiltration-in-google-antigravity)  
FireTail shows how invisible Unicode instructions in source comments can drive Google Antigravity to exfiltrate source code. The engineering lesson is simple and uncomfortable: human-in-the-loop review does not help when the human cannot see the instruction the model is processing.

📌 [ShadowPrompt: How Any Website Could Have Hijacked Claude's Chrome Extension](https://www.koi.ai/blog/shadowprompt-how-any-website-could-have-hijacked-anthropic-claude-chrome-extension)  
Koi Security chains an overly broad `*.claude.ai` trust boundary with XSS in a first-party subdomain to inject prompts into Claude's Chrome extension. This is useful threat modeling material for browser AI assistants, where extension messaging, trusted origins, and third-party embedded components become part of the agent control plane.

📌 [A Slopoly start to AI-enhanced ransomware attacks](https://www.ibm.com/think/x-force/slopoly-start-ai-enhanced-ransomware-attacks)  
IBM X-Force analyzes Slopoly, a likely LLM-generated PowerShell backdoor used during an Interlock ransomware intrusion. The malware was not especially advanced, which is the point: AI can lower development cost for disposable C2 clients and make malware lineage harder to attribute.

📌 [AI security: Defending against prompt injection and unsafe actions](https://www.redhat.com/en/blog/ai-security-defending-against-prompt-injection-and-unsafe-actions)  
Red Hat frames prompt injection as an instruction-confusion boundary problem, then walks through input, output, runtime, RAG, and capability-mediation controls. The useful takeaway is to enforce authorization at the tool boundary, not inside the model's willingness to comply.

📌 [Cursor Security: How to Secure AI-Generated Code in 2026](https://www.endorlabs.com/learn/cursor-security)  
Endor Labs maps coding-assistant risk into practical controls: workspace trust, dependency checks, secrets scanning, egress filtering, prompt/context hygiene, and review gates around auto-run execution. It is most valuable as an engineering checklist for teams standardizing on AI coding tools.

📌 [7.2% of MCP Servers Have Security Vulnerabilities - What We Found Scanning 1,899 Servers](https://prompttools.co/blog/mcp-server-security-study-2026)  
ClawGuard reports MCP server findings around credential exposure, tool poisoning, command injection, and missing authentication. Treat the exact vendor numbers as source-specific, but the pattern is important: MCP reviews need to inspect tool metadata, auth, path handling, and hidden instructions before an agent connects.

📌 [MCP Security 2026: 30 CVEs in 60 Days - What Went Wrong](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/)  
This MCP security deep dive catalogs recurring failures across MCP servers, clients, and infrastructure: shell injection, path traversal, authentication gaps, trust caching, and tool metadata abuse. It is a useful operator checklist for teams moving MCP from experiments into production.

📌 [Observability for AI Systems: Strengthening visibility for proactive risk detection](https://www.microsoft.com/en-us/security/blog/2026/03/18/observability-ai-systems-strengthening-visibility-proactive-risk-detection/)  
Microsoft argues that AI observability must cover prompts, grounding data, model behavior, agent actions, tool calls, and operational context. The practical lesson is that AI logging has to preserve enough evidence for abuse investigations while still controlling sensitive prompt and data exposure.

---

# 🧰 Tools & Resources

🧰 **[onecli](https://github.com/onecli/onecli)** - March-created credential vault for giving AI agents service access without exposing raw keys directly to the agent runtime. ⭐️2.2k

🧰 **[zerobox](https://github.com/afshinm/zerobox)** - March-created process sandboxing tool with file, network, and credential controls useful for constraining coding-agent execution. ⭐️602

🧰 **[api-relay-audit](https://github.com/toby-bridges/api-relay-audit)** - March-created audit tool for third-party AI API relay/proxy services, checking for hidden prompt injection, prompt leakage, instruction override, and context truncation. ⭐️452

🧰 **[hol-guard](https://github.com/hashgraph-online/hol-guard)** - March-created AI developer-agent protection tool for Codex, Claude Code, Cursor, Gemini, OpenCode, plugins, skills, MCP servers, and agent harnesses. ⭐️319

🧰 **[agentseal](https://github.com/getagentseal/agentseal)** - March-created toolkit for scanning local agent skills and MCP configs, monitoring for supply-chain issues, testing prompt-injection resistance, and auditing MCP servers. ⭐️257

🧰 **[claudit-sec](https://github.com/HarmonicSecurity/claudit-sec)** - March-created macOS audit tool for Claude Desktop and Claude Code environments, covering MCP servers, extensions, plugins, connectors, scheduled tasks, and permissions. ⭐️247

🧰 **[clawshield-public](https://github.com/SleuthCo/clawshield-public)** - March-created agent security proxy with prompt-injection, PII, secrets, policy, audit, firewall, and monitoring components for agent traffic. ⭐️130

🧰 **[AgentGuard](https://github.com/numbergroup/AgentGuard)** - March-created AI agent security framework focused on prompt injection, command injection, Unicode bypass handling, and defensive checks around agent workflows. ⭐️100

🧰 **[shellward](https://github.com/jnMetaCode/shellward)** - March-created AI agent security middleware and MCP server with DLP flow controls, prompt-injection detection, and integration hooks for agent frameworks. ⭐️93

🧰 **[agentsid-scanner](https://github.com/AgentsID-dev/agentsid-scanner)** - March-created MCP server security scanner that grades authentication, permissions, injection risk, and tool safety. ⭐️23

🧰 **[GRITS](https://github.com/X-Scale-AI/GRITS)** - March-created framework for scoring, hardening, and governing AI agents with zero-trust-oriented controls. ⭐️11

🧰 **[agent-security-playbook](https://github.com/cmaenner/agent-security-playbook)** - March-created OWASP-grounded procedures for prompt-injection testing, AI agent audits, and LLM risk assessment. ⭐️5

---

# 📄 Reports

📘 **[Artificial intelligence and machine learning: Supply chain risks and mitigations](https://www.cyber.gov.au/sites/default/files/2026-03/Artificial%20intelligence%20and%20machine%20learning%20-%20Supply%20chain%20risks%20and%20mitigations.pdf)**  
Joint government guidance from Australian, Canadian, Japanese, New Zealand, Singaporean, South Korean, UK, and US cyber agencies covering AI/ML supply-chain risks across data, models, software, infrastructure, hardware, and third-party services.

📘 **[Image-Based Prompt Injection: Hijacking Multimodal LLMs Through Visually Embedded Adversarial Instructions](https://labs.cloudsecurityalliance.org/research/csa-research-note-image-prompt-injection-multimodal-llm-2026/)**  
Cloud Security Alliance summarizes visual prompt-injection attack classes, multimodal threat scenarios, and defense-in-depth patterns for vision-capable AI systems.

📘 **[AI Chatbots as Covert Command-and-Control Infrastructure: Emerging Threat Patterns and Enterprise Defenses](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-chatbot-c2-proxy-abuse-20260308-csa-sty/)**  
Cloud Security Alliance reviews malware and threat-actor patterns that use commercial AI chatbot infrastructure as command-and-control, with defensive implications for API monitoring and abuse response.

📘 **[AI Cooperation Trajectories: Adversaries and Geostrategic Competitors](https://cetas.turing.ac.uk/publications/ai-cooperation-trajectories-adversaries-and-geostrategic-competitors)**  
CETaS examines hostile AI cooperation among adversaries and geostrategic competitors, with relevance for AI-enabled cyber operations, national-security risk, and resilience planning.

📘 **[Model Poisoning: Credential Exfiltration in Self-Hosted LLM Deployments](https://labs.cloudsecurityalliance.org/research/csa-research-note-model-poisoning-self-hosted-llm-stealer-20/)**  
Cloud Security Alliance analyzes model artifacts as a credential-theft vector in self-hosted LLM deployments, including risks from executable formats, unsafe loaders, templates, and trusted model registries.

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

1️⃣ [Attacking AI](https://www.youtube.com/watch?v=j51uMah-3js) - Jason Haddix at NDC Security 2026

2️⃣ [Hijacking Google's CI/CD Through Prompt Injection: The New Era of AI-Based Exploits](https://www.youtube.com/watch?v=OtG6hBDSt24) - Mackenzie Jackson at NDC Security 2026

3️⃣ [Black-hat LLMs](https://www.youtube.com/watch?v=1sd26pWhfmg) - Nicholas Carlini at [un]prompted 2026

4️⃣ [Training BrowseSafe: Lessons from Detecting Prompt Injection](https://www.youtube.com/watch?v=Fzgqx1MauJg) - Kyle Polley at [un]prompted 2026

5️⃣ [AI Security with Guarantees](https://www.youtube.com/watch?v=NU6l0Qcf5rU) - Ilia Shumailov at [un]prompted 2026

6️⃣ [Source to Sink: Improving LLM Vuln Discovery](https://www.youtube.com/watch?v=bxwEZMhqeR0) - Scott Behrens and Justice Cassel at [un]prompted 2026

7️⃣ [NDSS 2026 - Chasing Shadows: Pitfalls in LLM Security Research](https://www.youtube.com/watch?v=iPwKbwxsxAE) - NDSS Symposium

8️⃣ [The Responsibility Gap: AI and the Shift to True Security Accountability](https://www.youtube.com/watch?v=2DqsxSJM1mI) - RSAC 2026

9️⃣ [Ambient and Autonomous Security: Building Trust in the Agentic AI Era](https://www.youtube.com/watch?v=o4xrjdEPfoc) - RSAC 2026

🔟 [BSides Seattle 2026 Keynote: Attacking AI](https://www.youtube.com/watch?v=Y1mifbXqGDo) - BSides Seattle

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
