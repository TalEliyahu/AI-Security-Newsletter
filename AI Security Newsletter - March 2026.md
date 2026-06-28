# AI Security Newsletter - March 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

<p align="center">
  <a href="https://innovguard.com">
    <img src="assets/innovguard-sponsor.png" alt="InnovGuard" width="360">
  </a>
</p>

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month's issue is especially focused on agentic AI security, prompt injection, MCP risk, coding-agent exposure, AI malware, and runtime controls for systems that can read, reason, and act.

---

# 🔍 Insights

📌 [Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
Unit 42 documents observed indirect prompt injection against web-connected agents, including hidden or manipulated website content that agents process as instructions. The practical lesson is to treat browser content as untrusted input and enforce provenance, action limits, and monitoring before agents interact with arbitrary pages.

📌 [How Command Injection Vulnerability in OpenAI Codex Leads to GitHub Token Compromise](https://www.beyondtrust.com/blog/entry/openai-codex-command-injection-vulnerability-github-token)
BeyondTrust details a branch-name command injection path in an AI coding-agent environment with access to GitHub tokens. The finding is a reminder that repository metadata, setup scripts, branch names, and shell interpolation all become part of the agent runtime attack surface.

📌 [Claudy Day: Chaining Prompt Injection and Data Exfiltration in Claude.ai](https://www.oasis.security/blog/claude-ai-prompt-injection-data-exfiltration-vulnerability)
Oasis describes a Claude.ai attack chain combining invisible prompt injection, data exfiltration through the Anthropic Files API, and an open redirect delivery path. The case is useful for threat modeling pre-filled prompts, assistant memory, file APIs, and trusted-link assumptions.

📌 [MS-Agent does not properly sanitize commands sent to its shell tool, allowing for RCE](https://www.kb.cert.org/vuls/id/431821)
CERT/CC published CVE-2026-2256 for command injection in ModelScope's MS-Agent framework through unsanitized prompt-derived input passed to a shell tool. This is a clean example of why shell-capable agents need allowlists, sandboxing, and least privilege outside the model.

📌 [Claude Code has a Workspace Trust Dialog Bypass via Repo-Controlled Settings File](https://github.com/advisories/GHSA-mmgp-wc2j-qcv7)
GitHub Advisory Database tracks CVE-2026-33068, where Claude Code resolved repository-controlled settings before showing the workspace trust dialog. The broader lesson is that trust prompts fail if untrusted repository state can influence permission mode before the trust decision is made.

📌 [Snowflake Cortex AI Escapes Sandbox and Executes Malware](https://www.promptarmor.com/resources/snowflake-ai-escapes-sandbox-and-executes-malware)
PromptArmor details an indirect prompt injection chain against Snowflake Cortex Code CLI that bypassed command approval and escaped the sandbox. It shows why command validation, subagent behavior, and sandbox override flags need deterministic enforcement outside model reasoning.

📌 [Invisible Threats: Source Code Exfiltration in Google Antigravity](https://www.firetail.ai/blog/invisible-threats-source-code-exfiltration-in-google-antigravity)
FireTail shows how invisible Unicode instructions in source comments can steer Google Antigravity toward source-code exfiltration. Human review is not enough when the instruction stream visible to the model is not the same as the text visible to the developer.

📌 [ShadowPrompt: How Any Website Could Have Hijacked Claude's Chrome Extension](https://www.koi.ai/blog/shadowprompt-how-any-website-could-have-hijacked-anthropic-claude-chrome-extension)
Koi Security chains an overly broad `*.claude.ai` trust boundary with XSS in a first-party subdomain to inject prompts into Claude's Chrome extension. Browser AI assistants need strict extension messaging boundaries, origin review, and isolation around third-party components.

📌 [A Slopoly start to AI-enhanced ransomware attacks](https://www.ibm.com/think/x-force/slopoly-start-ai-enhanced-ransomware-attacks)
IBM X-Force analyzes Slopoly, a likely LLM-generated PowerShell backdoor used during an Interlock ransomware intrusion. The malware was not especially advanced, which is the point: AI can lower development cost for disposable C2 clients and complicate lineage analysis.

📌 [MCP Security 2026: 30 CVEs in 60 Days - What Went Wrong](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/)
This MCP security deep dive catalogs recurring failures across servers, clients, and infrastructure: shell injection, path traversal, authentication gaps, trust caching, and tool metadata abuse. It is useful as an operator checklist for moving MCP from experiments into production.

📌 [ChainFuzzer: Greybox Fuzzing for Workflow-Level Multi-Tool Vulnerabilities in LLM Agents](https://arxiv.org/abs/2603.12614)
ChainFuzzer pushes agent testing beyond single prompts by fuzzing workflow-level source-to-sink chains across tools. The work is relevant for teams building agent CI checks, pre-release reviews, and tool-chain threat models.

📌 [From Storage to Steering: Memory Control Flow Attacks on LLM Agents](https://arxiv.org/abs/2603.15125)
This paper frames persistent agent memory as a control-flow surface that can steer future behavior after the malicious context disappears. Agent builders should treat memory writes as privileged operations with provenance, expiry, review, and rollback.

📌 [Agent-Sentry: Bounding LLM Agents via Execution Provenance](https://arxiv.org/abs/2603.22868)
Agent-Sentry proposes runtime bounds that inspect action sequences and argument provenance rather than trusting the model's stated intent. The design is useful for teams looking at agent monitoring without changing the LLM, tools, or agent framework.

📌 [PAuth - Precise Task-Scoped Authorization For Agents](https://arxiv.org/abs/2603.17170)
PAuth argues that broad OAuth-style grants do not fit agents that translate natural-language tasks into concrete operations. Task-scoped authorization is a practical direction for payments, account changes, file access, and other side-effecting workflows.

📌 [AgentRAE: Remote Action Execution through Notification-based Visual Backdoors against Screenshots-based Mobile GUI Agents](https://arxiv.org/abs/2603.23007)
AgentRAE shows how screenshot-based mobile GUI agents can be steered by natural-looking notification triggers. Mobile and desktop agent teams need to treat notifications, screenshots, and visual context as potentially attacker-controlled inputs.

---

# 🧰 Tools & Resources

🧰 **[onecli](https://github.com/onecli/onecli)** - Credential vault for giving AI agents service access without exposing raw keys directly to the runtime. ⭐️2,194

🧰 **[ISC-Bench](https://github.com/wuyoscar/ISC-Bench)** - Benchmark for testing whether LLMs or agents can be pushed into sensitive-data leakage behavior. ⭐️774

🧰 **[zerobox](https://github.com/afshinm/zerobox)** - Process sandbox for agent tool execution with file, network, and credential controls. ⭐️605

🧰 **[api-relay-audit](https://github.com/toby-bridges/api-relay-audit)** - Audits third-party AI API relay and proxy services for prompt injection, prompt leakage, instruction override, and context truncation risks. ⭐️466

🧰 **[slowmist-agent-security](https://github.com/slowmist/slowmist-agent-security)** - AI agent security review framework centered on treating external inputs as untrusted until verified. ⭐️456

🧰 **[hol-guard](https://github.com/hashgraph-online/hol-guard)** - Pre-run scanner for developer agents, plugins, skills, MCP servers, and AI harnesses before tools execute. ⭐️319

🧰 **[agentseal](https://github.com/getagentseal/agentseal)** - AI agent security CLI for scanning dangerous skills and MCP configs, testing prompt injection resistance, and checking supply-chain risks. ⭐️263

🧰 **[claudit-sec](https://github.com/HarmonicSecurity/claudit-sec)** - macOS audit tool for Claude Desktop and Claude Code MCP servers, extensions, plugins, connectors, scheduled tasks, and permissions. ⭐️248

🧰 **[xalgorix](https://github.com/xalgord/xalgorix)** - Open-source AI pentesting agent for security testing and offensive-security workflows. ⭐️232

🧰 **[claudini](https://github.com/romovpa/claudini)** - Autoresearch tool for LLM adversarial attacks, jailbreaks, and prompt-injection exploration. ⭐️215

🧰 **[LLMMap](https://github.com/Hellsender01/LLMMap)** - Automated prompt-injection testing framework for LLM-integrated applications using a dual-LLM setup. ⭐️192

🧰 **[wirken](https://github.com/gebruder/wirken)** - Agent gateway with per-channel isolation, encrypted credential vaulting, and hash-chained audit logs. ⭐️147

---

# 📄 Reports

📘 **[Why cyber defenders need to be ready for frontier AI](https://www.ncsc.gov.uk/blogs/why-cyber-defenders-need-to-be-ready-for-frontier-ai)**
UK NCSC and the UK AI Security Institute summarize frontier-model performance on cyber ranges and what defenders should prioritize now. The value is practical: asset inventory, access control, secure configuration, and logging still break many AI-assisted attack chains.

📘 **[Artificial intelligence and machine learning: Supply chain risks and mitigations](https://www.cyber.gov.au/sites/default/files/2026-03/Artificial%20intelligence%20and%20machine%20learning%20-%20Supply%20chain%20risks%20and%20mitigations.pdf)**
Joint government guidance from Australian, Canadian, Japanese, New Zealand, Singaporean, South Korean, UK, and US cyber agencies covering AI/ML supply-chain risks across data, models, software, infrastructure, hardware, and third-party services.

📘 **[2026 Annual Threat Assessment of the U.S. Intelligence Community](https://www.odni.gov/index.php/newsroom/reports-publications/reports-publications-2026/4141-2026-annual-threat-assessment)**
ODNI's annual assessment gives high-authority threat context for AI, cyber operations, and adversary capability tracking. It is useful background for aligning AI security work with national threat priorities.

📘 **[Securing cloud infrastructure for AI](https://www.atlanticcouncil.org/in-depth-research-reports/issue-brief/securing-cloud-infrastructure-ai/)**
Atlantic Council's Cyber Statecraft Initiative maps AI infrastructure risk to cloud vulnerability discovery, disclosure incentives, remediation pressure, and provider accountability. It is relevant for teams deploying model workloads on shared cloud infrastructure.

📘 **[Challenges to the Monitoring of Deployed AI Systems](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-4.pdf)**
NIST CAISI outlines monitoring challenges for deployed AI systems across functionality, operations, human factors, security, compliance, and large-scale impacts. The report helps teams design monitoring programs that continue after pre-release testing.

---

# 📅 Upcoming Conferences

## April 2026

📅 [DiCyFor & AI Security Summit - Kuala Lumpur](https://www.dicyfor.com/kualalumpur2026) - April 15, 2026 · The Pullman Hotel KLCC, Kuala Lumpur, Malaysia · Organizer: DiCyFor

📅 [SANS AI Cybersecurity Summit 2026](https://www.sans.org/ai-cybersecurity-summit-2026) - April 20-21, 2026 · Arlington, VA, USA & Live Online · Organizer: SANS Institute

📅 [2026 Cyber Threat Intelligence Conference | FIRSTCTI26](https://www.first.org/conference/firstcti26/) - April 21-23, 2026 · Munich, Germany · Organizer: FIRST

📅 [AI Security Summit at Black Hat Asia 2026](https://blackhat.com/asia-26/ai-security-summit.html) - April 22, 2026 · Marina Bay Sands, Singapore · Organizer: Black Hat

## May 2026

📅 [AI Security Summit 2026](https://events.lynx.co/AI-Security-Summit/) - May 13, 2026 · Check Point HQ, Tel Aviv, Israel · Organizer: Lynx Events

## June 2026

📅 [Elbsides Conference 2026](https://www.elbsides.eu/2026/) - June 5, 2026 · Hamburg, Germany · Organizer: Elbsides

📅 [OWASP AppSec Italy Day 2026](https://owasp.org/events/) - June 17-18, 2026 · Cagliari, Sardinia, Italy · Organizer: OWASP Italy / OWASP Foundation

📅 [Area41 Conference 2026](https://area41.io/) - June 18-19, 2026 · Zurich, Switzerland · Organizer: Area41 / DC4131

## October 2026

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · University of Texas at Austin, Austin, TX, USA · Organizer: IEEE

---

# 📚 Research

📖 **How Vulnerable Are AI Agents to Indirect Prompt Injections? Insights from a Large-Scale Public Competition**
Mateusz Dziemian, Maxwell Lin, Xiaohan Fu, Micha Nowak, Nick Winter, Eliot Jones, Andy Zou, Lama Ahmad, Kamalika Chaudhuri, Sahana Chennabasappa, Xander Davies, Lauren Deason, Benjamin L. Edelman, Tanner Emek, Ivan Evtimov, Jim Gust, Maia Hamin, Kat He, Klaudia Krawiecka, Riccardo Patana, Neil Perry, Troy Peterson, Xiangyu Qi, Javier Rando, Zifan Wang, Zihan Wang, Spencer Whitman, Eric Winsor, Arman Zharmagambetov, Matt Fredrikson, Zico Kolter. [arXiv](https://arxiv.org/abs/2603.15714)

📖 **ClawWorm: Self-Propagating Attacks Across LLM Agent Ecosystems**
Yihao Zhang, Zeming Wei, Xiaokun Luan, Chengcan Wu, Zhixin Zhang, Jiangrong Wu, Haolin Wu, Huanran Chen, Jun Sun, Meng Sun. [arXiv](https://arxiv.org/abs/2603.15727)

📖 **Are AI-assisted Development Tools Immune to Prompt Injection?**
Charoes Huang, Xin Huang, Amin Milani Fard. [arXiv](https://arxiv.org/abs/2603.21642)

📖 **Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning**
Charoes Huang, Xin Huang, Ngoc Phu Tran, Amin Milani Fard. [arXiv](https://arxiv.org/abs/2603.22489)

📖 **T-MAP: Red-Teaming LLM Agents with Trajectory-aware Evolutionary Search**
Hyomin Lee, Sangwoo Park, Yumin Choi, Sohyun An, Seanie Lee, Sung Ju Hwang. [arXiv](https://arxiv.org/abs/2603.22341)

📖 **Invisible Threats from Model Context Protocol: Generating Stealthy Injection Payload via Tree-based Adaptive Search**
Yulin Shen, Xudong Pan, Geng Hong, Min Yang. [arXiv](https://arxiv.org/abs/2603.24203)

📖 **Evaluating Privilege Usage of Agents with Real-World Tools**
Quan Zhang, Lianhang Fu, Lvsi Lian, Gwihwan Go, Yujue Wang, Chijin Zhou, Yu Jiang, Geguang Pu. [arXiv](https://arxiv.org/abs/2603.28166)

📖 **Kill-Chain Canaries: Stage-Level Tracking of Prompt Injection Across Attack Surfaces and Model Safety Tiers**
Haochuan Kevin Wang, Zechen Zhang. [arXiv](https://arxiv.org/abs/2603.28013)

📖 **"Elementary, My Dear Watson." Detecting Malicious Skills via Neuro-Symbolic Reasoning across Heterogeneous Artifacts**
Shenao Wang, Junjie He, Yanjie Zhao, Yayi Wang, Kan Yu, Haoyu Wang. [arXiv](https://arxiv.org/abs/2603.27204)

📖 **PIDP-Attack: Combining Prompt Injection with Database Poisoning Attacks on Retrieval-Augmented Generation Systems**
Haozhen Wang, Haoyue Liu, Jionghao Zhu, Zhichao Wang, Yongxin Guo, Xiaoying Tang. [arXiv](https://arxiv.org/abs/2603.25164)

---

# 🎥 Videos

1️⃣ [Hijacking Google's CI/CD Through Prompt Injection: The New Era of AI-Based Exploits](https://www.youtube.com/watch?v=OtG6hBDSt24) - Mackenzie Jackson at NDC Security 2026

2️⃣ [Black-hat LLMs](https://www.youtube.com/watch?v=1sd26pWhfmg) - Nicholas Carlini at [un]prompted 2026

3️⃣ [NDSS 2026 - Chasing Shadows: Pitfalls in LLM Security Research](https://www.youtube.com/watch?v=iPwKbwxsxAE) - NDSS Symposium

4️⃣ [Ambient and Autonomous Security: Building Trust in the Agentic AI Era](https://www.youtube.com/watch?v=o4xrjdEPfoc) - RSAC 2026

5️⃣ [Attacking AI](https://www.youtube.com/watch?v=Y1mifbXqGDo) - Jason Haddix at BSides Seattle 2026

6️⃣ [Using LLMs For Vulnerability Discovery: Hacking Like Humans (Without Humans)](https://www.youtube.com/watch?v=CwSXtcRLC_w) - Jeevan Jutla at BSides London 2025

7️⃣ [Agentic Exposure Hijacking Web Browsing AI Assistants](https://www.youtube.com/watch?v=mcW_9bNjLrw) - Sarit Yerushalmi at BSides TLV 2025

8️⃣ [Hijacking AI Agents with Special Token Injection (STI)](https://www.youtube.com/watch?v=FFO9CAxLztg) - Armend Gashi at BSides Zagreb 2025

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
