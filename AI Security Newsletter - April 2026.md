# AI Security Newsletter - April 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month's issue focuses on technical AI security research, vulnerability analysis, exploit chains, agent/tool abuse, AI malware, and concrete defensive engineering lessons.

---

# 🔍 Insights

📌 [AI threats in the wild: The current state of prompt injections on the web](https://blog.google/security/prompt-injections-web/)
Google scanned public web content for indirect prompt injection patterns and separated benign research examples from attempts to influence AI agents, SEO outputs, and data exposure. The useful signal is operational: defenders need detection pipelines that can distinguish educational payloads from instructions positioned for agents that browse untrusted pages.

📌 [Google Workspace's continuous approach to mitigating indirect prompt injections](https://blog.google/security/google-workspaces-continuous-approach-to-mitigating-indirect-prompt-injections/)
Google details how Workspace with Gemini handles indirect prompt injection as a moving control problem rather than a one-time filter fix. The post is valuable for teams designing agent defenses because it emphasizes policy engines, URL handling, tool-chain constraints, ML defenses, and fast configuration updates at the product boundary.

📌 [Never Wait for Approval - Prompt Injection in Strix AI Pentesting Agent Steals Cloud Credentials](https://oddguan.com/blog/strix-ai-agent-security-scanner-prompt-injection-credential-theft/)
Aonan Guan shows how malicious project files can steer an autonomous pentesting agent into command execution and credential theft. The lesson travels beyond Strix: offensive agents that inspect untrusted repositories need the same isolation, approval, and secret-boundary discipline as the targets they assess.

📌 [Comment and Control: Prompt Injection to Credential Theft in Claude Code, Gemini CLI, and GitHub Copilot Agent](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)
This writeup demonstrates GitHub comments, issues, and pull request text as command-and-control surfaces for coding agents running in CI. For product security teams, it is a sharp reminder that repository metadata is attacker-controlled input when an agent can read it and access build secrets.

📌 [Rotten Apples: The Technical Details of RSAC's Successful Apple Intelligence Prompt Injection Attack](https://www.rsaconference.com/library/blog/rotten-apples-the-technical-details-of-rsacs-successful-apple-intelligence-prompt-injection-attack)
RSAC researchers explain a prompt-injection attack against Apple's on-device foundation model using filter-bypass techniques and model instruction manipulation. The practical takeaway is that local inference does not remove prompt-injection risk when applications expose OS-level model APIs to untrusted or transformed content.

📌 [Gemini CLI: Remote Code Execution via workspace trust and tool allowlisting bypasses](https://github.com/advisories/GHSA-wpqr-6v78-jr5g)
GitHub's advisory tracks a Gemini CLI issue where workspace trust and allowlisting behavior could be bypassed into code execution. The pattern matters for every coding-agent product: trust decisions must be enforced before repository-controlled state, tool configuration, or prompt-derived instructions can influence execution.

📌 [Flowise CVSS 10.0 RCE: AI Agent Builders Under Attack](https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/)
CSA analyzes active exploitation of a Flowise CustomMCP code injection flaw affecting agent-builder deployments. The risk is not just another web RCE: agent platforms often concentrate credentials, workflow definitions, tool links, and model-provider access in one exposed service.

📌 [MCP by Design: RCE Across the AI Agent Ecosystem](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/)
CSA summarizes OX Security's finding that MCP STDIO command definitions can become a host execution surface across SDKs and clients. Teams adopting MCP should treat server registration as privileged code installation, not as harmless tool discovery.

📌 [SGLang CVE-2026-5760: RCE via Poisoned GGUF Model Files](https://labs.cloudsecurityalliance.org/research/csa-research-note-sglang-cve-2026-5760-gguf-rce-20260422-csa/)
This note covers unauthenticated code execution in SGLang inference servers through malicious GGUF model handling. It is a model supply-chain warning: inference infrastructure has to verify model provenance and sandbox parsing paths, especially when models are pulled from public hubs.

📌 [LiteLLM Pre-Auth SQL Injection Exploited in 36 Hours](https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-pre-auth-sqli-20260428-csa-styled/)
CSA describes a LiteLLM proxy SQL injection in the token-verification path and the credential blast radius that follows when an LLM gateway stores virtual keys and upstream provider credentials. The defensive priority is urgent patching plus credential rotation, not only database cleanup.

📌 [LeRobot CVE-2026-25874: Unauthenticated RCE via Pickle](https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/)
CSA covers a LeRobot async inference RCE caused by unsafe pickle deserialization over unauthenticated gRPC. The security impact reaches beyond compute because compromised inference servers can sit in the control path of physical robotic hardware.

📌 [ATHR: Industrializing Credential Theft via AI Voice Agents](https://labs.cloudsecurityalliance.org/research/csa-research-note-athr-ai-vishing-platform-20260419-csa-styl/)
CSA summarizes ATHR, an AI-voice-agent platform for automating vishing and credential capture. The practical security relevance is clear: callback-only phishing flows, verification-code harvesting, and synthetic voice interaction need their own detection and user-defense patterns.

📌 [Slopsquatting: AI Code Hallucinations Fuel Supply Chain Attacks](https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/)
This CSA note frames hallucinated package names as a repeatable supply-chain attack path against AI-assisted development. Engineering teams should verify AI-recommended dependencies against registries, publishers, creation dates, lockfiles, and allowlists before package managers or agents install anything.

📌 [Entra Agent ID Administrator Flaw: Service Principal Takeover](https://labs.cloudsecurityalliance.org/research/csa-research-note-entra-agent-id-admin-takeover-20260428-csa/)
CSA analyzes a Microsoft Entra authorization boundary issue where an agent-identity administration role could affect broader service-principal ownership. The case is useful because agent identity is being built on existing non-human identity infrastructure, and small scope mistakes can become tenant-level privilege escalation.

📌 [AI Browser Extensions: Shadow AI's Hidden Attack Surface](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-browser-extension-attack-surface-202604/)
CSA maps risks from AI-capable browser extensions, including DOM scraping, conversation exfiltration, and indirect prompt injection through browser-visible content. For enterprise teams, extension governance is becoming part of AI security because these tools sit inside authenticated sessions and observe sensitive workflows.

📌 [Arbitrary Code Injection in LiteLLM](https://security.snyk.io/vuln/SNYK-PYTHON-LITELLM-16049285)
Snyk documents a LiteLLM code-injection issue in a guardrail testing endpoint reachable by authenticated callers. It is a useful reminder that LLM gateway admin and test routes need the same hardening as production inference paths because they often execute user-controlled templates or code.

---

# 🧰 Tools & Resources

🧰 **[deepsec](https://github.com/vercel-labs/deepsec)** - April-created security harness for finding codebase vulnerabilities with coding agents. ⭐️2736

🧰 **[ThinkWatch](https://github.com/ThinkWatchProject/ThinkWatch)** - April-created AI bastion host for secure AI API and MCP access with proxying, RBAC, audit logs, rate limiting, and cost tracking. ⭐️893

🧰 **[cve-mcp-server](https://github.com/mukul975/cve-mcp-server)** - April-created MCP server exposing CVE lookup, EPSS, CISA KEV, MITRE ATT&CK, Shodan, VirusTotal, and related security-intelligence tools. ⭐️565

🧰 **[pentest-ai](https://github.com/0xSteph/pentest-ai)** - April-created offensive-security MCP server with wrapped tools, specialist agents, and web-application probes for controlled testing. ⭐️258

🧰 **[kontext-cli](https://github.com/kontext-security/kontext-cli)** - April-created runtime security layer for tool-using AI agents with permissions, credential handling, policy enforcement, and audit trails. ⭐️195

🧰 **[SkillWard](https://github.com/Fangcun-AI/SkillWard)** - April-created scanner for agent skills that looks for hidden threats before deployment. ⭐️123

🧰 **[Talon](https://github.com/CarbeneAI/Talon)** - April-created penetration-testing MCP for Claude Code with recon, service enumeration, and reporting workflows. ⭐️55

🧰 **[vulnhawk](https://github.com/momenbasel/vulnhawk)** - April-created AI-assisted SAST scanner focused on auth bypass, IDOR, and logic bugs across common application languages. ⭐️55

🧰 **[vibecop](https://github.com/bhvbhushan/vibecop)** - April-created deterministic linter for AI-generated code review with detectors and a GitHub Action gate. ⭐️51

🧰 **[bordair-multimodal](https://github.com/Josh-blythe/bordair-multimodal)** - April-created multimodal prompt-injection test suite spanning text, image, document, and audio payloads. ⭐️49

🧰 **[crucible](https://github.com/crucible-security/crucible)** - April-created testing framework for autonomous red teaming, behavioral monitoring, and security checks for LLM agents. ⭐️40

🧰 **[Agent-Security-Regression-Harness](https://github.com/OWASP/Agent-Security-Regression-Harness)** - April-created OWASP harness for executable security regression tests against agentic applications and MCP-integrated systems. ⭐️20

---

# 📄 Reports

📘 **[The AI Velocity Gap](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-ai-velocity-gap-development-security-capacity/)**
Cloud Security Alliance examines how AI-assisted development changes application-security capacity planning, code-review pressure, vulnerability debt, and governance needs for software teams.

📘 **[The Collapsing Exploit Window](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-collapsing-exploit-window-ai-mtte-20260411-cs/)**
Cloud Security Alliance analyzes how AI-assisted exploit development, patch diffing, and attacker automation compress the time defenders have between disclosure and exploitation.

📘 **[The AI Agent Disclosure Vacuum](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-ai-agent-disclosure-accountability-gap-202604/)**
Cloud Security Alliance explains why traditional vulnerability disclosure, CVE assignment, and accountability workflows struggle with agentic AI systems, MCP components, and compositional toolchains.

📘 **[NIST AI Agent Standards: Listening Sessions and Emerging Controls](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-20260416-csa-style/)**
Cloud Security Alliance summarizes NIST's AI Agent Standards Initiative, identity and authorization work, and emerging control themes for agent deployment.

📘 **[EU AI Act Compliance: prEN 18286 and ISO 42001](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-pren-18286-iso-42001-20260428-cs/)**
Cloud Security Alliance maps the EU AI Act quality-management path, ISO/IEC 42001 limits, and control architecture implications for organizations operating high-risk AI systems.

---

# 📅 Upcoming Conferences

## May 2026

📅 [AI Security Summit 2026](https://events.lynx.co/AI-Security-Summit/) - May 13, 2026 · Check Point HQ, Tel Aviv, Israel · Organizer: Lynx Events

## August 2026

📅 [The AI Summit at Black Hat USA 2026](https://blackhat.com/us-26/ai-summit.html) - August 4, 2026 · Mandalay Bay, Las Vegas, NV, USA · Organizer: Black Hat

## October 2026

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · University of Texas at Austin, Austin, TX, USA · Organizer: IEEE

---

# 📚 Research

📖 **Indirect Prompt Injection in the Wild: An Empirical Study of Prevalence, Techniques, and Objectives**
Soheil Khodayari, Xuenan Zhang, Bhupendra Acharya, Giancarlo Pellegrino. [arXiv](https://arxiv.org/abs/2604.27202)

📖 **SnapGuard: Lightweight Prompt Injection Detection for Screenshot-Based Web Agents**
Mengyao Du, Han Fang, Haokai Ma, Jiahao Chen, Kai Xu, Quanjun Yin, Ee-Chien Chang. [arXiv](https://arxiv.org/abs/2604.25562)

📖 **AgentVisor: Defending LLM Agents Against Prompt Injection via Semantic Virtualization**
Zonghao Ying, Haozheng Wang, Jiangfan Liu, Quanchen Zou, Aishan Liu, Jian Yang, Yaodong Yang, Xianglong Liu. [arXiv](https://arxiv.org/abs/2604.24118)

📖 **Ghost in the Agent: Redefining Information Flow Tracking for LLM Agents**
Yuandao Cai, Wensheng Tang, Cheng Wen, Shengchao Qin. [arXiv](https://arxiv.org/abs/2604.23374)

📖 **Breaking MCP with Function Hijacking Attacks: Novel Threats for Function Calling and Agentic Models**
Yannis Belkhiter, Giulio Zizzo, Sergio Maffeis, Seshu Tirupathi, John D. Kelleher. [arXiv](https://arxiv.org/abs/2604.20994)

📖 **SafeAgent: A Runtime Protection Architecture for Agentic Systems**
Hailin Liu, Eugene Ilyushin, Jie Ni, Min Zhu. [arXiv](https://arxiv.org/abs/2604.17562)

📖 **CASCADE: A Cascaded Hybrid Defense Architecture for Prompt Injection Detection in MCP-Based Systems**
İpek Abasıkeleş Turgut, Edip Gümüş. [arXiv](https://arxiv.org/abs/2604.17125)

📖 **HarmfulSkillBench: How Do Harmful Skills Weaponize Your Agents?**
Yukun Jiang, Yage Zhang, Michael Backes, Xinyue Shen, Yang Zhang. [arXiv](https://arxiv.org/abs/2604.15415)

📖 **WebAgentGuard: A Reasoning-Driven Guard Model for Detecting Prompt Injection Attacks in Web Agents**
Yulin Chen, Tri Cao, Haoran Li, Yue Liu, Yibo Li, Yufei He, Le Minh Khoi, Yangqiu Song, Shuicheng Yan, Bryan Hooi. [arXiv](https://arxiv.org/abs/2604.12284)

📖 **ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection**
Wei Zhao, Zhe Li, Peixin Zhang, Jun Sun. [arXiv](https://arxiv.org/abs/2604.11790)

📖 **Credential Leakage in LLM Agent Skills: A Large-Scale Empirical Study**
Zhihao Chen, Ying Zhang, Yi Liu, Gelei Deng, Yuekang Li, Yanjun Zhang, Jianting Ning, Leo Yu Zhang, Lei Ma, Zhiqiang Li. [arXiv](https://arxiv.org/abs/2604.03070)

📖 **From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers**
Yiheng Huang, Zhijia Zhao, Bihuan Chen, Susheng Wu, Zhuotong Zhou, Yiheng Cao, Xin Hu, Xin Peng. [arXiv](https://arxiv.org/abs/2604.01905)

---

# 🎥 Videos

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
