# AI Security Newsletter - April 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month's issue focuses on technical AI security research, vulnerability analysis, exploit chains, agent/tool abuse, AI malware, and concrete defensive engineering lessons.

---

# 🔍 Insights

📌 [AI threats in the wild: The current state of prompt injections on the web](https://blog.google/security/prompt-injections-web/)
Google scanned public web content for indirect prompt injection patterns and separated benign research examples from attempts to influence AI agents, SEO outputs, and data exposure. The useful signal is operational: defenders need detection pipelines that can distinguish educational payloads from instructions positioned for agents that browse untrusted pages.

📌 [Comment and Control: Prompt Injection to Credential Theft in Claude Code, Gemini CLI, and GitHub Copilot Agent](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)
This writeup demonstrates GitHub comments, issues, and pull request text as command-and-control surfaces for coding agents running in CI. For product security teams, it is a sharp reminder that repository metadata is attacker-controlled input when an agent can read it and access build secrets.

📌 [Rotten Apples: The Technical Details of RSAC's Successful Apple Intelligence Prompt Injection Attack](https://www.rsaconference.com/library/blog/rotten-apples-the-technical-details-of-rsacs-successful-apple-intelligence-prompt-injection-attack)
RSAC researchers explain a prompt-injection attack against Apple's on-device foundation model using filter-bypass techniques and model instruction manipulation. The practical takeaway is that local inference does not remove prompt-injection risk when applications expose OS-level model APIs to untrusted or transformed content.

📌 [Flowise Custom MCP Code Injection](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c9gw-hvqq-f33r)
Flowise's advisory covers a code-injection issue in its Custom MCP path that could let authenticated users reach command execution on agent-builder infrastructure. The lesson for platform teams is direct: MCP configuration surfaces should be treated as privileged execution boundaries, not low-risk workflow metadata.

📌 [The MCP Vulnerability at the Heart of the AI Supply Chain](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
OX Security shows how MCP server registration can turn tool configuration into host command execution across multiple clients and SDKs. Teams adopting MCP need provenance checks, approval gates, and runtime isolation before accepting tool definitions from repositories or third-party packages.

📌 [SGLang CVE-2026-5760](https://cyberveille.esante.gouv.fr/alertes/sglang-cve-2026-5760-2026-04-24)
CERT Sante tracks an SGLang issue involving malicious GGUF model handling in inference infrastructure. It is a model supply-chain reminder: model files and tokenizer templates need the same sandboxing, signature, and provenance scrutiny as code artifacts.

📌 [Arbitrary Code Injection in LiteLLM](https://security.snyk.io/vuln/SNYK-PYTHON-LITELLM-16049285)
Snyk documents a LiteLLM code-injection issue in a guardrail testing endpoint reachable by authenticated callers. It is a useful reminder that LLM gateway admin and test routes need the same hardening as production inference paths because they often execute user-controlled templates or code.

📌 [Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass](https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc)
The marimo advisory describes a pre-authentication path to terminal access through WebSocket authentication bypass behavior. AI notebook and developer-tool servers should assume local productivity features become remote attack surfaces once exposed in shared workspaces.

📌 [langchain-openai Vulnerable to Server-Side Request Forgery](https://github.com/langchain-ai/langchain/security/advisories/GHSA-r7w7-9xr2-qq2r)
LangChain's advisory documents an SSRF issue tied to redirect and host handling. Even when impact is bounded, agent and LLM framework integrations should validate network destinations because prompt-driven workflows can turn library fetch behavior into data-plane access.

📌 [Cursor Triple Backtrick: Bypassing Guardrails for Arbitrary Command Execution](https://noma.security/blog/cursor-triple-backtrick-bypassing-guardrails-for-arbitrary-command-execution/)
Noma Security details a Cursor guardrail-bypass technique that used command substitution syntax to move from suggested code into shell execution. Coding-agent products need enforcement outside the model response path, because UI warnings and prompt-level intent checks are not a reliable execution boundary.

📌 [10 Indirect Prompt Injection Payloads That Actually Work](https://www.forcepoint.com/blog/x-labs/indirect-prompt-injection-payloads)
Forcepoint X-Labs collected indirect prompt-injection payload patterns that target web-connected assistants through hidden instructions, markdown, and content formatting tricks. The practical value is defensive testing: teams can turn these patterns into repeatable cases for browser agents, copilots, and RAG systems.

📌 [Inside Lazarus: How North Korea Uses AI to Industrialize Attacks on Developers](https://expel.com/blog/inside-lazarus-how-north-korea-uses-ai-to-industrialize-attacks-on-developers)
Expel walks through Lazarus activity using AI to scale developer targeting and social-engineering workflows. For security teams protecting engineering orgs, the important signal is not novelty for its own sake; it is that AI-assisted targeting reduces attacker cost across recruiting, messaging, and payload delivery.

📌 [Claude PromptMink Malware Crypto](https://www.reversinglabs.com/blog/claude-promptmink-malware-crypto)
ReversingLabs analyzes PromptMink, a malware campaign where AI-generated package content and social-engineering material were used around cryptocurrency theft. The case reinforces why package vetting, dependency provenance, and developer-environment monitoring need to account for AI-assisted supply-chain operations.

📌 [Skills Are the New npm Package](https://www.firstops.dev/blog/skills-are-the-new-npm-package)
FirstOps argues that reusable agent skills create a package-management problem for AI workflows. Security teams should track skill provenance, permissions, transitive dependencies, and update paths before allowing skills to run with repository, browser, or production-system access.

📌 [Agent ID Administrator Scope Overreach: Service Principal Takeover in Entra ID](https://www.silverfort.com/blog/agent-id-administrator-scope-overreach-service-principal-takeover-in-entra-id/)
Silverfort details an Entra role-boundary issue where agent identity administration could affect broader service-principal ownership. The case matters because agent identities are being grafted onto existing non-human identity systems, and small scoping mistakes can become high-impact privilege paths.

📌 [CVE-2026-25874: HuggingFace LeRobot Unauthenticated RCE via Pickle Deserialization in gRPC PolicyServer](https://chocapikk.com/posts/2026/lerobot-pickle-rce/)
Chocapikk documents unsafe pickle deserialization in LeRobot's gRPC PolicyServer path. Robotics and AI-inference teams should avoid treating internal policy-serving endpoints as trusted by default, especially when model-serving code is close to physical or operational control loops.

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

📘 **[Prompt Injection Attacks Pose Growing Risk to Generative AI](https://www.cisecurity.org/about-us/media/press-release/new-cis-report-warns-prompt-injection-attacks-pose-growing-risk-to-generative-ai)**
Center for Internet Security highlights prompt injection as a growing operational risk for generative AI deployments and frames the issue around practical controls, awareness, and secure adoption.

📘 **[Careful Adoption of Agentic AI Services](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/)**
NSA, CISA, ASD's ACSC, CCCS, NCSC-NZ, and NCSC-UK provide joint guidance for deploying agentic AI with least privilege, human oversight, reversibility, and security controls aligned to existing cybersecurity practice.

📘 **[AI Security Solutions Landscape for AI and Agentic Red Teaming Q2 2026](https://genai.owasp.org/resource/ai-security-solutions-landscape-for-ai-and-agentic-red-teaming-q2-2026/)**
OWASP maps tools and capabilities for AI and agentic red teaming, giving practitioners a non-vendor reference point for evaluating testing, attack simulation, and assurance coverage.

📘 **[GovRAMP Releases Policy Path Forward to Advance Cybersecurity Framework Harmonization](https://govramp.org/blog/govramp-releases-policy-path-forward-to-advance-cybersecurity-framework-harmonization/)**
GovRAMP's publications focus on reducing fragmented cybersecurity requirements across government environments where cloud and AI adoption are expanding. The useful angle is evidence reuse and control alignment for teams trying to secure AI-enabled public-sector systems without multiplying compliance work.

📘 **[The AI Velocity Gap](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-ai-velocity-gap-development-security-capacity/)**
Cloud Security Alliance examines how AI-assisted development changes application-security capacity planning, code-review pressure, vulnerability debt, and governance needs for software teams.

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

1️⃣ [BSides Charlotte 2026: Provisioned Privilege](https://www.youtube.com/watch?v=rMo1WbEmoZY) - Dr. Pravallika Devineni & Doug Garbarino at BSides Charlotte

2️⃣ [Model Context Protocol (MCP): The Future of AI-Powered SOC Workflows](https://www.youtube.com/watch?v=A8bWZUOO8Ps) - James "Pope" Pope at BSidesSLC

3️⃣ [Beyond Vibe Coding: Building Reliable AI AppSec Tools](https://www.youtube.com/watch?v=0MN9R5780Ds) - Emily Choi Greene at BSides Vancouver Island

4️⃣ [MCP LFI in 60 minutes (or your money back)](https://www.youtube.com/watch?v=_iZDkQ9q40U) - Kurt Boberg at BSides Seattle

5️⃣ [Up and Down Technique: Exposing Hidden Data from RAG Systems](https://www.youtube.com/watch?v=PEq-Njz4G70) - Pedro "drop" Paniago at BSides Limburg

6️⃣ [AI, MCP and Security](https://www.youtube.com/watch?v=pT6QY2CmAZA) - Dominik Guhr at Keycloak DevDay

7️⃣ [SnowFROC 2026 - Hacking AI-Enabled Apps](https://www.youtube.com/watch?v=Ki5VOTmT81w) - SnowFROC 2026

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
