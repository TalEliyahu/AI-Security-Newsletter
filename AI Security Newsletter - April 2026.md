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

📌 [Flowise Custom MCP Code Injection](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c9gw-hvqq-f33r)  
Flowise's advisory covers a code-injection issue in its Custom MCP path that could let authenticated users reach command execution on agent-builder infrastructure. The lesson for platform teams is direct: MCP configuration surfaces should be treated as privileged execution boundaries, not low-risk workflow metadata.

📌 [The MCP Vulnerability at the Heart of the AI Supply Chain](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)  
OX Security shows how MCP server registration can turn tool configuration into host command execution across multiple clients and SDKs. Teams adopting MCP need provenance checks, approval gates, and runtime isolation before accepting tool definitions from repositories or third-party packages.

📌 [SGLang CVE-2026-5760](https://cyberveille.esante.gouv.fr/alertes/sglang-cve-2026-5760-2026-04-24)  
CERT Sante tracks an SGLang issue involving malicious GGUF model handling in inference infrastructure. It is a model supply-chain reminder: model files and tokenizer templates need the same sandboxing, signature, and provenance scrutiny as code artifacts.

📌 [Azure MCP Server Missing Authentication for Critical Function](https://nvd.nist.gov/vuln/detail/CVE-2026-32211)  
NVD's entry for CVE-2026-32211 covers a missing-authentication flaw in Azure MCP Server that could disclose information over the network. The AI-security lesson is direct: MCP servers that bridge agents into cloud or developer infrastructure need ordinary authentication and authorization controls before they become reusable automation surfaces.

📌 [Guardrail Sandbox Escape in LiteLLM](https://x41-dsec.de/lab/advisories/x41-2026-001-litellm/)  
X41 documents a LiteLLM guardrail testing endpoint where regex-based filtering could be bypassed with bytecode rewriting to execute code as the server process. It is a useful reminder that LLM gateway admin and test routes need the same hardening as production inference paths because they often execute user-controlled templates or code.

📌 [FastGPT NoSQL Injection in loginByPassword Leads to Authentication Bypass](https://github.com/labring/FastGPT/security/advisories/GHSA-x8mx-2mr7-h9xg)  
FastGPT's advisory documents a NoSQL-injection path in the password login endpoint that could let unauthenticated attackers bypass authentication as any user, including root administrator. Agent-builder platforms need runtime input validation on control-plane APIs, not just TypeScript assertions that disappear at runtime.

📌 [Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass](https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc)  
The marimo advisory describes a pre-authentication path to terminal access through WebSocket authentication bypass behavior. AI notebook and developer-tool servers should assume local productivity features become remote attack surfaces once exposed in shared workspaces.

📌 [LMDeploy SSRF Exploited Against LLM Inference Engines](https://www.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours)  
Sysdig observed exploitation attempts against LMDeploy shortly after disclosure of an SSRF flaw in vision-language image loading. For teams running GPU-hosted inference, user-supplied image URLs, RAG fetchers, and agent retrieval paths should be treated as internal-network access primitives unless egress controls and metadata protections are enforced.

📌 [langchain-openai Vulnerable to Server-Side Request Forgery](https://github.com/langchain-ai/langchain/security/advisories/GHSA-r7w7-9xr2-qq2r)  
LangChain's advisory documents an SSRF issue tied to redirect and host handling. Even when impact is bounded, agent and LLM framework integrations should validate network destinations because prompt-driven workflows can turn library fetch behavior into data-plane access.

📌 [Cursor Triple Backtrick: Bypassing Guardrails for Arbitrary Command Execution](https://noma.security/blog/cursor-triple-backtrick-bypassing-guardrails-for-arbitrary-command-execution/)  
Noma Security details a Cursor guardrail-bypass technique that used command substitution syntax to move from suggested code into shell execution. Coding-agent products need enforcement outside the model response path, because UI warnings and prompt-level intent checks are not a reliable execution boundary.

📌 [Claude PromptMink Malware Crypto](https://www.reversinglabs.com/blog/claude-promptmink-malware-crypto)  
ReversingLabs analyzes PromptMink, a malware campaign where AI-generated package content and social-engineering material were used around cryptocurrency theft. The case reinforces why package vetting, dependency provenance, and developer-environment monitoring need to account for AI-assisted supply-chain operations.

📌 [PraisonAI Sensitive Environment Variable Exposure via Untrusted MCP Subprocess Execution](https://github.com/advisories/GHSA-pj2r-f9mw-vrcq)  
GitHub's advisory describes PraisonAI MCP subprocesses inheriting the parent process environment, exposing API keys and other secrets to untrusted MCP commands. The defensive takeaway is to pass explicit environment allowlists into tool subprocesses instead of letting agent integrations inherit every local credential by default.

📌 [Agent ID Administrator Scope Overreach: Service Principal Takeover in Entra ID](https://www.silverfort.com/blog/agent-id-administrator-scope-overreach-service-principal-takeover-in-entra-id/)  
Silverfort details an Entra role-boundary issue where agent identity administration could affect broader service-principal ownership. The case matters because agent identities are being grafted onto existing non-human identity systems, and small scoping mistakes can become high-impact privilege paths.

📌 [CVE-2026-25874: HuggingFace LeRobot Unauthenticated RCE via Pickle Deserialization in gRPC PolicyServer](https://chocapikk.com/posts/2026/lerobot-pickle-rce/)  
Chocapikk documents unsafe pickle deserialization in LeRobot's gRPC PolicyServer path. Robotics and AI-inference teams should avoid treating internal policy-serving endpoints as trusted by default, especially when model-serving code is close to physical or operational control loops.

---

# 🧰 Tools & Resources

🧰 **[deepsec](https://github.com/vercel-labs/deepsec)** - Security harness for finding codebase vulnerabilities with coding agents.

🧰 **[ThinkWatch](https://github.com/ThinkWatchProject/ThinkWatch)** - AI bastion host for secure AI API and MCP access with proxying, RBAC, audit logs, rate limiting, and cost tracking.

🧰 **[cve-mcp-server](https://github.com/mukul975/cve-mcp-server)** - MCP server exposing CVE lookup, EPSS, CISA KEV, MITRE ATT&CK, Shodan, VirusTotal, and related security-intelligence tools.

🧰 **[pentest-ai](https://github.com/0xSteph/pentest-ai)** - Offensive-security MCP server with wrapped tools, specialist agents, and web-application probes for controlled testing.

🧰 **[kontext-cli](https://github.com/kontext-security/kontext-cli)** - Runtime security layer for tool-using AI agents with permissions, credential handling, policy enforcement, and audit trails.

🧰 **[SkillWard](https://github.com/Fangcun-AI/SkillWard)** - Scanner for agent skills that looks for hidden threats before deployment.

🧰 **[Talon](https://github.com/CarbeneAI/Talon)** - Penetration-testing MCP for Claude Code with recon, service enumeration, and reporting workflows.

🧰 **[vulnhawk](https://github.com/momenbasel/vulnhawk)** - AI-assisted SAST scanner focused on auth bypass, IDOR, and logic bugs across common application languages.

🧰 **[vibecop](https://github.com/bhvbhushan/vibecop)** - Deterministic linter for AI-generated code review with detectors and a GitHub Action gate.

🧰 **[bordair-multimodal](https://github.com/Josh-blythe/bordair-multimodal)** - Multimodal prompt-injection test suite spanning text, image, document, and audio payloads.

🧰 **[crucible](https://github.com/crucible-security/crucible)** - Testing framework for autonomous red teaming, behavioral monitoring, and security checks for LLM agents.

🧰 **[vlnr](https://github.com/nandrzej/vlnr)** - AI security agent for Python supply-chain review that scans packages, generates exploits, and validates findings in Docker.

🧰 **[Agent-Security-Regression-Harness](https://github.com/OWASP/Agent-Security-Regression-Harness)** - OWASP regression harness for testing security behavior in agentic applications and MCP-integrated systems.

🧰 **[whitney](https://github.com/transilienceai/whitney)** - Static AI security scanner for prompt injection, broken LLM-as-judge patterns, and AI dependency SBOM coverage.

🧰 **[prompt-authgate](https://github.com/hswtnb-blip/prompt-authgate)** - Claude Code prompt-injection defense that separates trusted user prompts from untrusted file, web, and MCP input.

🧰 **[AgentForensics](https://github.com/aparnaa19/AgentForensics)** - Real-time LLM agent session monitor for detecting prompt injection across tool outputs, web pages, documents, and APIs.

🧰 **[pdf-injection-scanner](https://github.com/Andy8647/pdf-injection-scanner)** - CLI scanner for hidden prompt-injection content in PDFs, including white text, tiny fonts, and off-page text.

🧰 **[Armorer-Guard](https://github.com/ArmorerLabs/Armorer-Guard)** - Local scanner for AI-agent prompt injection, credential leaks, data exfiltration, and risky tool calls.

---

# 📄 Reports

📘 **[Careful Adoption of Agentic AI Services](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/)**  
NSA, CISA, ASD's ACSC, CCCS, NCSC-NZ, and NCSC-UK provide joint guidance for deploying agentic AI with least privilege, human oversight, reversibility, and security controls aligned to existing cybersecurity practice.

📘 **[OWASP GenAI Exploit Round-up Report Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)**  
OWASP consolidates AI-related exploit disclosures and incidents from early 2026, mapping them to LLM and agentic application risks. The useful value is pattern recognition across agent identity abuse, orchestration weaknesses, prompt injection, and supply-chain failures.

📘 **[AI Agents & Agency in the Internet Ecosystem](https://securityandtechnology.org/virtual-library/white-paper/ai-agents-agency-in-the-internet-ecosystem/)**  
The Institute for Security and Technology frames agentic AI around identity, attribution, evaluation, and security in machine-to-machine internet interactions. It is most useful for teams thinking about provenance, authorization scope, and accountability across autonomous agent workflows.

📘 **[Securing the Agentic State: A Practical Guide to Identity & Access Management for AI Agents in Federal Government](https://atarc.org/project/white-paper-securing-the-agentic-state/)**  
ATARC's Identity Management Working Group focuses on identity and access management for AI agents in federal environments. The practical takeaway is that agent permissions, delegation, speed, and auditability need controls beyond human-centric IAM assumptions.

📘 **[AI RMF Profile on Trustworthy AI in Critical Infrastructure](https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure)**  
NIST's concept note starts work on an AI RMF profile for critical infrastructure sectors using AI across IT, OT, and ICS environments. The security value is the focus on translating AI trustworthiness requirements into lifecycle and supply-chain practices for high-stakes infrastructure operators.

📘 **[General-Purpose AI Risk-Management Standards Profile](https://cltc.berkeley.edu/research/research-library/)**  
UC Berkeley CLTC's AI Security Initiative published version 1.2 of its general-purpose AI risk-management standards profile. It gives security and governance teams a non-vendor standards-mapping resource for identifying and mitigating GPAI risks across model development, deployment, and oversight.

---

# 📅 Upcoming Conferences

## May 2026

📅 [siberXcon 2026 / AiSecCon](https://siberx.org/event/siberxcon-2026/) - May 25-27, 2026 · Toronto, Canada · Organizer: siberX

## June 2026

📅 [SiMLA 2026 - Security in Machine Learning and its Applications](https://simlaacns.github.io/) - June 22-25, 2026 · Stony Brook, NY, USA · Organizer: SiMLA / ACNS

## October 2026

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · Austin, TX, USA · Organizer: IEEE

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

📖 **Evaluation of Prompt Injection Defenses in Large Language Models**  
Priyal Deep, Shane Emmons, Amy Fox, Kyle Bacon, Kelley McAllister, Krisztian Flautner. [arXiv](https://arxiv.org/abs/2604.23887)

📖 **SoK: Security of Autonomous LLM Agents in Agentic Commerce**  
Qian'ang Mao, Jiaxin Wang, Ya Liu, Li Zhu, Cong Ma, Jiaqi Yan. [arXiv](https://arxiv.org/abs/2604.15367)

📖 **Black-Box Skill Stealing Attack from Proprietary LLM Agents: An Empirical Study**  
Zihan Wang, Rui Zhang, Yu Liu, Chi Liu, Qingchuan Zhao, Hongwei Li, Guowen Xu. [arXiv](https://arxiv.org/abs/2604.21829)

📖 **Secret Stealing Attacks on Local LLM Fine-Tuning through Supply-Chain Model Code Backdoors**  
Zi Li, Tian Zhou, Wenze Li, Jingyu Hua, Yunlong Mao, Sheng Zhong. [arXiv](https://arxiv.org/abs/2604.27426)

---

# 🎥 Videos

1️⃣ [Provisioned Privilege: Agentic AI as Designed Lateral Movement](https://www.youtube.com/watch?v=rMo1WbEmoZY) - Dr. Pravallika Devineni & Doug Garbarino at BSides Charlotte

2️⃣ [Model Context Protocol (MCP): The Future of AI-Powered SOC Workflows](https://www.youtube.com/watch?v=A8bWZUOO8Ps) - James "Pope" Pope at BSidesSLC

3️⃣ [Beyond Vibe Coding: Building Reliable AI AppSec Tools](https://www.youtube.com/watch?v=0MN9R5780Ds) - Emily Choi-Greene at BSides Vancouver Island

4️⃣ [MCP LFI in 60 minutes (or your money back)](https://www.youtube.com/watch?v=_iZDkQ9q40U) - Kurt Boberg at BSides Seattle

5️⃣ [Exposing Hidden Data from RAG Systems](https://www.youtube.com/watch?v=PEq-Njz4G70) - Pedro Paniago at BSides Limburg

6️⃣ [What if we could teach machines to think like hackers?](https://www.youtube.com/watch?v=pW9Mu0N1VKo) - BSides Budapest

7️⃣ [Security and Safety Testing for Agentic AI](https://www.youtube.com/watch?v=tTp1uypVeCQ) - SecTor 2025

8️⃣ [Deceiving LLM into Attacking its Own Agent Through Natural Language](https://www.youtube.com/watch?v=5IA0cVN8tWA) - DefCamp 2025

9️⃣ [Don't be LLaMe: The Basics of Attacking LLMs in Your Red Team Exercises](https://www.youtube.com/watch?v=0Yu_igYLIe0) - Red Team Village RTV Overflow

🔟 [KEYNOTE: Attacking AI](https://www.youtube.com/watch?v=mYQgUHVgBPU) - Jason Haddix at Bug Bounty Village, DEF CON 33

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
