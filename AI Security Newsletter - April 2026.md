# AI Security Newsletter - April 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

This month's issue focuses on technical AI security research, vulnerability analysis, exploit chains, agent/tool abuse, AI malware, and concrete defensive engineering lessons.

---

# 🔍 Insights

📌 [Roo Code Command Auto-Approval OS Command Injection via Shell Substitution](https://www.sentinelone.com/vulnerability-database/cve-2026-30307/)  
SentinelOne tracks a Roo Code command auto-approval issue where shell substitution could turn an apparently approved command into unintended OS command execution. Coding-agent users should disable broad auto-approval, test allowlists against shell metacharacters, and enforce command policy outside the agent UI.

📌 [Claude Code Sandbox Escape via Symlink Following Enables Arbitrary File Write Outside Workspace](https://raxe.ai/labs/advisories/RAXE-2026-059)  
RAXE Labs documents a Claude Code sandbox-escape path where symlink following could allow arbitrary file writes outside the intended workspace. Teams running coding agents against untrusted repositories should add workspace isolation, symlink monitoring, and version gates before exposing credentials or build systems.

📌 [Mini Shai-Hulud npm Worm Targets SAP Packages to Steal AI Coding Tool Secrets](https://www.endorlabs.com/learn/mini-shai-hulud-npm-worm-hits-sap-developer-packages)  
Endor Labs analyzes an npm worm campaign that targeted SAP developer packages and looked for AI coding tool secrets and local configuration paths. The practical lesson is to include AI-tool config files in secret-response playbooks, lock down install scripts in CI, and scope npm OIDC trust to exact workflow refs.

📌 [The MCP Vulnerability at the Heart of the AI Supply Chain](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)  
OX Security shows how MCP server registration can turn tool configuration into host command execution across multiple clients and SDKs. Teams adopting MCP need provenance checks, approval gates, and runtime isolation before accepting tool definitions from repositories or third-party packages.

📌 [LMDeploy SSRF Exploited Against LLM Inference Engines](https://www.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours)  
Sysdig observed exploitation attempts against LMDeploy shortly after disclosure of an SSRF flaw in vision-language image loading. For teams running GPU-hosted inference, user-supplied image URLs, RAG fetchers, and agent retrieval paths should be treated as internal-network access primitives unless egress controls and metadata protections are enforced.

📌 [Comment and Control: Prompt Injection to Credential Theft in Claude Code, Gemini CLI, and GitHub Copilot Agent](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)  
This writeup demonstrates GitHub comments, issues, and pull request text as command-and-control surfaces for coding agents running in CI. For product security teams, it is a sharp reminder that repository metadata is attacker-controlled input when an agent can read it and access build secrets.

📌 [FastGPT NoSQL Injection in loginByPassword Leads to Authentication Bypass](https://github.com/labring/FastGPT/security/advisories/GHSA-x8mx-2mr7-h9xg)  
FastGPT's advisory documents a NoSQL-injection path in the password login endpoint that could let unauthenticated attackers bypass authentication as any user, including root administrator. Agent-builder platforms need runtime input validation on control-plane APIs, not just TypeScript assertions that disappear at runtime.

📌 [AgentScope Code Injection in execute_python_code / execute_shell_command Enables Unauthenticated RCE](https://advisories.gitlab.com/pypi/agentscope/CVE-2026-6603/)  
GitLab's advisory for AgentScope covers code-injection exposure around Python and shell execution helpers. Agent frameworks should treat code-execution tools as privileged capabilities, require explicit authorization around them, and keep remotely reachable tool paths away from unauthenticated users.

📌 [Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass](https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc)  
The marimo advisory describes a pre-authentication path to terminal access through WebSocket authentication bypass behavior. AI notebook and developer-tool servers should assume local productivity features become remote attack surfaces once exposed in shared workspaces.

📌 [langchain-openai Vulnerable to Server-Side Request Forgery](https://github.com/langchain-ai/langchain/security/advisories/GHSA-r7w7-9xr2-qq2r)  
LangChain's advisory documents an SSRF issue tied to redirect and host handling. Even when impact is bounded, agent and LLM framework integrations should validate network destinations because prompt-driven workflows can turn library fetch behavior into data-plane access.

📌 [Cursor Triple Backtrick: Bypassing Guardrails for Arbitrary Command Execution](https://noma.security/blog/cursor-triple-backtrick-bypassing-guardrails-for-arbitrary-command-execution/)  
Noma Security details a Cursor guardrail-bypass technique that used command substitution syntax to move from suggested code into shell execution. Coding-agent products need enforcement outside the model response path, because UI warnings and prompt-level intent checks are not a reliable execution boundary.

📌 [Server-Side Template Injection in BentoML Dockerfile Generation Allows Host Code Execution from Malicious Bento Archives](https://github.com/bentoml/BentoML/security/advisories/GHSA-v959-cwq9-7hr6)  
BentoML's advisory covers template injection in Dockerfile generation when processing malicious Bento archives. Model-serving and packaging pipelines should treat imported model bundles as untrusted build inputs and isolate builders from secrets and host resources.

📌 [FedML-AI gRPC Server Deserialization Vulnerability Enables RCE](https://securityvulnerability.io/vulnerability/CVE-2026-5536)  
SecurityVulnerability.io tracks a FedML-AI gRPC deserialization issue that could lead to remote code execution. ML orchestration services should restrict gRPC exposure, harden deserialization paths, and monitor training nodes for unexpected process execution.

📌 [AI threats in the wild: The current state of prompt injections on the web](https://blog.google/security/prompt-injections-web/)  
Google scanned public web content for indirect prompt injection patterns and separated benign research examples from attempts to influence AI agents, SEO outputs, and data exposure. The useful signal is operational: defenders need detection pipelines that can distinguish educational payloads from instructions positioned for agents that browse untrusted pages.

📌 [Azure MCP Server Missing Authentication for Critical Function](https://nvd.nist.gov/vuln/detail/CVE-2026-32211)  
NVD's entry for CVE-2026-32211 covers a missing-authentication flaw in Azure MCP Server that could disclose information over the network. The AI-security lesson is direct: MCP servers that bridge agents into cloud or developer infrastructure need ordinary authentication and authorization controls before they become reusable automation surfaces.

📌 [Claude PromptMink Malware Crypto](https://www.reversinglabs.com/blog/claude-promptmink-malware-crypto)  
ReversingLabs analyzes PromptMink, a malware campaign where AI-generated package content and social-engineering material were used around cryptocurrency theft. The case reinforces why package vetting, dependency provenance, and developer-environment monitoring need to account for AI-assisted supply-chain operations.

📌 [PraisonAI Sensitive Environment Variable Exposure via Untrusted MCP Subprocess Execution](https://github.com/advisories/GHSA-pj2r-f9mw-vrcq)  
GitHub's advisory describes PraisonAI MCP subprocesses inheriting the parent process environment, exposing API keys and other secrets to untrusted MCP commands. The defensive takeaway is to pass explicit environment allowlists into tool subprocesses instead of letting agent integrations inherit every local credential by default.

📌 [SGLang CVE-2026-5760](https://cyberveille.esante.gouv.fr/alertes/sglang-cve-2026-5760-2026-04-24)  
CERT Sante tracks an SGLang issue involving malicious GGUF model handling in inference infrastructure. It is a model supply-chain reminder: model files and tokenizer templates need the same sandboxing, signature, and provenance scrutiny as code artifacts.

📌 [Guardrail Sandbox Escape in LiteLLM](https://x41-dsec.de/lab/advisories/x41-2026-001-litellm/)  
X41 documents a LiteLLM guardrail testing endpoint where regex-based filtering could be bypassed with bytecode rewriting to execute code as the server process. It is a useful reminder that LLM gateway admin and test routes need the same hardening as production inference paths because they often execute user-controlled templates or code.

📌 [CVE-2026-25874: HuggingFace LeRobot Unauthenticated RCE via Pickle Deserialization in gRPC PolicyServer](https://chocapikk.com/posts/2026/lerobot-pickle-rce/)  
Chocapikk documents unsafe pickle deserialization in LeRobot's gRPC PolicyServer path. Robotics and AI-inference teams should avoid treating internal policy-serving endpoints as trusted by default, especially when model-serving code is close to physical or operational control loops.

📌 [Flowise Custom MCP Code Injection](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c9gw-hvqq-f33r)  
Flowise's advisory covers a code-injection issue in its Custom MCP path that could let authenticated users reach command execution on agent-builder infrastructure. The lesson for platform teams is direct: MCP configuration surfaces should be treated as privileged execution boundaries, not low-risk workflow metadata.

---

# 🧰 Tools & Resources

🧰 **[Armorer-Guard](https://github.com/ArmorerLabs/Armorer-Guard)** - Local scanner for AI-agent prompt injection, credential leaks, data exfiltration, and risky tool calls.

🧰 **[awesome-ai-agent-attacks](https://github.com/webpro255/awesome-ai-agent-attacks)** - Curated timeline of AI agent security incidents, breaches, and vulnerabilities for practitioner threat modeling.

🧰 **[llm-con](https://github.com/lulbitz/llm-con)** - LLM security assessment framework for recon, fingerprinting, jailbreak testing, guardrail bypass, and data-exfiltration simulation.

🧰 **[llm-red-team-toolkit](https://github.com/bastiaan365/llm-red-team-toolkit)** - Python CLI for automated LLM app security testing across prompt injection, jailbreak, exfiltration, and tool-abuse cases.

🧰 **[claude-mythos](https://github.com/anshug/claude-mythos)** - Claude-oriented vulnerability discovery framework with specialized agents for recon, chaining, exploit validation, and triage.

🧰 **[ClawArmor](https://github.com/Alibaba-AAIG/ClawArmor)** - Adaptive defense for AI agents against prompt injection, data exfiltration, and multi-stage attacks.

🧰 **[skillguard](https://github.com/obielin/skillguard)** - Security scanner for AI agent skills that checks prompt injection, data exfiltration, and malicious payloads before installation.

🧰 **[mcp-security-proxy](https://github.com/taha-kahya/mcp-security-proxy)** - Transparent MCP security proxy that monitors tool calls and responses for rug pulls, prompt injection, credential leakage, and anomalies.

🧰 **[ClawSafety](https://github.com/weibowen555/ClawSafety)** - Benchmark for personal AI agents under realistic prompt injection across domains, vectors, and harmful action types.

🧰 **[cve-mcp-server](https://github.com/mukul975/cve-mcp-server)** - MCP server exposing CVE lookup, EPSS, CISA KEV, MITRE ATT&CK, Shodan, VirusTotal, and related security-intelligence tools.

🧰 **[kontext-cli](https://github.com/kontext-security/kontext-cli)** - Runtime security layer for tool-using AI agents with permissions, credential handling, policy enforcement, and audit trails.

🧰 **[vulnhawk](https://github.com/momenbasel/vulnhawk)** - AI-assisted SAST scanner focused on auth bypass, IDOR, and logic bugs across common application languages.

🧰 **[crucible](https://github.com/crucible-security/crucible)** - Testing framework for autonomous red teaming, behavioral monitoring, and security checks for LLM agents.

🧰 **[vlnr](https://github.com/nandrzej/vlnr)** - AI security agent for Python supply-chain review that scans packages, generates exploits, and validates findings in Docker.

🧰 **[whitney](https://github.com/transilienceai/whitney)** - Static AI security scanner for prompt injection, broken LLM-as-judge patterns, and AI dependency SBOM coverage.

🧰 **[prompt-authgate](https://github.com/hswtnb-blip/prompt-authgate)** - Claude Code prompt-injection defense that separates trusted user prompts from untrusted file, web, and MCP input.

🧰 **[AgentForensics](https://github.com/aparnaa19/AgentForensics)** - Real-time LLM agent session monitor for detecting prompt injection across tool outputs, web pages, documents, and APIs.

🧰 **[deepsec](https://github.com/vercel-labs/deepsec)** - Security harness for finding codebase vulnerabilities with coding agents.

🧰 **[ThinkWatch](https://github.com/ThinkWatchProject/ThinkWatch)** - AI bastion host for secure AI API and MCP access with proxying, RBAC, audit logs, rate limiting, and cost tracking.

🧰 **[pentest-ai](https://github.com/0xSteph/pentest-ai)** - Offensive-security MCP server with wrapped tools, specialist agents, and web-application probes for controlled testing.

🧰 **[SkillWard](https://github.com/Fangcun-AI/SkillWard)** - Scanner for agent skills that looks for hidden threats before deployment.

🧰 **[Talon](https://github.com/CarbeneAI/Talon)** - Penetration-testing MCP for Claude Code with recon, service enumeration, and reporting workflows.

🧰 **[vibecop](https://github.com/bhvbhushan/vibecop)** - Deterministic linter for AI-generated code review with detectors and a GitHub Action gate.

🧰 **[bordair-multimodal](https://github.com/Josh-blythe/bordair-multimodal)** - Multimodal prompt-injection test suite spanning text, image, document, and audio payloads.

🧰 **[pdf-injection-scanner](https://github.com/Andy8647/pdf-injection-scanner)** - CLI scanner for hidden prompt-injection content in PDFs, including white text, tiny fonts, and off-page text.

---

# 📄 Reports

📘 **[OWASP GenAI Exploit Round-up Report Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)**  
OWASP consolidates AI-related exploit disclosures and incidents from early 2026, mapping them to LLM and agentic application risks. The useful value is pattern recognition across agent identity abuse, orchestration weaknesses, prompt injection, and supply-chain failures.

📘 **[AI Agents & Agency in the Internet Ecosystem](https://securityandtechnology.org/virtual-library/white-paper/ai-agents-agency-in-the-internet-ecosystem/)**  
The Institute for Security and Technology frames agentic AI around identity, attribution, evaluation, and security in machine-to-machine internet interactions. It is most useful for teams thinking about provenance, authorization scope, and accountability across autonomous agent workflows.

📘 **[Careful Adoption of Agentic AI Services](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/)**  
NSA, CISA, ASD's ACSC, CCCS, NCSC-NZ, and NCSC-UK provide joint guidance for deploying agentic AI with least privilege, human oversight, reversibility, and security controls aligned to existing cybersecurity practice.

📘 **[General-Purpose AI Risk-Management Standards Profile](https://cltc.berkeley.edu/research/research-library/)**  
UC Berkeley CLTC's AI Security Initiative published version 1.2 of its general-purpose AI risk-management standards profile. It gives security and governance teams a non-vendor standards-mapping resource for identifying and mitigating GPAI risks across model development, deployment, and oversight.

📘 **[Cybersecurity Risk Analysis for Medical Devices in the Era of Evolving Technologies](https://www.mitre.org/news-insights/publication/cybersecurity-risk-analysis-medical-devices-era-evolving-technologies)**  
MITRE's report focuses on cybersecurity risk analysis for medical devices as AI/ML, connectivity, and software complexity change device threat models. It is useful for teams translating AI-enabled system risk into supplier requirements, post-market monitoring, and safety-critical security reviews.

📘 **[Operationalizing AI Guidance: A Reference Guide for Translating High-Level Goals into Practical Implementation](https://cset.georgetown.edu/publication/operationalizing-ai-guidance-a-reference-guide-for-translating-high-level-goals-into-practical-implementation/)**  
Georgetown CSET maps high-level AI guidance into practical implementation steps. Security and governance teams can use it as a control-building reference for AI asset onboarding, secure deployment checklists, monitoring, ownership, and evidence collection.

---

# 📅 Upcoming Conferences

## June 2026

📅 [38th Annual FIRST Conference (FIRSTCON26)](https://www.first.org/conference/2026/) - June 14-19, 2026 · Denver, CO, USA · Organizer: FIRST

📅 [SiMLA 2026 - Security in Machine Learning and its Applications](https://simlaacns.github.io/) - June 22-25, 2026 · Stony Brook, NY, USA · Organizer: SiMLA / ACNS

## August 2026

📅 [IEEE CSR GenXSec 2026 - Generative and eXplainable AI for Security in Networking](https://www.ieee-csr.org/csr-genxsec/) - August 3-5, 2026 · Lisbon, Portugal · Organizer: IEEE CSR

## October 2026

📅 [CAMLIS 2026 - Conference on Applied Machine Learning in Information Security](https://www.camlis.org/) - October 21-23, 2026 · Arlington, VA, USA · Organizer: CAMLIS

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · Austin, TX, USA · Organizer: IEEE

## November 2026

📅 [19th ACM Workshop on Artificial Intelligence and Security (AISec 2026)](https://aisec.cc/) - November 15, 2026 · The Hague, Netherlands · Organizer: ACM AISec / ACM CCS

📅 [ISAICS 2026 - IEEE International Symposium on AI and Cybersecurity](https://www.isaics.net/) - November 20-22, 2026 · Rizhao, China · Organizer: ISAICS

---

# 📚 Research

📖 **Alignment Contracts for Agentic Security Systems**  
Isaac David, Marco Guarnieri, Arthur Gervais. [arXiv](https://arxiv.org/abs/2605.00081)

📖 **Architecture Matters for Multi-Agent Security**  
Ben Hagag, William L. Anderson, Christian Schroeder de Witt, Sarah Scheffler. [arXiv](https://arxiv.org/abs/2604.23459)

📖 **ShieldNet: Network-Level Guardrails against Emerging Supply-Chain Injections in Agentic Systems**  
Zhuowen Yuan, Zhaorun Chen, Zhen Xiang, Nathaniel D. Bastian, Seyyed Hadi Hashemi, Chaowei Xiao, Wenbo Guo, Bo Li. [arXiv](https://arxiv.org/abs/2604.04426)

📖 **LLM-Enabled Open-Source Systems in the Wild: An Empirical Study of Vulnerabilities in GitHub Security Advisories**  
Fariha Tanjim Shifat, Hariswar Baburaj, Ce Zhou, Jaydeb Sarker, Mia Mohammad Imran. [arXiv](https://arxiv.org/abs/2604.04288)

📖 **SnapGuard: Lightweight Prompt Injection Detection for Screenshot-Based Web Agents**  
Mengyao Du, Han Fang, Haokai Ma, Jiahao Chen, Kai Xu, Quanjun Yin, Ee-Chien Chang. [arXiv](https://arxiv.org/abs/2604.25562)

📖 **CASCADE: A Cascaded Hybrid Defense Architecture for Prompt Injection Detection in MCP-Based Systems**  
İpek Abasıkeleş Turgut, Edip Gümüş. [arXiv](https://arxiv.org/abs/2604.17125)

📖 **Jailbreaking Large Language Models with Morality Attacks**  
Ying Su, Mingen Zheng, Weili Diao, Haoran Li. [arXiv](https://arxiv.org/abs/2604.17053)

📖 **AdversarialCoT: Single-Document Retrieval Poisoning for LLM Reasoning**  
Hongru Song, Yu-An Liu, Ruqing Zhang, Jiafeng Guo, Maarten de Rijke, Yixing Fan, Xueqi Cheng. [arXiv](https://arxiv.org/abs/2604.12201)

📖 **A Formal Security Framework for MCP-Based AI Agents: Threat Taxonomy, Verification Models, and Defense Mechanisms**  
Nirajan Acharya, Gaurav Kumar Gupta. [arXiv](https://arxiv.org/abs/2604.05969)

📖 **Security Attack and Defense Strategies for Autonomous Agent Frameworks: A Layered Review with OpenClaw as a Case Study**  
Luyao Xu, Xiang Chen. [arXiv](https://arxiv.org/abs/2604.27464)

📖 **Credential Leakage in LLM Agent Skills: A Large-Scale Empirical Study**  
Zhihao Chen, Ying Zhang, Yi Liu, Gelei Deng, Yuekang Li, Yanjun Zhang, Jianting Ning, Leo Yu Zhang, Lei Ma, Zhiqiang Li. [arXiv](https://arxiv.org/abs/2604.03070)

📖 **SoK: Security of Autonomous LLM Agents in Agentic Commerce**  
Qian'ang Mao, Jiaxin Wang, Ya Liu, Li Zhu, Cong Ma, Jiaqi Yan. [arXiv](https://arxiv.org/abs/2604.15367)

📖 **Test Before You Deploy: Governing Updates in the LLM Supply Chain**  
Mohd Sameen Chishti, Damilare Peter Oyinloye, Jingyue Li. [arXiv](https://arxiv.org/abs/2604.27789)

📖 **Enforcing Benign Trajectories: A Behavioral Firewall for Structured-Workflow AI Agents**  
Hung Dang. [arXiv](https://arxiv.org/abs/2604.26274)

📖 **Indirect Prompt Injection in the Wild: An Empirical Study of Prevalence, Techniques, and Objectives**  
Soheil Khodayari, Xuenan Zhang, Bhupendra Acharya, Giancarlo Pellegrino. [arXiv](https://arxiv.org/abs/2604.27202)

📖 **ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection**  
Wei Zhao, Zhe Li, Peixin Zhang, Jun Sun. [arXiv](https://arxiv.org/abs/2604.11790)

📖 **Evaluation of Prompt Injection Defenses in Large Language Models**  
Priyal Deep, Shane Emmons, Amy Fox, Kyle Bacon, Kelley McAllister, Krisztian Flautner. [arXiv](https://arxiv.org/abs/2604.23887)

📖 **BadSkill: Backdoor Attacks on Agent Skills via Model-in-Skill Poisoning**  
Guiyao Tie, Jiawen Shi, Pan Zhou, Lichao Sun. [arXiv](https://arxiv.org/abs/2604.09378)

📖 **STAR-Teaming: A Strategy-Response Multiplex Network Approach to Automated LLM Red Teaming**  
MinJae Jung, YongTaek Lim, Chaeyun Kim, Junghwan Kim, Kihyun Kim, Minwoo Kim. [arXiv](https://arxiv.org/abs/2604.18976)

📖 **AgentVisor: Defending LLM Agents Against Prompt Injection via Semantic Virtualization**  
Zonghao Ying, Haozheng Wang, Jiangfan Liu, Quanchen Zou, Aishan Liu, Jian Yang, Yaodong Yang, Xianglong Liu. [arXiv](https://arxiv.org/abs/2604.24118)

📖 **WebAgentGuard: A Reasoning-Driven Guard Model for Detecting Prompt Injection Attacks in Web Agents**  
Yulin Chen, Tri Cao, Haoran Li, Yue Liu, Yibo Li, Yufei He, Le Minh Khoi, Yangqiu Song, Shuicheng Yan, Bryan Hooi. [arXiv](https://arxiv.org/abs/2604.12284)

---

# 🎥 Videos

1️⃣ [Universal and Context-Independent Triggers for Precise Control of LLM Outputs](https://www.youtube.com/watch?v=W8zzpTGVHRE) - Black Hat USA 2025

2️⃣ [Security and Safety Testing for Agentic AI](https://www.youtube.com/watch?v=tTp1uypVeCQ) - SecTor 2025

3️⃣ [Don't be LLaMe: The Basics of Attacking LLMs in Your Red Team Exercises](https://www.youtube.com/watch?v=0Yu_igYLIe0) - Red Team Village RTV Overflow

4️⃣ [Deceiving LLM into Attacking its Own Agent Through Natural Language](https://www.youtube.com/watch?v=5IA0cVN8tWA) - DefCamp 2025

5️⃣ [Provisioned Privilege: Agentic AI as Designed Lateral Movement](https://www.youtube.com/watch?v=rMo1WbEmoZY) - Dr. Pravallika Devineni & Doug Garbarino at BSides Charlotte

6️⃣ [Model Context Protocol (MCP): The Future of AI-Powered SOC Workflows](https://www.youtube.com/watch?v=A8bWZUOO8Ps) - James "Pope" Pope at BSidesSLC

7️⃣ [Beyond Vibe Coding: Building Reliable AI AppSec Tools](https://www.youtube.com/watch?v=0MN9R5780Ds) - Emily Choi-Greene at BSides Vancouver Island

8️⃣ [MCP LFI in 60 minutes (or your money back)](https://www.youtube.com/watch?v=_iZDkQ9q40U) - Kurt Boberg at BSides Seattle

9️⃣ [Exposing Hidden Data from RAG Systems](https://www.youtube.com/watch?v=PEq-Njz4G70) - Pedro Paniago at BSides Limburg

🔟 [What if we could teach machines to think like hackers?](https://www.youtube.com/watch?v=pW9Mu0N1VKo) - BSides Budapest

1️⃣1️⃣ [KEYNOTE: Attacking AI](https://www.youtube.com/watch?v=mYQgUHVgBPU) - Jason Haddix at Bug Bounty Village, DEF CON 33

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
