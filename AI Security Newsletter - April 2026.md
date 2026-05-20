# AI Security Newsletter - April 2026

A monthly technical digest for AI security practitioners, researchers, builders, and security leaders tracking how AI systems fail, get attacked, and can be defended. This issue covers technical AI security research, vulnerability analysis, exploit chains, agent/tool abuse, AI malware, CVEs, newly created tools, non-vendor reports, upcoming events, practitioner discussions, and cybersecurity conference talks.

Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

---

# 🔍 Insights

📌 [The (In)security Landscape of AI-Powered GitHub Actions (Part 2/2)](https://www.wiz.io/blog/github-actions-security-ai-powered-actions-vulnerabilities)  
Wiz Research analyzes AI-powered GitHub Actions where prompt injection, permission boundaries, and dynamically created credential files can turn CI automation into a secret-exfiltration path. The practical lesson is to treat agentic CI workflows as privileged code execution, not just text review.

📌 [Can AI Attack the Cloud? Lessons From Building an Autonomous Cloud Offensive Multi-Agent System](https://unit42.paloaltonetworks.com/autonomous-ai-cloud-attacks/)  
Unit 42 describes a multi-agent cloud attack system that chains reconnaissance, exploitation, cloud identity abuse, and data exfiltration. The useful signal is where autonomy helps offensive workflows and where human approval, scoped credentials, and cloud guardrails still matter.

📌 [Comment and Control: Prompt Injection to Credential Theft in Claude Code, Gemini CLI, and GitHub Copilot Agent](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)  
This writeup demonstrates GitHub comments, issues, and pull request text as command-and-control surfaces for coding agents running in CI. For product security teams, it is a sharp reminder that repository metadata is attacker-controlled input when an agent can read it and access build secrets.

📌 [AI Agent Security in 2026: Tool Poisoning, Prompt Leaking, and MCP Sandbox Escapes](https://kensai.app/blog/2026-04-06-ai-agent-security-framework-tool-poisoning-prompt-leaking-mcp-sandbox-escapes)  
KENSAI maps agent attack surfaces across MCP tool poisoning, prompt leakage, and sandbox escape patterns. The strongest takeaway is that agent defenses need to cover tool metadata, execution isolation, and prompt-visible context rather than relying on model behavior alone.

📌 [10 Indirect Prompt Injection Payloads Caught in the Wild](https://www.forcepoint.com/blog/x-labs/indirect-prompt-injection-payloads)  
Forcepoint X-Labs catalogs real indirect prompt-injection payload patterns in web content, hidden HTML, and agent-facing text. The value is operational: defenders can turn those patterns into detection ideas for browser agents, RAG ingestion, and tool-output monitoring.

📌 [Cursor Triple Backtrick: Bypassing Guardrails for Arbitrary Command Execution](https://noma.security/blog/cursor-triple-backtrick-bypassing-guardrails-for-arbitrary-command-execution/)  
Noma Security details a Cursor guardrail-bypass technique that used command substitution syntax to move from suggested code into shell execution. Coding-agent products need enforcement outside the model response path, because UI warnings and prompt-level intent checks are not a reliable execution boundary.

📌 [A Branch Name as RCE: OpenAI Codex, a Shell Argument, and the GitHub Token It Held](https://rafter.so/blog/incidents/codex-branch-injection)  
Rafter breaks down how an unsanitized branch-name argument in Codex became a shell-command injection path around a GitHub token. The engineering lesson is narrow but important: agent wrappers need strict argv handling, shell-escaping discipline, and secret scoping even when the model itself is not the vulnerable component.

📌 [AI threats in the wild: The current state of prompt injections on the web](https://blog.google/security/prompt-injections-web/)  
Google scanned public web content for indirect prompt injection patterns and separated benign research examples from attempts to influence AI agents, SEO outputs, and data exposure. The useful signal is operational: defenders need detection pipelines that can distinguish educational payloads from instructions positioned for agents that browse untrusted pages.

📌 [Malware Now Hunts AI Coding Tools: The Bitwarden Supply Chain Attack and Defending Your Codex CLI Installation](https://codex.danielvaughan.com/2026/04/28/malware-targets-ai-coding-tools-bitwarden-supply-chain-codex-cli-defence/)  
Daniel Vaughan analyzes how a poisoned Bitwarden CLI release treated coding agents as valuable credential-bearing targets. The defensive takeaway is to combine ordinary supply-chain hygiene with agent-specific controls such as deny-read policies, sandboxing, hooks, and credential isolation.

📌 [The Mother of All AI Supply Chains: Technical Deep Dive](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-technical-deep-dive/)  
OX Security traces how MCP server definitions, especially stdio command configuration, can turn tool registration into host command execution across clients and SDKs. Teams adopting MCP should treat new tool definitions as executable supply-chain inputs, with provenance checks, approval gates, and runtime isolation before they enter agent environments.

📌 [Tool poisoning: how MCP tool descriptions hijack agents](https://usewire.io/blog/tool-poisoning-mcp-attack-hiding-in-context/)  
Wire explains how MCP tool descriptions can carry hidden instructions that models treat as trusted context. The useful engineering lesson is to pin and review tool metadata, constrain tool permissions, and monitor changes to the agent-visible tool surface.

📌 [Why Standard Input Validation Fails Against MCP Prompt Injection — And What Actually Works](https://agentmarketcap.ai/blog/2026/04/10/prompt-injection-defense-mcp-production-2026)  
This writeup explains why regex checks and conventional input validation do not solve the core MCP problem: untrusted data can still be presented to the model as instructions through tool metadata, retrieved content, or tool output. The practical value is the shift toward structural controls around trust labeling, tool permissions, and execution boundaries.

📌 [MCP Tool Poisoning: How Attackers Hijack AI Agents Through Tool Descriptions](https://langsight.dev/blog/mcp-tool-poisoning/)  
LangSight explains tool poisoning through MCP descriptions that are visible to models but often invisible to users. The lesson for defenders is to log and review tool descriptions as part of the trusted computing base, not as harmless documentation.

📌 [Prompt Injection Attacks on AI Agents: Threats, Patterns, and Defences](https://devops.gheware.com/blog/posts/prompt-injection-attacks-ai-agents-2026.html)  
Rajesh Gheware lays out direct and indirect prompt-injection patterns for AI agents and maps defenses to privilege minimization, guard models, human approval, and treating tool output as untrusted input. It is most useful as a practical control checklist for agent builders.

📌 [Claude PromptMink Malware Crypto](https://www.reversinglabs.com/blog/claude-promptmink-malware-crypto)  
ReversingLabs analyzes PromptMink, a malicious dependency campaign in which a Claude Opus co-authored commit introduced layered npm and PyPI packages with secret-stealing behavior into a crypto agent. The practical lesson is to monitor AI-added dependencies, inspect transitive package behavior, and include developer-environment secrets in supply-chain response playbooks.

---

# 🧰 Tools & Resources

🧰 **[deepsec](https://github.com/vercel-labs/deepsec)** - Security harness for finding codebase vulnerabilities with coding agents. ⭐️2,772

🧰 **[ThinkWatch](https://github.com/ThinkWatchProject/ThinkWatch)** - AI bastion host for secure AI API and MCP access with proxying, RBAC, audit logs, rate limiting, and cost tracking. ⭐️909

🧰 **[cve-mcp-server](https://github.com/mukul975/cve-mcp-server)** - MCP server exposing CVE lookup, EPSS, CISA KEV, MITRE ATT&CK, Shodan, VirusTotal, and related security-intelligence tools. ⭐️565

🧰 **[pentest-ai](https://github.com/0xSteph/pentest-ai)** - Offensive-security MCP server with wrapped tools, specialist agents, and web-application probes for controlled testing. ⭐️260

🧰 **[kontext-cli](https://github.com/kontext-security/kontext-cli)** - Runtime security layer for tool-using AI agents with permissions, credential handling, policy enforcement, and audit trails. ⭐️195

🧰 **[SkillWard](https://github.com/Fangcun-AI/SkillWard)** - Scanner for agent skills that looks for hidden threats before deployment. ⭐️123

🧰 **[vulnhawk](https://github.com/momenbasel/vulnhawk)** - AI-assisted SAST scanner focused on auth bypass, IDOR, and logic bugs across common application languages. ⭐️55

🧰 **[Talon](https://github.com/CarbeneAI/Talon)** - Penetration-testing MCP for Claude Code with recon, service enumeration, and reporting workflows. ⭐️55

🧰 **[vibecop](https://github.com/bhvbhushan/vibecop)** - Deterministic linter for AI-generated code review with detectors and a GitHub Action gate. ⭐️51

🧰 **[bordair-multimodal](https://github.com/Josh-blythe/bordair-multimodal)** - Multimodal prompt-injection test suite spanning text, image, document, and audio payloads. ⭐️50

🧰 **[vlnr](https://github.com/nandrzej/vlnr)** - AI security agent for Python supply-chain review that scans packages, generates exploits, and validates findings in Docker. ⭐️43

🧰 **[crucible](https://github.com/crucible-security/crucible)** - Testing framework for autonomous red teaming, behavioral monitoring, and security checks for LLM agents. ⭐️40

🧰 **[claude-mythos](https://github.com/anshug/claude-mythos)** - Claude-oriented vulnerability discovery framework with specialized agents for recon, chaining, exploit validation, and triage. ⭐️31

🧰 **[whitney](https://github.com/transilienceai/whitney)** - Static AI security scanner for prompt injection, broken LLM-as-judge patterns, and AI dependency SBOM coverage. ⭐️29

🧰 **[Armorer-Guard](https://github.com/ArmorerLabs/Armorer-Guard)** - Local scanner for AI-agent prompt injection, credential leaks, data exfiltration, and risky tool calls. ⭐️24

🧰 **[awesome-ai-agent-attacks](https://github.com/webpro255/awesome-ai-agent-attacks)** - Curated timeline of AI agent security incidents, breaches, and vulnerabilities for practitioner threat modeling. ⭐️20

🧰 **[ClawArmor](https://github.com/Alibaba-AAIG/ClawArmor)** - Adaptive defense for AI agents against prompt injection, data exfiltration, and multi-stage attacks. ⭐️19

🧰 **[llm-con](https://github.com/lulbitz/llm-con)** - LLM security assessment framework for recon, fingerprinting, jailbreak testing, guardrail bypass, and data-exfiltration simulation. ⭐️16

🧰 **[ClawSafety](https://github.com/weibowen555/ClawSafety)** - Benchmark for personal AI agents under realistic prompt injection across domains, vectors, and harmful action types. ⭐️16

🧰 **[prompt-authgate](https://github.com/hswtnb-blip/prompt-authgate)** - Claude Code prompt-injection defense that separates trusted user prompts from untrusted file, web, and MCP input. ⭐️14

🧰 **[skillguard](https://github.com/obielin/skillguard)** - Security scanner for AI agent skills that checks prompt injection, data exfiltration, and malicious payloads before installation. ⭐️12

🧰 **[AgentForensics](https://github.com/aparnaa19/AgentForensics)** - Real-time LLM agent session monitor for detecting prompt injection across tool outputs, web pages, documents, and APIs. ⭐️11

🧰 **[pdf-injection-scanner](https://github.com/Andy8647/pdf-injection-scanner)** - CLI scanner for hidden prompt-injection content in PDFs, including white text, tiny fonts, and off-page text. ⭐️11

🧰 **[llm-red-team-toolkit](https://github.com/bastiaan365/llm-red-team-toolkit)** - Python CLI for automated LLM app security testing across prompt injection, jailbreak, exfiltration, and tool-abuse cases. ⭐️0

🧰 **[mcp-security-proxy](https://github.com/taha-kahya/mcp-security-proxy)** - Transparent MCP security proxy that monitors tool calls and responses for rug pulls, prompt injection, credential leakage, and anomalies. ⭐️0

---

# 📄 Reports

📘 **[OWASP GenAI Exploit Round-up Report Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)**  
OWASP consolidates AI-related exploit disclosures and incidents from early 2026 and maps them to LLM and agentic application risks. The practical value is pattern recognition across agent identity abuse, orchestration weaknesses, prompt injection, and supply-chain failures that teams can feed back into threat models and control reviews.

📘 **[AI Agents & Agency in the Internet Ecosystem](https://securityandtechnology.org/virtual-library/white-paper/ai-agents-agency-in-the-internet-ecosystem/)**  
The Institute for Security and Technology frames agentic AI around identity, attribution, evaluation, and security in machine-to-machine internet interactions. It is most useful for teams thinking about provenance, authorization scope, and accountability across autonomous agent workflows.

📘 **[Careful Adoption of Agentic AI Services](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/)**  
NSA, CISA, ASD's ACSC, CCCS, NCSC-NZ, and NCSC-UK provide joint guidance for deploying agentic AI with least privilege, human oversight, reversibility, and security controls aligned to existing cybersecurity practice.

📘 **[General-Purpose AI Risk-Management Standards Profile](https://cltc.berkeley.edu/research/research-library/)**  
UC Berkeley CLTC's AI Security Initiative published version 1.2 of its general-purpose AI risk-management standards profile. It gives security and governance teams a non-vendor standards-mapping resource for turning GPAI risk categories into reviewable controls across model development, deployment, monitoring, and oversight.

📘 **[Cybersecurity Risk Analysis for Medical Devices in the Era of Evolving Technologies](https://www.mitre.org/news-insights/publication/cybersecurity-risk-analysis-medical-devices-era-evolving-technologies)**  
MITRE's report focuses on cybersecurity risk analysis for medical devices as AI/ML, connectivity, and software complexity change device threat models. It is useful for teams translating AI-enabled system risk into supplier requirements, post-market monitoring, and safety-critical security reviews.

📘 **[Operationalizing AI Guidance: A Reference Guide for Translating High-Level Goals into Practical Implementation](https://cset.georgetown.edu/publication/operationalizing-ai-guidance-a-reference-guide-for-translating-high-level-goals-into-practical-implementation/)**  
Georgetown CSET maps high-level AI guidance into practical implementation steps. Security and governance teams can use it as a control-building reference for AI asset onboarding, secure deployment checklists, monitoring, ownership, and evidence collection.

---

# 🛡️ CVEs

🛡️ [CVE-2026-39861: Claude Code sandbox escape via symlink following](https://raxe.ai/labs/advisories/RAXE-2026-059)  
RAXE documents a Claude Code sandbox-boundary failure where prompt-injection-steered symlink creation and later unsandboxed writes could land outside the intended workspace.

🛡️ [CVE-2026-5760: SGLang rerank RCE via malicious GGUF template](https://cyberveille.esante.gouv.fr/alertes/sglang-cve-2026-5760-2026-04-24)  
SGLang's `/v1/rerank` path could render malicious GGUF tokenizer templates with unsandboxed Jinja2, turning model files into executable supply-chain inputs for inference servers.

🛡️ [CVE-2026-25874: Hugging Face LeRobot unauthenticated pickle RCE](https://chocapikk.com/posts/2026/lerobot-pickle-rce/)  
LeRobot's gRPC PolicyServer accepted attacker-controlled pickle payloads over an unauthenticated channel, a sharp reminder that AI robotics and inference control planes cannot trust internal serialization by default.

🛡️ [CVE-2026-35044: BentoML Dockerfile template injection](https://nvd.nist.gov/vuln/detail/CVE-2026-35044)  
BentoML rendered user-controlled Dockerfile templates with unsandboxed Jinja2 during container generation, so malicious Bento archives could execute Python on the host before model-serving containers ever started.

🛡️ [CVE-2026-5752: Terrarium sandbox escape](https://kb.cert.org/vuls/id/414811)  
CERT/CC documents a critical Terrarium sandbox escape that reaches Node.js internals and executes commands as root inside the host process, reinforcing why AI code-execution sandboxes need container, network, and credential isolation.

🛡️ [CVE-2026-42208: LiteLLM proxy API key verification SQL injection](https://github.com/BerriAI/litellm/security/advisories/GHSA-r75f-5x8p-qvmc)  
Critical pre-authentication SQL injection in LiteLLM's API-key verification path could expose or modify proxy database records, making LLM gateway credential stores and provider access a priority patch target.

🛡️ [CVE-2026-33626: LMDeploy vision-language SSRF](https://nvd.nist.gov/vuln/detail/CVE-2026-33626)  
LMDeploy's vision-language image loader fetched arbitrary URLs without internal-address validation, making GPU inference nodes potential paths to cloud metadata services and internal network resources.

🛡️ [CVE-2026-6603: AgentScope code injection in Python and shell execution helpers](https://nvd.nist.gov/vuln/detail/CVE-2026-6603)  
NVD tracks remotely exploitable code injection in AgentScope's Python and shell execution helpers, reinforcing that agent framework tool-execution paths need authentication, isolation, and explicit capability boundaries.

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
[arXiv](https://arxiv.org/abs/2605.00081)  
A framework for bounding agentic security systems that need offensive capability inside authorized engagements while preserving scope, safety, and reporting controls.

📖 **Architecture Matters for Multi-Agent Security**  
[arXiv](https://arxiv.org/abs/2604.23459)  
Analyzes how multi-agent architecture changes security behavior, showing why agent coordination, delegation, and inter-agent trust boundaries need their own threat modeling.

📖 **ShieldNet: Network-Level Guardrails against Emerging Supply-Chain Injections in Agentic Systems**  
[arXiv](https://arxiv.org/abs/2604.04426)  
Proposes network-level guardrails for agentic systems that depend on third-party tools and MCP-style services, with a focus on supply-chain injections that bypass prompt-only defenses.

📖 **LLM-Enabled Open-Source Systems in the Wild: An Empirical Study of Vulnerabilities in GitHub Security Advisories**  
[arXiv](https://arxiv.org/abs/2604.04288)  
Studies vulnerabilities in open-source systems that embed LLM capabilities, giving AppSec teams a clearer view of how model calls, prompts, and execution paths appear in real advisories.

📖 **SnapGuard: Lightweight Prompt Injection Detection for Screenshot-Based Web Agents**  
[arXiv](https://arxiv.org/abs/2604.25562)  
Presents a prompt-injection detector for screenshot-driven web agents, targeting attacks hidden in visual webpage content before agents turn observations into tool actions.

📖 **CASCADE: A Cascaded Hybrid Defense Architecture for Prompt Injection Detection in MCP-Based Systems**  
[arXiv](https://arxiv.org/abs/2604.17125)  
Designs a layered detection architecture for MCP-based systems where prompt injection, tool poisoning, and tool invocation risk need controls across more than one enforcement point.

📖 **Jailbreaking Large Language Models with Morality Attacks**  
[arXiv](https://arxiv.org/abs/2604.17053)  
Explores jailbreaks that use moral framing to steer model behavior, giving red teamers another test pattern for evaluating safety-aligned models under persuasive adversarial prompts.

📖 **AdversarialCoT: Single-Document Retrieval Poisoning for LLM Reasoning**  
[arXiv](https://arxiv.org/abs/2604.12201)  
Shows how a single poisoned retrieval document can influence chain-of-thought reasoning in RAG systems, making document trust and retrieval hygiene part of the security boundary.

📖 **A Formal Security Framework for MCP-Based AI Agents: Threat Taxonomy, Verification Models, and Defense Mechanisms**  
[arXiv](https://arxiv.org/abs/2604.05969)  
Frames MCP-based agents through threat taxonomy, verification models, and defense mechanisms so teams can reason about tool trust, agent permissions, and protocol-level failure modes.

📖 **Security Attack and Defense Strategies for Autonomous Agent Frameworks: A Layered Review with OpenClaw as a Case Study**  
[arXiv](https://arxiv.org/abs/2604.27464)  
Uses OpenClaw as a case study for mapping autonomous-agent risks across framework layers, from prompts and memory to tools, orchestration, and runtime controls.

📖 **Credential Leakage in LLM Agent Skills: A Large-Scale Empirical Study**  
[arXiv](https://arxiv.org/abs/2604.03070)  
Measures credential leakage risk across LLM agent skills, highlighting how third-party skills can expose secrets when agents run with privileged environment access.

📖 **SoK: Security of Autonomous LLM Agents in Agentic Commerce**  
[arXiv](https://arxiv.org/abs/2604.15367)  
Surveys security risks in agentic commerce, where LLM agents may negotiate, purchase, transact, and operate across systems that require stronger authorization and fraud controls.

📖 **Test Before You Deploy: Governing Updates in the LLM Supply Chain**  
[arXiv](https://arxiv.org/abs/2604.27789)  
Treats hosted model updates as a software supply-chain risk, arguing for pre-deployment testing when provider-side changes can alter application behavior without version changes.

📖 **Enforcing Benign Trajectories: A Behavioral Firewall for Structured-Workflow AI Agents**  
[arXiv](https://arxiv.org/abs/2604.26274)  
Introduces a behavioral firewall concept for structured-workflow agents, using telemetry and anomaly detection to catch risky tool-use trajectories during execution.

📖 **Indirect Prompt Injection in the Wild: An Empirical Study of Prevalence, Techniques, and Objectives**  
[arXiv](https://arxiv.org/abs/2604.27202)  
Studies indirect prompt injection on real web content, helping defenders distinguish research examples, benign text, and instructions positioned to influence browsing or retrieval agents.

📖 **ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection**  
[arXiv](https://arxiv.org/abs/2604.11790)  
Proposes runtime protection for tool-augmented agents facing indirect prompt injection, focusing on the point where untrusted external content can trigger privileged tool actions.

📖 **Evaluation of Prompt Injection Defenses in Large Language Models**  
[arXiv](https://arxiv.org/abs/2604.23887)  
Evaluates prompt-injection defenses with an adaptive attacker, giving builders a more realistic view of how defensive prompts and model-level mitigations hold up over repeated attempts.

📖 **BadSkill: Backdoor Attacks on Agent Skills via Model-in-Skill Poisoning**  
[arXiv](https://arxiv.org/abs/2604.09378)  
Examines backdoors hidden inside agent skills that bundle model artifacts, extending supply-chain concerns beyond prompt text and ordinary plugin code.

📖 **STAR-Teaming: A Strategy-Response Multiplex Network Approach to Automated LLM Red Teaming**  
[arXiv](https://arxiv.org/abs/2604.18976)  
Presents an automated red-teaming method for generating and evaluating jailbreak strategies, useful for teams building repeatable LLM abuse testing pipelines.

📖 **AgentVisor: Defending LLM Agents Against Prompt Injection via Semantic Virtualization**  
[arXiv](https://arxiv.org/abs/2604.24118)  
Uses semantic virtualization to separate untrusted external content from privileged agent execution, aiming to reduce prompt-injection impact in tool-using workflows.

📖 **WebAgentGuard: A Reasoning-Driven Guard Model for Detecting Prompt Injection Attacks in Web Agents**  
[arXiv](https://arxiv.org/abs/2604.12284)  
Builds a reasoning-driven guard model for web agents that must interpret visual and textual page content while resisting malicious instructions embedded in the environment.

---

# 💬 Practitioner Discussions

💬 [Systemic Flaw in MCP Protocol Could Expose 150 Million Downloads](https://www.reddit.com/r/webdev/comments/1so5gzp/systemic_flaw_in_mcp_protocol_could_expose_150/)  
Commenters push past the headline into MCP trust boundaries, local versus remote tool execution, STDIO-backed launches, and whether validation belongs in protocol SDKs or downstream clients.

💬 [Anyone else feel like AI security is being figured out in production right now?](https://www.reddit.com/r/artificial/comments/1sbgw8y/anyone_else_feel_like_ai_security_is_being/)  
The useful part of the thread is the practitioner discussion around production AI risk: prompt injection, shadow AI, sensitive data handling, logging gaps, and why traditional controls do not map cleanly onto LLM applications.

💬 [Prompt Injection Detection?](https://www.reddit.com/r/cybersecurity/comments/1semk5r/prompt_injection_detection/)  
Practitioners discuss why prompt-injection detection has to move beyond input filtering toward canary tokens, tool-call telemetry, RAG context logging, and post-execution behavioral signals.

💬 [System prompts are not a security layer. Here's what actually stops prompt injection in production.](https://www.reddit.com/r/PromptEngineering/comments/1shsmdz/system_prompts_are_not_a_security_layer_heres/)  
The thread is a useful reminder that system prompts are not enforcement boundaries; the security value is in how commenters separate prompt design from authorization, isolation, and tool-permission controls.

💬 [Open dataset: 100k+ multimodal prompt injection samples with per-category academic sourcing](https://www.reddit.com/r/netsec/comments/1sn2o3v/open_dataset_100k_multimodal_prompt_injection/)  
The discussion covers dataset methodology, multimodal prompt-injection coverage, MCP tool-descriptor poisoning, reasoning-trace attacks, and why benchmark class ratios can mislead teams about production detector performance.

---

# 🎥 Videos

1️⃣ [Universal and Context-Independent Triggers for Precise Control of LLM Outputs](https://www.youtube.com/watch?v=W8zzpTGVHRE) - conference recording at Black Hat USA 2025 · Recording published Apr 2026

2️⃣ [Security and Safety Testing for Agentic AI](https://www.youtube.com/watch?v=tTp1uypVeCQ) - conference recording at SecTor 2025 · Recording published Apr 2026

3️⃣ [Don't be LLaMe: The Basics of Attacking LLMs in Your Red Team Exercises](https://www.youtube.com/watch?v=0Yu_igYLIe0) - conference recording at Red Team Village RTV Overflow · Recording published Apr 2026

4️⃣ [Deceiving LLM into Attacking its Own Agent Through Natural Language](https://www.youtube.com/watch?v=5IA0cVN8tWA) - conference recording at DefCamp 2025 · Recording published Apr 2026

5️⃣ [Provisioned Privilege: Agentic AI as Designed Lateral Movement](https://www.youtube.com/watch?v=rMo1WbEmoZY) - Dr. Pravallika Devineni & Doug Garbarino at BSides Charlotte

6️⃣ [Model Context Protocol (MCP): The Future of AI-Powered SOC Workflows](https://www.youtube.com/watch?v=A8bWZUOO8Ps) - James "Pope" Pope at BSidesSLC

7️⃣ [Beyond Vibe Coding: Building Reliable AI AppSec Tools](https://www.youtube.com/watch?v=0MN9R5780Ds) - Emily Choi-Greene at BSides Vancouver Island

8️⃣ [MCP LFI in 60 minutes (or your money back)](https://www.youtube.com/watch?v=_iZDkQ9q40U) - Kurt Boberg at BSides Seattle

9️⃣ [Exposing Hidden Data from RAG Systems](https://www.youtube.com/watch?v=PEq-Njz4G70) - Pedro Paniago at BSides Limburg

🔟 [What if we could teach machines to think like hackers?](https://www.youtube.com/watch?v=pW9Mu0N1VKo) - conference recording at BSides Budapest · Recording published Apr 2026

1️⃣1️⃣ [KEYNOTE: Attacking AI](https://www.youtube.com/watch?v=mYQgUHVgBPU) - Jason Haddix at Bug Bounty Village, DEF CON 33

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
