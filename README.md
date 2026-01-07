# AI Security Newsletter - December 2025

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AI Security community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.


# 🔍 Insights

📌 [186 Jailbreaks: Applying MLOps to AI Red Teaming](https://dreadnode.io/blog/186-jailbreaks-applying-mlops-to-ai-red-teaming)  
Dreadnode shows how treating AI red teaming as an MLOps-style optimization problem enabled automatic generation of 186 successful jailbreaks (reported 78 percent success rate) against Llama Maverick-17B-128E-Instruct, benchmarking Crescendo, GOAT, and TAP across harm categories, and arguing for continuous algorithmic red teaming for modern multimodal systems.

📌 [I hacked the System Instructions for Nano Banana](https://generativeai.pub/i-hacked-the-system-instructions-for-nano-banana-bd53703eff36)  
Extracts system instructions for Google’s Gemini 2.5 Flash Image “Nano Banana”, including a “Depiction Protocol” that forces it to always emit `<img>` and defer content judgment to an external safety layer, raising questions about hidden rulebooks, pre-filter generation, and guardrail effectiveness.

📌 [8 Million Users' AI Conversations Sold for Profit by "Privacy" Extensions](https://www.koi.security/blog/8-million-users-ai-conversations-sold-for-profit-by-privacy-extensions)  
Koi reports Urban VPN and related Featured browser extensions intercepting and exfiltrating millions of users’ AI chat conversations (ChatGPT, Claude, Gemini, Copilot) for marketing/analytics while branding as privacy-protecting tools.

📌 [IDEsaster: A Novel Vulnerability Class in AI IDEs](https://maccarita.com/posts/idesaster/)  
Describes “IDEsaster” as an attack chain where prompt-injected AI coding agents abuse shared base IDE features (VS Code, JetBrains, Zed) to turn ordinary tools/settings into cross-product data exfiltration and RCE paths, arguing IDEs need “Secure for AI” redesign.

📌 [NDAA puts AI cyber risk in the crosshairs](https://www.reversinglabs.com/blog/ndaa-ai-risk)  
Argues the latest U.S. NDAA signals upcoming enterprise requirements such as AI-focused SBOMs (“AI-BOMs”), explicit model-tampering and AI supply-chain controls, and ML-model malware scanning.

📌 [Data Leakage: AI’s Plumbing Problem](https://www.crowdstrike.com/en-us/blog/data-leakage-ai-plumbing-problem/)  
Explains AI apps leak sensitive data across layers (RAG, agents, training data, user behavior, logs, context storage) and argues a defense-in-depth approach is required to prevent systemic exposure.

📌 [How AI Is Transforming the Adoption of Secure-by-Default Mobile Frameworks](https://engineering.fb.com/2025/12/15/android/how-ai-transforming-secure-by-default-mobile-frameworks-adoption/)  
Describes how secure-by-default mobile frameworks (e.g., SecureLinkLauncher) combined with Llama-based automated patching can wrap risky Android/iOS APIs, enforce scoped intent handling, and migrate large codebases to safer APIs.

📌 [XBOW vs CAI: Assessments vs Security Capability](https://news.aliasrobotics.com/xbow-vs-cai-assessments-vs-security-capability/)  
Argues XBOW optimizes point-in-time assessments/reports while CAI focuses on building continuous in-house security capability via reusable in-environment workflows that compound over time.

📌 [AI Malware: Hype vs. Reality](https://www.recordedfuture.com/blog/ai-malware-hype-vs-reality)  
Maps most “AI malware” to AIM3 Levels 1–3 (GenAI accelerating existing tradecraft/orchestration) and argues defenders should focus on AI service abuse monitoring and baseline hardening rather than fully autonomous malware hype.

📌 [Microsoft Copilot Studio Security Risk: How Simple Prompt Injection Leaked Credit Cards and Booked a $0 Trip](https://www.tenable.com/blog/microsoft-copilot-studio-security-risk-how-simple-prompt-injection-leaked-sensitive-data)  
Walks through prompt-injection against a Copilot Studio agent leading to sensitive data exposure and workflow manipulation, highlighting the risk of excessive agent permissions and untrusted instruction handling.

📌 [LLM Security Risks in 2026](https://sombrainc.com/blog/llm-security-risks-2026)  
Claims LLM risk clusters into prompt injection, agent/tool misuse, RAG/data-layer leakage or poisoning, and operational “Shadow AI”, and argues organizations must design for containment because prevention will not be perfect.

📌 [Task Injection – Exploiting agency of autonomous AI agents](https://bughunters.google.com/blog/4823857172971520/task-injection-exploiting-agency-of-autonomous-ai-agents)  
Explains “task injection”: attackers embed plausible subtasks in an agent’s environment so it takes rogue actions or leaks data while still appearing aligned, motivating deterministic runtime policy enforcement plus checkpoints for sensitive actions.

📌 [PromptPwnd: Prompt Injection Vulnerabilities in GitHub Actions Using AI Agents](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents)  
Describes a CI/CD pattern where untrusted PR/issue/commit text is injected into prompts for AI agents (Gemini CLI, Claude Code, OpenAI Codex, GitHub AI Inference), leading to privileged tool misuse (secrets leak / workflow manipulation) in GitHub Actions/GitLab contexts.

📌 [PyTorch Users at Risk: Unveiling 3 Zero-Day PickleScan Vulnerabilities](https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/)  
Reports three bypasses in PickleScan (extension spoofing, ZIP CRC errors, unsafe-globals subimports) that can allow malicious model artifacts to evade detection and still execute upon load in PyTorch.

📌 [New Prompt Injection Attack Vectors Through MCP Sampling](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)  
Warns MCP sampling can be abused by malicious servers to drain token/compute budgets, plant persistent instructions, and trigger hidden tool calls, motivating stricter templates, sanitization, rate limits, and approvals for sensitive actions.

📌 [Ghosts in the Machine: ASCII Smuggling across Various LLMs](https://www.firetail.ai/blog/ghosts-in-the-machine-ascii-smuggling-across-various-llms)  
Tests ASCII/Unicode smuggling (tag/control characters) to hide instructions from humans but not LLMs, enabling spoofing and poisoning; reports differing normalization behavior across major models.

📌 [From Inbox to Wipeout: Perplexity Comet’s AI Browser Quietly Erasing Google Drive](https://www.straiker.ai/blog/from-inbox-to-wipeout-perplexity-comets-ai-browser-quietly-erasing-google-drive)  
Shows how plausible inbox instructions combined with powerful connectors can drive destructive actions (e.g., bulk moves to Trash), highlighting excessive agency and weak safeguards around high-impact connector operations.

📌 [CVE-2025-34291: Critical Account Takeover and RCE Vulnerability in the Langflow AI Agent & Workflow Platform](https://www.obsidiansecurity.com/blog/cve-2025-34291-critical-account-takeover-and-rce-vulnerability-in-the-langflow-ai-agent-workflow-platform)  
Describes an exploit chain (permissive CORS + missing CSRF on token refresh → session hijack; then RCE via code validation endpoint) expanding blast radius via stored tokens/API keys.

📌 [Cryptographers Show That AI Protections Will Always Have Holes](https://www.quantamagazine.org/cryptographers-show-that-ai-protections-will-always-have-holes-20251210/)  
Summarizes research arguing two-tier external safety filters can be bypassed because the LLM can solve “puzzles” the filter cannot, leaving exploitable compute gaps.

📌 [Patch Wednesday: Root Cause Analysis with LLMs](https://www.akamai.com/blog/security-research/patch-wednesday-root-cause-analysis-with-llms)  
Describes PatchDiff-AI: a multi-agent system that combines KB metadata and binary diffs to guide root-cause analysis for Patch Tuesday CVEs, reporting strong hit rates on file/function/RCA identification.

📌 [Autonomous Pentesting: How AI is Changing Offensive Security](https://blog.securelayer7.net/autonomous-pentesting/)  
Argues autonomous pentesting shifts cadence to continuous coverage (asset discovery, recon, validation, prioritization) in cloud/API-heavy environments, complementing humans on edge cases and judgment.

📌 [Architecting Security for Agentic Capabilities in Chrome](https://chromeos.dev/en/posts/architecting-security-for-agentic-capabilities-in-chrome)  
Outlines Chrome’s agentic threat model and mitigations (alignment critic, origin sets, deterministic checks, confirmations, parallel detection, red-teaming, VRP incentives) focused on indirect prompt injection and unsafe actions.

📌 [UEFI Vulnerability Analysis Using AI: Part 1](https://whiteknightlabs.com/2025/12/02/uefi-vulnerability-analysis-using-ai-part-1/)  
Walks through UEFI vuln analysis at scale and argues multi-GB codebases exceed typical upload/context limits, motivating RAG workflows and local infrastructure.

📌 [DIG AI: Uncensored Darknet AI Assistant At The Service Of Criminals And Terrorists](https://www.resecurity.com/blog/article/dig-ai-uncensored-darknet-ai-assistant-at-the-service-of-criminals-and-terrorists)  
Reports an “uncensored” Tor-hosted GenAI assistant marketed for scaling cybercrime workflows, noting abuse potential and enforcement challenges in darknet distribution.

📌 [LLM-Powered AMSI Provider vs. Red Team Agent](https://dreadnode.io/blog/llm-powered-amsi-provider-vs-red-team-agent)  
Implements a Windows AMSI provider using an LLM for detection logic, emphasizing an operational interface integrated into execution flow rather than a notebook-only prototype.

📌 [AI Shared Responsibility Model](https://www.linkedin.com/pulse/understanding-ai-shared-responsibility-model-framework-castro-yd0ae/)  
Proposes a shared-responsibility framework mapping governance/security/ops responsibilities across AI deployment models (managed SaaS through on-prem) given shifting data, autonomy, and model behavior.

📌 [AI Risk Map](https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map)  
Framework for identifying/analyzing/mitigating AI system security risks across the AI development lifecycle.

📌 [HexStrike on Kali Linux 2025.4: A Comprehensive Guide](https://medium.com/ai-security-hub/hexstrike-on-kali-linux-2025-4-a-comprehensive-guide-85a0e5752949)  
Overview of HexStrike AI as an offensive security framework combining multi-agent AI with a large toolset.

📌 [Red Teaming BrowseSafe: Prompt Injection Risks in Perplexity’s Open-Source Model](https://www.lasso.security/blog/red-teaming-browsesafe-prompt-injection-risks-in-perplexitys-open-source-model)  
Reports red-teaming results for Perplexity’s BrowseSafe prompt-injection filter and highlights residual risk even with filtering.

📌 [How Amazon uses AI agents to anticipate and counter cyber threats](https://www.amazon.science/blog/how-amazon-uses-ai-agents-to-anticipate-and-counter-cyber-threats)  
Describes Amazon’s Autonomous Threat Analysis (ATA): competitive red/blue agent simulations in isolated environments that validate detections via telemetry and accelerate detection engineering cycles.

📌 [Claude in Chrome: A Threat Analysis](https://labs.zenity.io/p/claude-in-chrome-a-threat-analysis)  
Maps agentic browser risks (indirect prompt injection, destructive actions, sensitive disclosure, lateral movement, impersonation) and highlights capability exposure plus “always logged-in” posture risks.

📌 [AG-UI and A2UI Protocols Explained: Building Production-Ready Agentic Systems with MAESTRO Security](https://kenhuangus.substack.com/p/ag-ui-and-a2ui-protocols-explained)  
Explains AG-UI (bidirectional event stream) and A2UI (declarative whitelisted rendering) and maps threats (state corruption, leakage, tool abuse, transport hijack, deceptive UI) with corresponding control themes.

📌 [Cyber & Dev: MCP](https://zkorman.com/posts/cyber-and-dev-2-mcp/)  
Explains Model Context Protocol (MCP) as a standard for tool discovery/calls (stdio local or streamable HTTP remote via JSON-RPC) and argues security hinges on permissioning and treating connected servers as broad read/write extensions of the agent’s context.

# 🧰 Tools & Resources

🧰 **[mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)** - MCP security scanner that probes MCP servers/tools for common vulnerability classes and unsafe exposure patterns. ⭐️730  
🧰 **[GhidraGPT](https://github.com/weirdmachine64/GhidraGPT)** - Integrate LLM models directly into Ghidra for automated code rewrite and analysis. ⭐️225  
🧰 **[ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS)** - Automated Red Teaming Engine with multi-agent intelligent supervision. ⭐️268  
🧰 **[genai-security-training](https://github.com/schwartz1375/genai-security-training)** - Self-paced training curriculum for red teaming GenAI and AI/ML systems. ⭐️225  
🧰 **[MCPScan](https://github.com/antgroup/MCPScan)** - MCP security scanner focused on tool/server vulnerabilities and risky deployment patterns. ⭐️192  
🧰 **[cupcake](https://github.com/eqtylab/cupcake)** - Enforces OPA/Rego policies to constrain AI coding agents’ actions, tool calls, and data access. ⭐️128  
🧰 **[VulnLLM-R](https://github.com/ucsb-mlsec/VulnLLM-R)** - Reasoning-focused LLM+agent pipeline for project-level vulnerability discovery and evaluation. ⭐️78  
🧰 **[opengrep-rules](https://github.com/AikidoSec/opengrep-rules)** - Opengrep ruleset to detect prompt-injection risks in GitHub Actions workflows and related configs. ⭐️28  
🧰 **[prompt-siren](https://github.com/facebookresearch/prompt-siren)** - Research workbench for testing prompt-injection attacks and defenses against LLM agents. ⭐️26  
🧰 **[AI for the Win](https://github.com/depalmar/ai_for_the_win)** - Hands-on training program for building AI/ML tools for detection, forensics, and incident response. ⭐️16  
🧰 **[mcp-cybersec-watchdog](https://github.com/girste/mcp-cybersec-watchdog)** - MCP server that runs security analyzers and produces qualitative assessments for MCP implementations. ⭐️9  
🧰 **[go-promptguard](https://github.com/mdombrov-33/go-promptguard)** - Go library/CLI for detecting LLM prompt-injection attempts in application inputs. ⭐️8  
🧰 **[PromptScreen](https://github.com/cross-codes/PromptScreen)** - Detects prompt-injection patterns in GitHub Actions workflows and logs. ⭐️7  
🧰 **[Mcpwn](https://github.com/Teycir/Mcpwn)** - MCP security testing framework scanning for RCE, path traversal, prompt injection, and protocol weaknesses. ⭐️5  
🧰 **[ARES-Dashboard](https://github.com/Arnoldlarry15/ARES-Dashboard)** - AI red-team operations console aligned to OWASP LLM Top 10 and MITRE. ⭐️5  
🧰 **[async-control](https://github.com/UKGovernmentBEIS/async-control)** - Stress-tests asynchronous control measures and monitor prompts for LLM agents. ⭐️4  
🧰 **[PromptGuard](https://github.com/Brightlord5/PromptGuard)** - Pre-commit hook and CLI that flags prompt-injection patterns (OWASP LLM Top 10-inspired rules). ⭐️3  

# 📄 Reports

📘 [An Addendum to the Guidelines and Companion Guide on Securing AI Systems](https://www.linkedin.com/feed/update/urn:li:activity:7412047391094181888)  
CSA addendum expanding practical guidance and controls for securing AI systems across the lifecycle.

📘 [The State of AI Security and Governance](https://www.linkedin.com/feed/update/urn:li:activity:7407548266768166912)  
CSA report on enterprise AI adoption patterns, security/gov skills gaps, and top risk concerns (including persistent data exposure).

📘 [Frontier AI Trends Report](https://www.linkedin.com/feed/update/urn:li:activity:7407527990101704704)  
AI Security Institute report summarizing capability trends from extensive testing across domains.

📘 [Cyber AI Profile - NIST (Preliminary Draft)](https://www.linkedin.com/feed/update/urn:li:activity:7407313095309787136)  
NIST’s preliminary Cyber AI Profile framing focus areas: Secure (AI components), Defend (AI-enabled defense), Thwart (AI-enabled attacks).

📘 [OWASP Top 10 for Agentic Applications for 2026](https://www.linkedin.com/feed/update/urn:li:activity:7404450511539712001)  
Peer-reviewed OWASP framework identifying critical security risks for autonomous/agentic AI systems.

📘 [Data Security within AI Environments](https://www.linkedin.com/feed/update/urn:li:activity:7402742675893817344)  
CSA-aligned practitioner guide on AI-era data protection, mapping AI data risks to controls and governance patterns.

📘 [Principles for the Secure Integration of Artificial Intelligence in Operational Technology](https://www.linkedin.com/feed/update/urn:li:activity:7402515508647858178)  
Guidance on introducing AI into OT environments while managing safety, security, and reliability risks.

# 📅 Upcoming Conferences

## January 2026

📅 [NHIcon 2026 — The Rise of Agentic AI Security](https://aembit.io/nhicon/)  
January 27, 2026 · Virtual · Organizer: Aembit

📅 [CSA AI Summit 2026](https://cloudsecurityalliance.org/events/csa-ai-summit-2026)  
January 28–29, 2026 · Virtual · Organizer: Cloud Security Alliance

## February 2026

📅 [DiCyFor & AI Security Summit (Singapore)](https://www.dicyfor.com/singapore2026)  
February 10, 2026 · Singapore · Organizer: DiCyFor

📅 [IEEE ICAIC 2026 — International Conference on AI in Cybersecurity](https://icaic.gyancity.com/)  
February 18–20, 2026 · University of Houston, Houston, TX, USA · Organizer: IEEE / ICAIC

## March 2026

📅 [[un]prompted — The AI Security Practitioner Conference](https://unpromptedcon.org/)  
March 3–4, 2026 · Salesforce Tower, San Francisco, CA, USA · Organizer: [un]prompted

📅 [AI Security Summit 2026](https://events.lynx.co/ai-security-summit/)  
March 10, 2026 · Check Point HQ, Tel Aviv, Israel · Organizer: Lynx Events

📅 [DiCyFor & AI Security Summit (Bangkok)](https://www.dicyfor.com/bangkok2026)  
March 11–12, 2026 · Bangkok, Thailand · Organizer: DiCyFor

📅 [IEEE SaTML 2026 — Secure and Trustworthy Machine Learning](https://satml.org/)  
March 23–25, 2026 · Munich, Germany · Organizer: IEEE SaTML

## April 2026

📅 [DiCyFor & AI Security Summit (Kuala Lumpur)](https://www.dicyfor.com/kualalumpur2026)  
April 15, 2026 · Kuala Lumpur, Malaysia · Organizer: DiCyFor

📅 [SANS AI Cybersecurity Summit 2026](https://www.sans.org/cyber-security-training-events/ai-summit-2026)  
April 20–21, 2026 · Arlington, VA, USA & Virtual · Organizer: SANS Institute

📅 [AI Security Summit @ Black Hat Asia](https://www.blackhat.com/asia-26/ai-security-summit.html)  
April 22, 2026 · Marina Bay Sands, Singapore · Organizer: Black Hat

# 📚 Research

📖 [AI Deception: Risks, Dynamics, and Controls](https://arxiv.org/abs/2511.22619)  
Survey covering definitions, empirical studies, risks, and a “deception cycle” framing deception emergence and treatment.

📖 [From Rookie to Expert: Manipulating LLMs for Automated Vulnerability Exploitation](https://arxiv.org/pdf/2512.22753v1)  
Introduces RSA (Role-play, Scenario, Action) as a pretexting methodology to manipulate LLMs into producing functional exploit code.

📖 [Agentic AI for 6G: A New Paradigm for Autonomous RAN Security Compliance](https://www.arxiv.org/pdf/2512.12400)  
Discusses agentic AI for autonomous RAN security compliance in next-generation 6G environments.

📖 [Bootstrapping Code Security Benchmarking](https://arxiv.org/pdf/2512.21132v1)  
Presents AutoBaxBuilder, an automated framework for generating code security benchmark tasks with large efficiency gains.

📖 [PACEbench: A Framework for Evaluating Practical AI Cyber Exploitation Capabilities](https://arxiv.org/pdf/2510.11688v1)  
Introduces PACEbench and PACEagent for evaluating practical AI cyber exploitation across realistic scenarios.

📖 [STAC: When Innocent Tools Form Dangerous Chains to Jailbreak LLM Agents](https://arxiv.org/pdf/2509.25624)  
Introduces Sequential Tool Attack Chaining (STAC): multi-turn attack sequences where individually benign tool calls combine into harmful outcomes.

📖 [Comparing AI Agents to Cybersecurity Professionals in Real-World Penetration Testing](https://arxiv.org/abs/2512.09882)  
Compares AI agents and human pentesters in a live enterprise environment; introduces ARTEMIS and reports comparative performance metrics.

📖 [Decompiling the Synergy: An Empirical Study of Human–LLM Teaming in Software Reverse Engineering](https://www.zionbasque.com/files/papers/dec-synergy-study.pdf)  
Human study on LLM assistance in SRE, highlighting where LLMs help (esp. novices) and where they fail (hallucinations, unhelpful suggestions).

📖 [AprielGuard](https://arxiv.org/abs/2512.20293)  
SLM for safety/adversarial risk detection across multiple categories and attack types; also released on Hugging Face.

# 🎥 Videos

▶️ [AI & Product Security: Attack Vectors, Model Risks, and Defensive AI](https://www.youtube.com/watch?v=Da9fL9LaeUs&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=35)  
▶️ [AI Security Summit | Secure Vibe Coding | Andrew Oates, Snyk](https://www.youtube.com/watch?v=OcjJa04HreA&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=37)  
▶️ [AI, Identity Security, and the Offense/Defense Balance | ZT Summit 2025 - Dr. Christopher Porter](https://www.youtube.com/watch?v=CfVDHKHcueM&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=38)  
▶️ [Hack the planet! LangGraph AI HackBot Dev & Q/A - BlaiseBits](https://www.youtube.com/watch?v=HNPdfW5rP2w&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=39)  
▶️ [I’m A Machine, And You Should Trust Me: The Future Of Non-Human Identity - Dwayne McDaniel](https://www.youtube.com/watch?v=sQSlAITPQpk&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=40)  
▶️ [Why AI Security Begins and Ends in the Browser - Todd Hathaway](https://www.youtube.com/watch?v=wsdnO4jRI2s&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=41)  
▶️ [Cross-Layered Design for Security and Resilience in AI-Driven Cyber Physical Human Systems](https://www.youtube.com/watch?v=yRyILxRIcOY&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=42)  
▶️ [Human Attack Surfaces in Agentic Web](https://www.youtube.com/watch?v=rrHZm6FEQoc&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=43)  
▶️ [Large Language Models in Cybersecurity: Threats, Exposure and Mitigation - Vincent Lenders](https://www.youtube.com/watch?v=LasVFLBRXt0&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=44)  
▶️ [Josiah Hagen - Applying Personality to LLMs: Customized Security for the Agentic Age of AI](https://www.youtube.com/watch?v=MG7ItQVgT28&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=45)  
▶️ [RAGnarok: Assisting Your Threat Hunting with Local LLM](https://www.youtube.com/watch?v=NRWmSZPZ9sc&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=46)  
▶️ [RAG Against the Machine: Using Retrieval-Augmented Generation & MCP](https://www.youtube.com/watch?v=7Go4KRNFZ_I&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=47)  
▶️ [Jesse Merhi - Model Context Protocol is Insecure by Design](https://www.youtube.com/watch?v=26vCssimYyA&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=48)  
▶️ [Agentic AI Malware: Why the Cybersecurity Battle Isn’t Over](https://www.youtube.com/watch?v=MhDdAb7UxM8&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=49)  
▶️ [Inside the Open-Source Kill Chain: How LLMs Helped Catch Lazarus and Stop a Crypto Backdoor](https://www.youtube.com/watch?v=-5-uosSfwyg&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=50)  
▶️ [Harnessing AI and Post-Quantum Cryptography for Cybersecurity in the Quantum Era](https://www.youtube.com/watch?v=sjRNI_FV1pI&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=51)  
▶️ [Teaching AI to Hunt for Vulnerabilities - Roald Nefs](https://www.youtube.com/watch?v=ii90UM4S5B0&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=52)  
▶️ [Securing AI Infrastructure: Lessons from National Cybersecurity Strategies](https://www.youtube.com/watch?v=K7j56RJI7ao&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=53)  
▶️ [Itamar Sher - Why LLMs Fall Short in Vulnerability Management](https://www.youtube.com/watch?v=mL4MR27y3lE&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=54)  
▶️ [Hazard Analysis of Military AI Systems Using STPA-Sec](https://www.youtube.com/watch?v=pQNgIF2r7as&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=55)  
▶️ [Don’t be LLaMe – The basics of attacking LLMs in your Red Team exercises](https://www.youtube.com/watch?v=WZZrqGFdCj8&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=56)  
▶️ [When Attackers Tune In: Weaponizing LLM Tuning for Stealthy C2 and Exfiltration](https://www.youtube.com/watch?v=HSb0ct_lcuY&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=57)  
▶️ [Machine Identity & Attack Path: The Danger of Misconfigurations](https://www.youtube.com/watch?v=cN0pLRzmEe8&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=58)  
▶️ [Creating the Torment Nexus: Using Machine Learning to Defeat Machine Learning](https://www.youtube.com/watch?v=XGhabe4Fc2s&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=59)  
▶️ [Crawl, Walk, Run: Building AI Tools for Third-Party Security Evaluation](https://www.youtube.com/watch?v=jq8w3nADzO0&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=60)  
▶️ [Dreadnode at Offensive AI Con (OAIC) 2025 | From Benchmarks to Breaches: Scaling Offensive Security](https://www.youtube.com/watch?v=W3pRfofIv2E&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=61)  
▶️ [Show Me The Honey: Creating Elasticsearch Honeypots Powered By LLMs - Claire Dickson (Burn)](https://www.youtube.com/watch?v=Jt4W9wwAaOM&list=PLFO56KBxdGBfdxGr2rXoNVaFboTPp7Xwx&index=62)  

