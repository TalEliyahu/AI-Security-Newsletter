# AI Security Newsletter – July 2025

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AI Security community](https://linktr.ee/AISECHUB) on [Twitter](https://x.com/AISecHub) and [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates.

Sponsored by [InnovGuard.com](https://innovguard.com) – Technology Risk & Cybersecurity Advisory, Innovate and Invest with Confidence, Lead with Assurance.

## 🔍 Insights

📌 [AIDEFEND: An AI Defense Framework](https://edward-playground.github.io/aidefense-framework/) — An open-source knowledge base of defensive countermeasures for AI/ML systems. Maps defenses to known threats from MITRE ATLAS, MAESTRO, and OWASP, offering interactive views for practitioners. Inspired by MITRE D3FEND, ATT&CK, ATLAS, Google SAIF, and OWASP Top 10, but developed independently. By Edward Lee.

📌 [AI slop and fake reports are coming for your bug bounty programs](https://techcrunch.com/2025/07/24/ai-slop-and-fake-reports-are-exhausting-some-security-bug-bounties/) — Growing issue of “AI slop” bug bounty reports where LLMs fabricate vulnerabilities packaged in professional-looking writeups. Includes cases from CycloneDX and other open-source maintainers. By Lorenzo Franceschi-Bicchierai.

📌 [The Road to Agentic AI: Navigating Architecture, Threats, and Solutions](https://www.trendmicro.com/vinfo/in/security/news/security-technology/the-road-to-agentic-ai-navigating-architecture-threats-and-solutions) — Breaks down the multi-layered architecture of agentic AI systems, examining risks at each layer and offering actionable defenses. By Vincenzo Ciancaglini, Marco Balduzzi, Ph.D., Salvatore Gariuolo, Rainer Vosseler, Fernando Tucci.

📌 [Deepfake It Till You Make It: A Comprehensive View of the New AI Criminal Toolset](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/deepfake-it-til-you-make-it-a-comprehensive-view-of-the-new-ai-criminal-toolset) — Survey of deepfake-enabled criminal operations, underground toolkits, and case studies. By David Sancho, Salvatore Gariuolo, Vincenzo Ciancaglini.

📌 [Code Execution Through Deception: Gemini AI CLI Hijack](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) — Discovery of a Gemini CLI flaw allowing silent malicious command execution via prompt injection and misleading UX. By Sam Cox @ Tracebit.

📌 [An Executive Guide to Secure-by-Design AI](https://mitsloan.mit.edu/ideas-made-to-matter/new-framework-helps-companies-build-secure-ai-systems) — Ten strategic questions aligned to AI system development stages for embedding security early in design. By Dr. Keri P. and Nelson Novaes Neto.

📌 [How we Rooted Copilot](https://research.eye.security/how-we-rooted-copilot/) — Exploitation of a Microsoft Copilot Enterprise misconfiguration allowing privileged command execution in its Jupyter-based sandbox. By Vaisha Bernard @ Eye Security.

📌 [Artificial Exploits, Real Limitations](https://www.forescout.com/blog/artificial-exploits-real-limitations-how-ai-cyber-attacks-fall-short/) — Research showing LLMs are more effective in social engineering, influence ops, and boilerplate malware than in discovering novel vulnerabilities. By Michele Campobasso, Forescout.

📌 [A summer of security: empowering cyber defenders with AI](https://blog.google/technology/safety-security/cybersecurity-updates-summer-2025/) — Google’s Big Sleep agent, leveraging threat intel, discovered and mitigated a live SQLite zero-day (CVE-2025-6965) before exploitation. By Kent Walker.

📌 [11 Questions You Must Ask When Evaluating AI SOC Analysts](https://www.prophetsecurity.ai/blog/11-questions-you-must-ask-when-evaluating-ai-soc-analysts) — Key questions for selecting AI SOC vendors, covering capabilities, integration, and governance. By George Dimitrov @ Prophet Security.

📌 [Living Off the Land 2.0: AI-First Platforms, UI Abuse, and Coyote Malware](https://www.akamai.com/blog/security-research/active-exploitation-coyote-malware-first-ui-automation-abuse-in-the-wild) — Coyote malware uses native UI automation for stealthy credential theft and surveillance, illustrating UI abuse in AI-first OS environments. By Tomer Peled.

📌 [Detection at Scale – The Cursor Moment for Security Operations](https://www.detectionatscale.com/p/the-cursor-moment-for-security-operations) — MCP and AI agents accelerate detection engineering with environment-specific SIEM rules and efficiency gains. By Jack Naglieri.

📌 [Bad Actors are Grooming LLMs to Produce Falsehoods](https://americansunlight.substack.com/p/bad-actors-are-grooming-llms-to-produce) — Research into LLM “grooming” to mass-produce disinformation by manipulating model reasoning. By Sophia F., Nina Jankowicz, Gary Marcus.

📌 [AI Vibe Coding Tool Goes Rogue](https://cybernews.com/ai-news/ai-coding-tool-wipes-database-lies/) — Case of an AI coding assistant deleting production databases, fabricating users, and hiding test failures.

📌 [Phishing for Gemini](https://0din.ai/blog/phishing-for-gemini) — Prompt injection in Google Gemini enabling credential theft via hidden HTML/CSS tags in email summaries. By Marco Figueroa @ 0DIN.ai.

📌 [AI-Generated malicious package found in NPM Registry](https://getsafety.com/blog-posts/threat-actor-uses-ai-to-create-a-better-crypto-wallet-drainer) — AI-crafted crypto wallet drainer malware in the NPM registry. By Paul McCarty @ Safety Cybersecurity.

📌 [2025 SANS Institute SOC Survey – Modern SOC Challenges](https://www.sans.org/white-papers/sans-2025-soc-survey) — AI/automation expansion planned despite low reported value; warns against replacing SOC analysts with AI. By Seth Misenar.

📌 [Asana MCP server back online after plugging a data-leak hole](https://adversa.ai/blog/asana-ai-incident-comprehensive-lessons-learned-for-enterprise-security-and-ciso/) — Logic flaw in beta MCP server exposed cross-tenant data for ~1,000 enterprises. By Alex Polyakov @ Adversa AI.

📌 [GitHub MCP Exploited: Accessing private repositories via MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability) — MCP flaw in GitHub integration leaks private repo data via malicious issues. By Marco Milanta & Luca Beurer-Kellner @ Invariant Labs.

📌 [PoC Attack Targeting Atlassian’s MCP](https://www.catonetworks.com/blog/cato-ctrl-poc-attack-targeting-atlassians-mcp/) — Prompt injection in Jira Service Management MCP creates “Living Off AI” risks. By Guy Waizel, Dolev Attiya, Shlomo Bamberger @ Cato Networks.

📌 [Agentic Misalignment: How LLMs Could Be Insider Threats](https://www.anthropic.com/research/agentic-misalignment) — Anthropic research shows LLM agents in simulated corporate settings choosing harmful actions when goals conflict.

📌 [Code Execution Through Email: How I Used Claude to Hack Itself](https://www.pynt.io/blog/llm-security-blogs/code-execution-through-email-how-i-used-claude-mcp-to-hack-itself) — MCP-enabled Claude exploit chain from crafted Gmail message to code execution. By Golan Yosef @ Pynt.

📌 [10 Ways AI is Enhancing Ransomware-as-a-Service](https://www.linkedin.com/feed/update/urn:li:activity:7353604333646606336) — AI-powered RaaS tactics: ransom chatbots, recon, adaptive encryption, dynamic pricing, deepfake voice extortion.

📌 [ISC2 Survey – AI in Cybersecurity](https://www.isc2.org/Insights/2025/07/2025-isc2-ai-pulse-survey) — 42% testing AI security tools, 70% report improved effectiveness; notes new AI-focused roles emerging.

📌 [The Race to Secure Enterprise AI – Insight Partners](https://www.insightpartners.com/ideas/securing-ai/) — Market view on secure model dev, runtime AI firewalls, and threat detection guardrails.

📌 [Malware with Embedded Prompt Injection](https://research.checkpoint.com/2025/ai-evasion-prompt-injection) — Skynet malware embeds prompt injection to evade AI analysis tools.

📌 Security for Agents and Agents for Security — [Menlo Ventures blog](https://menlovc.com/) on why securing AI agents requires rethinking authentication, privileges, and observability.

📌 [Repeater Strike: Manual Testing, Amplified](https://portswigger.net/research/repeater-strike-manual-testing-amplified) — Burp Suite extension using AI to generate regex rules for IDOR detection. By Gareth Heyes.

📌 [AI Cybersecurity Careers: The Complete Guide](https://robtlee73.substack.com/p/ai-cybersecurity-careers-the-complete) — Breakdown of emerging AI-security hybrid roles. By Rob T. Lee @ SANS.

📌 [Checklist for LLM Compliance in Government](https://www.newline.co/@zaoyang/checklist-for-llm-compliance-in-government--1bf1bfd0) — Compliance steps for LLM deployment in government agencies. By Sizhao Yang.

📌 [Grok-4 Jailbreak with Echo Chamber and Crescendo](https://neuraltrust.ai/blog/grok-4-jailbreak-echo-chamber-and-crescendo) — Multi-turn jailbreak achieving up to 67% success on harmful prompts. By Ahmed Alobaid @ NeuralTrust.

📌 [NVIDIAScape – Critical NVIDIA AI Vulnerability](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape) — CVE-2025-23266 container escape in NVIDIA Toolkit enabling root access. By Nir Ohfeld & Shir Tamari @ Wiz.

📌 [Hacker Plants Computer 'Wiping' Commands in Amazon's AI Coding Agent](https://www.404media.co/hacker-plants-computer-wiping-commands-in-amazons-ai-coding-agent) — Malicious PR in Amazon Q added destructive wipe commands. By Joseph Cox.

## 📄 Reports

📘 [SBOM for AI Use Cases](https://www.linkedin.com/feed/update/urn:li:activity:7352420212471709697) — Community-driven resource for applying SBOM practices to AI systems. Covers business, legal, and security risks from GenAI and LLMs, mirroring software supply chain challenges. Provides a standardized approach to improve transparency, trust, and governance. Authors: Helen Oakley, Daniel Bardenstein, Dmitry R.

📘 [Securing Agentic Applications Guide](https://www.linkedin.com/feed/update/urn:li:activity:7355648811236511745) — Practical, actionable guidance for designing and deploying secure agentic applications powered by LLMs. Complements OWASP Agentic AI Threats & Mitigations with concrete technical recommendations for builders and defenders.

📘 [America’s AI Action Plan – 12 AI Cybersecurity Priorities](https://www.linkedin.com/feed/update/urn:li:activity:7353987917704294400) — U.S. strategy for securing AI, including secure-by-design dev, AI incident response, AI-ISAC threat intel sharing, deepfake detection standards, and model risk evaluations. Targets IP protection, critical infrastructure defense, red-teaming, and export controls.

📘 [Google's Approach for Secure AI Agents](https://www.linkedin.com/feed/update/urn:li:activity:7347701762813829120) — Framework for secure AI agents combining deterministic controls with dynamic, reasoning-based defenses. Principles: clear human controllers, limited powers, and full observability. By Santiago Díaz Muñoz, Christoph Kern, Kara Olive.

📘 [Preparing Defenders of AI Systems V1.0](https://github.com/cosai-oasis/ws2-defenders/blob/main/preparing-defenders-of-ai-systems.md) — Coalition for Secure AI paper on shifting enterprise security priorities from models to agents. Highlights layered defenses, governance gaps, and AI-specific strategies.

📘 [AI Controls Matrix (AICM)](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix) — CSA vendor-agnostic framework with 243 controls across 18 domains for secure, responsible AI. Maps to ISO 42001, ISO 27001, NIST AI RMF 1.0, and BSI AIC4.

📘 [AI Safety Practices Compared – 2025 FLI Report](https://www.linkedin.com/feed/update/urn:li:activity:7352842152759971840) — Evaluation of Anthropic, OpenAI, DeepMind, Meta, xAI, Zhipu AI, and DeepSeek across 33 safety indicators. Finds gaps in cyber misuse testing, red-teaming, incident reporting, and bug bounties.

📘 [AI Risk Trends – 2025 Team8 CISO Village](https://www.linkedin.com/feed/update/urn:li:activity:7353987917704294400) — Survey of 110+ CISOs: 67% use AI agents, 25% faced AI-driven attacks, 77% expect AI to replace SOC tasks. Shadow AI governance remains weak.

📘 [Understanding and Safeguarding Children’s Use of AI Chatbots](https://www.linkedin.com/feed/update/urn:li:activity:7351249793546924045) — Risks include misinformation, harmful content, emotional dependence, and privacy issues. Calls for age-appropriate design and stronger moderation.

📘 [AI Coding Assistants: Security-Safe Navigation](https://www.linkedin.com/feed/update/urn:li:activity:7351007465494171649) — Secure Code Warrior report: top LLMs only ~47% correct and secure; insecure coding patterns persist. Highlights misconfigurations, lack of runtime awareness, and supply chain risks.

📘 [Cyber and Artificial Intelligence Risk in Financial Services](https://www.linkedin.com/feed/update/urn:li:activity:7347449832065613825) — DFSA report on AI and cyber risks in financial services. By Justin Baldacchino and Herman Schueller.

📘 [The AI Tech Stack: A Primer for Tech and Cyber Policy](https://www.linkedin.com/feed/update/urn:li:activity:7348456040172048385) — Paladin Capital Group defines five AI stack layers and stresses integrating security across governance, application, infrastructure, models, and data.

📘 [AI Maturity Model for Cybersecurity](https://www.linkedin.com/feed/update/urn:li:activity:7352156064244514816) — Darktrace’s 5-level model from Manual Operations to AI Delegation, guiding CISOs toward autonomous defense with governance.

📘 [The SAIL (Secure AI Lifecycle) Framework](https://www.linkedin.com/feed/update/urn:li:activity:7346638798056800257/) — Pillar Security’s practical guide for building and deploying secure AI applications, authored by 20+ industry experts.

📘 [State of Cybersecurity Resilience 2025](https://www.linkedin.com/feed/update/urn:li:activity:7350979113358184451) — Accenture report: 90% of orgs lack maturity for modern AI threats, 77% miss foundational AI security practices. Recommends governance, AI-secure cores, and resilient systems.

📘 [Databricks AI Governance Framework](https://www.linkedin.com/feed/update/urn:li:activity:7346374987928260613) — Guide for responsible, effective enterprise AI programs. By David Wells and Abhi A.

📘 [State of LLM Application Security](https://www.linkedin.com/feed/update/urn:li:activity:7352038190066651136) — Cobalt report: 32% of LLM pentest issues are high/critical. Top risks include prompt injection, data leaks, poisoning, and bias; only 21% of serious AI vulns remediated.

📘 [Multi-Layered AI Defense](https://www.linkedin.com/feed/update/urn:li:activity:7352381103879475203) — Darktrace outlines unsupervised, supervised, and generative AI in a continuous Learn → Detect → Investigate → Respond → Re-learn cycle with human oversight.

📘 [Trustworthiness for AI in Defence](https://eda.europa.eu/docs/default-source/brochures/taid-white-paper-final-09052025.pdf) — European Defence Agency white paper on trusted AI, verification/validation, and certification requirements.

📘 [The Mitigating ‘Hidden’ AI Risks Toolkit](https://www.linkedin.com/feed/update/urn:li:activity:7349585719247446016) — UK Government Communications guide for managing unintended AI risks. Draws from lessons deploying the “Assist” GenAI tool.

📘 [SAFE-AI: A Framework for Securing AI-Enabled Systems](https://www.linkedin.com/feed/update/urn:li:activity:7347734136868020224) — MITRE framework addressing supply chain, adversarial inputs, poisoning, bias, and sensitive data exposure. By John Kressel.

📘 [The General-Purpose AI Code of Practice – Safety & Security](https://www.linkedin.com/feed/update/urn:li:activity:7349138123362091009) — EU voluntary framework under the AI Act for managing systemic risks in advanced models, developed via multi-stakeholder process.

## 📂 Upcoming Events

📅 [The AI Summit at Black Hat](https://www.blackhat.com/us-25/ai-summit.html) — August 5, 2025 | Mandalay Bay, Las Vegas, USA  

📅 [AI Village @ DEF CON 33](https://aivillage.org/events/defcon33/) — August 7, 2025 | Las Vegas Convention Center, Las Vegas, USA  

📅 [Vegas AI Security Forum ‘25](https://aisecurity.forum/vegas-25) — August 7, 2025 | 10:00 AM – 11:00 PM | Palms Casino Resort, Las Vegas, USA  

📅 [GRC Data & AI Summit](https://www.anecdotes.ai/grc-data-ai-summit) — August 13, 2025 | 9:00 AM PDT | Virtual | By Anecdotes  

📅 [Artificial Intelligence Risk Summit](https://www.airisksummit.com/) — August 19–20, 2025 | Virtual & In-person  

📅 [Agentic AI Security Summit 2025](https://web.cvent.com/event/6a48aa4b-a67c-40ca-81a5-3c3e8f78884c/) — August 19, 2025 | Cloud Security Alliance | Virtual  

📅 [The International Conference on Cybersecurity and AI-Based Systems](https://www.cyber-ai.org/) — September 1–4, 2025 | Bulgaria  

📅 [HackATHon 2025](https://hackaicon.ethiack.com/) — September 25, 2025 | LX Factory, Lisbon, Portugal | By ETHIACK  

📅 [The AI Summit at Security Education Conference Toronto (SecTor) 2025](https://www.blackhat.com/sector/2025/ai-summit.html) — September 30, 2025 | MTCC, Toronto, Ontario, Canada

## 📚 Research

📖 [We Urgently Need Privilege Management in MCP: A Measurement of API Usage in MCP Ecosystems](https://arxiv.org/abs/2507.06250) — Analysis of 2,562 MCP servers across 23 categories shows 1,438 using network APIs, 1,237 system-level, 613 file, and 25 memory APIs. High-risk operations cluster in low-star repos and categories like Dev Tools, API Dev, and Data Science, exposing privilege-escalation, tampering, and content-manipulation risks from insufficient isolation and overprivileged access. By Zhihao Li, Kun Li, Boyang Ma, Minghui Xu, Yue Zhang, Xiuzhen Cheng.

📖 [TRiSM for Agentic AI: A Review of Trust, Risk, and Security Management in LLM-based Agentic Multi-Agent Systems](https://arxiv.org/abs/2506.04133) — Reviews lifecycle safeguards for agentic systems (prompt infection, memory poisoning, collusion, tool misuse). Aligns with NIST AI RMF and OWASP LLM Top 10 using explainability, ModelOps, security, privacy, and governance. By Shaina Raza, Ranjan Sapkota, Manoj Karkee, Christos Emmanouilidis.

📖 [AIRTBench: Measuring Autonomous AI Red Teaming Capabilities in Language Models](https://arxiv.org/abs/2506.14682) — Benchmark of 70 CTF challenges testing vulnerability finding/exploitation. Results: Claude-3.7-Sonnet 61%, Gemini-2.5-Pro 56%, GPT-4.5-Preview 49%. Strong at prompt injection; weak at system exploitation and model inversion. By Ads Dawson, Rob Mulla, Nick Landers, Shane Caldwell.

📖 [A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures](https://arxiv.org/abs/2506.19676) — Reviews agent comms (e.g., Anthropic MCP, Google A2A), stages, risks (prompt injection, data leaks), and defenses (sandboxing, monitoring).

📖 [RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing](https://arxiv.org/abs/2501.18160) — Agent with memory + validator for end-to-end repo audits. 78.43% precision; 40 true bugs across 15 benchmarks (~0.44h, $2.54 per project); 185 new bugs found in major projects, 174 confirmed/fixed. By Jinyao Guo et al.

📖 [Decompiling Smart Contracts with a Large Language Model](https://arxiv.org/pdf/2506.19624) — Addresses opacity from low verification rates on Etherscan; proposes LLM-based semantic analysis of bytecode to surface vulnerabilities and malicious logic. By Isaac David, Liyi Zhou, Dawn Song, Arthur Gervais, Kaihua Qin.

📖 [Dynamic Risk Assessments for Offensive Cybersecurity Agents](https://arxiv.org/pdf/2505.18384) — Argues static evaluations understate risk; proposes dynamic, compute-aware, continuously updated assessments for offensive agents. By Boyi Wei et al.

📖 [When LLMs Autonomously Attack](https://engineering.cmu.edu/news-events/news/2025/07/24-when-llms-autonomously-attack.html) — CMU shows LLMs can plan/execute real-world cyberattacks in enterprise-grade networks; implications for future defenses. By Brian Singer et al.

📖 [ETrace: Event-Driven Vulnerability Detection in Smart Contracts via LLM-Based Trace Analysis](https://arxiv.org/pdf/2506.15790) — Event-driven trace analysis to detect vulns where source code is unavailable.

📖 [BaxBench: Can LLMs Generate Correct and Secure Backends?](https://arxiv.org/abs/2502.11844) — 392-task benchmark on production-grade backend generation. Top model (OpenAI o1) reaches 62% correctness; ~half of “correct” programs remain exploitable; performance drops on less common frameworks. By Mark Vero et al.

📖 [Autonomous AI-based Cybersecurity Framework for Critical Infrastructure](https://arxiv.org/abs/2507.07416) — Hybrid AI framework for real-time vuln detection, threat modeling, and automated remediation across energy/health/transport/water; tackles adversarial AI, compliance, integration. By Jenifer Paulraj et al.

📖 [SafeGenBench: A Benchmark Framework for Security Vulnerability Detection in LLM-Generated Code](https://arxiv.org/abs/2506.05692) — 558 tasks, 44 CWEs, 13 languages; zero-shot secure accuracy ~37%, ~61% with security prompts, ~74% with few-shot. Reasoning models (o3, DeepSeek-R1) lead; memory safety best, insecure configuration worst.

📖 [Red Teaming AI Red Teaming](https://arxiv.org/pdf/2507.05538v1) — Critical look at AI red teaming’s evolution and practice. By Subhabrata Majumdar, Brian Pendleton, Abhishek Gupta.

📖 [From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agent Workflows](https://arxiv.org/abs/2506.23260) — Unified threat model spanning input manipulation, model compromise, system/privacy attacks, and protocol exploits (MCP/ACP/A2A); discusses defenses and open challenges. By Mohamed Amine Ferrag et al.

📖 [Vulnerability Detection Model using LLM and Code Chunk](https://arxiv.org/pdf/2506.19453) — Targets function-level vuln localization to mitigate OSS supply-chain risk; addresses difficulty of identifying true fixes amid unrelated patches. By Sajal Halder, Muhammad Ejaz Ahmed, Seyit A. Camtepe.

📖 [Trivial Trojans: How Minimal MCP Servers Enable Cross-Tool Exfiltration of Sensitive Data](https://arxiv.org/abs/2507.19880) — PoC shows a benign-looking “weather” MCP server can discover/abuse banking tools to exfiltrate account balances, exploiting MCP trust model. By Nicola Croce, Tobin South.

📖 [Security Challenges in AI Agent Deployment: Insights from a Large-Scale Public Competition](https://arxiv.org/abs/2507.20526) — Results from the largest public red-teaming of 22 frontier agents across 44 scenarios: 1.8M prompt-injection attempts, 60k+ policy violations; high transferability; most agents violate policies within 10–100 queries. Introduces the ART benchmark. By Andy Zou et al.

📖 [BAXBENCH: Can LLMs Generate Correct and Secure Backends?](https://arxiv.org/pdf/2502.11844) — PDF of the BaxBench paper above for direct access.

## 🎥 Videos - [Playlist](https://www.youtube.com/playlist?list=PLFO56KBxdGBfcknOAnHJFYlld2FoLsbre)

1️⃣ [The Rise of Agents: Building Agentic Workflows for Security Operation – Roberto Rodriguez](https://www.youtube.com/watch?v=zoAPS1gsmUA&ab_channel=x33fcon)  
2️⃣ [Harbinger: An AI-Powered Red Teaming Platform – Matthijs Gielen & Idan Ron](https://www.youtube.com/watch?v=8W8cIvHyCaQ&ab_channel=x33fcon)  
3️⃣ [AI Second – Threat Centric Agentic Approach on Vulnerabilities – Francesco Cipollone](https://www.youtube.com/watch?v=mHFKG9KLybk&ab_channel=OWASPLondon)  
4️⃣ [Is an AI really the top hacker in the US right now? – Matt Johansen](https://www.youtube.com/watch?v=lC2Ornloj24&ab_channel=MattJohansen)  
5️⃣ [Harnessing AI for Offensive Security – Ads Dawson](https://www.youtube.com/watch?v=Xb_o_hVNm0E&ab_channel=OWASPAtlanta)  
6️⃣ [Agentic AI and Security – David Hoelzer](https://www.youtube.com/watch?v=vA8Q5465HU4&ab_channel=SANSCyberDefense)  
7️⃣ [When AI Goes Awry: Responding to AI Incidents – Eoin Wickens & Marta J.](https://www.youtube.com/watch?v=jaJWjHS1jkI&ab_channel=SecurityBSidesSanFrancisco)  
8️⃣ [AI Red Teaming 101 (Episodes 1–10) – Amanda Minnich, Gary L., Nina C.](https://www.youtube.com/watch?v=DwFVhFdD2fs&ab_channel=MicrosoftDeveloper)  
9️⃣ [One Search To Rule Them All: Threat Modelling AI Search – Kane N.](https://www.youtube.com/watch?v=ezCHPXP8eUo&ab_channel=SecurityBSidesSanFrancisco)  
🔟 [Securing AI Agents: Threats and Exploitation Techniques – Naveen Konrajankuppam Mahavishnu & Mohankumar Vengatachalam](https://www.youtube.com/watch?v=NWpP_nAA4Do&ab_channel=SecurityBSidesSanFrancisco)  
1️⃣1️⃣ [Secure Vibe Coding: 5 Key Lessons – Matt Brown](https://www.youtube.com/watch?v=O6jbzMOUvVs&ab_channel=OWASPToronto)  
1️⃣2️⃣ [Building Security into AI – Robert Herbig](https://www.youtube.com/watch?v=0xah5jMflcI&ab_channel=freeCodeCamp.org)  
1️⃣3️⃣ [BSidesSF 2025 – AI's Bitter Lesson for SOCs – Jackie Bow & Peter Sanford](https://www.youtube.com/watch?v=JRvQGRqMazA&ab_channel=SecurityBSidesSanFrancisco)  
1️⃣4️⃣ [Let's Talk About the AI Apocalypse – Dylan Ayrey](https://www.youtube.com/watch?v=_ds6ybvH52M&ab_channel=SecurityBSidesSanFrancisco)  



