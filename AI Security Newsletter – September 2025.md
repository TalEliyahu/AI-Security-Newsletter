# AI Security Newsletter - September 2025

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AI Security community](https://linktr.ee/AISECHUB) on [Twitter](https://x.com/AISecHub) and the [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory, Innovate and Invest with Confidence, Lead with Assurance.

# 🔍 Insights
📌 [Bypassing AI Agent Defenses With Lies-In-The-Loop](https://checkmarx.com/zero-post/bypassing-ai-agent-defenses-with-lies-in-the-loop/) - Ori Ron (Checkmarx Zero) identifies “lies-in-the-loop” that persuades users to grant dangerous agent permissions by shaping the AI’s safety narrative.  
📌 [Rogue AI Agents In Your SOCs and SIEMs - Indirect Prompt Injection via Log Files](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rogue-ai-agents-in-your-socs-and-siems-indirect-prompt-injection-via-log-files/) - Tom Neaves (Trustwave, a LevelBlue company) shows how log-file payloads can coerce SOC agents to hide, alter, or fabricate events and pivot when over-privileged.  
📌 [New Invisible Attack Creates Parallel Poisoned Web Only for AI Agents](https://jfrog.com/blog/parallel-poison-web-for-ai-agents/) - Shaked Zychlinski (JFrog) demonstrates AI-only cloaking that serves benign pages to humans and malicious content to autonomous agents.  
📌 [Cyberspike Villager - Cobalt Strike's AI-native Successor](https://www.straiker.ai/blog/cyberspike-villager-cobalt-strike-ai-native-successor) - Straiker profiles “Villager,” a Chinese AI-powered framework that automates intrusion workflows.  
📌 [The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/) - Unit 42 analyzes IDE-integrated assistants enabling backdoors, data leaks, and harmful code via chat, autocomplete, and unit tests.  
📌 [ShadowLeak: A Zero-Click, Service-Side Attack Exfiltrating Sensitive Data Using ChatGPT's Deep Research Agent](https://www.radware.com/blog/threat-intelligence/shadowleak/) - Radware documents zero-click agent hijacking and exfiltration through Deep Research.  
📌 [Automated Patch Diff Analysis using LLMs](https://blog.syss.com/posts/automated-patch-diff-analysis-using-llms/) - SySS pipelines binary diffs into LLM scoring and summaries to speed triage on patch days.  
📌 [A Security Engineer's Guide to MCP + Security Cheatsheet](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/) - Semgrep's MCP primer covering attack surface, safe testing, and hardening patterns.  
📌 [Build secure network architectures for generative AI applications using AWS services - Part 5](https://aws.amazon.com/blogs/security/build-secure-network-architectures-for-generative-ai-applications-using-aws-services/) - Defense-in-depth for GenAI workloads across VPC, firewalls, application and edge layers.  
📌 [Open Repo, Get Pwned (Cursor RCE)](https://pages.oasis.security/rs/106-PZV-596/images/cursor-workspace-trust-autorum-rce.pdf) - Oasis Security shows Cursor's default workspace trust enables hidden autorun tasks that execute on folder open.  
📌 [From Deepfakes to Dark LLMs: 5 use-cases of how AI is Powering Cybercrime](https://www.group-ib.com/blog/ai-cybercrime-usecases/) - Group-IB breaks down AI phishing, voice cloning, deepfakes, and “Dark LLMs”.  
📌 [Detecting Exposed LLM Servers: A Shodan Case Study on Ollama](https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama) - Cisco Security finds 1,100+ exposed Ollama servers and urges baseline hardening.  
📌 [The Ongoing Fallout from a Breach at AI Chatbot Maker Salesloft](https://krebsonsecurity.com/2025/09/the-ongoing-fallout-from-a-breach-at-ai-chatbot-maker-salesloft/) - Krebs details token theft impacting hundreds of integrated services.  
📌 [Prompt-injecting the United Airlines bot to reach a human](https://x.com/itsandrewgao/status/1964117887943094633) - Andrew Gao demonstrates prompt injection to escalate to a human agent.  
📌 [Hexstrike-AI: When LLMs Meet Zero-Day Exploitation](https://blog.checkpoint.com/executive-insights/hexstrike-ai-when-llms-meet-zero-day-exploitation/) - Check Point tracks dark-web chatter on orchestrated zero-day exploitation using HexStrike-AI.  
📌 [Hackers threaten to turn stolen art into AI training data](https://www.politico.com/newsletters/weekly-cybersecurity/2025/09/08/hackers-threaten-to-turn-stolen-art-into-ai-training-data-00549940) - Ransom group targets Artists&Clients and threatens dataset training with stolen art.  
📌 [How Three New Gemini Vulnerabilities in Cloud Assist, Search Model, and Browsing Allowed Private Data Exfiltration](https://www.tenable.com/blog/the-trifecta-how-three-new-gemini-vulnerabilities-in-cloud-assist-search-model-and-browsing) - Tenable's Liv Matan analyzes three Gemini exfiltration vectors.  
📌 [How AI-Native Development Platforms Enable Fake Captcha Pages](https://www.trendmicro.com/en_us/research/25/i/ai-development-platforms-enable-fake-captcha-pages.html) - Trend Micro on phishing campaigns abusing modern hosting platforms.  
📌 [AI Reasoning Leakage Vulnerability: Self-betrayal attack (MBZUAI G42 K2 Think)](https://adversa.ai/ai-reasoning-leakage-vulnerability-uae-mbzuai-g42-k2-think-jailbreak/) - Adversa shows iterative jailbreaks via leaked reasoning traces.  
📌 [EvilAI Operators Use AI-Generated Code and Fake Apps for Far-Reaching Attacks](https://www.trendmicro.com/en_us/research/25/i/evilai.html) - Trend Micro on signed, polished fake AI tools distributing malware.  
📌 [AI-Powered App Exposes User Data, Creates Risk of Supply Chain Attacks](https://www.trendmicro.com/en_us/research/25/i/ai-powered-app-exposes-user-data.html) - Attackers can pivot into model or binary tampering and malicious updates.  
📌 [ForcedLeak: AI Agent risks exposed in Salesforce AgentForce](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce/) - Noma Security reports a CVSS 9.4 indirect prompt-injection chain enabling CRM exfiltration.  
📌 [Admin-style jailbreak prompt](https://www.linkedin.com/feed/update/urn:li:activity:7376238154787364864/) - Greg Isenberg and Cameron Mattis share an instruction-injection pattern to override guardrails - see also [X post](https://x.com/gregisenberg/status/1970547792520110158).  
📌 [Enabling AI adoption at scale through ERMF (Parts 1-2)](https://aws.amazon.com/blogs/security/enabling-ai-adoption-at-scale-through-enterprise-risk-management-framework-part-1/) - AWS outlines enterprise risk governance for AI - see also [Part 2](https://aws.amazon.com/blogs/security/enabling-ai-adoption-at-scale-through-enterprise-risk-management-framework-part-2/).  
📌 [Malicious MCP in the Wild: The Postmark Backdoor That's Stealing Your Emails](https://koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft) - Koi on the `postmark-mcp` npm package quietly exfiltrating emails since v1.0.16.  
📌 [Agentic AI Security: The New Battleground](https://substack.com/home/post/p-173772725) - Ken Huang summarizes 2025 acquisitions: Check Point-Lakera, SentinelOne-Prompt Security, Snyk-Invariant Labs, CrowdStrike-Pangea, Cato-Aim, Palo Alto-Protect AI, Tenable-Apex, F5-CalypsoAI and F5-Fletch, Zscaler-Red Canary.  
📌 [AI SOC Shift Left and Shift Right!](https://www.cybersec-automation.com/p/ai-soc-shift-left-and-shift-right) - Filip Stojkovski on shifting guardrails across the AI SOC lifecycle.  
📌 [MCP Tools: Attack Vectors and Defense Recommendations for Autonomous Agents](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations) - Elastic maps tool exploitation paths and hardening guidance.  
📌 [Modeling Attacks on AI-Powered Apps with the AI Kill Chain Framework](https://developer.nvidia.com/blog/modeling-attacks-on-ai-powered-apps-with-the-ai-kill-chain-framework/) - Rich Harang (NVIDIA) introduces an AI-specific kill chain for attacks against AI systems.  
📌 [MCP Security Top 25 Vulnerabilities - Summary Table](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/) - Adversa's canonical mapping of MCP risks for adopters.

# 📄 Reports
📘 [MLOps Overview](https://www.linkedin.com/feed/update/urn:li:activity:7366954293167325186) - CSA on extending DevSecOps to MLOps, LLMOps, and AgentOps and addressing novel threats.  
📘 [Cyber Risks Associated with Deepfakes](https://www.linkedin.com/feed/update/urn:li:activity:7376133159869939712) - Monetary Authority of Singapore on biometric bypass, social engineering, and mitigation.  
📘 [ATLANTIS: AI-driven Threat Localization, Analysis, and Triage Intelligence System](https://www.linkedin.com/feed/update/urn:li:activity:7375633200221655041) - Team Atlanta's AIxCC-winning CRS combining symex, directed fuzzing, static analysis, and LLMs.  
📘 [OWASP GenAI Security Project - Threat Defense COMPASS RunBook](https://www.linkedin.com/feed/update/urn:li:activity:7373801517017001984) - Threat, vulnerability, mitigation dashboard and method for enterprise AI programs.  
📘 [CyberSOCEval - Benchmarking LLMs for Malware Analysis and Threat Intel Reasoning](https://www.linkedin.com/feed/update/urn:li:activity:7373570303358193664) - Evaluation suite focused on SOC-relevant tasks.  
📘 [An autonomous AI hacker that hides inside a USB cable](https://palisaderesearch.org/assets/reports/hacking-cable-report.pdf) - Cable-resident agent explores hosts, maps connections, and exfiltrates data.  
📘 [80% of Ransomware Attacks are AI-Driven](https://www.linkedin.com/feed/update/urn:li:activity:7371289074898366464) - MIT Sloan and Safe Security analyze 2,800 incidents and AI’s growing role.  
📘 [Analyzing Log Data with AI Models to Meet Zero Trust Principles](https://www.linkedin.com/feed/update/urn:li:activity:7377724937509195776) - Event correlation, predictive analytics, and federated learning for detection and IR.  
📘 [DoD Artificial Intelligence Cybersecurity Risk Management Tailoring Guide](https://www.linkedin.com/feed/update/urn:li:activity:7369526869118906369) - Tailoring aligned to DoDI 8500.01, DoDI 8510.01, and EO 13800.

# 📅 Upcoming Events
To view all 2025 events: https://medium.com/ai-security-hub/top-ai-security-events-28ee7eb4d79c

📅 The AI Summit at Security Education Conference Toronto (SecTor) 2025 - **September 30, 2025** | MTCC, Toronto, Ontario, Canada | https://www.blackhat.com/sector/2025/ai-summit.html | Black Hat Events | Security Education Conference Toronto (SecTor)  
📅 Offensive AI Con - **October 5-8, 2025** | Oceanside (San Diego), CA, USA | https://www.offensiveaicon.com/ | Offensive AI Con  
📅 AI Agent Security Summit - **October 8, 2025** | Commonwealth Club, San Francisco, CA, USA | https://zenity.io/resources/events/ai-agent-security-summit-2025 | Zenity  
📅 AI Village @ c0c0n - **October 10-11, 2025** | Grand Hyatt, Kochi, India | https://c0c0n.org/AI-village | AI Village | c0c0n  
📅 GameSec 2025 - Game Theory & AI for Security - **October 13-15, 2025** | Athens, Greece | https://www.gamesec-conf.org/  
📅 AI Village @ Swiss Cyber Storm - **October 28, 2025** | Kursaal Bern, Switzerland | https://www.swisscyberstorm.com/ai-village/ | Swiss Cyber Storm  
📅 IAPP Privacy. Security. Risk. 2025 - **October 30-31, 2025** | San Diego, CA, USA | https://iapp.org/conference/iapp-privacy-security-risk/ | IAPP  
📅 SANS Fall Cyber Solutions Fest - AI Track - **November 6, 2025 (8:00 AM-4:00 PM EST)** | Virtual | https://www.sans.org/webcasts/fall-cyber-solutions-fest-2025-ai-track | SANS Institute  
📅 AI Security Summit 2025 - **November 12-13, 2025** | London, UK | https://www.securitysummit.ai/ | AI Security Summit 2025  
📅 NHI Global Summit - Tackling NHI in the World of Agentic AI - **November 13, 2025** | Searcys at The Gherkin, London, UK | https://nhimg.org/nhi-global-summit-london | NHI Mgmt Group | Entro Security  
📅 AI Security Summit @ Black Hat Europe - **December 9, 2025** | ExCeL London, UK | https://www.blackhat.com/eu-25/ai-summit.html | Black Hat  
📅 AI Hacking Village @ BSidesTLV - **December 11, 2025** | Tel Aviv University, Tel Aviv, Israel | https://bsidestlv.com/ | BSidesTLV

# 📚 Research
📖 [Comparing Model- vs Agentic-Level Red Teaming with Action-Graph Observability on GPT-OSS-20B](https://www.arxiv.org/pdf/2509.17259) - Agent behavior depends on planning, chain-of-thought, tools, and environment, creating distinct agent-level vulnerabilities.  
📖 [Toward Stealthy Bit-Flip Attacks on Large Language Models (SilentStriker)](https://arxiv.org/pdf/2509.17371) - Bit-flip attack degrades performance while maintaining naturalness via token-targeted loss.  
📖 [Vulnerabilities of LLM-Integrated XR Systems](https://arxiv.org/pdf/2509.15213) - Systematization of XR-LLM pipelines and their attack surfaces.  
📖 [Stress Testing Deliberative Alignment for Anti-Scheming Training](https://arxiv.org/pdf/2509.15541) - Probes for misaligned goal pursuit and deceptive behavior.  
📖 [CyberSOCEval - Benchmarking LLMs Capabilities for Malware Analysis and Threat Intelligence Reasoning](https://arxiv.org/pdf/2509.20166) - SOC-centric evaluations for operational usefulness.  
📖 [Backdoor Attribution: Elucidating and Controlling Backdoor in Language Models](https://arxiv.org/pdf/2509.21761) - BkdAttr and BAHA reveal and localize backdoor features and attention heads.  
📖 [xOffense - AI-driven Autonomous Penetration Testing with Multi-Agent Systems](https://arxiv.org/abs/2509.13021) - Knowledge-enhanced multi-agent penetration testing workflows.  
📖 [Evaluating LLM-Generated Detection Rules in Cybersecurity](https://arxiv.org/abs/2509.16749) - Holdout-based benchmark comparing LLM-authored rules to expert baselines.  
📖 [A Systematic Evaluation of Parameter-Efficient Fine-Tuning Methods for the Security of Code LLMs](https://arxiv.org/pdf/2509.12649v1) - Prompt-tuning raises secure-code rate on CodeGen2 16B to 80.86 percent.  
📖 [When MCP Servers Attack - Taxonomy, Feasibility, and Mitigation](https://arxiv.org/abs/2509.24272) - Component-based taxonomy with 12 attack categories and cross host-LLM evaluations plus mitigations.  
📖 [Your AI, My Shell - Demystifying Prompt Injection Attacks on Agentic AI Coding Editors](https://arxiv.org/pdf/2509.2204) - Editors with terminal and file access introduce new exploitation paths.  
📖 [LLM-based Vulnerability Discovery through the Lens of Code Metrics](https://www.arxiv.org/abs/2509.19117) - Simple syntactic metrics rival state-of-the-art LLMs for vulnerability discovery.  
📖 [Enterprise AI Must Enforce Participant-Aware Access Control](https://arxiv.org/abs/2509.14608) - Without participant-aware access enforcement, RAG and fine-tuning can leak sensitive data.

# 🧰 Tools & Resources
🧰 [fickling](https://github.com/trailofbits/fickling) - Python pickling decompiler and static analyzer - ⭐️560  
🧰 [GhidraGPT](https://github.com/ZeroDaysBroker/GhidraGPT) - GPT integration for Ghidra for analysis, renaming, and vulnerability detection - ⭐️67  
🧰 [strix](https://github.com/usestrix/strix) - Autonomous agents that dynamically run code to find and validate vulnerabilities - ⭐️1,600  
🧰 [DeepSeek Pentest AI - Burp Suite](https://github.com/HernanRodriguez1/DeepSeek-Pentest-AI) - Generative AI plus smart fuzzing for web vulnerability testing - ⭐️39  
🧰 [100 n8n Cybersecurity Workflow Ideas](https://github.com/CyberSecurityUP/n8n-CyberSecurity-Workflows) - Cookbook of flows, nodes, and integrations - ⭐️107  
🧰 [indexleak-scanner](https://github.com/riza/indexleak-scanner) - MCP server to discover exposed directory listings - ⭐️31  
🧰 [ai-security-shared-responsibility](https://github.com/mikeprivette/ai-security-shared-responsibility) - Responsibility mapping across 8 deployment models and 16 domains - ⭐️30  
🧰 [proximity](https://github.com/fr0gger/proximity) - NOVA-powered MCP security scanner - ⭐️30  
🧰 [BruteForceAI](https://github.com/MorDavid/BruteForceA) - LLM-aided brute-force framework - ⭐️155  
🧰 [fuzzforge_ai](https://github.com/FuzzingLabs/fuzzforge_ai) - AI-assisted AppSec and fuzzing automation - ⭐️49

# 🎥 Videos
▶️ [Prompt. Scan. Exploit - AI's Journey Through Zero-Days And A Thousand Bugs](https://youtu.be/y_aQQmDMaY4?si=Ex7foh2RaTeHYWm0) - Joel Noguera and Diego Jurado Pallarés (XBOW)  
▶️ [AI Jailbreaking - Social Engineering for LLMs](https://www.youtube.com/watch?v=XS1pm3H_Chc) - David Willis-Owen (JPMorgan)  
▶️ [Security & AI Governance - Reducing Risks in AI Systems](https://youtu.be/4QXtObc61Lw?si=YamKU2tNiX2vmIPA) - Jeff Crume, PhD, CISSP (IBM Research)  
▶️ [New Protocol - Novel Threats - Exploring MCP's Emerging Security Risks](https://youtu.be/eD_NLTexpKk?si=LKxsVi5DWl9VuEJY) - David Melamed (Jit.io)  
▶️ [Securing AI Agent Identities](https://youtu.be/n_sZ9MWCk-g?si=Ei4XvjAdZa_FgE7N) - Itamar Apelblat (Token Security)  
▶️ [RiskRubric.ai - Standardizing LLM Risk Assessment](https://youtu.be/4cuF6TSaOu8?si=lvZps30z8bbmd9W9) - Caleb Sima (WhiteRabbit) and Michael Machado (Hyland)  
▶️ [Securing Agentic AI - The Next Frontier of Intelligent Systems](https://youtu.be/s1ApBOjRJ28?si=PSqMxbDUT5wKg9nS) - Diana Kelley (Noma Security)  
▶️ [AI Agents - Augmenting Vulnerability Analysis and Remediation](https://youtu.be/s6tU84-ZqJw?si=ThXNPoKaKopoVLUj) - Peyton Smith (Specular)  
▶️ [Utilizing AI Models to Conceal and Extract Commands in C2 Images](https://youtu.be/MoDYOm2fPJ0?si=1OCJtlfq5Ha_HH7_) - Qian Feng and Chris Navarrete (Palo Alto Networks)  
▶️ [The Pivotal Role of Large Language Models in Extracting Actionable TTP Attack Chains](https://youtu.be/7S3OSvWXP0I?si=TtBBoQ_EG3W83yBG) - Lorin Wu, Porot Mo, and Jack Tang (360 Digital Security Group)

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.

