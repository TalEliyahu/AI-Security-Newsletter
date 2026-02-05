# AI Security Newsletter - January 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

---

# 🔍 Insights

📌 [ZombieAgent: New ChatGPT Vulnerabilities Let Data Theft Continue and Spread](https://www.radware.com/blog/threat-intelligence/zombieagent/)  
Radware's Zvika Babo breaks down "ZombieAgent" abuse paths where prompt injection + agent memory / tool access / connectors enable persistent data exposure, lateral spread across sessions, and follow-on abuse through connected apps and agent workflows.

📌 [OWASP AI Security Guide](https://owaspai.org)  
Free access to 300+ pages of practical guidance on protecting AI and data-centric systems - as contributed to the AI Act and ISO 27090 through a unique liaison partnership.

📌 [Personal AI Agents like Moltbot Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-moltbot-are-a-security-nightmare)  
Amy Chang and Vineeth Sai Narajala explain why Moltbot's "skills" model is dangerous: it can execute local commands, touch files, and leak credentials, and malicious skills can hide prompt-injection and data-exfiltration steps - so Cisco released the open-source Skill Scanner to flag risky skill content before it's installed.

📌 [OWASP Agentic AI Top 10: Threats in the Wild](https://labs.lares.com/owasp-agentic-top-10)  
Raúl Redondo maps real-world agent failures to the OWASP Agentic AI Top 10, showing how prompt injection, tool misuse, insecure data flows, and weak isolation show up in practical deployments, not just theory.

📌 [Coding Agents: The Insider Threat You Installed Yourself](https://blog.securitybreak.io/coding-agents-the-insider-threat-you-installed-yourself-35644a1d5409)  
Thomas Roccia frames coding agents as "pre-installed insiders" where excessive repo access, secrets exposure, and auto-execution can turn normal dev workflows into high-impact compromise paths without classic malware delivery.

📌 [AI Security Challenges in 2026](https://hi120ki.github.io/blog/posts/20260103/)  
The year 2025 witnessed a continuous cycle of emerging and evolving AI/LLM technologies. Across the industry, various security measures for AI have been advancing. In 2026, AI adoption is expected to expand further, bringing new technologies and demanding corresponding security measures. This article reviews the major topics from 2025, breaks down the anticipated industry-wide challenges in AI Security for 2026 into concrete action items, and summarizes security measures for safely using and providing AI. - Hiroki Akamatsu

📌 [BodySnatcher: Broken Authentication and Agentic Hijacking in ServiceNow](https://appomni.com/ao-labs/bodysnatcher-agentic-ai-security-vulnerability-in-servicenow)  
AppOmni's Aaron C. details how a ServiceNow Virtual Agent API + Now Assist AI Agents flaw enabled unauthenticated impersonation using only an email address, bypassing MFA/SSO assumptions and allowing hijacked agent workflows to access data and actions as the victim.

📌 [IBM AI ("Bob") Downloads and Executes Malware](https://www.promptarmor.com/resources/ibm-ai-%28-bob-%29-downloads-and-executes-malware)  
PromptArmor walks through a concrete failure mode where prompt injection can push an agent into download + execute when users enable auto-approve / "always allow" for tool actions (even a seemingly safe one like echo), highlighting why execute chains need strict allowlists, sandboxing, and policy enforcement.

📌 [Cyber Toolkits Update: Models Are Getting Better at Finding and Exploiting Vulns on Realistic Ranges](https://red.anthropic.com/2026/cyber-toolkits-update/)  
Brian S. summarizes red-team observations that capability is shifting from toy CTFs to more realistic cyber ranges, implying higher baseline exploit discovery risk as models gain planning depth and tool proficiency.

📌 [ChainLeak: Critical AI Framework Vulnerabilities Expose Data, Enable Cloud Takeover](https://www.zafran.io/resources/chainleak-critical-ai-framework-vulnerabilities-expose-data-enable-cloud-takeover)  
Gal Zaban and Ido Shani describe Chainlit vulnerabilities where insecure defaults/misconfig and exposed interfaces can lead to cloud API key leakage and sensitive file theft (CVE-2026-22218) plus SSRF (CVE-2026-22219) - which can expand into broader cloud compromise depending on what's reachable.

📌 [Exploiting LLM Write Primitives: System Prompt Extraction When Chat Output Is Locked Down](https://www.praetorian.com/blog/exploiting-llm-write-primitives-system-prompt-extraction-when-chat-output-is-locked-down/)  
Winston H. shows how "write primitives" and constrained-output environments can still be coerced into leaking system prompts via indirect channels, formatting constraints, and output-lock bypass patterns.

📌 [The ServiceNow AI Vulnerability: What Went Wrong and How to Secure Your AI Agents](https://opena2a.org/blogs/servicenow-ai-vulnerability)  
Abdel Fane reframes the ServiceNow incident as an agent security design problem: least privilege on actions, strict tool authorization, robust identity boundaries, and continuous monitoring for anomalous agent behavior.

📌 [Reprompt: The Single-Click Microsoft Copilot Attack That Silently Steals Your Personal Data](https://www.varonis.com/blog/reprompt)  
Dolev Taler explains a "single-click" Copilot exploitation flow where crafted content triggers unsafe retrieval/disclosure behaviors, emphasizing that UX-level interactions can be enough to trigger high-impact exfiltration.

📌 [How We Found Code Execution in Anthropic's Official Git MCP Server](https://cyata.ai/blog/cyata-research-breaking-anthropics-official-mcp-server)  
Cyata's Yarden Porat details an RCE-class issue in an MCP server context, showing how "official" integrations can still expand the attack surface through input handling, plugin logic, and trust assumptions around tool servers.

📌 [Achieving Remote Code Execution on n8n Via Sandbox Escape - CVE-2026-1470 & CVE-2026-0863](https://research.jfrog.com/post/achieving-remote-code-execution-on-n8n-via-sandbox-escape/)  
Natan Nehorai describes a sandbox escape chain leading to RCE in n8n, illustrating how isolation layers fail in practice when combined with deserialization, escaping primitives, or weak boundary controls.

📌 [NI8MARE: Unauthenticated Remote Code Execution in n8n (CVE-2026-21858, CVSS 10.0)](https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858)  
Dor Attias reports an unauthenticated RCE path to full takeover of exposed n8n instances, a reminder that low-friction automation platforms become high-value targets when Internet-facing and misconfigured.

📌 [The Hidden Backdoor in Claude Code: Why Its Power Is Also Its Greatest Vulnerability](https://www.lasso.security/blog/the-hidden-backdoor-in-claude-coding-assistant)  
Or Oxenberg and Eliran Suisa argue that coding assistants amplify insider-style risk: they sit inside privileged dev contexts, touch secrets and repos, and can be influenced by poisoned context, dependencies, or instructions.

📌 [Securing Agents in Production (Agentic Runtime, #1)](https://blog.palantir.com/securing-agents-in-production-agentic-runtime-1-5191a0715240)  
Palantir outlines an "agentic runtime" mindset for production: treat agent actions like code execution, enforce policies at the action layer, record full traces, and design for containment when the model behaves unexpectedly.

📌 [KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)  
From Check Point Research, this post shows threat actors using GenAI to accelerate scripting and payload development, lowering the barrier to producing varied PowerShell backdoors and social engineering content.

📌 [Supply-Chain Risk of Agentic AI: Infecting Infrastructures via Skill Worms](https://blog.lukaszolejnik.com/supply-chain-risk-of-agentic-ai-infecting-infrastructures-via-skill-worms/)  
Lukasz Olejnik, Ph.D, LL.M discusses "skill worms" as a propagation mechanism in agent ecosystems, where compromised skills, plugins, or tool bundles can spread across organizations through reuse, marketplaces, and inherited trust.

---

# 🧰 Tools & Resources

🧰 **[skills](https://github.com/trailofbits/skills)** - Claude Code skills marketplace from Trail of Bits for security research, vuln detection, and audit workflows (includes insecure-defaults plugin for insecure defaults + hardcoded creds). ⭐️2.2k Dan Guido

🧰 **[anamnesis-release](https://github.com/SeanHeelan/anamnesis-release)** - Evaluation framework for testing how LLM agents generate exploits from bug reports under exploit mitigations. ⭐️479 Sean Heelan

🧰 **[awesome-dfir-skills](https://github.com/tsale/awesome-dfir-skills)** - Community library of DFIR skills, prompts, workflows, and helpers for faster, consistent incident response. ⭐️240 Thomas Roccia

🧰 **[Burp AI Agent](https://github.com/six2dez/burp-ai-agent)** - Burp Suite extension adding MCP tooling plus AI-assisted analysis, privacy controls, and passive/active scanning. ⭐️221 Alexis Fernández

🧰 **[vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab)** - Intentionally vulnerable MCP server implementations to learn, demo, and practice exploiting MCP flaws. ⭐️216 Riyaz Walikar

🧰 **[OpenRT](https://github.com/AI45Lab/OpenRT)** - Open-source red teaming framework for multimodal LLMs. ⭐️216

🧰 **[Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP)** - MCP server for querying Sigma, Splunk ESCU, Elastic, and KQL detection rules from one database. ⭐️173 Michael H.

🧰 **[Vulnhalla](https://github.com/cyberark/Vulnhalla)** - Runs CodeQL on GitHub databases, adds code context, and uses LLM-guided review to reduce false positives. ⭐️163

🧰 **[medusa](https://github.com/Pantheon-Security/medusa)** - AI-first security scanner with analyzers + agent rules, focused on reducing false positives and CVE detection. ⭐️122

🧰 **[a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner)** - Security scanner for Agent-to-Agent protocol implementations using static analysis, runtime monitoring, and semantic detection. ⭐️105 Vineeth Sai Narajala

🧰 **[ai_for_the_win](https://github.com/depalmar/ai_for_the_win)** - Hands-on labs for building AI security tools across ML, LLMs, RAG, DFIR, and red teaming. ⭐️72

🧰 **[GitHub Security Lab Taskflow Agent](https://github.com/GitHubSecurityLab/seclab-taskflow-agent)** - Open, collaborative framework from GitHub Security Lab for AI-assisted security research workflows. ⭐️59

🧰 **[Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner)** - Security scanner for agent skills (prompt injection, data exfil, malicious code) via rules + LLM-as-judge + behavioral dataflow; SARIF + plugins. ⭐️59 Cisco

🧰 **[MCP-Dandan](https://github.com/82ch/MCP-Dandan)** - Desktop monitoring tool that observes MCP traffic and flags threats in real time. ⭐️57

🧰 **[syd](https://github.com/Sydsec/syd)** - Air-gapped pentest assistant that analyzes scan outputs with local LLMs and RAG, no internet required. ⭐️52

🧰 **[ToolSafe](https://github.com/MurrayTom/ToolSafe)** - Safer agent tool use via step-level guardrails, monitoring, and feedback-driven reasoning. ⭐️32

🧰 **[ai-soc-agent](https://github.com/M507/ai-soc-agent)** - AI SOC investigation platform using MCP for case management, SIEM analysis, and CTI enrichment. ⭐️10

🧰 **[promptshield](https://github.com/Neural-alchemy/promptshield)** - Framework to protect LLM apps from prompt injection and jailbreaks across common providers and stacks. ⭐️4

🧰 **[mcp-fortress](https://github.com/mcp-fortress/mcp-fortress)** - MCP scanner plus runtime protection layer to detect and block unsafe MCP behavior. ⭐️2

🧰 **[promptxploit](https://github.com/Neural-alchemy/promptxploit)** - Security testing framework for finding LLM application vulnerabilities before deployment. ⭐️2

🧰 **[lockllm-npm](https://github.com/lockllm/lockllm-npm)** - Official JS/TS SDK for LockLLM runtime protection (prompt injection/hidden instructions/data exfil detection). ⭐️1

🧰 **[BlackIce](https://hub.docker.com/r/databricksruntime/blackice)** - Ready-to-run Docker image for AI security red teaming (Kali-inspired), avoids tool setup pain and dependency conflicts. ⭐️ [Databricks blog](https://databricks.com/blog/announcing-blackice-containerized-red-teaming-toolkit-ai-security-testing) | [Paper](https://arxiv.org/abs/2510.11823)

---

# 📄 Reports

📘 **[The State of Non-Human Identity and AI Security](https://www.linkedin.com/feed/update/urn:li:activity:7422210133281304576)**  
CSA Oasis survey Aug-Sep 2025 sample 383 finds orgs treat AI identities like NHIs such as service accounts, API keys, chatbots, inheriting credential sprawl and unclear ownership. Biggest gaps include 51% no clear owner, 51% over permissioned access, 49% low visibility, 46% stale or orphaned IDs. Token control lags with 16% not tracking creation and 24% needing over 24h to rotate or revoke after exposure.

📘 **[Securing Artificial Intelligence Baseline Cyber Security Requirements for AI Models and Systems](https://www.linkedin.com/feed/update/urn:li:activity:7418008087607001089)**  
European standard defining baseline cyber security requirements for AI systems including deep neural networks and generative AI. Organizes 13 principles across the lifecycle secure design, development, deployment, maintenance, end of life. Covers threat awareness, risk assessment and threat modelling, least privilege permissions, asset inventory, secure infrastructure and supply chain, documentation of data models prompts, testing, incident readiness, monitoring, updates, secure disposal.

📘 **[Deepfakes: Toolkit for Schools and Parents](https://www.linkedin.com/feed/update/urn:li:activity:7416774408511463424)**  
Hong Kong's Office of the Privacy Commissioner for Personal Data (PCPD) has published guidance on the use of an AI deepfake protection toolkit aimed at schools and parents. The guidance explains common types of deepfakes and typical scenarios involving abusive deepfakes in school settings, focusing on risks faced by students. The toolkit provides practical measures for prevention and incident response, outlining the roles of schools, parents, and students. Recommended school-level safeguards include data minimization, restricting access to personal data, and implementing general data security measures to reduce exposure to deepfake misuse.

📘 **[Securing Agentic AI](https://www.linkedin.com/feed/update/urn:li:activity:7412047391094181888)**  
CSA Singapore draft for public consultation addendum to Securing AI Systems guide targets agentic AI systems that plan and act across steps. Practical controls cover risk assessment hardening and supply chain, asset and secret hygiene, authentication authorisation, limiting agency, segmentation, secure MCP and inter agent comms, monitoring logging, human in loop, and vulnerability disclosure.

📘 **[Global Cybersecurity Outlook 2026](https://www.linkedin.com/feed/update/urn:li:activity:7416787754149171200)**  
The World Economic Forum's Global Cybersecurity Outlook 2026 report explores how accelerating AI adoption, geopolitical fragmentation and widening cyber inequity are reshaping the global risk landscape. As attacks grow faster, more complex and more unevenly distributed, organizations and governments face rising pressure to adapt amid persistent sovereignty challenges and widening capability gaps. Drawing on leaders' perspectives, the report provides actionable insights to inform strategy, investment and policy.

---

# 📅 Upcoming Conferences

## February 2026

📅 [DiCyFor & AI Security Summit (Singapore)](https://www.dicyfor.com/singapore2026) - February 10, 2026 · Singapore · Organizer: DiCyFor  
📅 [IEEE ICAIC 2026 - International Conference on AI in Cybersecurity](https://icaic.gyancity.com/) - February 18-20, 2026 · University of Houston, Houston, TX, USA · Organizer: IEEE / ICAIC

## March 2026

📅 [[un]prompted - The AI Security Practitioner Conference](https://unpromptedcon.org/) - March 3-4, 2026 · Salesforce Tower, San Francisco, CA, USA · Organizer: [un]prompted  
📅 [AI Security Summit 2026](https://events.lynx.co/ai-security-summit/) - March 10, 2026 · Check Point HQ, Tel Aviv, Israel · Organizer: Lynx Events  
📅 [DiCyFor & AI Security Summit (Bangkok)](https://www.dicyfor.com/bangkok2026) - March 11-12, 2026 · Bangkok, Thailand · Organizer: DiCyFor  
📅 [IEEE SaTML 2026 - Secure and Trustworthy Machine Learning](https://satml.org/) - March 23-25, 2026 · Munich, Germany · Organizer: IEEE SaTML

## April 2026

📅 [DiCyFor & AI Security Summit (Kuala Lumpur)](https://www.dicyfor.com/kualalumpur2026) - April 15, 2026 · Kuala Lumpur, Malaysia · Organizer: DiCyFor  
📅 [SANS AI Cybersecurity Summit 2026](https://www.sans.org/cyber-security-training-events/ai-summit-2026) - April 20-21, 2026 · Arlington, VA, USA & Virtual · Organizer: SANS Institute  
📅 [AI Security Summit @ Black Hat Asia](https://www.blackhat.com/asia-26/ai-security-summit.html) - April 22, 2026 · Marina Bay Sands, Singapore · Organizer: BlackHat

---

# 📚 Research

📖 **The Promptware Kill Chain: How Prompt Injections Gradually Evolved Into a Multi-Step Malware**  
Ben Nassi, PhD, Bruce Schneier, Oleg Brodt. [arXiv](https://arxiv.org/abs/2601.09625)

📖 **When Bots Take the Bait: Exposing and Mitigating the Emerging Social Engineering Attack in Web Automation Agent**  
Xinyi W., Hongshan Geng, Yueyue C., Mingxuan L., 静菲儿, PAN Xudong, Jiarun Dai, Baojun Liu [PDF](https://arxiv.org/pdf/2601.07263)

📖 **SecMLOps: A Comprehensive Framework for Integrating Security Throughout the Machine Learning Operations Lifecycle**  
Xinrui (Michaela) Z., Pincan Zhao, Jason Jaskolka, Heng Li, Rongxing Lu [PDF](https://arxiv.org/pdf/2601.10848)

📖 **System-level Security for Computer Use Agents**  
Hanna Foerster, Robert Mullins, Tom Blanchard, Nicolas Papernot, Kristina Nikolić, Florian Tramèr, Ilia Shumailov, 张程, Yiren Z. [PDF](https://arxiv.org/pdf/2601.09923)

📖 **Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale**  
Yi Liu, Weizhe Wang, Ruitao Feng, Yao Zhang, Guangquan Xu, Gelei Deng, Yuekang Li, Leo Zhang [PDF](https://arxiv.org/pdf/2601.10338)

📖 **FinVault: Benchmarking Financial Agent Safety in Execution-Grounded Environments**  
Zhi Yang, runguo li, 强琪琪, Jiashun Wang, 娄方淇, MENGPING LI, 程东坡, Rui Xu, Heng Lian, shuo zhang, XiaoLong Liang, Xiaoming Huang, John Wei Zheng, Zhaowei Liu, Xin Guo, Huacan Wang, RongHao Chen, Liwen ZHANG [PDF](https://arxiv.org/pdf/2601.07853)

📖 **Cybersecurity AI: A Game-Theoretic AI for Guiding Attack and Defense**  
Víctor Mayoral-Vilches, PhD, María Sanz Gómez, Francesco Balassone, Stefan Rass, Lidia Salas-Espejo, Benjamin Jablonski, Luis Javier Navarete, Maite del Mundo, Cristóbal R. J. Veas Chavez [PDF](https://arxiv.org/pdf/2601.05887)

📖 **HoneyTrap: Deceiving Large Language Model Attackers to Honeypot Traps with Resilient Multi-Agent Defense**  
Siyuan Li, Xi Lin, Jun W., Zehao Liu, Haoyu Li, 鞠天杰, Xiang Chen, jianhua liu [arXiv](https://arxiv.org/abs/2601.04034)

📖 **Multi-Agent Framework for Threat Mitigation and Resilience in AI-Based Systems**  
Armstrong Foundjem, Lionel T., Ph.D, Léuson Da Silva, Foutse Khomh [PDF](https://arxiv.org/pdf/2512.23132)

📖 **It's a TRAP! Task-Redirecting Agent Persuasion Benchmark for Web Agents**  
Karolina Korgul, Yushi Yang, Arkadiusz Drohomirecki, Piotr Błaszczyk, Will Howards, Lukas Aichberger, Chris Russell, Ethan (Philip) H. SEOW, 萧鸿业, Adel Bibi [PDF](https://arxiv.org/pdf/2512.23128)

---

# 🎥 Videos

1️⃣ When Vibe Scammers Met Vibe Hackers: Pwning PhaaS with Their Own Weapons - Chiao-Lin Yu (Steven Meow) at Trend Micro  
2️⃣ How to Build an AI Security Program from Scratch - Shannon Murphy at TrendAI  
3️⃣ Security AI Agent! Automated Penetration Testing - Loi Liang Yang  
4️⃣ AI-Generated Malware: Ireland Legalizes Spyware - Steve Gibson and Leo Laporte at TWiT  
5️⃣ AI and Its Impact on Offensive Security Roles in 2026 - Stephen Sims at Off By One Security  
6️⃣ MCP with .NET: Securely Exposing Your Data to LLMs - Callum Whyte at Bump  
7️⃣ AI Red Teaming: What Breaks, How It Breaks, and the Human Role - rez0  
8️⃣ Exploiting AI: A Case Study on Voice Biometric Penetration Testing - Skyler Tuter at TrustedSec  
9️⃣ Stochastic Garrotes: A Data-Driven Approach to LLM-Generated Malware - Ryan Ashley at IQT Labs  
🔟 Backdooring LLMs and Bypassing HuggingFace Malware Scanners - Davide Cioccia at DCODX  
1️⃣1️⃣ Building a Practical AI Assistant for Security Operations - Vincent Ruijter at Sourcegraph  
1️⃣2️⃣ GenAI Agentic Security in Practice - Black Hat Europe AI Summit  
1️⃣3️⃣ The AI Triple Security Gap: Why Your Gateway Strategy Is Already Obsolete - Carlos Villanúa Fernández at Traefik Labs  
1️⃣4️⃣ The Three Horsemen of the AppSec AI-pocalypse - Adam Krieger at Online Business Systems  
1️⃣5️⃣ Practical Automation of Penetration Testing with Agentic AI - Hiroaki Toyota at LAC  
1️⃣6️⃣ Building Secure AI Applications with the OWASP Top 10 - Gavin Klondike at GlitchSecure  
1️⃣7️⃣ AI Agents with Gemini 2.0: Beyond the Chatbot - Márton Kodok at Google  
1️⃣8️⃣ Why Should We Be Careful with AI? - Maciej Krzysica at j-labs  
1️⃣9️⃣ Panel: The Present and Future of AI and Security - David Brumley and panel  
2️⃣0️⃣ Governance and Security of APIs and MCPs - Isabelle Mauny at WSO2  
2️⃣1️⃣ How I Used and Abused LLMs to Get Top 250 on HTB - Rambo Anderson-You  
2️⃣2️⃣ Securing the AI Revolution - François  
2️⃣3️⃣ MCP: Making Compromise Possible - AI Workflows and Security Implications - Nathan Getty at Menlo Security  
2️⃣4️⃣ AI Is Undermining Our Privacy: What Can We Do About It? - Robert Stribley at Technique

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.

