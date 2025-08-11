# AI Security Digest – July 2025

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AI Security community](https://linktr.ee/AISECHUB) on [Twitter](https://twitter.com) and [LinkedIn group](https://linkedin.com) for additional updates.

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
