# AI Security Newsletter - February 2026

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AISecHub community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

---

# 🔍 Insights

📌 [Evaluating and mitigating the growing risk of LLM-discovered 0-days](https://red.anthropic.com/2026/zero-days/)  
Anthropic reports that Claude Opus 4.6 found high-severity vulnerabilities in heavily tested open-source projects and says its team has validated more than 500 high-severity findings. The security relevance is clear: AI-assisted vuln discovery is moving from demos to disclosure workflow pressure, and defenders need validation, triage, and patch capacity that can keep up.

📌 [Manipulating AI memory for profit: The rise of AI Recommendation Poisoning](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/)  
Microsoft Defender researchers describe "Summarize with AI" links that hide memory-manipulation prompts in URL parameters, pushing assistants to remember a vendor as trusted or preferred. The post includes hunting ideas for security teams looking for prompt-bearing AI assistant URLs in email, Teams, proxy, and endpoint logs.

📌 [A one-prompt attack that breaks LLM safety alignment](https://www.microsoft.com/en-us/security/blog/2026/02/09/prompt-attack-breaks-llm-safety/)  
Microsoft researchers show that GRPO, a training technique normally used to improve behavior, can also push a model away from its safety alignment when the reward objective changes. This matters for model governance because downstream fine-tuning, reinforcement learning, and post-training updates can become security control changes, not only model-quality changes.

📌 [Detecting and preventing distillation attacks](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks)  
Anthropic details large-scale campaigns it attributes to DeepSeek, Moonshot AI, and MiniMax that used fraudulent accounts and proxy infrastructure to extract Claude capabilities, including agentic reasoning, tool use, coding, and computer-use development. Treat this as model supply-chain risk: capability theft can strip safeguards and accelerate offensive cyber use.

📌 [Introducing Trusted Access for Cyber](https://openai.com/index/trusted-access-for-cyber/)  
OpenAI introduced a trust-based access pilot for frontier cyber capabilities, including identity verification and enterprise access paths for defensive security work. The piece is useful because it names the hard dual-use boundary: "find vulnerabilities in my code" can mean responsible patching or attacker preparation, so access and monitoring become part of the control plane.

📌 [Protecting AI conversations at Microsoft with Model Context Protocol security and governance](https://www.microsoft.com/insidetrack/blog/protecting-ai-conversations-at-microsoft-with-model-context-protocol-security-and-governance/)  
Microsoft describes how it is governing MCP internally with approved server catalogs, API gateways, short-lived least-privilege tokens, consent gates for high-risk actions, metadata drift checks, and inventory. The practical takeaway: MCP security is not just protocol security; it is communications security across server identity, tool descriptions, data sharing, and runtime behavior.

📌 [A guide to agentic AI security](https://www.ibm.com/think/insights/agentic-ai-security)  
IBM frames AI agents as "digital insiders" and maps the security work to oversight, containment, least privilege, lifecycle data protection, and securing the action layer. Good concise framing for teams moving from chatbot controls to agents that call APIs, invoke functions, and hold credentials.

📌 [MCP Security: Understanding Vulnerabilities in Model Context Protocol](https://marmelab.com/blog/2026/02/16/mcp-security-vulnerabilities.html)  
Thibault Barrat walks through external prompt injection, tool prompt injection, and cross-tool hijacking in MCP setups, including how one malicious tool description can contaminate another tool's behavior. The strongest lesson is operational: third-party MCP servers need review, re-review after updates, and no "always allow" shortcut for sensitive actions.

📌 [Indirect Prompt Injection in MCP Tools: 10 Real Examples & Defenses](https://www.stackone.com/blog/prompt-injection-mcp-10-examples/)  
Emmanuel Delorme maps indirect injection patterns across Gmail, Salesforce, GitHub, Slack, Zendesk, Google Drive, web search, Gong, Jira, and Notion MCP-style integrations. Useful for threat modeling because the dangerous content is not in the user's prompt; it is in the business system data the agent retrieves.

📌 [From runtime risk to real-time defense: Securing AI agents](https://www.microsoft.com/en-us/security/blog/2026/01/23/runtime-risk-realtime-defense-securing-ai-agents/)  
Microsoft Defender researchers treat each agent tool invocation as a high-value event and show runtime checks blocking unsafe knowledge searches, email exfiltration, and capability reconnaissance. The post is a concrete example of moving AI security from prompt review to action-layer inspection.

---

# 🧰 Tools & Resources

🧰 **[mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)** - Scanner and proxy for MCP connections, agent skills, and AI-agent security checks, including tool call constraints, data-flow controls, PII detection, and indirect prompt-injection monitoring. ⭐️2.4k

🧰 **[agent-security-scanner-mcp](https://github.com/sinewaveai/agent-security-scanner-mcp)** - MCP server for AI coding-agent security checks, with prompt-injection firewalling, package hallucination detection, vulnerability rules, AST analysis, and taint analysis. ⭐️101

🧰 **[AgentDyn](https://github.com/leolee99/AgentDyn)** - Official benchmark implementation for testing prompt-injection defenses in dynamic, open-ended agent environments across shopping, GitHub, and daily-life scenarios. ⭐️50

🧰 **[mcp-vulnerability](https://github.com/marmelab/mcp-vulnerability)** - Educational demo code for MCP external prompt injection, tool prompt injection, and cross-tool hijacking examples from Marmelab's write-up.

🧰 **[ObliInjection](https://github.com/ReachalWang/ObliInjection)** - Code and data for the NDSS 2026 work on order-oblivious prompt injection against LLM agents that consume multi-source inputs.

🧰 **[Arcanum AI Sec Resource Hub](https://arcanum-sec.github.io/ai-sec-resources/)** - Curated hands-on AI security lab index covering prompt-injection labs, agentic challenges, bug bounty programs, and testing tools.

---

# 📄 Reports

📘 **[The State of AI Security Report 2026](https://www.cisco.com/c/en/us/products/security/state-of-ai-security.html)**  
Cisco's annual AI security report covers AI threat intelligence, policy shifts, supply-chain risk, MCP and agentic AI attack surfaces, open-weight model vulnerabilities, and related open-source defensive projects.

📘 **[Cloud and AI Security Risk Report 2026](https://www.tenable.com/press-releases/tenable-research-reveals-growing-ai-exposure-gap-fueled-by-supply-chain-risks-and-lack-of-identity-controls)**  
Tenable's report focuses on the "AI exposure gap" across applications, infrastructure, identities, agents, data, cloud, and third-party code. Findings include broad AI/MCP package adoption, critical third-party code exposure, and risky administrative permissions granted to AI services.

📘 **[Disrupting malicious uses of AI](https://openai.com/index/disrupting-malicious-ai-uses/)**  
OpenAI's February 2026 threat report shares case studies on how threat actors combine AI models with traditional infrastructure, websites, and social media accounts. Useful for defenders tracking AI misuse patterns that cross providers and platforms.

📘 **[Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)**  
NIST NCCoE concept paper on applying identity standards and authorization practices to software agents, with a focus on agentic AI applications that access diverse tools, applications, and datasets.

📘 **[Agentic Artificial Intelligence and Cyberattacks](https://www.everycrsreport.com/reports/IF13151.html)**  
Congressional Research Service overview of agentic AI and cyberattack implications, including military interest, AIxCC-style autonomous vulnerability discovery, cyber operations speed, and open policy questions.

---

# 📅 Upcoming Conferences

## March 2026

📅 [[un]prompted - The AI Security Practitioner Conference](https://unpromptedcon.org/) - March 3-4, 2026 · San Francisco, CA, USA · Organizer: [un]prompted

📅 [IEEE SaTML 2026 - Secure and Trustworthy Machine Learning](https://satml.org/) - March 23-25, 2026 · Technical University of Munich, Germany · Organizer: IEEE SaTML

## April 2026

📅 [SANS AI Cybersecurity Summit 2026](https://www.sans.org/ai-cybersecurity-summit-2026) - April 20-21, 2026 · Arlington, VA, USA & Live Online · Organizer: SANS Institute

## May 2026

📅 [AI Security Summit 2026](https://events.lynx.co/ai-security-summit/) - May 13, 2026 · Check Point HQ, Tel Aviv, Israel · Organizer: Lynx Events

## August 2026

📅 [The AI Summit at Black Hat USA 2026](https://blackhat.com/us-26/ai-summit.html) - August 4, 2026 · Mandalay Bay, Las Vegas, NV, USA · Organizer: Black Hat

## October 2026

📅 [GAISS 2026 - IEEE Conference on Generative AI for Secure Systems](https://gaiss.info/) - October 28-30, 2026 · University of Texas at Austin, Austin, TX, USA · Organizer: IEEE

---

# 📚 Research

📖 **Prompt Injection Attack to Tool Selection in LLM Agents**  
Jiawen Shi, Zenghui Yuan, Guiyao Tie, Pan Zhou, Neil Zhenqiang Gong, Lichao Sun. [NDSS 2026](https://www.ndss-symposium.org/ndss-paper/prompt-injection-attack-to-tool-selection-in-llm-agents/)

📖 **ObliInjection: Order-Oblivious Prompt Injection Attack to LLM Agents with Multi-source Data**  
Reachal Wang, Yuqi Jia, Neil Zhenqiang Gong. [NDSS 2026](https://www.ndss-symposium.org/ndss-paper/obliinjection-order-oblivious-prompt-injection-attack-to-llm-agents-with-multi-source-data/)

📖 **AgentDyn: Are Your Agent Security Defenses Deployable in Real-World Dynamic Environments?**  
Hao Li, Ruoyao Wen, Shanghao Shi, Ning Zhang, Yevgeniy Vorobeychik, Chaowei Xiao. [arXiv](https://arxiv.org/abs/2602.03117)

📖 **The Landscape of Prompt Injection Threats in LLM Agents: From Taxonomy to Analysis**  
Peiran Wang, Xinfeng Li, Chong Xiang, Jinghuai Zhang, Ying Li, Lixia Zhang, Xiaofeng Wang, Yuan Tian. [arXiv](https://arxiv.org/abs/2602.10453)

📖 **AgentSentry: Mitigating Indirect Prompt Injection in LLM Agents via Temporal Causal Diagnostics and Context Purification**  
Tian Zhang, Yiwei Xu, Juan Wang, Keyan Guo, Xiaoyang Xu, Bowen Xiao, Quanlong Guan, Jinlin Fan, Jiawei Liu, Zhiquan Liu, Hongxin Hu. [arXiv](https://arxiv.org/abs/2602.22724)

📖 **SOK: A Taxonomy of Attack Vectors and Defense Strategies for Agentic Supply Chain Runtime**  
Xiaochong Jiang, Shiqi Yang, Wenting Yang, Yichen Liu, Cheng Ji. [arXiv](https://arxiv.org/abs/2602.19555)

📖 **Human Society-Inspired Approaches to Agentic AI Security: The 4C Framework**  
Alsharif Abuadbba, Nazatul Sultan, Surya Nepal, Sanjay Jha. [arXiv](https://arxiv.org/abs/2602.01942)

📖 **LLM Scalability Risk for Agentic-AI and Model Supply Chain Security**  
Kiarash Ahi, Vaibhav Agrawal, Saeed Valizadeh. [arXiv](https://arxiv.org/abs/2602.19021)

📖 **Agentic AI for Cybersecurity: A Meta-Cognitive Architecture for Governable Autonomy**  
Andrei Kojukhov, Arkady Bovshover. [arXiv](https://arxiv.org/abs/2602.11897)

📖 **Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents**  
Narek Maloyan, Dmitry Namiot. [arXiv](https://arxiv.org/abs/2601.17549)

---

# 🎥 Videos

1️⃣ [NDSS 2026 - Prompt Injection Attack to Tool Selection in LLM Agents](https://www.youtube.com/watch?v=radUxOZ8IKY) - NDSS Symposium

2️⃣ [NDSS 2026 - ObliInjection](https://www.youtube.com/watch?v=4XEUiaJ7btw) - NDSS Symposium

3️⃣ [AI Privilege Escalation: Agentic Identity & Prompt Injection Risks](https://www.youtube.com/watch?v=xHJ0_Vm7lK8) - IBM Technology

4️⃣ [Understanding AI Agent Security: Safeguard LLM Systems Effectively](https://www.youtube.com/watch?v=SAYmsKxNDF4) - IBM Technology

5️⃣ [Zero-Trust AI Agents: Secure Microsoft Foundry Workflows](https://www.youtube.com/watch?v=bEP3upJcurQ) - Microsoft Developer

6️⃣ [become an AI HACKER (it's easier than you think)](https://www.youtube.com/watch?v=_yfiUQSbdPY) - NetworkChuck with Jason Haddix

---

# 🤝 Let's Connect
If you're a founder building something new or an investor evaluating early-stage opportunities - [let's connect](https://calendly.com/innovguard/meeting).

💬 Read something interesting? Share your thoughts in the comments.
