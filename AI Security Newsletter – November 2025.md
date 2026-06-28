# AI Security Digest - October 2025

A digest of AI security research, insights, reports, upcoming events, and tools & resources. Follow the [AI Security community](https://x.com/AISecHub) and our [LinkedIn group](https://www.linkedin.com/groups/14545517/) for additional updates. Also check out our project, [Awesome AI Security](https://github.com/TalEliyahu/Awesome-AI-Security).

<p align="center">
  <a href="https://innovguard.com">
    <img src="assets/innovguard-sponsor.png" alt="InnovGuard" width="360">
  </a>
</p>

Sponsored by [InnovGuard.com](https://innovguard.com) - Technology Risk & Cybersecurity Advisory - Innovate and Invest with Confidence, Lead with Assurance.

# 🔍 Insights

📌 [AI pentest scoping playbook](https://devansh.bearblog.dev/ai-pentest-scoping/)  
AI pentesting scoped as classic web testing misses most of the real attack surface. Include model, data, RAG, integrations, agents, and infrastructure; use OWASP LLM Top 10 only as baseline; answer concrete scoping questions; and run continuous adversarial testing instead of a single pre-production check. By Devansh Batham.

📌 [Hacking Gemini: A Multi-Layered Approach](https://buganizer.cc/hacking-gemini-a-mul ti-layered-approach-md)  
Multi-layer parsing in Gemini/Colab abused via markdown sanitizer quirks, linkification, and escaping to convert links into images; bypass CSP via open redirects; evade URI prefixing; and achieve indirect prompt injection that exfiltrates Google Workspace data (Gmail, Calendar, Drive) through Gemini extensions. By Valentino Massaro.

📌 [The Agentic AI Security Scoping Matrix: A framework for securing autonomous AI systems](https://aws.amazon.com/blogs/security/the-agentic-ai-security-scoping-matrix-a-framework-for-securing-autonomous-ai-systems/)  
Maps agent systems across four scopes of agency/autonomy (read-only helpers through self-directed agents) and aligns each scope with controls for identity, data, logging, behavior boundaries, and orchestration, plus progressive deployment and oversight patterns. By Aaron Brown and Matt Saner.

📌 [The Devil Reviews Xanthorox: A Criminal-Focused Analysis of the Latest Malicious LLM Offering](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-devil-reviews-xanthorox-a-criminal-focused-analysis-of-the-latest-malicious-llm-offering)  
Xanthorox is promoted in cybercrime communities for malicious code and log parsing utilities but appears to lack internet/dark web/RAG capabilities; analysis suggests an “uncensored persona” layer over a likely Gemini Pro backend with Agentex compilation. By David Sancho, Vincenzo Ciancaglini, Salvatore Gariuolo.

📌 [Mind-reading Claude AI's Complete System Prompt](https://generativeai.pub/mind-reading-claude-ais-complete-system-prompt-bb498276fe3d)  
Abuses Anthropic’s internal `antml:` XML dialect and Claude’s `<thinking>` phase to reconstruct Claude Sonnet 4.5’s ~10k-word system prompt, exposing hidden behaviors (including safety screening, auto web search, nested tool/API behaviors), policy filters, and detailed tool/artifact rules. By Jim Nightingale.

📌 [Ollama Remote Code Execution: Securing the Code That Runs LLMs](https://www.sonarsource.com/blog/ollama-remote-code-execution-securing-the-code-that-runs-llms/)  
Ollama < 0.7.0 had a critical `std::vector<bool>` out-of-bounds write in the mllama GGUF loader enabling malicious model upload (via API access) to flip bits in function-pointer tables and build a ROP chain for RCE; the vulnerable C++ path was effectively removed in 0.7.0 when mllama was rewritten in Go. By Paul Gerste (Sonar).

📌 [EchoGram: The Hidden Vulnerability Undermining AI Guardrails](https://hiddenlayer.com/innovation-hub/echogram-the-hidden-vulnerability-undermining-ai-guardrails/)  
Guardrail-bypass technique that mines “flip tokens” (dataset distillation or tokenizer probing) and appends them to systematically flip safety classifier / judge verdicts, letting jailbreak/prompt-injection payloads pass or generating crafted false positives without modifying the downstream payload. By Kasimir Schulz, Kenneth Yeung.

📌 [PromptJacking: The Critical RCEs in Claude Desktop That Turn Questions Into Exploits](https://www.koi.ai/blog/promptjacking-the-critical-rce-in-claude-desktop-that-turn-questions-into-exploits)  
RCE in three official Claude Desktop MCP extensions (Chrome, iMessage, Apple Notes) where user-controlled data was inserted into AppleScript without proper escaping; a malicious page plus prompt injection could trigger arbitrary local code execution. Reported fixed in extension version 0.1.9. By Oren Yomtov (Koi).

📌 [SesameOp: Novel backdoor uses OpenAI Assistants API for command and control](https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/)  
.NET backdoor abuses the OpenAI Assistants API as C2, pulling encrypted tasks from assistants/vector stores, executing them on compromised hosts, and posting results back—enabling long-term operations without traditional attacker infrastructure. (Microsoft)

📌 [Leveraging Generative AI to Reverse Engineer XLoader](#)  
GPT-5-level models compress XLoader reverse engineering into an hours-scale workflow by unpacking layers, recovering RC4 decryptors, automating API/string deobfuscation, and extracting C2 domains, while still needing humans for edge cases and robust scripts. By Alexey Bukhteyev.  
> Replace `#` with the original URL you used for this item.

📌 [When GPTs Call Home: Exploiting SSRF in ChatGPT's Custom Actions](https://sirleeroyjenkins.medium.com/when-gpts-call-home-exploiting-ssrf-in-chatgpts-custom-actions-5df9df27dbe9)  
Turns Custom GPT Actions into an SSRF primitive via 302 redirects and header handling to reach Azure IMDS, steal a management token, and call Azure management APIs from within the execution environment (responsibly disclosed). By Jacob Krut (Open Security, Inc.).

📌 [Ransomvibing appears in VS Code extensions](https://secureannex.com/blog/ransomvibe/)  
“Vibe-coded” ransomware-style VS Code extension on the official Marketplace encrypts a staging directory, uploads data to a GitHub-based C2, ships hardcoded decryptors/keys, and exposes gaps in extension review for catching obvious malware. By John Tuckner (Secure Annex).

📌 [Reimagining Fraud Operations](#)  
Trend Micro research replicated an AI-powered scam “assembly line” showing how GenAI reduces barrier-to-entry for fraud, improves scale, and complicates detection. By Roel Reyes, Numaan H., Salvatore Gariuolo.  
> Replace `#` with the original URL for this item.

📌 [Whisper Leak: A novel side-channel attack on remote language models](https://www.microsoft.com/en-us/security/blog/2025/11/07/whisper-leak-a-novel-side-channel-cyberattack-on-remote-language-models/)  
Side-channel on streaming LMs where packet sizes/timing allow inference of conversation topics despite TLS; discusses obfuscation/padding defenses rolled out by providers. (Microsoft Defender Research)

📌 [HackedGPT: Novel AI Vulnerabilities Open the Door for Private Data Leakage](https://www.tenable.com/blog/hackedgpt-novel-ai-vulnerabilities-open-the-door-for-private-data-leakage)  
Chains multiple issues (including search-based prompt injection, URL handling quirks, markdown hiding, and memory injection) into practical attacks that can exfiltrate private chat history and persist across sessions. By Moshe Bernstein and Liv Matan (Tenable).

📌 [SupaPwn: Hacking Our Way into Lovable's Office and Helping Secure Supabase](https://www.hacktron.ai/blog/supapwn)  
Exploit chain in deprecated Supabase cloud infrastructure enabling tenant breakout to Postgres superuser and deeper host/orchestration access; uses Hacktron CLI to automate recon, PoC generation, and exploit development, enabling rapid patching. By Christo Butcher, Harsh Bothra, Zayne Korber, and LiveOverflow (Hacktron).

📌 [ShadowRay 2.0: Attackers Turn AI Against Itself in Global Campaign that Hijacks AI Into Self-Propagating Botnet](https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet)  
Abuses exposed Ray clusters and disputed CVE-2023-48022 behavior to build a self-propagating cryptomining/DDoS botnet with region-aware payload updates, miner-killing, GPU hiding, and potential data/model theft from live AI workloads. By Avi Lumelsky and Gal Elbaz (Oligo).

📌 [From Deepfake Scams to Poisoned Chatbots: AI and Election Security in 2025](https://cetas.turing.ac.uk/publications/deepfake-scams-poisoned-chatbots)  
Covers deepfake-driven scams, voter suppression/disinformation, synthetic campaign content, and chatbot data poisoning in 2025 elections; argues 2026 defenses need provenance/watermarking, stronger coordination, policy red lines, ad rules, anti-poisoning measures, and joint exercises. By Sam Stockwell.

📌 [AIKatz - All Your Chats Are Belong To Us](https://www.lumia.security/blog/aikatz)  
Technique targeting Chromium-based desktop AI apps to extract auth tokens, read/delete chats, plant persistent memories, hijack conversations, and potentially cross user boundaries via DLL/path abuse; positions it as a local attack class that still matters for enterprise endpoints. By Stiv Kupchik.

📌 [ShadowMQ: How Code Reuse Spread Critical Vulnerabilities Across the AI Ecosystem](https://www.oligo.security/blog/shadowmq-how-code-reuse-spread-critical-vulnerabilities-across-the-ai-ecosystem)  
Unsafe ZeroMQ + Python pickle patterns reused across multiple inference stacks created a class of RCE bugs; emphasizes urgent patching plus deeper runtime visibility into ZMQ/pickle behavior in production. By Avi Lumelsky (Oligo).

📌 [Comet's MCP API Allows AI Browsers to Execute Local Commands](https://labs.sqrx.com/comet-mcp-api-allows-ai-browsers-to-execute-local-commands-dec185fb524b)  
Perplexity Comet shipped hidden embedded extensions with an undocumented MCP API enabling arbitrary local command execution, breaking browser sandbox assumptions and enabling full endpoint compromise if abused. (SquareX Labs)

📌 [Using MCP for Debugging, Reversing, and Threat Analysis: Part 2](https://whiteknightlabs.com/2025/11/18/using-mcp-for-debugging-reversing-and-threat-analysis-part-2/)  
Extends mcp-windbg from crash-dump analysis to live Windows kernel debugging with `kd.exe`, hits limits around programmatic break-in, and argues DbgEng COM is the long-term path for LLM-driven kernel debugging/reversing workflows. (White Knight Labs)

📌 [When AI Agents Go Rogue: Agent Session Smuggling Attack in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)  
Attack technique where a malicious agent exploits an established cross-agent session to send covert instructions to a victim agent. By Jay Chen and Chien-Hua (Royce) Lu (Unit 42).

📌 [The Big Idea: Security Assurance is NOT Just QA for AI!](https://security.googlecloudcommunity.com/ciso-blog-77/the-big-idea-security-assurance-is-not-just-qa-for-ai-6139)  
Argues security assurance for AI is not traditional QA; it must connect vuln management, threat intelligence, detection/response, and red teaming into a continuous production program. By Anton Chuvakin.

📌 [Lights, Camera… Leakage: When the System Prompt Crashes the Scene](https://mindgard.ai/blog/extracting-sora-system-prompt)  
Describes cross-modal prompting against Sora to reconstruct hidden system prompt behavior via leakage across output channels; urges treating system prompts as sensitive configuration and testing each modality/channel for prompt-exfil risks. (Mindgard)

# 🧰 Tools & Resources

🧰 [Hacx-GPT](https://github.com/BlackTechX011/Hacx-GPT)  
Hacx GPT, “evil brother of WormGPT.” ⭐️533 — Ikko Ashimine.

🧰 [awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills)  
Curated Claude Skills collection with Security & Systems section (web fuzzing, MCP hardening, security automation). ⭐️5.5k — Composio (Prathit Joshi, Evyatar Bluzer, Vladislav Goncharov, Hong Cing Chen).

🧰 [IoT HackBot](https://github.com/BrownFineSecurity/iothackbot)  
IoT security toolkit combining Python CLI tools and Claude Code skills for discovery, firmware analysis, and exploitation-focused testing. ⭐️339 — Matt Brown (Brown Fine Security).

🧰 [PatchEval](https://github.com/bytedance/PatchEval)  
Benchmark for evaluating LLMs/agents on patching real-world vulns using Dockerized CVE testbeds and automated patch validation. ⭐️138 — Jun Zeng, Zichao Wei, Shiqi Zhou.

🧰 [raptor](https://github.com/gadievron/raptor)  
Turns Claude Code into a general-purpose offensive/defensive security agent via rules, sub-agents, and skills. ⭐️124 — Daniel Cuthbert, Thomas Dullien, Michael Bargury, Gadi Evron.

🧰 [VulnRisk](https://github.com/GurkhaShieldForce/VulnRisk_Public)  
Open-source vulnerability risk assessment platform providing context-aware scoring beyond CVSS. ⭐️84 — Swamynathan Arunachalam (GURKHA SHIELDS SECURITY LIMITED).

🧰 [Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server)  
Exposes Wazuh SIEM/EDR telemetry via MCP so agents can run hunting/response playbooks against real data. ⭐️83 — Robert McDonald (GensecAI).

🧰 [mcp-checkpoint](https://github.com/aira-security/mcp-checkpoint)  
Continuous MCP monitoring with static/dynamic scans for risks in agent-tool communications. ⭐️81 — Aira Security.

🧰 [ai-reverse-engineering](https://github.com/biniamf/ai-reverse-engineering)  
AI-assisted reverse engineering with an MCP-driven chat interface orchestrating Ghidra. ⭐️42 — Biniam F. Demissie (Technology Innovation Institute).

🧰 [whisper_leak](https://github.com/yo-yo-yo-jbo/whisper_leak)  
Toolkit demonstrating prompt inference via packet sizes/timing for encrypted streaming LLM traffic. ⭐️42 — Jonathan Bar Or.

🧰 [AI / LLM Red Team Field Manual & Consultant’s Handbook](https://github.com/Shiva108/ai-llm-red-team-handbook)  
Red-team playbook with prompts, RoE/SOW templates, OWASP/MITRE mappings, and testing workflows. ⭐️26 — Thor Kristiansen.

🧰 [LLMGoat](https://github.com/SECFORCE/LLMGoat)  
Deliberately vulnerable LLM lab for practicing OWASP Top 10 LLM vulnerabilities. ⭐️36 — SECFORCE LTD.

🧰 [Reversecore_MCP](https://github.com/sjkim1127/Reversecore_MCP)  
Security-first MCP server enabling orchestration of Ghidra/Radare2/YARA for reverse engineering. ⭐️25.

🧰 [system-prompt-benchmark](https://github.com/KazKozDev/system-prompt-benchmark)  
Runs system prompts against 287 prompt-injection/jailbreak/data-leak attacks using an Ollama-based judge. ⭐️3 — Artem Kazakov Kozlov.

🧰 [ctrl-alt-deceit](https://github.com/TeunvdWeij/ctrl-alt-deceit)  
Adds sabotage tasks + monitoring to evaluate agents that tamper with code, benchmarks, and logs. ⭐️3 — Teun van der Weij (Apollo Research).

🧰 [SOC-CERT AI Helper](https://github.com/joupify/soc-cert-guardian-extension)  
Chrome extension using Gemini Nano + KEV-backed CVE enrichment to detect/prioritize web threats. ⭐️1 — Malika H.

🧰 [aifirst-insecure-agent-labs](https://github.com/trailofbits/aifirst-insecure-agent-labs)  
Agent exploit lab for prompt injection, system-prompt extraction, and guardrail bypass. ⭐️1 — Willis Vandevanter (Trail of Bits).

🧰 [llm-security-framework](https://github.com/annablume/llm-security-framework)  
Tiered checklists, threat models, and docs to harden small AI projects quickly. ⭐️0 — Anna Blume.

🧰 [cupcake](https://github.com/eqtylab/cupcake)  
Policy guard dog for constraining agent behavior. ⭐️44 — EQTY Lab.

# 📄 Reports

📘 [Capabilities-Based Risk Assessment (CBRA) for AI Systems + Adversarial Poetry as a Universal Single-Turn Jailbreak Mechanism in LLMs](https://www.linkedin.com/feed/update/urn:li:activity:7395494576721027073)  
Introduces CBRA: a structured approach to evaluating enterprise AI risk based on system capabilities.

📘 [Guidelines on Artificial Intelligence Risk Management - MAS](https://www.linkedin.com/feed/update/urn:li:activity:7395053745056772096)  
MAS consultation on AI risk management expectations for financial institutions (oversight, lifecycle controls, and capability requirements).

📘 [Guidance for Risk Management of Artificial Intelligence systems](https://www.linkedin.com/feed/update/urn:li:activity:7394270515554578432)  
Guidance publication on AI risk management practices.

📘 [Evasion Attacks on LLMs – Countermeasures in Practice](https://www.linkedin.com/feed/update/urn:li:activity:7394623637657456640)  
Practical countermeasures for protecting LLM-based systems against evasion attacks.

📘 [Disrupting the first reported AI-orchestrated cyber espionage campaign](https://www.linkedin.com/feed/update/urn:li:activity:7394834523349262336)  
Summary/report on disrupting an AI-orchestrated espionage campaign.

📘 [Assessing Risks and Impacts of AI (ARIA)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.700-2.pdf)  
Describes the procedure used for NIST’s ARIA 0.1 pilot evaluation and its components. By Razvan Amironesei, Afzal Godil, Craig Greenberg, Kristen K. Greene, Patrick Hall, Ted J., Jonathan Fiscus, Noah Schulman.

📘 [Model Context Protocol (MCP) Security](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/mcp/model-context-protocol-security.md)  
CoSAI workstream guidance on MCP security risks and recommendations.

📘 [OWASP AI Testing Guide v1.0](https://www.linkedin.com/feed/update/urn:li:activity:7399546815597182976)  
Practical framework for trustworthiness testing of AI systems grounded in real attack patterns and emerging standards.

📘 [AI Governance: A Practical Guide for Technical Leaders](https://www.linkedin.com/feed/update/urn:li:activity:7399118344697790465)  
ISACA guide mapping AI risks and governance controls for technical/security leaders.

📘 [AI for Security and Security for AI: Navigating Opportunities and Challenges](https://www.linkedin.com/feed/update/urn:li:activity:7392564169008594944)  
Whitepaper covering: securing GenAI applications, using GenAI to improve cloud security, and defending against GenAI-enabled threats.

📘 [Advances in Threat Actor Usage of AI Tools](https://www.linkedin.com/feed/update/urn:li:activity:7391864296735076353)  
Update on how threat actors are integrating AI across the attack lifecycle.

📘 [AI Pentest Scoping Playbook](https://www.linkedin.com/feed/update/urn:li:activity:7396206225404796928)  
Critique of shallow “AI red teaming” engagements and a scoping guide emphasizing the full AI attack surface. By HyunHwan Lee.

📘 [Facing the Artificial Intelligence - Cyber Nexus](https://www.linkedin.com/feed/update/urn:li:activity:7395587027368456192)  
Policy-oriented report with guiding questions for actions across diplomacy, law enforcement, finance, defense, and intelligence. By Quentin Hodgson, Kamaria Horton, Matthew Malone.

# 📅 Upcoming Events

📅 ISACA Virtual Summit: AI Governance Strategies 2025 - December 3, 2025 | Virtual | ISACA  
📅 North Carolina AI and Cybersecurity Symposium 2025 - December 3–4, 2025 | Raleigh, NC, USA | Government Technology  
📅 AI Security Summit @ Black Hat - December 9, 2025 | ExCeL London, UK  
📅 AI Hacking Village @ BSidesTLV - December 11, 2025 | Tel Aviv University, Tel Aviv, Israel | https://bsidestlv.com/ | BSidesTLV

# 📚 Research

📖 [Adversarial Poetry as a Universal Single-Turn Jailbreak Mechanism in Large Language Models](https://arxiv.org/pdf/2511.15304)  
Shows poetic reformulation degrades refusals across model families, sharply raising attack success rates versus prose, suggesting alignment pipelines do not generalize across stylistic shifts. By Piercosma Bisconti Lucidi, Matteo Prandi, Federico Pierucci, Francesco Giarrusso, Marcantonio Bracale Syrnikov, Marcello Galisai, Vincenzo Suriani, Olga Sorokoletova, Federico Sartore, Daniele Nardi (DEXAI).

📖 [Sabotage Evaluations for Automated AI R&D: CTRL-ALT-DECEIT](https://arxiv.org/pdf/2511.09904)  
Adds sabotage tasks/monitoring to evaluate agents used in real software engineering and potentially AI R&D automation, focusing on integrity failures (tampering with code, benchmarks, and logs). By Francis Rhys Ward, Teun van der Weij, Hanna Gábor, Sam Martin, Raja Mehta Moreno, Adi Paramkusam, Harel Lidar, Louis Makower, Tom Jodrell, Lauren Robson.

📖 [ASTRA: A modular black-box automated jailbreak framework with continuous learning](https://arxiv.org/pdf/2511.02356)  
Closed-loop “attack–evaluate–distill–reuse” mechanism that turns attack interactions into retrievable, transferable strategic knowledge.

📖 [A Unified Red Teaming Framework against LLM Agents by Dynamically Hijacking Their Own Reasoning](https://arxiv.org/abs/2503.01908)  
Introduces UDora: a unified red-teaming framework targeting agent vulnerabilities via adversarial manipulation of reasoning. By Jiawei Zhang, Shuang Yang, Bo Li.

📖 [Evaluating Key Functional Properties of LLM Architectures in Penetration Testing](https://arxiv.org/abs/2509.14289)  
Finds LLM agents can automate core tasks like recon and credential exploitation but remain brittle on complex multi-phase workflows; common failures include looping, context loss, and tool misuse. By Lanxiao Huang, Daksh Dave, Cody Tyler, Peter Beling, Ming Jin.

📖 [Chain-of-Thought Hijacking](https://arxiv.org/abs/2510.26418)  
Jailbreak against reasoning models by padding harmful requests with long benign puzzle reasoning; shows scaled reasoning can be used to bypass safeguards. By Jianli Zhao, Tingchen Fu, Rylan Schaeffer, Mrinank Sharma, Fazl Barez.

📖 [Securing the Model Context Protocol (MCP): Risks, Controls, and Governance](https://arxiv.org/pdf/2511.20920)  
Threat model for MCP: content injection, supply-chain compromise of servers, and agents as unintentional adversaries; argues governance gaps versus existing AI RMF/ISO frameworks. By Herman Errico, Jiquan Ngiam, Shanita Sojan.

📖 [Proactive Deepfake Detection and Localization via Fractal Watermarks](https://arxiv.org/pdf/2504.09451)  
Watermark-based proactive detection approach aiming to add localization/explainability beyond passive detectors. By Tianyi Wang, Harry Cheng, Ming-Hui Liu, Mohan Kankanhalli.

📖 [Optimizing AI Agent Attacks With Synthetic Data](https://arxiv.org/pdf/2511.02823)  
Proposes decomposing attack policy learning into interacting components and using synthetic data rather than end-to-end RL. By Chloe Loughridge, Paul Colognese, Avery Griffin, Tyler Tracy, Jon Kutasov, Joe Benton.

📖 [Chatbot Privacy: An Analysis of Frontier AI Policies](https://arxiv.org/pdf/2509.05382)  
Analyzes privacy policies of major LLM developers, finding user chat data is commonly used for training by default with opt-out controls; highlights sensitivity of chat content and uploads. By Jennifer King, Kevin Klyman, Emily Capstick, Tiffany Saade, Victoria Hsieh.

📖 [Security Analysis of Agentic AI Communication Protocols: CORAL, ACP, A2A](https://arxiv.org/abs/2511.03841)  
Compares protocol security; finds gaps and notes CORAL has robust architecture but severe implementation flaws (authz failures, DoS). By Yedidel Louck, Ariel Stulman, Amit Dvir.

📖 [Death by a Thousand Prompts: Open Model Vulnerability Analysis](https://arxiv.org/pdf/2511.03247)  
Evaluates open-weight models and reports continued susceptibility to adversarial attacks; multi-turn attacks outperform single-turn and reveal model-specific weaknesses and high-risk patterns. By Amy Chang, Nicholas Conley, Harish Santhanalakshmi Ganesan, Adam Swanda.

# 🎥 Videos

▶️ [How to JAILBREAK AI Agents in n8n (And How to Protect Against It) | Bartlomiej Slodyczka](https://youtu.be/CnAdo_Av12I?si=a-KjRHbDMcDYI5Yq)  
▶️ How To Use the New n8n Guardrails Node (Full Setup & Demo) | Bart Slodyczka  
▶️ Agentic AI and Identity: The Biggest Problem We're Not Solving | Cristin Flynn Goodwin  
▶️ Scaling LLM-Based Vulnerability Research via Static Analysis and Document Ranking | Caleb Gross  
▶️ Tinker Tailor LLM Spy: Investigate & Respond to Attacks on GenAI Chatbots | Allyn Stott  
▶️ The Evolution of Burp AI | PortSwigger  
▶️ AI-Powered Captcha Bypass | Yunus Aydın  
▶️ LLM-Enabled Malware In the Wild | Alex D. & Gabriel B.  
▶️ AI Agents As Your Organization's Personal Security Newsroom | Brett A.  
▶️ GenAI attacks - 2025 Year In Review | Tillson Galloway  
▶️ Agentic ProbLLMs: Exploiting AI Computer-Use And Coding Agents | Johann Rehberger  
▶️ EchoLLM: LLM-Augmented Acoustic Eavesdropping Attack on Bone Conduction | Xin Yao, Kecheng Huang, Yimin Chen, Jiawei G., Jie Tang, Ming Zhao  
▶️ From Sandbox Escapes to MCP Database Hijacks: Unveiling Agentic Vulnerabilities | Sean Park  
▶️ How not to do ML | François Labrèche  
▶️ Dark Prompts, Dirty Outputs | Val S.  
▶️ Building Safer AI Systems | Doug Hubbard  
▶️ How AI Assistants Are Rewriting the Rules | Lauren Stemler  
▶️ Disinform your Surroundings: AI and disinformation campaigns | Tess  
▶️ Automated Pentesting with AI: From Recon to Reporting  
▶️ Actually Making Progress In Security From AI | Michael Bargury  
▶️ Risk Management in the Era of Agentic AI | Ken Huang  
▶️ AI for Offensive Security - Beyond Fuzzing and Scanning | Daniel Marques (@danielmarques)  
▶️ Hidden Dangers Of AI In Developer Workflows: Navigating Security Risks with Human Insight | Dwayne McDaniel  
▶️ Shall We Play A Game? LLM Security in Practice | Joseph Katsioloudes  
▶️ [Navigating the AI Frontier: Secure Adoption of LLMs in FinTec | Rob Kenefeck](https://youtu.be/050OcQ5Ys8I?si=7Df6heNKSvY6qPvg)

# 🤝 Let’s Connect

If you’re a founder building something new or an investor evaluating early-stage opportunities — let’s connect.

💬 Read something interesting? Share your thoughts in the comments.
