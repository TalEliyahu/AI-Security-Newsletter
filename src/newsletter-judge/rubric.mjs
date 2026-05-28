import { CATEGORIES, SOURCE_TYPES } from "./schema.mjs";

const AI_TERMS = [
  "ai",
  "llm",
  "large language model",
  "model",
  "agent",
  "agentic",
  "mcp",
  "model context protocol",
  "rag",
  "embedding",
  "prompt",
  "jailbreak",
  "multimodal"
];

const AI_SECURITY_TERMS = [
  "prompt injection",
  "indirect prompt injection",
  "tool poisoning",
  "agent abuse",
  "agent security",
  "mcp security",
  "model extraction",
  "model stealing",
  "data poisoning",
  "model poisoning",
  "jailbreak",
  "data leakage",
  "exfiltration",
  "ai red team",
  "llm security",
  "ai supply chain",
  "coding agent",
  "autonomous agent",
  "adversarial ml",
  "model misuse"
];

const SECURITY_MECHANISMS = [
  "exploit",
  "vulnerability",
  "cve",
  "rce",
  "remote code execution",
  "code injection",
  "command injection",
  "credential theft",
  "authentication bypass",
  "auth bypass",
  "ssrf",
  "server-side request forgery",
  "sandbox",
  "bypass",
  "guardrail",
  "threat model",
  "trust boundary",
  "exfiltration",
  "detection",
  "mitigation",
  "benchmark",
  "evaluation",
  "red team",
  "attack path",
  "abuse",
  "malware",
  "credential",
  "authorization",
  "supply chain",
  "poisoning",
  "privacy leakage"
];

const MARKETING_TERMS = [
  "announces",
  "launches",
  "partnership",
  "partnering",
  "platform",
  "solution",
  "research preview",
  "customer",
  "roi",
  "accelerate",
  "transform",
  "industry-leading",
  "next-generation"
];

const FUNDING_TERMS = [
  "raises",
  "raised",
  "funding",
  "series a",
  "series b",
  "series c",
  "valuation",
  "acquires",
  "acquisition"
];

const GOVERNMENT_OR_STANDARDS_DOMAINS = [
  ".gov",
  "nist.gov",
  "ncsc.gov.uk",
  "cisa.gov",
  "cyber.gov.au",
  "owasp.org",
  "iso.org",
  "first.org",
  "enisa.europa.eu",
  "atlanticcouncil.org"
];

const SOCIAL_DOMAINS = ["x.com", "twitter.com", "linkedin.com", "bsky.app", "mastodon"];
const VENDOR_DOMAINS = [
  "anthropic.com",
  "cisco.com",
  "cloudflare.com",
  "google",
  "ibm.com",
  "microsoft.com",
  "openai.com",
  "paloaltonetworks.com",
  "promptarmor.com",
  "redhat.com",
  "snyk.io",
  "tenable.com"
];

export function buildHeuristicJudgeReport({ items, sourceResults = [], parserWarnings = [] }) {
  const judgedItems = items.map((item, index) => judgeItem(item, sourceResults[index]));
  const overallScore = calculateOverallScore(judgedItems);
  const strongest = [...judgedItems]
    .sort((a, b) => b.scores.total - a.scores.total)
    .slice(0, 5)
    .map((item) => item.title);
  const weakest = [...judgedItems]
    .sort((a, b) => a.scores.total - b.scores.total)
    .slice(0, 5)
    .map((item) => item.title);

  const needsEdits = judgedItems.some((item) =>
    ["KEEP_BUT_REWRITE", "NEEDS_SOURCE_VERIFICATION"].includes(item.decision)
  );
  const dropRate = judgedItems.length
    ? judgedItems.filter((item) => item.decision === "DROP").length / judgedItems.length
    : 1;

  let finalRecommendation = "PUBLISH_AFTER_EDITS";
  if (overallScore >= 82 && !needsEdits && dropRate < 0.15) finalRecommendation = "PUBLISH";
  if (overallScore < 55 || dropRate >= 0.4) finalRecommendation = "DO_NOT_PUBLISH_YET";

  const bestSection = findBestSection(judgedItems);
  const missingThemes = findMissingThemes(judgedItems);
  const needsStrongerTechnicalFraming = judgedItems
    .filter((item) => item.decision === "KEEP_BUT_REWRITE")
    .map((item) => item.title);

  return {
    overall_score: overallScore,
    final_recommendation: finalRecommendation,
    summary: {
      main_issue: summarizeMainIssue(judgedItems),
      best_section: bestSection,
      biggest_weakness: summarizeWeakness(judgedItems)
    },
    items: judgedItems,
    issue_level_review: {
      strongest_items: strongest,
      weakest_items: weakest,
      vendor_noise: judgedItems.filter((item) => item._flags.vendorNoise).map((item) => item.title),
      generic_ai_news: judgedItems.filter((item) => item._flags.genericAiNews).map((item) => item.title),
      needs_stronger_technical_framing: needsStrongerTechnicalFraming,
      missing_themes: missingThemes,
      recommended_order: [...judgedItems]
        .filter((item) => item.decision !== "DROP")
        .sort((a, b) => b.scores.total - a.scores.total)
        .map((item) => item.title),
      suggested_headline: suggestHeadline(judgedItems),
      editors_note: suggestEditorsNote(judgedItems, missingThemes)
    },
    warnings: parserWarnings
  };
}

export function judgeItem(item, sourceResult = null) {
  const text = [item.title, item.summary, item.section, item.source].filter(Boolean).join(" ");
  const lower = text.toLowerCase();
  const sourceStatus = sourceResult?.source_verification_status || (item.url ? "not_requested" : "no_url");
  const sourceType = classifySourceType(item, sourceResult);
  const categories = classifyCategories(item, lower, sourceType);
  const flags = {
    vendorNoise: isVendorNoise(lower, sourceType),
    genericAiNews: isGenericAiNews(lower),
    governanceOnly: isGovernanceOnly(lower),
    weakSource: ["marketing page", "social post", "unknown"].includes(sourceType)
  };

  const accuracyConcerns = [];
  if (sourceStatus === "unavailable") {
    accuracyConcerns.push("Source could not be fetched or read; claims need manual verification.");
  }
  if (sourceStatus === "verified") {
    accuracyConcerns.push(...findUnsupportedClaims(item, sourceResult.source_text));
  }
  if (hasOverstatedLanguage(lower)) {
    accuracyConcerns.push("The current text uses high-impact language that should be supported or softened.");
  }

  const scores = {
    ai_security_relevance: scoreAiSecurityRelevance(lower, flags),
    technical_substance: scoreTechnicalSubstance(lower, flags),
    correctness: scoreCorrectness(sourceStatus, accuracyConcerns, lower),
    practitioner_value: scorePractitionerValue(lower, flags),
    source_quality: scoreSourceQuality(sourceType),
    novelty_timeliness: scoreNoveltyTimeliness(item, lower),
    audience_fit: 0,
    total: 0
  };
  scores.audience_fit = scoreAudienceFit(scores, flags);
  scores.total = sumScores(scores);

  const decision = decide(scores, flags, sourceStatus, accuracyConcerns);
  const rewrite = rewriteGuidance(decision, item, categories.primary, flags, accuracyConcerns);

  const publicItem = {
    title: item.title,
    url: item.url || null,
    source_verification_status: sourceStatus,
    decision,
    primary_category: categories.primary,
    secondary_categories: categories.secondary,
    source_type: sourceType,
    scores,
    reason: reasonForDecision(decision, scores, flags, categories.primary),
    accuracy_concerns: accuracyConcerns,
    rewrite_guidance: rewrite.guidance,
    suggested_rewrite: rewrite.suggested,
    reviewer_notes: reviewerNotes(categories, scores, flags, lower)
  };

  Object.defineProperty(publicItem, "_flags", {
    value: flags,
    enumerable: false
  });
  return publicItem;
}

export function sumScores(scores) {
  return [
    scores.ai_security_relevance,
    scores.technical_substance,
    scores.correctness,
    scores.practitioner_value,
    scores.source_quality,
    scores.novelty_timeliness,
    scores.audience_fit
  ].reduce((sum, value) => sum + value, 0);
}

export function decide(scores, flags, sourceStatus, accuracyConcerns = []) {
  if (sourceStatus === "unavailable" && scores.correctness <= 2) {
    return "NEEDS_SOURCE_VERIFICATION";
  }
  if (flags.vendorNoise || flags.genericAiNews) {
    return scores.ai_security_relevance >= 3 && scores.technical_substance >= 3 ? "MOVE_TO_OPTIONAL" : "DROP";
  }
  if (scores.ai_security_relevance <= 1 || scores.audience_fit <= 1) {
    return "DROP";
  }
  if (accuracyConcerns.length > 0 && scores.correctness <= 2) {
    return sourceStatus === "verified" ? "KEEP_BUT_REWRITE" : "NEEDS_SOURCE_VERIFICATION";
  }
  if (scores.total >= 30) return accuracyConcerns.length ? "KEEP_BUT_REWRITE" : "KEEP";
  if (scores.total >= 24) return scores.technical_substance >= 4 ? "KEEP" : "KEEP_BUT_REWRITE";
  if (scores.total >= 18) return scores.ai_security_relevance >= 4 ? "KEEP_BUT_REWRITE" : "MOVE_TO_OPTIONAL";
  if (scores.total >= 10) return "MOVE_TO_OPTIONAL";
  return "DROP";
}

function classifySourceType(item, sourceResult) {
  const url = item.url || "";
  const lowerUrl = url.toLowerCase();
  const text = [item.title, item.summary, item.section, item.source].filter(Boolean).join(" ").toLowerCase();
  const host = hostname(lowerUrl);
  if (/arxiv\.org|doi\.org|acm\.org|ieee\.org|usenix\.org|ndss-symposium\.org/.test(lowerUrl)) return "primary research paper";
  if (/github\.com\/advisories|kb\.cert\.org|nvd\.nist\.gov|cve\.org/.test(lowerUrl)) return "official advisory";
  if (/github\.com/.test(lowerUrl)) return "GitHub/tool release";
  if (/youtube\.com|youtu\.be|conference|blackhat|def con|bsides|rsac|ndss/.test(lowerUrl + " " + text)) return "conference talk";
  if (GOVERNMENT_OR_STANDARDS_DOMAINS.some((domain) => host.includes(domain) || lowerUrl.includes(domain))) {
    return /blog|newsroom|threat|advisory/.test(lowerUrl) ? "official advisory" : "standards/framework document";
  }
  if (SOCIAL_DOMAINS.some((domain) => host.includes(domain))) return "social post";
  if (/press-release|prnewswire|businesswire|pricing|contact-sales/.test(lowerUrl)) {
    return "marketing page";
  }
  if (/blog|research|labs|security|threat|vulnerability|advisory/.test(lowerUrl + " " + text)) {
    if (/launches|announces|partnership|platform/.test(text) && !hasSecurityMechanism(text)) {
      return "marketing page";
    }
    return VENDOR_DOMAINS.some((domain) => host.includes(domain))
      ? "vendor technical blog"
      : "security research blog";
  }
  if (sourceResult?.source_verification_status === "verified") return "news article";
  return "unknown";
}

function classifyCategories(item, lower, sourceType) {
  const categories = [];
  if (sourceType === "GitHub/tool release" || /tools?|resources/i.test(item.section || "")) categories.push("Tool Release");
  if (/prompt injection|indirect prompt|system prompt|tool poisoning/.test(lower)) categories.push("Prompt Injection");
  if (/mcp|model context protocol/.test(lower)) categories.push("MCP Security");
  if (/agent|agentic|coding assistant|tool invocation|autonomous/.test(lower)) categories.push("Agent Security");
  if (/llm app|rag|retrieval|application security|system prompt|data leakage/.test(lower)) categories.push("LLM Application Security");
  if (/red team|jailbreak|bypass|abuse path|attack path/.test(lower)) categories.push("AI Red Teaming");
  if (/model extraction|model stealing|poisoning|adversarial|privacy leakage|membership inference/.test(lower)) categories.push("Model Security");
  if (/supply chain|dependency|package|model registry|checkpoint|artifact/.test(lower)) categories.push("AI Supply Chain");
  if (/data leakage|privacy|exfiltration|credential|secret/.test(lower)) categories.push("Data Leakage / Privacy");
  if (/malware|phishing|ransomware|abuse|c2|command and control/.test(lower)) categories.push("AI Malware / Abuse");
  if (/mitigation|monitoring|detection|sandbox|authorization|secure engineering|architecture|control/.test(lower)) categories.push("Secure AI Engineering");
  if (/governance|risk|standard|framework|compliance|policy|assurance/.test(lower)) categories.push("AI Governance / Risk");
  if (sourceType === "primary research paper" || /paper|arxiv/.test(lower)) categories.push("Research Paper");
  if (/incident|case study|observed in the wild|breach|campaign/.test(lower)) categories.push("Incident / Case Study");
  if (/benchmark|evaluation|dataset|test suite|leaderboard/.test(lower)) categories.push("Benchmark / Evaluation");

  const unique = [...new Set(categories)].filter((category) => CATEGORIES.has(category));
  return {
    primary: unique[0] || "Not Relevant",
    secondary: unique.slice(1, 3)
  };
}

function scoreAiSecurityRelevance(lower, flags) {
  if (flags.genericAiNews) return 1;
  if (flags.vendorNoise && !hasSecurityMechanism(lower)) return 1;
  const direct = countMatches(lower, AI_SECURITY_TERMS);
  const ai = countMatches(lower, AI_TERMS);
  const security = countMatches(lower, SECURITY_MECHANISMS);
  if (direct >= 2) return 5;
  if (direct === 1 && security >= 2) return 5;
  if (direct === 1) return 4;
  if (ai > 0 && security >= 2) return 4;
  if (ai > 0 && security === 1) return 3;
  if (security >= 2) return 2;
  return 0;
}

function scoreTechnicalSubstance(lower, flags) {
  if (flags.vendorNoise || flags.genericAiNews) return hasSecurityMechanism(lower) ? 2 : 1;
  const mechanisms = countMatches(lower, SECURITY_MECHANISMS);
  if (mechanisms >= 5) return 5;
  if (mechanisms >= 3) return 4;
  if (mechanisms >= 2) return 3;
  if (mechanisms === 1) return 2;
  return 1;
}

function scoreCorrectness(sourceStatus, accuracyConcerns, lower) {
  if (sourceStatus === "unavailable") return 2;
  if (sourceStatus === "no_url") return 2;
  let score = sourceStatus === "verified" ? 5 : 4;
  score -= Math.min(3, accuracyConcerns.length);
  if (hasOverstatedLanguage(lower)) score -= 1;
  return clamp(score, 0, 5);
}

function scorePractitionerValue(lower, flags) {
  if (flags.genericAiNews || flags.vendorNoise) return 1;
  let score = 1;
  if (/mitigation|detection|monitoring|sandbox|authorization|test|scanner|benchmark|exploit|vulnerability|attack path|threat model|credential|exfiltration|rce|code execution|ssrf|auth bypass|authentication bypass/.test(lower)) {
    score += 3;
  }
  if (/agent|prompt injection|mcp|llm app|coding agent|data leakage|supply chain/.test(lower)) score += 1;
  return clamp(score, 0, 5);
}

function scoreSourceQuality(sourceType) {
  return {
    "primary research paper": 5,
    "official advisory": 5,
    "standards/framework document": 4,
    "security research blog": 4,
    "GitHub/tool release": 4,
    "vendor technical blog": 3,
    "conference talk": 3,
    "news article": 2,
    "marketing page": 1,
    "social post": 1,
    unknown: 1
  }[sourceType] ?? 1;
}

function scoreNoveltyTimeliness(item, lower) {
  if (item.date) return 4;
  if (/new|released|discovered|published|observed|cve-|202[5-9]|research|benchmark|tool|advisory/.test(lower)) return 4;
  if (/evergreen|primer|overview|introduction/.test(lower)) return 2;
  return 3;
}

function scoreAudienceFit(scores, flags) {
  if (flags.genericAiNews || flags.vendorNoise) return 1;
  return clamp(Math.round((scores.ai_security_relevance + scores.technical_substance + scores.practitioner_value) / 3), 0, 5);
}

function isVendorNoise(lower, sourceType) {
  if (sourceType === "marketing page") return true;
  return countMatches(lower, MARKETING_TERMS) >= 2 && !hasSecurityMechanism(lower);
}

function isGenericAiNews(lower) {
  return countMatches(lower, FUNDING_TERMS) > 0 && !hasSecurityMechanism(lower);
}

function isGovernanceOnly(lower) {
  return /governance|policy|regulation|compliance/.test(lower) && !hasSecurityMechanism(lower);
}

function hasSecurityMechanism(lower) {
  return countMatches(lower, SECURITY_MECHANISMS) > 0 || countMatches(lower, AI_SECURITY_TERMS) > 0;
}

function hasOverstatedLanguage(lower) {
  const withoutFormalCveSeverity = lower.replace(/\bcritical\s+\d+(?:\.\d+)?\b/g, "");
  return /\b(devastating|catastrophic|critical|breach|proves|guarantees|unstoppable|zero day|0-day|always|never)\b/.test(withoutFormalCveSeverity);
}

function findUnsupportedClaims(item, sourceText) {
  const concerns = [];
  const source = sourceText.toLowerCase();
  const summary = [item.title, item.summary].join(" ").toLowerCase();
  const claimPairs = [
    ["rce", /\brce\b|remote code execution/, ["rce", "remote code execution"]],
    ["cve", /\bcve-\d{4}-\d+\b|\bcve\b/, ["cve"]],
    ["breach", /\bbreach\b|\bcompromise\b|\bincident\b/, ["breach", "compromise", "incident"]],
    ["malware", /\bmalware\b|\bransomware\b|\bbackdoor\b/, ["malware", "ransomware", "backdoor"]],
    ["exfiltration", /\bexfiltration\b|\bexfiltrate\b|\bdata leak(?:age)?\b/, ["exfiltration", "exfiltrate", "data leak"]],
    ["prompt injection", /\bprompt injection\b/, ["prompt injection", "injection"]]
  ];
  for (const [claim, summaryPattern, sourceWords] of claimPairs) {
    if (summaryPattern.test(summary) && !sourceWords.some((word) => source.includes(word))) {
      concerns.push(`Source text did not clearly support the "${claim}" claim.`);
    }
  }
  return concerns;
}

function rewriteGuidance(decision, item, primaryCategory, flags, accuracyConcerns) {
  if (decision === "KEEP") {
    return {
      guidance: "",
      suggested: ""
    };
  }
  if (decision === "DROP") {
    return {
      guidance: flags.vendorNoise
        ? "Remove this item unless it can be replaced with a primary technical source and a concrete AI security mechanism."
        : "Remove this item from the main newsletter because it does not provide enough technical AI security signal.",
      suggested: ""
    };
  }
  if (decision === "NEEDS_SOURCE_VERIFICATION") {
    return {
      guidance: "Verify the source before inclusion. Do not preserve strong claims until source text supports them.",
      suggested: ""
    };
  }
  const concernText = accuracyConcerns.length ? ` Address: ${accuracyConcerns.join(" ")}` : "";
  return {
    guidance: `Refocus the summary on the concrete ${primaryCategory.toLowerCase()} mechanism, affected system, and practical security takeaway.${concernText}`,
    suggested: suggestedRewrite(item, primaryCategory)
  };
}

function suggestedRewrite(item, primaryCategory) {
  const title = item.title.replace(/\.$/, "");
  return `${title} is relevant for ${primaryCategory.toLowerCase()} because it describes a concrete AI-security mechanism. Emphasize the affected system, attack or control path, and what practitioners should test or change.`;
}

function reasonForDecision(decision, scores, flags, primaryCategory) {
  if (decision === "DROP" && primaryCategory === "Not Relevant") {
    return "The item does not show enough concrete AI security relevance for the intended technical audience.";
  }
  if (decision === "DROP" && flags.vendorNoise) {
    return "The item reads like vendor/product promotion and does not provide enough concrete AI security mechanism.";
  }
  if (decision === "DROP" && flags.genericAiNews) {
    return "The item is generic AI business news without a concrete AI security takeaway.";
  }
  if (decision === "NEEDS_SOURCE_VERIFICATION") {
    return "The item may be relevant, but source verification failed or is needed before trusting the claims.";
  }
  if (decision === "KEEP_BUT_REWRITE") {
    return `The item has useful ${primaryCategory.toLowerCase()} signal, but the current framing needs tighter technical support.`;
  }
  if (decision === "MOVE_TO_OPTIONAL") {
    return "The item is related, but its technical depth or practitioner value is weaker than a main-slot item.";
  }
  return `The item has strong ${primaryCategory.toLowerCase()} relevance, technical substance, and practitioner value.`;
}

function reviewerNotes(categories, scores, flags, lower) {
  return {
    prompt_injection_llm_appsec: categories.primary === "Prompt Injection" || categories.secondary.includes("Prompt Injection")
      ? "Check the trust boundary, external content path, and whether tool or data access makes the injection exploitable."
      : "",
    enterprise_architect: scores.practitioner_value >= 4
      ? "Useful for architecture review because it points to controls, monitoring, authorization, or deployment boundaries."
      : "",
    ai_red_teamer: /exploit|bypass|jailbreak|red team|attack path|abuse/.test(lower)
      ? "Has offensive testing value; preserve the mechanics and avoid turning it into generic risk language."
      : "",
    ml_security_researcher: categories.primary === "Model Security" || categories.secondary.includes("Research Paper")
      ? "Review methodology, benchmark design, and whether claims are empirical or speculative."
      : "",
    governance_assurance: categories.primary === "AI Governance / Risk" || flags.governanceOnly
      ? "Keep only if the item leads to practical security assurance, control design, or deployable governance requirements."
      : ""
  };
}

function calculateOverallScore(items) {
  if (!items.length) return 0;
  const average = items.reduce((sum, item) => sum + item.scores.total, 0) / items.length;
  const dropRate = items.filter((item) => item.decision === "DROP").length / items.length;
  const dropPenalty = dropRate * 25;
  return clamp(Math.round((average / 35) * 100 - dropPenalty), 0, 100);
}

function findBestSection(items) {
  const sectionScores = new Map();
  for (const item of items) {
    const category = item.primary_category;
    const existing = sectionScores.get(category) || { total: 0, count: 0 };
    existing.total += item.scores.total;
    existing.count += 1;
    sectionScores.set(category, existing);
  }
  let best = "No strong section";
  let bestScore = -1;
  for (const [section, score] of sectionScores.entries()) {
    const average = score.total / score.count;
    if (average > bestScore) {
      best = section;
      bestScore = average;
    }
  }
  return best;
}

function summarizeMainIssue(items) {
  if (!items.length) return "No items were found.";
  if (items.some((item) => item.decision === "NEEDS_SOURCE_VERIFICATION")) {
    return "Some potentially useful items still need source verification before publication.";
  }
  if (items.some((item) => item._flags.vendorNoise)) {
    return "Vendor or product noise is diluting the technical signal.";
  }
  if (items.some((item) => item.decision === "KEEP_BUT_REWRITE")) {
    return "Several worthwhile items need stronger technical framing before publication.";
  }
  return "The issue is technically focused and mostly publication-ready.";
}

function summarizeWeakness(items) {
  if (!items.length) return "No content to judge.";
  const weak = [...items].sort((a, b) => a.scores.total - b.scores.total)[0];
  return weak ? `${weak.title}: ${weak.reason}` : "No major weakness found.";
}

function findMissingThemes(items) {
  const present = new Set(items.filter((item) => item.decision !== "DROP").map((item) => item.primary_category));
  const expected = [
    "Prompt Injection",
    "Agent Security",
    "MCP Security",
    "AI Supply Chain",
    "Model Security",
    "AI Malware / Abuse",
    "Secure AI Engineering"
  ];
  return expected.filter((category) => !present.has(category)).slice(0, 5);
}

function suggestHeadline(items) {
  const top = [...items].sort((a, b) => b.scores.total - a.scores.total)[0];
  if (!top) return "AI Security Newsletter";
  if (top.primary_category === "Prompt Injection") return "Prompt Injection and Agent Security Lead This Month's AI Security Signal";
  if (top.primary_category === "Agent Security") return "Agent Security, Tool Boundaries, and Practical AI Defense";
  return `${top.primary_category} and Practical AI Security Lessons`;
}

function suggestEditorsNote(items, missingThemes) {
  const kept = items.filter((item) => ["KEEP", "KEEP_BUT_REWRITE"].includes(item.decision)).length;
  const needsVerification = items.filter((item) => item.decision === "NEEDS_SOURCE_VERIFICATION").length;
  const missing = missingThemes.length ? ` Missing themes to consider: ${missingThemes.join(", ")}.` : "";
  return `${kept} items look suitable for the main issue after edits. ${needsVerification} items need source verification.${missing}`.trim();
}

function countMatches(lower, terms) {
  return terms.filter((term) => lower.includes(term)).length;
}

function hostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
