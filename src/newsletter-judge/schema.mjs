export const DECISIONS = new Set([
  "KEEP",
  "KEEP_BUT_REWRITE",
  "MOVE_TO_OPTIONAL",
  "DROP",
  "NEEDS_SOURCE_VERIFICATION"
]);

export const FINAL_RECOMMENDATIONS = new Set([
  "PUBLISH",
  "PUBLISH_AFTER_EDITS",
  "DO_NOT_PUBLISH_YET"
]);

export const SOURCE_VERIFICATION_STATUSES = new Set([
  "verified",
  "unavailable",
  "not_requested",
  "no_url"
]);

export const CATEGORIES = new Set([
  "Prompt Injection",
  "Agent Security",
  "MCP Security",
  "LLM Application Security",
  "AI Red Teaming",
  "Model Security",
  "AI Supply Chain",
  "Data Leakage / Privacy",
  "AI Malware / Abuse",
  "Secure AI Engineering",
  "AI Governance / Risk",
  "Tool Release",
  "Research Paper",
  "Incident / Case Study",
  "Benchmark / Evaluation",
  "Not Relevant"
]);

export const SOURCE_TYPES = new Set([
  "primary research paper",
  "security research blog",
  "vendor technical blog",
  "GitHub/tool release",
  "official advisory",
  "standards/framework document",
  "conference talk",
  "news article",
  "marketing page",
  "social post",
  "unknown"
]);

export const REVIEWER_NOTE_KEYS = [
  "prompt_injection_llm_appsec",
  "enterprise_architect",
  "ai_red_teamer",
  "ml_security_researcher",
  "governance_assurance"
];

export const SCORE_KEYS = [
  "ai_security_relevance",
  "technical_substance",
  "correctness",
  "practitioner_value",
  "source_quality",
  "novelty_timeliness",
  "audience_fit",
  "total"
];

export function validateJudgeReport(report) {
  const errors = [];

  if (!isObject(report)) {
    throw new Error("Judge report must be an object.");
  }

  requireNumber(report, "overall_score", errors, 0, 100);
  requireEnum(report, "final_recommendation", FINAL_RECOMMENDATIONS, errors);

  if (!isObject(report.summary)) {
    errors.push("summary must be an object.");
  } else {
    requireString(report.summary, "main_issue", errors);
    requireString(report.summary, "best_section", errors);
    requireString(report.summary, "biggest_weakness", errors);
  }

  if (!Array.isArray(report.items)) {
    errors.push("items must be an array.");
  } else {
    report.items.forEach((item, index) => validateItem(item, index, errors));
  }

  if (!isObject(report.issue_level_review)) {
    errors.push("issue_level_review must be an object.");
  } else {
    for (const key of [
      "strongest_items",
      "weakest_items",
      "vendor_noise",
      "generic_ai_news",
      "needs_stronger_technical_framing",
      "missing_themes",
      "recommended_order"
    ]) {
      requireStringArray(report.issue_level_review, key, errors);
    }
    requireString(report.issue_level_review, "suggested_headline", errors);
    requireString(report.issue_level_review, "editors_note", errors);
  }

  requireStringArray(report, "warnings", errors);

  if (errors.length > 0) {
    throw new Error(`Invalid judge report:\n- ${errors.join("\n- ")}`);
  }

  return report;
}

function validateItem(item, index, errors) {
  const prefix = `items[${index}]`;
  if (!isObject(item)) {
    errors.push(`${prefix} must be an object.`);
    return;
  }

  requireString(item, "title", errors, prefix);
  if (item.url !== null && typeof item.url !== "string") {
    errors.push(`${prefix}.url must be a string or null.`);
  }
  requireEnum(item, "source_verification_status", SOURCE_VERIFICATION_STATUSES, errors, prefix);
  requireEnum(item, "decision", DECISIONS, errors, prefix);
  requireEnum(item, "primary_category", CATEGORIES, errors, prefix);
  requireStringArray(item, "secondary_categories", errors, prefix);
  if (Array.isArray(item.secondary_categories)) {
    for (const category of item.secondary_categories) {
      if (!CATEGORIES.has(category)) {
        errors.push(`${prefix}.secondary_categories contains invalid category "${category}".`);
      }
    }
    if (item.secondary_categories.length > 2) {
      errors.push(`${prefix}.secondary_categories must contain at most two categories.`);
    }
  }
  requireEnum(item, "source_type", SOURCE_TYPES, errors, prefix);

  if (!isObject(item.scores)) {
    errors.push(`${prefix}.scores must be an object.`);
  } else {
    for (const key of SCORE_KEYS) {
      const max = key === "total" ? 35 : 5;
      requireNumber(item.scores, key, errors, 0, max, `${prefix}.scores`);
    }
  }

  requireString(item, "reason", errors, prefix);
  requireStringArray(item, "accuracy_concerns", errors, prefix);
  requireString(item, "rewrite_guidance", errors, prefix);
  requireString(item, "suggested_rewrite", errors, prefix);

  if (!isObject(item.reviewer_notes)) {
    errors.push(`${prefix}.reviewer_notes must be an object.`);
  } else {
    for (const key of REVIEWER_NOTE_KEYS) {
      requireString(item.reviewer_notes, key, errors, `${prefix}.reviewer_notes`);
    }
  }
}

function requireString(object, key, errors, prefix = "") {
  if (typeof object[key] !== "string") {
    errors.push(`${field(prefix, key)} must be a string.`);
  }
}

function requireStringArray(object, key, errors, prefix = "") {
  if (!Array.isArray(object[key]) || object[key].some((value) => typeof value !== "string")) {
    errors.push(`${field(prefix, key)} must be an array of strings.`);
  }
}

function requireNumber(object, key, errors, min, max, prefix = "") {
  if (typeof object[key] !== "number" || Number.isNaN(object[key])) {
    errors.push(`${field(prefix, key)} must be a number.`);
    return;
  }
  if (object[key] < min || object[key] > max) {
    errors.push(`${field(prefix, key)} must be between ${min} and ${max}.`);
  }
}

function requireEnum(object, key, allowed, errors, prefix = "") {
  if (!allowed.has(object[key])) {
    errors.push(`${field(prefix, key)} has invalid value "${object[key]}".`);
  }
}

function field(prefix, key) {
  return prefix ? `${prefix}.${key}` : key;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
