import fs from "node:fs/promises";
import path from "node:path";
import { validateJudgeReport } from "./schema.mjs";

export async function writeReports(report, outputDir) {
  const validated = validateJudgeReport(report);
  await fs.mkdir(outputDir, { recursive: true });
  const jsonPath = path.join(outputDir, "judge-report.json");
  const markdownPath = path.join(outputDir, "judge-report.md");
  await fs.writeFile(jsonPath, `${JSON.stringify(validated, null, 2)}\n`, "utf8");
  await fs.writeFile(markdownPath, renderMarkdownReport(validated), "utf8");
  return {
    jsonPath,
    markdownPath
  };
}

export function renderMarkdownReport(report) {
  validateJudgeReport(report);
  return [
    "# AI Security Newsletter Judge Report",
    "",
    "## Executive Verdict",
    `- Overall score: ${report.overall_score}`,
    `- Recommendation: ${report.final_recommendation}`,
    `- Main issue: ${report.summary.main_issue}`,
    `- Best section: ${report.summary.best_section}`,
    `- Biggest weakness: ${report.summary.biggest_weakness}`,
    "",
    "## Item-by-Item Review",
    "",
    ...report.items.flatMap((item, index) => renderItem(item, index)),
    "## Issue-Level Review",
    "",
    "### Strongest Items",
    renderList(report.issue_level_review.strongest_items),
    "",
    "### Weakest Items",
    renderList(report.issue_level_review.weakest_items),
    "",
    "### Vendor Noise",
    renderList(report.issue_level_review.vendor_noise),
    "",
    "### Generic AI News",
    renderList(report.issue_level_review.generic_ai_news),
    "",
    "### Needs Stronger Technical Framing",
    renderList(report.issue_level_review.needs_stronger_technical_framing),
    "",
    "### Missing Themes",
    renderList(report.issue_level_review.missing_themes),
    "",
    "### Recommended Order",
    renderList(report.issue_level_review.recommended_order),
    "",
    "### Suggested Headline",
    report.issue_level_review.suggested_headline,
    "",
    "### Suggested Editor's Note",
    report.issue_level_review.editors_note,
    "",
    "### Final Recommendation",
    report.final_recommendation,
    "",
    report.warnings.length ? "## Parser Warnings" : "",
    report.warnings.length ? renderList(report.warnings) : ""
  ]
    .filter((line, index, lines) => line !== "" || lines[index - 1] !== "")
    .join("\n")
    .trimEnd() + "\n";
}

function renderItem(item, index) {
  return [
    `### Item ${index + 1}: ${item.url ? `[${item.title}](${item.url})` : item.title}`,
    `- Decision: ${item.decision}`,
    `- Total score: ${item.scores.total}`,
    `- Primary category: ${item.primary_category}`,
    `- Secondary categories: ${item.secondary_categories.join(", ") || "None"}`,
    `- Source verification: ${item.source_verification_status}`,
    `- Source type: ${item.source_type}`,
    "",
    "Reason:",
    item.reason || "None.",
    "",
    "Accuracy concerns:",
    renderList(item.accuracy_concerns),
    "",
    "Rewrite guidance:",
    item.rewrite_guidance || "None.",
    "",
    "Suggested rewrite:",
    item.suggested_rewrite || "None.",
    "",
    "Reviewer notes:",
    renderReviewerNotes(item.reviewer_notes),
    ""
  ];
}

function renderReviewerNotes(notes) {
  const rows = [
    ["Prompt injection / LLM appsec", notes.prompt_injection_llm_appsec],
    ["Enterprise architect", notes.enterprise_architect],
    ["AI red teamer", notes.ai_red_teamer],
    ["ML security researcher", notes.ml_security_researcher],
    ["Governance / assurance", notes.governance_assurance]
  ].filter(([, value]) => value);
  return rows.length ? rows.map(([name, value]) => `- ${name}: ${value}`).join("\n") : "None.";
}

function renderList(values) {
  return values.length ? values.map((value) => `- ${value}`).join("\n") : "- None";
}
