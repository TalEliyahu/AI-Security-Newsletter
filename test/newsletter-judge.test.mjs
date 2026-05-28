import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseJsonNewsletter, parseMarkdownNewsletter } from "../src/newsletter-judge/parser.mjs";
import { verifySourcesForItems } from "../src/newsletter-judge/source-verifier.mjs";
import { judgeNewsletter } from "../src/newsletter-judge/judge-engine.mjs";
import { HeuristicJudgeModelClient, MockJudgeModelClient, OpenAIJudgeModelClient } from "../src/newsletter-judge/model-client.mjs";
import { decide, sumScores } from "../src/newsletter-judge/rubric.mjs";
import { validateJudgeReport } from "../src/newsletter-judge/schema.mjs";
import { runJudgeWorkflow } from "../src/newsletter-judge/cli.mjs";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

test("markdown parser extracts item titles, urls, summaries, and sections", async () => {
  const text = await fs.readFile(path.join(__dirname, "fixtures", "sample-newsletter.md"), "utf8");
  const parsed = parseMarkdownNewsletter(text);
  assert.equal(parsed.items.length, 3);
  assert.equal(parsed.items[0].title, "Indirect Prompt Injection in Browser Agents");
  assert.equal(parsed.items[0].url, "https://example.com/prompt-injection");
  assert.equal(parsed.items[0].section, "Research");
  assert.match(parsed.items[0].summary, /exfiltrate user data/);
  assert.equal(parsed.items[2].title, "Agent Guard Tool");
  assert.equal(parsed.items[2].url, "https://github.com/example/agent-guard");
});

test("markdown parser treats CVEs and Practitioner Discussions as sections, not items", () => {
  const parsed = parseMarkdownNewsletter(`# AI Security Newsletter - May 2026

# 🚨 CVEs

🛡️ [CVE-2026-41497](https://nvd.nist.gov/vuln/detail/CVE-2026-41497)
Critical MCP command handling issue in an agent orchestration path.

---

# 💬 Practitioner Discussions

💬 [Production AI security thread](https://www.reddit.com/r/cybersecurity/comments/example/thread/)
Practitioners compare agent access control, logging, and revocation.
`);
  assert.deepEqual(parsed.items.map((item) => item.title), [
    "CVE-2026-41497",
    "Production AI security thread"
  ]);
  assert.equal(parsed.items[0].section, "CVEs");
  assert.equal(parsed.items[1].section, "Practitioner Discussions");
});

test("markdown parser handles multi-keycap numbered video items", () => {
  const parsed = parseMarkdownNewsletter(`# AI Security Newsletter - May 2026

# 🎥 Videos

🔟 [MCPwned](https://www.youtube.com/watch?v=example10) - Speaker at Conference

1️⃣1️⃣ [Prompt, Commit, Repeat](https://www.youtube.com/watch?v=example11) - Speaker at Conference
`);
  assert.deepEqual(parsed.items.map((item) => item.title), [
    "MCPwned",
    "Prompt, Commit, Repeat"
  ]);
});

test("json parser supports object with items array", async () => {
  const text = await fs.readFile(path.join(__dirname, "fixtures", "sample-newsletter.json"), "utf8");
  const parsed = parseJsonNewsletter(text);
  assert.equal(parsed.items.length, 7);
  assert.equal(parsed.items[0].title, "Indirect Prompt Injection Against Web-Connected Agents");
  assert.equal(parsed.items[0].section, "Insights");
});

test("score aggregation sums seven rubric scores", () => {
  const total = sumScores({
    ai_security_relevance: 5,
    technical_substance: 4,
    correctness: 3,
    practitioner_value: 5,
    source_quality: 4,
    novelty_timeliness: 4,
    audience_fit: 5
  });
  assert.equal(total, 30);
});

test("decision thresholds remain strict around weak and strong scores", () => {
  assert.equal(
    decide({
      ai_security_relevance: 5,
      technical_substance: 5,
      correctness: 5,
      practitioner_value: 5,
      source_quality: 5,
      novelty_timeliness: 3,
      audience_fit: 5,
      total: 33
    }, { vendorNoise: false, genericAiNews: false }, "not_requested", []),
    "KEEP"
  );
  assert.equal(
    decide({
      ai_security_relevance: 1,
      technical_substance: 1,
      correctness: 4,
      practitioner_value: 1,
      source_quality: 1,
      novelty_timeliness: 3,
      audience_fit: 1,
      total: 12
    }, { vendorNoise: true, genericAiNews: false }, "not_requested", []),
    "DROP"
  );
});

test("formal CVE critical severity labels are not treated as hype", async () => {
  const report = await judgeNewsletter({
    items: [
      {
        title: "CVE-2026-41497",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2026-41497",
        section: "CVEs",
        summary: "Critical 9.8 MCP command handling vulnerability in an AI agent framework with RCE, authorization, sandbox, and mitigation impact."
      }
    ],
    sourceResults: [
      {
        source_verification_status: "verified",
        source_title: "CVE-2026-41497",
        source_text: "CVE-2026-41497 MCP command handling vulnerability RCE authorization sandbox mitigation",
        final_url: "https://nvd.nist.gov/vuln/detail/CVE-2026-41497",
        error: null
      }
    ],
    modelClient: new HeuristicJudgeModelClient()
  });
  assert.deepEqual(report.items[0].accuracy_concerns, []);
});

test("unsupported claim detection does not match claim acronyms inside ordinary words", async () => {
  const report = await judgeNewsletter({
    items: [
      {
        title: "LinkedIn profile prompt injection joke",
        url: "https://example.com/reddit-thread",
        section: "Practitioner Discussions",
        summary: "The post describes how profile text can force recruiting automation to write in Olde English prose."
      }
    ],
    sourceResults: [
      {
        source_verification_status: "verified",
        source_title: "LinkedIn profile prompt injection joke",
        source_text: "profile prompt injection recruiting automation Olde English prose",
        final_url: "https://example.com/reddit-thread",
        error: null
      }
    ],
    modelClient: new HeuristicJudgeModelClient()
  });
  assert.equal(report.items[0].accuracy_concerns.some((item) => item.includes('"rce"')), false);
});

test("schema validation rejects malformed reports", () => {
  assert.throws(() => validateJudgeReport({ items: [] }), /Invalid judge report/);
});

test("judge engine rejects malformed model JSON", async () => {
  await assert.rejects(
    () => judgeNewsletter({
      items: [],
      sourceResults: [],
      modelClient: new MockJudgeModelClient("{not valid json")
    }),
    /malformed JSON/
  );
});

test("OpenAI provider uses env-style API config without live network", async () => {
  let requestBody = null;
  const client = new OpenAIJudgeModelClient({
    apiKey: "test-key",
    model: "test-model",
    fetchImpl: async (url, options) => {
      assert.equal(url, "https://api.openai.com/v1/responses");
      assert.equal(options.headers.authorization, "Bearer test-key");
      requestBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          output_text: JSON.stringify(minimalValidReport())
        })
      };
    }
  });

  const output = await client.judgeIssue({
    items: [{ title: "Prompt injection item", url: null, summary: "Prompt injection in an LLM app." }],
    sourceResults: [{ source_verification_status: "no_url" }],
    parserWarnings: []
  });
  assert.equal(JSON.parse(output).final_recommendation, "PUBLISH_AFTER_EDITS");
  assert.equal(requestBody.model, "test-model");
  assert.equal(requestBody.text.format.type, "json_schema");
});

test("source verification failure is safe and does not invent source text", async () => {
  const results = await verifySourcesForItems(
    [{ title: "Broken URL", url: "https://example.invalid/source", summary: "AI security claim." }],
    {
      verifySources: true,
      fetchImpl: async () => {
        throw new Error("network disabled");
      }
    }
  );
  assert.equal(results[0].source_verification_status, "unavailable");
  assert.equal(results[0].source_text, "");
  assert.match(results[0].error, /network disabled/);
});

test("source verification extracts text from PDFs when requested", async () => {
  const results = await verifySourcesForItems(
    [{ title: "Agentic AI Services Guidance", url: "https://example.gov/agentic-ai.pdf", summary: "Agentic AI service controls." }],
    {
      verifySources: true,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        url: "https://example.gov/agentic-ai.pdf",
        headers: { get: () => "application/pdf" },
        arrayBuffer: async () => new Uint8Array([37, 80, 68, 70]).buffer
      }),
      pdfTextExtractor: async () => "Agentic AI services should use scoped privileges, monitoring, and containment."
    }
  );
  assert.equal(results[0].source_verification_status, "verified");
  assert.match(results[0].source_text, /scoped privileges/);
  assert.equal(results[0].source_title, "Agentic AI Services Guidance");
});

test("fixture decisions cover strong, vendor, funding, governance, overstated, tool, and weak news items", async () => {
  const text = await fs.readFile(path.join(__dirname, "fixtures", "sample-newsletter.json"), "utf8");
  const parsed = parseJsonNewsletter(text);
  const sourceResults = await verifySourcesForItems(parsed.items, { verifySources: false });
  const report = await judgeNewsletter({
    items: parsed.items,
    sourceResults,
    parserWarnings: parsed.warnings,
    modelClient: new HeuristicJudgeModelClient()
  });

  const byTitle = new Map(report.items.map((item) => [item.title, item]));
  assert.match(byTitle.get("Indirect Prompt Injection Against Web-Connected Agents").decision, /KEEP/);
  assert.equal(byTitle.get("VendorCorp launches Secure AI Platform").decision, "DROP");
  assert.equal(byTitle.get("Generic AI Startup Raises Series B").decision, "DROP");
  assert.notEqual(byTitle.get("AI Risk Framework Adds Model Supply Chain Controls").decision, "DROP");
  assert.match(
    byTitle.get("Critical Prompt Injection Breach Proves All Agents Are Unsafe").decision,
    /KEEP_BUT_REWRITE|NEEDS_SOURCE_VERIFICATION/
  );
  assert.equal(byTitle.get("agent-sandbox-checker").primary_category, "Tool Release");
  assert.ok(byTitle.get("agent-sandbox-checker").secondary_categories.includes("MCP Security"));
  assert.match(byTitle.get("AI Is Changing Everything").decision, /DROP|MOVE_TO_OPTIONAL/);
});

test("url fetch failure pushes correctness-sensitive item toward source verification", async () => {
  const parsed = parseJsonNewsletter(JSON.stringify({
    items: [
      {
        title: "Prompt Injection RCE in Agent Tool",
        url: "https://example.invalid/rce",
        summary: "A prompt injection exploit claims RCE and credential exfiltration in an AI agent."
      }
    ]
  }));
  const sourceResults = await verifySourcesForItems(parsed.items, {
    verifySources: true,
    fetchImpl: async () => {
      throw new Error("offline");
    }
  });
  const report = await judgeNewsletter({
    items: parsed.items,
    sourceResults,
    modelClient: new HeuristicJudgeModelClient()
  });
  assert.equal(report.items[0].source_verification_status, "unavailable");
  assert.equal(report.items[0].decision, "NEEDS_SOURCE_VERIFICATION");
});

test("workflow writes valid json and markdown reports", async () => {
  const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), "newsletter-judge-"));
  const result = await runJudgeWorkflow({
    inputPath: path.join(__dirname, "fixtures", "sample-newsletter.md"),
    outputDir,
    verifySources: false,
    provider: "heuristic"
  });
  const json = JSON.parse(await fs.readFile(result.paths.jsonPath, "utf8"));
  const markdown = await fs.readFile(result.paths.markdownPath, "utf8");
  assert.equal(json.items.length, 3);
  assert.match(markdown, /# AI Security Newsletter Judge Report/);
});

test("cli smoke test works for json input", async () => {
  const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), "newsletter-judge-cli-"));
  const { stdout } = await execFileAsync(
    process.execPath,
    [
      path.join(rootDir, "bin", "newsletter-judge.mjs"),
      path.join(__dirname, "fixtures", "sample-newsletter.json"),
      "--format",
      "json",
      "--output",
      outputDir,
      "--provider",
      "heuristic"
    ],
    { cwd: rootDir }
  );
  assert.match(stdout, /Recommendation:/);
  await fs.access(path.join(outputDir, "judge-report.md"));
  await fs.access(path.join(outputDir, "judge-report.json"));
});

function minimalValidReport() {
  return {
    overall_score: 75,
    final_recommendation: "PUBLISH_AFTER_EDITS",
    summary: {
      main_issue: "Needs a little source verification.",
      best_section: "Insights",
      biggest_weakness: "One item needs rewriting."
    },
    items: [
      {
        title: "Prompt injection item",
        url: null,
        source_verification_status: "no_url",
        decision: "KEEP_BUT_REWRITE",
        primary_category: "Prompt Injection",
        secondary_categories: [],
        source_type: "unknown",
        scores: {
          ai_security_relevance: 5,
          technical_substance: 4,
          correctness: 3,
          practitioner_value: 4,
          source_quality: 1,
          novelty_timeliness: 3,
          audience_fit: 4,
          total: 24
        },
        reason: "Relevant but needs a source.",
        accuracy_concerns: ["No source URL."],
        rewrite_guidance: "Add concrete mechanism and source.",
        suggested_rewrite: "Prompt injection item shows a concrete LLM appsec risk.",
        reviewer_notes: {
          prompt_injection_llm_appsec: "Useful if the trust boundary is clear.",
          enterprise_architect: "",
          ai_red_teamer: "",
          ml_security_researcher: "",
          governance_assurance: ""
        }
      }
    ],
    issue_level_review: {
      strongest_items: ["Prompt injection item"],
      weakest_items: ["Prompt injection item"],
      vendor_noise: [],
      generic_ai_news: [],
      needs_stronger_technical_framing: ["Prompt injection item"],
      missing_themes: ["Agent Security"],
      recommended_order: ["Prompt injection item"],
      suggested_headline: "Prompt Injection Needs Cleaner Framing",
      editors_note: "Verify sources before publishing."
    },
    warnings: []
  };
}
