import { buildHeuristicJudgeReport } from "./rubric.mjs";
import { JUDGE_REPORT_JSON_SCHEMA } from "./schema.mjs";

export class JudgeModelClient {
  async judgeIssue() {
    throw new Error("JudgeModelClient.judgeIssue must be implemented by a concrete client.");
  }
}

export class HeuristicJudgeModelClient extends JudgeModelClient {
  async judgeIssue(input) {
    return buildHeuristicJudgeReport(input);
  }
}

export class OpenAIJudgeModelClient extends JudgeModelClient {
  constructor(options = {}) {
    super();
    this.apiKey = options.apiKey || process.env.OPENAI_API_KEY || "";
    this.model = options.model || process.env.NEWSLETTER_JUDGE_MODEL || process.env.OPENAI_MODEL || "gpt-5.2";
    this.endpoint = options.endpoint || process.env.OPENAI_BASE_URL || "https://api.openai.com/v1";
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  async judgeIssue(input) {
    if (!this.apiKey) {
      throw new Error("OPENAI_API_KEY is required when using --provider openai.");
    }
    if (typeof this.fetchImpl !== "function") {
      throw new Error("fetch is not available in this Node runtime.");
    }

    const response = await this.fetchImpl(`${this.endpoint.replace(/\/$/, "")}/responses`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: this.model,
        input: [
          {
            role: "system",
            content: openAiSystemPrompt()
          },
          {
            role: "user",
            content: JSON.stringify(buildOpenAiInput(input))
          }
        ],
        text: {
          format: {
            type: "json_schema",
            name: "ai_security_newsletter_judge_report",
            strict: false,
            schema: JUDGE_REPORT_JSON_SCHEMA
          }
        }
      })
    });

    const payload = await response.json().catch(async () => {
      const text = typeof response.text === "function" ? await response.text() : "";
      throw new Error(`OpenAI response was not JSON: ${text.slice(0, 500)}`);
    });

    if (!response.ok) {
      throw new Error(`OpenAI request failed (${response.status}): ${JSON.stringify(payload).slice(0, 1000)}`);
    }

    const outputText = extractOutputText(payload);
    if (!outputText) {
      throw new Error("OpenAI response did not contain output text.");
    }
    return outputText;
  }
}

export class MockJudgeModelClient extends JudgeModelClient {
  constructor(response) {
    super();
    this.response = response;
  }

  async judgeIssue() {
    return this.response;
  }
}

export function createModelClient(options = {}) {
  const provider = resolveProvider(options.provider);
  if (provider === "openai") {
    return new OpenAIJudgeModelClient(options);
  }
  if (provider === "heuristic") {
    return new HeuristicJudgeModelClient();
  }
  throw new Error(`Unsupported judge provider "${provider}". Use heuristic or openai.`);
}

export function resolveProvider(provider) {
  if (provider && provider !== "auto") return provider;
  if (process.env.NEWSLETTER_JUDGE_PROVIDER) return process.env.NEWSLETTER_JUDGE_PROVIDER;
  return process.env.OPENAI_API_KEY ? "openai" : "heuristic";
}

function openAiSystemPrompt() {
  return [
    "You are a strict technical editor for the AI Security Newsletter.",
    "Return only valid JSON matching the supplied schema.",
    "Judge technical AI security signal, correctness, source quality, practitioner value, and audience fit.",
    "Be strict: drop vendor marketing, generic AI news, broad cyber without AI-specific security mechanics, and unsupported claims.",
    "Do not invent facts. If source verification is unavailable and correctness depends on it, use NEEDS_SOURCE_VERIFICATION.",
    "Use the requested reviewer archetypes only when they add useful technical signal. Do not force fake consensus.",
    "The audience is AI security engineers, AppSec/product security teams, AI red teamers, ML/platform engineers, security architects, founders/builders, and technically minded investors/advisors."
  ].join(" ");
}

function buildOpenAiInput(input) {
  return {
    task: "Judge this AI Security Newsletter draft item by item and at issue level.",
    parser_warnings: input.parserWarnings || [],
    items: (input.items || []).map((item, index) => ({
      index: index + 1,
      title: item.title,
      url: item.url,
      source: item.source,
      summary: item.summary,
      section: item.section,
      date: item.date,
      source_verification: summarizeSource(input.sourceResults?.[index])
    })),
    rubric: {
      score_range: "Each score is 0-5; total is 0-35.",
      decisions: ["KEEP", "KEEP_BUT_REWRITE", "MOVE_TO_OPTIONAL", "DROP", "NEEDS_SOURCE_VERIFICATION"],
      hard_rules: [
        "Do not reward generic AI hype.",
        "Do not reward vendor marketing.",
        "Do not accept vague claims without a concrete AI security mechanism.",
        "Treat missing or inaccessible sources as uncertainty.",
        "Prefer primary technical sources over summaries."
      ]
    }
  };
}

function summarizeSource(source) {
  if (!source) return null;
  return {
    source_verification_status: source.source_verification_status,
    source_title: source.source_title,
    final_url: source.final_url,
    error: source.error,
    source_excerpt: (source.source_text || "").slice(0, 4000)
  };
}

function extractOutputText(payload) {
  if (typeof payload.output_text === "string") {
    return payload.output_text;
  }
  const chunks = [];
  for (const output of payload.output || []) {
    for (const content of output.content || []) {
      if (typeof content.text === "string") chunks.push(content.text);
      if (typeof content.output_text === "string") chunks.push(content.output_text);
    }
  }
  return chunks.join("\n").trim();
}
