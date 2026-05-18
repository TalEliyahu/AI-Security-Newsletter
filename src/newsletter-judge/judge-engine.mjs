import { createModelClient } from "./model-client.mjs";
import { validateJudgeReport } from "./schema.mjs";

export function buildJudgingPrompt({ items, sourceResults = [] }) {
  return [
    "You are a strict technical editor for an AI security newsletter.",
    "Judge each candidate for AI security relevance, technical substance, correctness, source quality, practitioner value, novelty, and audience fit.",
    "Do not reward vendor marketing, generic AI news, or broad cybersecurity items without an AI-specific security mechanism.",
    `Items: ${JSON.stringify(items)}`,
    `Source verification: ${JSON.stringify(sourceResults.map((source) => ({
      status: source.source_verification_status,
      source_title: source.source_title,
      final_url: source.final_url,
      error: source.error
    })))}`
  ].join("\n\n");
}

export async function judgeNewsletter({ items, sourceResults = [], parserWarnings = [], modelClient } = {}) {
  const client = modelClient || createModelClient();
  const prompt = buildJudgingPrompt({ items, sourceResults });
  const rawOutput = await client.judgeIssue({
    prompt,
    items,
    sourceResults,
    parserWarnings
  });
  const report = parseModelOutput(rawOutput);
  return validateJudgeReport(stripPrivateFields(report));
}

export function parseModelOutput(output) {
  if (typeof output === "string") {
    try {
      return JSON.parse(output);
    } catch (error) {
      throw new Error(`Judge model returned malformed JSON: ${error.message}`);
    }
  }
  if (output && typeof output === "object") {
    return output;
  }
  throw new Error("Judge model returned an unsupported output type.");
}

function stripPrivateFields(report) {
  return JSON.parse(JSON.stringify(report));
}
