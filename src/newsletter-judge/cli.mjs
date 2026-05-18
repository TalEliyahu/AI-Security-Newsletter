import path from "node:path";
import { parseNewsletterFile } from "./parser.mjs";
import { verifySourcesForItems } from "./source-verifier.mjs";
import { judgeNewsletter } from "./judge-engine.mjs";
import { writeReports } from "./report-generator.mjs";

export async function runCli(argv, options = {}) {
  const parsed = parseArgs(argv);
  if (parsed.help) {
    console.log(helpText());
    return { exitCode: 0 };
  }
  if (!parsed.inputPath) {
    console.error(helpText());
    return { exitCode: 1 };
  }

  const result = await runJudgeWorkflow({
    inputPath: parsed.inputPath,
    outputDir: parsed.outputDir,
    format: parsed.format,
    verifySources: parsed.verifySources,
    fetchImpl: options.fetchImpl
  });

  console.log(`Wrote ${result.paths.markdownPath}`);
  console.log(`Wrote ${result.paths.jsonPath}`);
  console.log(`Recommendation: ${result.report.final_recommendation}`);
  console.log(`Overall score: ${result.report.overall_score}`);
  return { exitCode: 0, ...result };
}

export async function runJudgeWorkflow({ inputPath, outputDir, format = "auto", verifySources = false, fetchImpl } = {}) {
  if (!inputPath) throw new Error("Missing newsletter input path.");
  const absoluteInput = path.resolve(inputPath);
  const absoluteOutput = path.resolve(outputDir || process.cwd());
  const parsed = await parseNewsletterFile(absoluteInput, { format });
  const sourceResults = await verifySourcesForItems(parsed.items, {
    verifySources,
    fetchImpl
  });
  const report = await judgeNewsletter({
    items: parsed.items,
    sourceResults,
    parserWarnings: parsed.warnings
  });
  const paths = await writeReports(report, absoluteOutput);
  return {
    report,
    paths,
    parsed,
    sourceResults
  };
}

export function parseArgs(argv) {
  const result = {
    inputPath: null,
    outputDir: process.cwd(),
    format: "auto",
    verifySources: false,
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      result.help = true;
      continue;
    }
    if (arg === "--output" || arg === "-o") {
      result.outputDir = requireValue(argv, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--format") {
      result.format = requireValue(argv, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--verify-sources") {
      result.verifySources = true;
      continue;
    }
    if (arg === "--no-source-verification") {
      result.verifySources = false;
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`Unknown option ${arg}`);
    }
    if (!result.inputPath) {
      result.inputPath = arg;
      continue;
    }
    throw new Error(`Unexpected positional argument ${arg}`);
  }

  return result;
}

function requireValue(argv, index, optionName) {
  const value = argv[index + 1];
  if (!value || value.startsWith("-")) {
    throw new Error(`${optionName} requires a value.`);
  }
  return value;
}

function helpText() {
  return [
    "Usage:",
    "  newsletter-judge ./newsletter.md",
    "  newsletter-judge ./newsletter.md --output ./reports/",
    "  newsletter-judge ./newsletter.json --format json",
    "  newsletter-judge ./newsletter.md --verify-sources",
    "  newsletter-judge ./newsletter.md --no-source-verification",
    "",
    "The tool writes judge-report.md and judge-report.json to the current directory unless --output is provided."
  ].join("\n");
}
