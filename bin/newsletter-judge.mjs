#!/usr/bin/env node

import { runCli } from "../src/newsletter-judge/cli.mjs";

try {
  const result = await runCli(process.argv.slice(2));
  process.exitCode = result.exitCode;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
