#!/usr/bin/env node

import { runDailyCurator } from "../src/telegram-bot/daily-curator.mjs";

try {
  const result = await runDailyCurator();
  process.exitCode = result.exitCode;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

