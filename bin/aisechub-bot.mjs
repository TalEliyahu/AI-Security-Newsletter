#!/usr/bin/env node

import { runTelegramCli } from "../src/telegram-bot/cli.mjs";

const result = await runTelegramCli(process.argv.slice(2));
process.exitCode = result.exitCode;

