import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";

import { BOT_COMMANDS, handlePrivateMessageCommand } from "./command-handler.mjs";
import { DEFAULT_ALLOWED_UPDATES, TelegramBotApi } from "./api.mjs";
import { fetchPublicChannelPosts, formatPublicChannelPost } from "./public-channel.mjs";
import {
  extractUpdateMessage,
  formatMessageSummary,
  parseAllowedUserIds,
  summarizeMessageUpdate
} from "./messages.mjs";

const DEFAULT_CHANNEL = "@AISecHub";
const DEFAULT_STATE_PATH = ".telegram-bot-state.json";

function parseArgs(argv) {
  const args = [...argv];
  const command = args.shift() || "help";
  const options = {};
  const positionals = [];

  while (args.length) {
    const arg = args.shift();
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }

    const [rawKey, inlineValue] = arg.slice(2).split("=", 2);
    const key = rawKey.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (inlineValue !== undefined) {
      options[key] = inlineValue;
    } else if (args[0] && !args[0].startsWith("--")) {
      options[key] = args.shift();
    } else {
      options[key] = true;
    }
  }

  return { command, options, positionals };
}

function intOption(value, fallback, { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function boolOption(value, fallback = false) {
  if (value === undefined) return fallback;
  if (value === true) return true;
  return !/^(false|0|no|off)$/i.test(String(value));
}

function channelFrom(options, env) {
  return options.channel || env.TELEGRAM_CHANNEL || DEFAULT_CHANNEL;
}

function createBot(options, env, fetchImpl) {
  return new TelegramBotApi({
    token: options.token || env.TELEGRAM_BOT_TOKEN,
    fetchImpl
  });
}

function printHelp(stdout) {
  stdout.write(`AISecHub Telegram bot helper

Usage:
  npm run telegram -- status
  npm run telegram -- latest-public --limit 20
  npm run telegram -- updates --limit 20 --timeout 10
  npm run telegram -- listen
  npm run telegram -- send --text "message"
  npm run telegram -- edit --message-id 123 --text "new text"
  npm run telegram -- delete --message-id 123
  npm run telegram -- register-commands
  npm run telegram -- webhook status
  npm run telegram -- webhook set --url https://example.com/telegram/webhook
  npm run telegram -- webhook delete
  npm run telegram -- webhook serve --port 8787 --path /telegram/webhook

Environment:
  TELEGRAM_BOT_TOKEN       Required for Bot API commands.
  TELEGRAM_CHANNEL         Defaults to @AISecHub.
  TELEGRAM_ALLOWED_USER_IDS Comma-separated user ids allowed to /send from DM.
  TELEGRAM_WEBHOOK_SECRET  Optional webhook secret token.
`);
}

function printJson(stdout, value) {
  stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

async function loadLocalEnv(env, envPath = path.resolve(process.cwd(), ".env")) {
  try {
    const text = await fs.readFile(envPath, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (!match) continue;

      const [, key, rawValue] = match;
      if (env[key] !== undefined) continue;

      env[key] = rawValue
        .replace(/^['"]|['"]$/g, "")
        .replace(/\\n/g, "\n");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

async function readState(statePath) {
  try {
    return JSON.parse(await fs.readFile(statePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw error;
  }
}

async function writeState(statePath, state) {
  await fs.writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`);
}

async function printUpdates({ bot, options, stdout }) {
  const limit = intOption(options.limit, 20, { min: 1, max: 100 });
  const timeout = intOption(options.timeout, 0, { min: 0, max: 50 });
  const offset = options.offset === undefined ? undefined : intOption(options.offset, undefined);
  const updates = await bot.getUpdates({ offset, limit, timeout });

  if (options.raw) {
    printJson(stdout, updates);
  } else if (updates.length === 0) {
    stdout.write("No pending Bot API updates.\n");
  } else {
    for (const update of updates) {
      stdout.write(`${formatMessageSummary(summarizeMessageUpdate(update))}\n\n`);
    }
  }

  if (options.ack && updates.length) {
    const nextOffset = Math.max(...updates.map((update) => update.update_id)) + 1;
    await bot.getUpdates({ offset: nextOffset, limit: 1, timeout: 0 });
    stdout.write(`Acknowledged updates through offset ${nextOffset}.\n`);
  }
}

async function status({ bot, channel, stdout }) {
  const me = await bot.getMe();
  const chat = await bot.getChat(channel);
  const member = await bot.getChatMember(chat.id, me.id);
  const webhook = await bot.getWebhookInfo();

  printJson(stdout, {
    bot: {
      id: me.id,
      username: me.username,
      can_join_groups: me.can_join_groups,
      can_read_all_group_messages: me.can_read_all_group_messages
    },
    channel: {
      id: chat.id,
      title: chat.title,
      username: chat.username,
      type: chat.type,
      has_visible_history: chat.has_visible_history
    },
    membership: {
      status: member.status,
      can_manage_chat: member.can_manage_chat,
      can_post_messages: member.can_post_messages,
      can_edit_messages: member.can_edit_messages,
      can_delete_messages: member.can_delete_messages,
      can_manage_direct_messages: member.can_manage_direct_messages
    },
    webhook: {
      url: webhook.url,
      pending_update_count: webhook.pending_update_count,
      allowed_updates: webhook.allowed_updates
    }
  });
}

async function listen({ bot, channel, options, env, fetchImpl, stdout, stderr }) {
  const statePath = options.state || env.TELEGRAM_STATE_PATH || path.resolve(process.cwd(), DEFAULT_STATE_PATH);
  const state = await readState(statePath);
  let offset = options.offset === undefined
    ? state.offset
    : intOption(options.offset, undefined);

  if (options.fromNow) {
    const pending = await bot.getUpdates({ limit: 100, timeout: 0 });
    if (pending.length) {
      offset = Math.max(...pending.map((update) => update.update_id)) + 1;
      await bot.getUpdates({ offset, limit: 1, timeout: 0 });
      await writeState(statePath, { offset, updated_at: new Date().toISOString() });
    }
  }

  const allowedUserIds = parseAllowedUserIds(env.TELEGRAM_ALLOWED_USER_IDS);
  stdout.write(`Listening for Telegram updates on ${channel}. State: ${statePath}\n`);

  let keepRunning = true;
  const stop = () => {
    keepRunning = false;
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  while (keepRunning) {
    try {
      const updates = await bot.getUpdates({
        offset,
        limit: 100,
        timeout: intOption(options.timeout, 30, { min: 1, max: 50 })
      });

      for (const update of updates) {
        const summary = summarizeMessageUpdate(update);
        stdout.write(`${formatMessageSummary(summary)}\n\n`);

        const extracted = extractUpdateMessage(update);
        if (extracted?.kind === "message" && extracted.message.chat?.type === "private") {
          await handlePrivateMessageCommand({
            bot,
            message: extracted.message,
            channel,
            fetchImpl,
            allowedUserIds
          });
        }
      }

      if (updates.length) {
        offset = Math.max(...updates.map((update) => update.update_id)) + 1;
        await writeState(statePath, { offset, updated_at: new Date().toISOString() });
      }
    } catch (error) {
      stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }

  stdout.write("Stopped Telegram listener.\n");
}

async function send({ bot, channel, options, positionals, stdout }) {
  const text = options.text || positionals.join(" ");
  if (!text) throw new Error("Provide message text with --text or as arguments.");

  const sent = await bot.sendMessage({
    chatId: channel,
    text,
    parseMode: options.parseMode,
    disableWebPagePreview: options.disableWebPagePreview === undefined
      ? undefined
      : boolOption(options.disableWebPagePreview)
  });
  stdout.write(`Sent message ${sent.message_id} to ${channel}.\n`);
}

async function edit({ bot, channel, options, positionals, stdout }) {
  const text = options.text || positionals.join(" ");
  const messageId = intOption(options.messageId, undefined);
  if (!messageId) throw new Error("--message-id is required.");
  if (!text) throw new Error("Provide replacement text with --text or as arguments.");

  await bot.editMessageText({
    chatId: channel,
    messageId,
    text,
    parseMode: options.parseMode,
    disableWebPagePreview: options.disableWebPagePreview === undefined
      ? undefined
      : boolOption(options.disableWebPagePreview)
  });
  stdout.write(`Edited message ${messageId} in ${channel}.\n`);
}

async function remove({ bot, channel, options, stdout }) {
  const messageId = intOption(options.messageId, undefined);
  if (!messageId) throw new Error("--message-id is required.");

  await bot.deleteMessage({ chatId: channel, messageId });
  stdout.write(`Deleted message ${messageId} from ${channel}.\n`);
}

async function latestPublic({ channel, options, fetchImpl, stdout }) {
  const limit = intOption(options.limit, 20, { min: 1, max: 100 });
  const posts = await fetchPublicChannelPosts({ channel, fetchImpl });
  const latest = posts.slice(-limit);

  if (options.raw) {
    printJson(stdout, latest);
    return;
  }

  if (!latest.length) {
    stdout.write("No public channel posts were found.\n");
    return;
  }

  stdout.write(`${latest.map(formatPublicChannelPost).join("\n\n---\n\n")}\n`);
}

async function webhook({ bot, options, positionals, env, fetchImpl, stdout, stderr, channel }) {
  const subcommand = positionals.shift() || "status";

  if (subcommand === "status") {
    printJson(stdout, await bot.getWebhookInfo());
    return;
  }

  if (subcommand === "set") {
    const url = options.url || positionals[0];
    if (!url) throw new Error("webhook set requires --url.");
    await bot.setWebhook({
      url,
      secretToken: options.secret || env.TELEGRAM_WEBHOOK_SECRET,
      dropPendingUpdates: boolOption(options.dropPendingUpdates)
    });
    stdout.write(`Webhook set to ${url}.\n`);
    return;
  }

  if (subcommand === "delete") {
    await bot.deleteWebhook({ dropPendingUpdates: boolOption(options.dropPendingUpdates) });
    stdout.write("Webhook deleted.\n");
    return;
  }

  if (subcommand === "serve") {
    await serveWebhook({ bot, channel, options, env, fetchImpl, stdout, stderr });
    return;
  }

  throw new Error(`Unknown webhook subcommand: ${subcommand}`);
}

async function serveWebhook({ bot, channel, options, env, fetchImpl, stdout, stderr }) {
  const port = intOption(options.port || env.PORT, 8787, { min: 1, max: 65535 });
  const webhookPath = options.path || env.TELEGRAM_WEBHOOK_PATH || "/telegram/webhook";
  const allowedUserIds = parseAllowedUserIds(env.TELEGRAM_ALLOWED_USER_IDS);
  const secret = options.secret || env.TELEGRAM_WEBHOOK_SECRET || "";

  const server = http.createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true }));
      return;
    }

    if (request.method !== "POST" || request.url !== webhookPath) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false, error: "not found" }));
      return;
    }

    if (secret && request.headers["x-telegram-bot-api-secret-token"] !== secret) {
      response.writeHead(401, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false, error: "bad secret" }));
      return;
    }

    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const update = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const summary = summarizeMessageUpdate(update);
      stdout.write(`${formatMessageSummary(summary)}\n\n`);

      const extracted = extractUpdateMessage(update);
      if (extracted?.kind === "message" && extracted.message.chat?.type === "private") {
        await handlePrivateMessageCommand({
          bot,
          message: extracted.message,
          channel,
          fetchImpl,
          allowedUserIds
        });
      }

      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true }));
    } catch (error) {
      stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false }));
    }
  });

  await new Promise((resolve) => server.listen(port, resolve));
  stdout.write(`Webhook server listening on http://127.0.0.1:${port}${webhookPath}\n`);
  stdout.write("Use a public HTTPS URL or tunnel, then run webhook set --url <public-url>.\n");

  await new Promise((resolve) => {
    const stop = () => server.close(resolve);
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

export async function runTelegramCli(
  argv,
  {
    env = process.env,
    fetchImpl = globalThis.fetch,
    stdout = process.stdout,
    stderr = process.stderr
  } = {}
) {
  await loadLocalEnv(env);

  const { command, options, positionals } = parseArgs(argv);
  const channel = channelFrom(options, env);

  try {
    if (command === "help" || command === "--help" || command === "-h") {
      printHelp(stdout);
      return { exitCode: 0 };
    }

    if (command === "latest-public") {
      await latestPublic({ channel, options, fetchImpl, stdout });
      return { exitCode: 0 };
    }

    const bot = createBot(options, env, fetchImpl);

    if (command === "status") {
      await status({ bot, channel, stdout });
    } else if (command === "updates") {
      await printUpdates({ bot, options, stdout });
    } else if (command === "listen") {
      await listen({ bot, channel, options, env, fetchImpl, stdout, stderr });
    } else if (command === "send") {
      await send({ bot, channel, options, positionals, stdout });
    } else if (command === "edit") {
      await edit({ bot, channel, options, positionals, stdout });
    } else if (command === "delete") {
      await remove({ bot, channel, options, stdout });
    } else if (command === "register-commands") {
      await bot.setMyCommands(BOT_COMMANDS);
      stdout.write("Bot command menu registered.\n");
    } else if (command === "webhook") {
      await webhook({ bot, options, positionals, env, fetchImpl, stdout, stderr, channel });
    } else {
      throw new Error(`Unknown command: ${command}`);
    }

    return { exitCode: 0 };
  } catch (error) {
    stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return { exitCode: 1 };
  }
}

export { parseArgs };
