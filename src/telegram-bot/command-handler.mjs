import { fetchPublicChannelPosts, formatPublicChannelPost } from "./public-channel.mjs";
import { isAllowedUser, parseAllowedUserIds, truncateTelegramText } from "./messages.mjs";

export const BOT_COMMANDS = [
  { command: "start", description: "Show bot help" },
  { command: "help", description: "Show bot help" },
  { command: "whoami", description: "Show your Telegram user id" },
  { command: "status", description: "Check the bot and channel connection" },
  { command: "latest", description: "Read latest public AISecHub posts" },
  { command: "send", description: "Send a message to the AISecHub channel" }
];

function commandName(text = "") {
  return text.trim().split(/\s+/, 1)[0]?.replace(/^\/+/, "").split("@")[0].toLowerCase() || "";
}

function commandArgs(text = "") {
  return text.trim().replace(/^\/\S+\s*/, "");
}

function helpText() {
  return [
    "AISecHub bot commands:",
    "/whoami - show your Telegram user id",
    "/status - verify bot/channel connection",
    "/latest 5 - show latest public channel posts",
    "/send text - send text to the channel",
    "",
    "Mutating commands require TELEGRAM_ALLOWED_USER_IDS."
  ].join("\n");
}

async function reply(bot, chatId, text, options = {}) {
  return bot.sendMessage({
    chatId,
    text: truncateTelegramText(text),
    disableWebPagePreview: options.disableWebPagePreview ?? true
  });
}

export async function handlePrivateMessageCommand({
  bot,
  message,
  channel,
  fetchImpl = globalThis.fetch,
  allowedUserIds = parseAllowedUserIds(process.env.TELEGRAM_ALLOWED_USER_IDS)
}) {
  const chatId = message?.chat?.id;
  const userId = message?.from?.id;
  const text = message?.text || "";
  const name = commandName(text);

  if (!chatId || !name) return null;

  if (name === "start" || name === "help") {
    await reply(bot, chatId, helpText());
    return "help";
  }

  if (name === "whoami") {
    await reply(bot, chatId, `Your Telegram user id is ${userId}.`);
    return "whoami";
  }

  if (name === "status") {
    const [me, chat, webhook] = await Promise.all([
      bot.getMe(),
      bot.getChat(channel),
      bot.getWebhookInfo()
    ]);
    const member = await bot.getChatMember(chat.id, me.id);
    await reply(bot, chatId, [
      `Bot: @${me.username}`,
      `Channel: ${chat.title || channel} (${chat.id})`,
      `Bot status: ${member.status}`,
      `Can post: ${Boolean(member.can_post_messages)}`,
      `Can edit: ${Boolean(member.can_edit_messages)}`,
      `Can delete: ${Boolean(member.can_delete_messages)}`,
      `Webhook: ${webhook.url || "[none]"}`
    ].join("\n"));
    return "status";
  }

  if (name === "latest") {
    const requested = Number.parseInt(commandArgs(text), 10);
    const limit = Number.isFinite(requested) ? Math.max(1, Math.min(10, requested)) : 5;
    const posts = await fetchPublicChannelPosts({ channel, fetchImpl });
    const formatted = posts.slice(-limit).map(formatPublicChannelPost).join("\n\n---\n\n");
    await reply(bot, chatId, formatted || "No public posts were found.");
    return "latest";
  }

  if (name === "send") {
    if (!isAllowedUser(userId, allowedUserIds)) {
      await reply(bot, chatId, [
        "Sending to the channel is locked.",
        "Send /whoami, then add that id to TELEGRAM_ALLOWED_USER_IDS on the bot host."
      ].join("\n"));
      return "send_denied";
    }

    const outbound = commandArgs(text);
    if (!outbound) {
      await reply(bot, chatId, "Usage: /send message text");
      return "send_empty";
    }

    const sent = await bot.sendMessage({
      chatId: channel,
      text: outbound,
      disableWebPagePreview: false
    });
    await reply(bot, chatId, `Sent to ${channel}. Message id: ${sent.message_id}.`);
    return "send";
  }

  return null;
}

