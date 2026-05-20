export const DEFAULT_ALLOWED_UPDATES = [
  "message",
  "edited_message",
  "channel_post",
  "edited_channel_post"
];

export class TelegramApiError extends Error {
  constructor(method, response, payload) {
    const description = payload?.description || response?.statusText || "Telegram API request failed";
    super(`${method}: ${description}`);
    this.name = "TelegramApiError";
    this.method = method;
    this.status = response?.status;
    this.payload = payload;
  }
}

export class TelegramBotApi {
  constructor({
    token = process.env.TELEGRAM_BOT_TOKEN,
    baseUrl = "https://api.telegram.org",
    fetchImpl = globalThis.fetch
  } = {}) {
    if (!token) {
      throw new Error("TELEGRAM_BOT_TOKEN is required");
    }
    if (!fetchImpl) {
      throw new Error("A fetch implementation is required");
    }

    this.token = token;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetchImpl = fetchImpl;
  }

  async request(method, params = {}) {
    const body = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value) || typeof value === "object") {
        body.set(key, JSON.stringify(value));
      } else {
        body.set(key, String(value));
      }
    }

    const response = await this.fetchImpl(`${this.baseUrl}/bot${this.token}/${method}`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body
    });

    let payload;
    try {
      payload = await response.json();
    } catch (error) {
      throw new TelegramApiError(method, response, { description: `Invalid JSON response: ${error.message}` });
    }

    if (!response.ok || !payload.ok) {
      throw new TelegramApiError(method, response, payload);
    }

    return payload.result;
  }

  getMe() {
    return this.request("getMe");
  }

  getChat(chatId) {
    return this.request("getChat", { chat_id: chatId });
  }

  getChatMember(chatId, userId) {
    return this.request("getChatMember", { chat_id: chatId, user_id: userId });
  }

  getWebhookInfo() {
    return this.request("getWebhookInfo");
  }

  getUpdates({
    offset,
    limit = 20,
    timeout = 0,
    allowedUpdates = DEFAULT_ALLOWED_UPDATES
  } = {}) {
    return this.request("getUpdates", {
      offset,
      limit,
      timeout,
      allowed_updates: allowedUpdates
    });
  }

  sendMessage({
    chatId,
    text,
    parseMode,
    disableWebPagePreview,
    replyToMessageId
  }) {
    return this.request("sendMessage", {
      chat_id: chatId,
      text,
      parse_mode: parseMode,
      link_preview_options: disableWebPagePreview === undefined
        ? undefined
        : { is_disabled: Boolean(disableWebPagePreview) },
      reply_parameters: replyToMessageId === undefined
        ? undefined
        : { message_id: Number(replyToMessageId) }
    });
  }

  editMessageText({
    chatId,
    messageId,
    text,
    parseMode,
    disableWebPagePreview
  }) {
    return this.request("editMessageText", {
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: parseMode,
      link_preview_options: disableWebPagePreview === undefined
        ? undefined
        : { is_disabled: Boolean(disableWebPagePreview) }
    });
  }

  deleteMessage({ chatId, messageId }) {
    return this.request("deleteMessage", {
      chat_id: chatId,
      message_id: messageId
    });
  }

  setWebhook({
    url,
    secretToken,
    allowedUpdates = DEFAULT_ALLOWED_UPDATES,
    dropPendingUpdates = false
  }) {
    return this.request("setWebhook", {
      url,
      secret_token: secretToken,
      allowed_updates: allowedUpdates,
      drop_pending_updates: dropPendingUpdates
    });
  }

  deleteWebhook({ dropPendingUpdates = false } = {}) {
    return this.request("deleteWebhook", {
      drop_pending_updates: dropPendingUpdates
    });
  }

  setMyCommands(commands) {
    return this.request("setMyCommands", { commands });
  }
}

