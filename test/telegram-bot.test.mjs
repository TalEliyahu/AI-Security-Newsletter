import assert from "node:assert/strict";
import test from "node:test";

import { TelegramApiError, TelegramBotApi } from "../src/telegram-bot/api.mjs";
import { handlePrivateMessageCommand } from "../src/telegram-bot/command-handler.mjs";
import { parsePublicChannelPosts } from "../src/telegram-bot/public-channel.mjs";
import { summarizeMessageUpdate } from "../src/telegram-bot/messages.mjs";

test("TelegramBotApi sends form-encoded requests and parses results", async () => {
  let seenUrl;
  let seenBody;
  const api = new TelegramBotApi({
    token: "test-token",
    fetchImpl: async (url, options) => {
      seenUrl = url;
      seenBody = new URLSearchParams(options.body.toString());
      return {
        ok: true,
        json: async () => ({
          ok: true,
          result: { message_id: 42 }
        })
      };
    }
  });

  const result = await api.sendMessage({
    chatId: "@AISecHub",
    text: "hello",
    disableWebPagePreview: true
  });

  assert.equal(result.message_id, 42);
  assert.equal(seenUrl, "https://api.telegram.org/bottest-token/sendMessage");
  assert.equal(seenBody.get("chat_id"), "@AISecHub");
  assert.equal(seenBody.get("text"), "hello");
  assert.equal(seenBody.get("link_preview_options"), "{\"is_disabled\":true}");
});

test("TelegramBotApi throws useful errors on Bot API failures", async () => {
  const api = new TelegramBotApi({
    token: "test-token",
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        ok: false,
        description: "Bad Request: chat not found"
      })
    })
  });

  await assert.rejects(() => api.getChat("@missing"), TelegramApiError);
});

test("public channel parser extracts visible Telegram preview posts", () => {
  const posts = parsePublicChannelPosts(`
    <div class="tgme_widget_message_wrap js-widget_message_wrap">
      <div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="AISecHub/3115">
        <div class="tgme_widget_message_text js-message_text" dir="auto">
          AI Threat Report<br/>
          <a href="https://flashpoint.io/blog/ai-threat-report-monthly/">https://flashpoint.io/blog/ai-threat-report-monthly/</a>
        </div>
        <span class="tgme_widget_message_views">19</span>
        <time datetime="2026-05-20T22:06:23+00:00">22:06</time>
      </div>
    </div>
    <div class="tgme_widget_message_wrap js-widget_message_wrap">
      <div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="AISecHub/3116">
        <a class="tgme_widget_message_photo_wrap"></a>
        <time datetime="2026-05-20T23:00:00+00:00">23:00</time>
      </div>
    </div>
  `);

  assert.equal(posts.length, 2);
  assert.equal(posts[0].messageId, 3115);
  assert.match(posts[0].text, /AI Threat Report/);
  assert.equal(posts[0].links[0].href, "https://flashpoint.io/blog/ai-threat-report-monthly/");
  assert.equal(posts[1].media.hasPhoto, true);
});

test("channel post updates summarize text and metadata", () => {
  const summary = summarizeMessageUpdate({
    update_id: 10,
    channel_post: {
      message_id: 3115,
      date: 1779314783,
      chat: {
        id: -1002370456097,
        title: "AISecHub",
        type: "channel"
      },
      text: "AI Threat Report"
    }
  });

  assert.equal(summary.kind, "channel_post");
  assert.equal(summary.messageId, 3115);
  assert.equal(summary.chatTitle, "AISecHub");
  assert.equal(summary.text, "AI Threat Report");
});

test("private /send command is locked without an allowed user id", async () => {
  const replies = [];
  const bot = {
    sendMessage: async (message) => {
      replies.push(message);
      return { message_id: replies.length };
    }
  };

  const result = await handlePrivateMessageCommand({
    bot,
    channel: "@AISecHub",
    allowedUserIds: new Set(),
    message: {
      text: "/send hello channel",
      from: { id: 123 },
      chat: { id: 456, type: "private" }
    }
  });

  assert.equal(result, "send_denied");
  assert.equal(replies.length, 1);
  assert.equal(replies[0].chatId, 456);
  assert.match(replies[0].text, /locked/);
});

