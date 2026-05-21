import assert from "node:assert/strict";
import test from "node:test";

import { TelegramApiError, TelegramBotApi } from "../src/telegram-bot/api.mjs";
import { handlePrivateMessageCommand } from "../src/telegram-bot/command-handler.mjs";
import {
  buildEngagementProfile,
  buildPostedSet,
  parseViews,
  rankCandidates,
  scoreCandidate,
  updateEngagementState
} from "../src/telegram-bot/daily-curator.mjs";
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

test("daily curator parses Telegram view counts", () => {
  assert.equal(parseViews("42"), 42);
  assert.equal(parseViews("1.2K"), 1200);
  assert.equal(parseViews("2M"), 2000000);
});

test("daily curator stores engagement snapshots and normalized views", () => {
  const now = new Date("2026-05-22T00:00:00Z");
  const state = updateEngagementState(
    { postedUrls: [], engagement: { posts: [] } },
    [
      {
        messageId: 3120,
        url: "https://t.me/AISecHub/3120",
        datetime: "2026-05-19T23:00:00Z",
        views: "1.2K",
        text: "MCP Server RCE in Agent Tools\nhttps://example.com/mcp-rce",
        links: [{ href: "https://example.com/mcp-rce" }]
      }
    ],
    now
  );

  const record = state.engagement.posts[0];
  assert.equal(record.views, 1200);
  assert.equal(record.url, "https://example.com/mcp-rce");
  assert.ok(record.normalizedViewsPerDay > 500);
  assert.equal(record.performance24h.views, 1200);
  assert.equal(record.performance48h.views, 1200);
  assert.deepEqual(record.topics.sort(), ["agent-security", "exploit-vuln-research", "mcp-security"].sort());
});

test("daily curator blocks duplicate titles and URLs", () => {
  const posted = buildPostedSet(
    [
      {
        url: "https://t.me/AISecHub/3124",
        text: "Breaking Anthropic MCP Server\nhttps://cyata.ai/blog/mcp",
        links: [{ href: "https://cyata.ai/blog/mcp" }]
      }
    ],
    { postedUrls: ["https://example.com/already-posted"], engagement: { posts: [] } }
  );

  const result = rankCandidates(
    [
      {
        title: "Breaking Anthropic MCP Server",
        url: "https://new.example.com/same-title",
        source: "Example",
        sourceWeight: 10,
        summary: "MCP server exploit research."
      },
      {
        title: "New MCP Server RCE",
        url: "https://cyata.ai/blog/mcp",
        source: "Cyata",
        sourceWeight: 15,
        summary: "RCE in MCP server."
      }
    ],
    posted,
    { limit: 5, threshold: 0, engagementProfile: {}, now: new Date("2026-05-22T00:00:00Z") }
  );

  assert.equal(result.selected.length, 0);
  assert.equal(result.rejected.filter((candidate) => candidate.decisionReason === "duplicate title or URL").length, 2);
});

test("daily curator weighted scoring prefers technical AI security over generic AI posts", () => {
  const now = new Date("2026-05-22T00:00:00Z");
  const strong = scoreCandidate(
    {
      title: "MCP Server Remote Code Execution in AI Agent Tooling",
      url: "https://cyata.ai/blog/mcp-rce",
      source: "Cyata",
      sourceWeight: 15,
      summary: "Technical exploit analysis with prompt injection, MCP tool abuse, and code execution.",
      published: "2026-05-21T00:00:00Z"
    },
    { engagementProfile: {}, now }
  );
  const generic = scoreCandidate(
    {
      title: "AI Startup Launches New Productivity Assistant",
      url: "https://example.com/ai-productivity",
      source: "Example",
      sourceWeight: 1,
      summary: "Product launch announcement for workflow automation.",
      published: "2026-05-21T00:00:00Z"
    },
    { engagementProfile: {}, now }
  );
  const arxiv = scoreCandidate(
    {
      title: "Agent Audit: A Security Analysis System for LLM Agent Applications",
      url: "https://arxiv.org/abs/2603.22853",
      source: "arXiv",
      sourceWeight: 18,
      summary: "Research paper on detecting vulnerabilities in LLM agent applications.",
      published: "2026-05-20T00:00:00Z"
    },
    { engagementProfile: {}, now }
  );

  assert.ok(strong.score > 120);
  assert.ok(arxiv.score > 90);
  assert.ok(generic.score < 0);
});

test("daily curator boosts topics with above-baseline engagement", () => {
  const now = new Date("2026-05-22T00:00:00Z");
  const engagementProfile = buildEngagementProfile(
    {
      engagement: {
        posts: [
          {
            title: "MCP Server Exploit",
            url: "https://example.com/mcp-1",
            sourceDomain: "example.com",
            postedAt: "2026-05-20T00:00:00Z",
            views: 1000,
            normalizedViewsPerDay: 500,
            topics: ["mcp-security"]
          },
          {
            title: "MCP Prompt Injection",
            url: "https://example.com/mcp-2",
            sourceDomain: "example.com",
            postedAt: "2026-05-20T00:00:00Z",
            views: 900,
            normalizedViewsPerDay: 450,
            topics: ["mcp-security"]
          },
          {
            title: "Governance Framework",
            url: "https://example.com/gov",
            sourceDomain: "example.org",
            postedAt: "2026-05-20T00:00:00Z",
            views: 100,
            normalizedViewsPerDay: 50,
            topics: ["ai-governance"]
          },
          {
            title: "AI RMF",
            url: "https://example.com/rmf",
            sourceDomain: "example.org",
            postedAt: "2026-05-20T00:00:00Z",
            views: 120,
            normalizedViewsPerDay: 60,
            topics: ["ai-governance"]
          }
        ]
      }
    },
    now
  );

  assert.ok(engagementProfile.topicBoosts["mcp-security"] > 0);
  assert.ok(engagementProfile.topicBoosts["ai-governance"] < 0);
});
