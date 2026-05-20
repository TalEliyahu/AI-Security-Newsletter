import fs from "node:fs/promises";
import path from "node:path";

import { TelegramBotApi } from "./api.mjs";
import { fetchPublicChannelPosts } from "./public-channel.mjs";

const DEFAULT_CHANNEL = "@AISecHub";
const DEFAULT_STATE_PATH = ".telegram-curator-state.json";

const SOURCES = [
  {
    name: "Microsoft Security",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    weight: 14
  },
  {
    name: "Google Security",
    url: "https://security.googleblog.com/feeds/posts/default?alt=rss",
    weight: 14
  },
  {
    name: "Trail of Bits",
    url: "https://blog.trailofbits.com/feed/",
    weight: 13
  },
  {
    name: "Snyk",
    url: "https://snyk.io/blog/feed/",
    weight: 12
  },
  {
    name: "GitHub Security",
    url: "https://github.blog/security/feed/",
    weight: 10
  },
  {
    name: "Cloudflare",
    url: "https://blog.cloudflare.com/tag/security/rss/",
    weight: 10
  }
];

const ARXIV_QUERIES = [
  "all:%22prompt injection%22",
  "all:%22AI agent%22 AND cat:cs.CR",
  "all:%22Model Context Protocol%22",
  "all:%22agentic AI%22 AND cat:cs.CR",
  "all:%22LLM agent%22 AND cat:cs.CR"
];

function parseArgs(argv) {
  const options = {
    limit: 5,
    dryRun: false,
    channel: process.env.TELEGRAM_CHANNEL || DEFAULT_CHANNEL
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--limit") options.limit = Number.parseInt(argv[++index], 10);
    else if (arg === "--channel") options.channel = argv[++index];
    else if (arg === "--state") options.statePath = argv[++index];
  }

  if (!Number.isFinite(options.limit) || options.limit < 1) options.limit = 5;
  options.limit = Math.min(options.limit, 10);
  options.statePath ||= path.resolve(process.cwd(), DEFAULT_STATE_PATH);
  return options;
}

async function loadLocalEnv(env = process.env, envPath = path.resolve(process.cwd(), ".env")) {
  try {
    const text = await fs.readFile(envPath, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (!match || env[match[1]] !== undefined) continue;
      env[match[1]] = match[2].replace(/^['"]|['"]$/g, "");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

async function readJson(filePath, fallback) {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw error;
  }
}

async function writeJson(filePath, value) {
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function decodeXml(value = "") {
  const named = {
    amp: "&",
    apos: "'",
    gt: ">",
    lt: "<",
    quot: "\""
  };

  return String(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal) => String.fromCodePoint(Number.parseInt(decimal, 10)))
    .replace(/&([a-z]+);/gi, (match, name) => named[name] ?? match)
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function firstMatch(block, patterns) {
  for (const pattern of patterns) {
    const match = block.match(pattern);
    if (match) return decodeXml(match[1]);
  }
  return "";
}

function parseFeedItems(xml, source) {
  const items = [];
  const itemBlocks = [...xml.matchAll(/<item\b[\s\S]*?<\/item>/gi)].map((match) => match[0]);
  const entryBlocks = [...xml.matchAll(/<entry\b[\s\S]*?<\/entry>/gi)].map((match) => match[0]);

  for (const block of itemBlocks) {
    items.push({
      source: source.name,
      sourceWeight: source.weight,
      title: firstMatch(block, [/<title[^>]*>([\s\S]*?)<\/title>/i]),
      url: firstMatch(block, [/<link[^>]*>([\s\S]*?)<\/link>/i, /<guid[^>]*>(https?:\/\/[\s\S]*?)<\/guid>/i]),
      summary: firstMatch(block, [/<description[^>]*>([\s\S]*?)<\/description>/i, /<content:encoded[^>]*>([\s\S]*?)<\/content:encoded>/i]),
      published: firstMatch(block, [/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i, /<dc:date[^>]*>([\s\S]*?)<\/dc:date>/i])
    });
  }

  for (const block of entryBlocks) {
    items.push({
      source: source.name,
      sourceWeight: source.weight,
      title: firstMatch(block, [/<title[^>]*>([\s\S]*?)<\/title>/i]),
      url: firstMatch(block, [
        /<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["'][^>]*>/i,
        /<link[^>]*href=["']([^"']+)["'][^>]*rel=["']alternate["'][^>]*>/i,
        /<id[^>]*>(https?:\/\/[\s\S]*?)<\/id>/i
      ]),
      summary: firstMatch(block, [/<summary[^>]*>([\s\S]*?)<\/summary>/i, /<content[^>]*>([\s\S]*?)<\/content>/i]),
      published: firstMatch(block, [/<published[^>]*>([\s\S]*?)<\/published>/i, /<updated[^>]*>([\s\S]*?)<\/updated>/i])
    });
  }

  return items.filter((item) => item.title && item.url?.startsWith("http"));
}

async function fetchText(url, fetchImpl = globalThis.fetch) {
  const response = await fetchImpl(url, {
    headers: {
      "user-agent": "AISecHubDailyCurator/1.0"
    }
  });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.text();
}

async function fetchFeedCandidates(fetchImpl = globalThis.fetch) {
  const results = await Promise.allSettled(
    SOURCES.map(async (source) => parseFeedItems(await fetchText(source.url, fetchImpl), source))
  );
  return results.flatMap((result) => result.status === "fulfilled" ? result.value : []);
}

async function fetchArxivCandidates(fetchImpl = globalThis.fetch) {
  const sources = ARXIV_QUERIES.map((query) => ({
    name: "arXiv",
    weight: 15,
    url: `https://export.arxiv.org/api/query?search_query=${encodeURIComponent(query)}&start=0&max_results=8&sortBy=submittedDate&sortOrder=descending`
  }));

  const results = await Promise.allSettled(
    sources.map(async (source) => parseFeedItems(await fetchText(source.url, fetchImpl), source))
  );

  return results
    .flatMap((result) => result.status === "fulfilled" ? result.value : [])
    .map((item) => ({
      ...item,
      url: item.url.replace(/^http:\/\//, "https://")
    }));
}

function normalize(value = "") {
  return value.toLowerCase().replace(/https?:\/\/(www\.)?/, "").replace(/\/$/, "").trim();
}

function buildPostedSet(posts, state) {
  const posted = new Set(state.postedUrls || []);
  for (const post of posts) {
    posted.add(normalize(post.url));
    posted.add(normalize(post.text?.split("\n")[0] || ""));
    for (const link of post.links || []) posted.add(normalize(link.href || link));
  }
  return posted;
}

function scoreCandidate(candidate) {
  const text = `${candidate.title} ${candidate.summary}`.toLowerCase();
  let score = candidate.sourceWeight || 0;
  const strongSignal = /model context protocol|\bmcp\b|prompt injection|indirect prompt|instruction injection|\bagentic\b|\bagent\b|ai agent|llm agent|supply.?chain|skill|plugin|coding agent|cursor|claude code|copilot|rce|code execution|cve|vulnerability|exploit|sandbox escape|red team|benchmark|eval|detection|response|telemetry|ai security|threat|attack/.test(text);
  if (!strongSignal) return -100;
  const titleSignal = /model context protocol|\bmcp\b|prompt injection|indirect prompt|instruction injection|\bagentic\b|\bagent\b|ai agent|llm agent|supply.?chain|skill|plugin|coding agent|cursor|claude code|copilot|rce|code execution|cve|vulnerability|exploit|sandbox escape|red team|benchmark|eval|detection|response|telemetry|ai security|threat|attack/.test(candidate.title.toLowerCase());
  if (!titleSignal) score -= 70;

  const bonuses = [
    [/model context protocol|\bmcp\b/, 34],
    [/prompt injection|indirect prompt|instruction injection/, 32],
    [/\bagentic\b|\bagent\b|ai agent|llm agent/, 26],
    [/supply.?chain|skill|plugin|coding agent|cursor|claude code|copilot/, 22],
    [/rce|code execution|cve|vulnerability|exploit|sandbox escape/, 22],
    [/red team|benchmark|eval|detection|response|telemetry/, 16],
    [/security framework|runtime|isolation|least privilege|policy/, 12],
    [/arxiv|research|paper|technical analysis/, 8]
  ];
  for (const [pattern, value] of bonuses) {
    if (pattern.test(text)) score += value;
  }

  const penalties = [
    [/funding|raises|acquires|launches|announces|press release/, 25],
    [/opinion|why .* matters|what you need to know|guide for beginners/, 14],
    [/marketing|webinar|sponsored|customer story/, 18],
    [/ai-native|productivity|workflow automation/, 10]
  ];
  for (const [pattern, value] of penalties) {
    if (pattern.test(text)) score -= value;
  }

  const publishedTime = Date.parse(candidate.published);
  if (Number.isFinite(publishedTime)) {
    const ageDays = (Date.now() - publishedTime) / 86400000;
    if (ageDays <= 7) score += 12;
    else if (ageDays <= 30) score += 7;
    else if (ageDays > 180) score -= 8;
  }

  return score;
}

function selectCandidates(candidates, posted, limit) {
  const byUrl = new Map();
  for (const candidate of candidates) {
    const urlKey = normalize(candidate.url);
    const titleKey = normalize(candidate.title);
    if (!urlKey || posted.has(urlKey) || posted.has(titleKey)) continue;
    if (!byUrl.has(urlKey)) byUrl.set(urlKey, candidate);
  }

  return [...byUrl.values()]
    .map((candidate) => ({ ...candidate, score: scoreCandidate(candidate) }))
    .filter((candidate) => candidate.score >= 35)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}

function formatPost(candidate) {
  return `${candidate.title}\n${candidate.url}`;
}

export async function runDailyCurator({
  argv = process.argv.slice(2),
  fetchImpl = globalThis.fetch,
  stdout = process.stdout,
  stderr = process.stderr
} = {}) {
  await loadLocalEnv();
  const options = parseArgs(argv);

  const [recentPosts, state, feedCandidates, arxivCandidates] = await Promise.all([
    fetchPublicChannelPosts({ channel: options.channel, fetchImpl }),
    readJson(options.statePath, { postedUrls: [] }),
    fetchFeedCandidates(fetchImpl),
    fetchArxivCandidates(fetchImpl)
  ]);

  const posted = buildPostedSet(recentPosts, state);
  const selected = selectCandidates([...feedCandidates, ...arxivCandidates], posted, options.limit);

  if (!selected.length) {
    stdout.write("No new high-confidence AISecHub candidates found.\n");
    return { exitCode: 0, posted: [] };
  }

  if (options.dryRun) {
    for (const candidate of selected) {
      stdout.write(`[${candidate.score}] ${formatPost(candidate)}\n\n`);
    }
    return { exitCode: 0, posted: [] };
  }

  const bot = new TelegramBotApi({ token: process.env.TELEGRAM_BOT_TOKEN, fetchImpl });
  const sent = [];
  for (const candidate of selected) {
    const message = await bot.sendMessage({
      chatId: options.channel,
      text: formatPost(candidate),
      disableWebPagePreview: false
    });
    sent.push({ ...candidate, messageId: message.message_id });
    stdout.write(`Sent message ${message.message_id}: ${candidate.title}\n`);
  }

  const nextState = {
    postedUrls: [...new Set([...(state.postedUrls || []), ...sent.map((item) => item.url)])].slice(-500),
    updatedAt: new Date().toISOString()
  };
  await writeJson(options.statePath, nextState);

  try {
    const latest = await fetchPublicChannelPosts({ channel: options.channel, fetchImpl });
    for (const post of latest.slice(-sent.length)) {
      stdout.write(`${post.url}\n`);
    }
  } catch (error) {
    stderr.write(`Preview verification failed: ${error.message}\n`);
  }

  return { exitCode: 0, posted: sent };
}
