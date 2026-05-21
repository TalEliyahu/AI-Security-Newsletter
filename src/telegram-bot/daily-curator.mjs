import fs from "node:fs/promises";
import path from "node:path";

import { TelegramBotApi } from "./api.mjs";
import { parsePublicChannelPosts, publicChannelUrl } from "./public-channel.mjs";

const DEFAULT_CHANNEL = "@AISecHub";
const DEFAULT_STATE_PATH = ".telegram-curator-state.json";
const DEFAULT_LOG_PATH = "logs/aisechub-daily-curator.jsonl";
const HIGH_CONFIDENCE_THRESHOLD = 78;

const FEED_SOURCES = [
  { name: "Microsoft Security", url: "https://www.microsoft.com/en-us/security/blog/feed/", weight: 16 },
  { name: "Google Security", url: "https://security.googleblog.com/feeds/posts/default?alt=rss", weight: 16 },
  { name: "Trail of Bits", url: "https://blog.trailofbits.com/feed/", weight: 15 },
  { name: "JFrog Research", url: "https://research.jfrog.com/feed.xml", weight: 15 },
  { name: "Snyk", url: "https://snyk.io/blog/feed/", weight: 14 },
  { name: "GitHub Security", url: "https://github.blog/security/feed/", weight: 12 },
  { name: "Cloudflare Security", url: "https://blog.cloudflare.com/tag/security/rss/", weight: 12 },
  { name: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/", weight: 12 },
  { name: "Wiz", url: "https://www.wiz.io/blog/rss.xml", weight: 11 },
  { name: "Endor Labs", url: "https://www.endorlabs.com/learn/rss.xml", weight: 11 }
];

const PAGE_SOURCES = [
  { name: "Invariant Labs", url: "https://invariantlabs.ai/blog", baseUrl: "https://invariantlabs.ai", weight: 16 },
  { name: "Cyata", url: "https://cyata.ai/blog", baseUrl: "https://cyata.ai", weight: 15 },
  { name: "OX Security", url: "https://www.ox.security/blog", baseUrl: "https://www.ox.security", weight: 14 },
  { name: "Akamai Security Research", url: "https://www.akamai.com/blog/security-research", baseUrl: "https://www.akamai.com", weight: 13 },
  { name: "Google Cloud Threat Intelligence", url: "https://cloud.google.com/blog/topics/threat-intelligence", baseUrl: "https://cloud.google.com", weight: 13 },
  { name: "Anthropic Research", url: "https://www.anthropic.com/research", baseUrl: "https://www.anthropic.com", weight: 11 }
];

const ARXIV_QUERIES = [
  "all:%22prompt injection%22",
  "all:%22AI agent%22 AND cat:cs.CR",
  "all:%22Model Context Protocol%22",
  "all:%22agentic AI%22 AND cat:cs.CR",
  "all:%22LLM agent%22 AND cat:cs.CR",
  "all:%22AI security%22 AND cat:cs.CR",
  "all:%22coding agent%22 AND cat:cs.CR"
];

const TOPIC_RULES = [
  {
    id: "mcp-security",
    label: "MCP security",
    weight: 30,
    pattern: /model context protocol|\bmcp\b|tool poisoning|context poisoning|mcp server|mcp tool/i
  },
  {
    id: "prompt-injection",
    label: "prompt injection",
    weight: 29,
    pattern: /prompt injection|indirect prompt|instruction injection|hidden instruction|jailbreak|promptware/i
  },
  {
    id: "agent-security",
    label: "agent security",
    weight: 25,
    pattern: /\bagentic\b|\bagent\b|ai agent|llm agent|agentic browser|browser agent|tool use|runtime/i
  },
  {
    id: "ai-supply-chain",
    label: "AI supply chain",
    weight: 23,
    pattern: /supply.?chain|malicious (skill|plugin|extension|package)|skill ecosystem|agent skill|coding agent|claude code|copilot|cursor|pypi|npm|package/i
  },
  {
    id: "exploit-vuln-research",
    label: "exploit and vulnerability research",
    weight: 21,
    pattern: /rce|remote code execution|code execution|cve|vulnerability|exploit|sandbox escape|file read|data exfiltration/i
  },
  {
    id: "red-team-evals",
    label: "AI red teaming and evals",
    weight: 17,
    pattern: /red team|benchmark|eval|capability|attack simulation|offensive cyber|autonomous cyber/i
  },
  {
    id: "ai-soc-automation",
    label: "AI SOC and automation",
    weight: 13,
    pattern: /soc|detection|response|triage|telemetry|security operations|renovate/i
  },
  {
    id: "ai-governance",
    label: "AI governance",
    weight: 9,
    pattern: /governance|risk management|framework|standard|nist|rmf|policy|assurance/i
  }
];

const DOMAIN_AUTHORITY = new Map([
  ["arxiv.org", 18],
  ["microsoft.com", 17],
  ["security.googleblog.com", 17],
  ["blog.google", 17],
  ["cloud.google.com", 16],
  ["blog.trailofbits.com", 17],
  ["research.jfrog.com", 16],
  ["snyk.io", 15],
  ["github.blog", 13],
  ["github.com", 13],
  ["invariantlabs.ai", 16],
  ["cyata.ai", 15],
  ["ox.security", 14],
  ["akamai.com", 14],
  ["unit42.paloaltonetworks.com", 14],
  ["wiz.io", 13],
  ["endorlabs.com", 13],
  ["cloudflare.com", 13],
  ["anthropic.com", 12]
]);

const TECHNICAL_DEPTH_PATTERNS = [
  [/remote code execution|code execution|\brce\b|sandbox escape|arbitrary file read|sql injection/i, 18],
  [/cve-\d{4}-\d+|vulnerability|exploit|attack chain|proof of concept|poc/i, 16],
  [/prompt injection|indirect prompt|tool poisoning|context poisoning|data exfiltration/i, 16],
  [/mcp server|model context protocol|agentic browser|tool use|runtime isolation/i, 14],
  [/benchmark|dataset|evaluation|measurement|telemetry|detection system/i, 10],
  [/github\.com|open source|tool|framework|scanner|lab/i, 8],
  [/research|analysis|audit|threat model|technical/i, 6]
];

const PENALTY_PATTERNS = [
  [/funding|raises|series [abc]|acquires|acquisition|appoints|partnership/i, 35],
  [/launches|announces|now available|press release|customer story/i, 22],
  [/webinar|ebook|whitepaper download|sponsored|demo/i, 20],
  [/beginner|what is|guide for beginners|everything you need to know|top \d+ tips/i, 18],
  [/ai-native|productivity|workflow automation|leadership|future of work/i, 12]
];

function parseArgs(argv) {
  const options = {
    limit: 5,
    dryRun: false,
    channel: process.env.TELEGRAM_CHANNEL || DEFAULT_CHANNEL,
    historyPages: 6,
    threshold: HIGH_CONFIDENCE_THRESHOLD,
    logPath: path.resolve(process.cwd(), DEFAULT_LOG_PATH)
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--limit") options.limit = Number.parseInt(argv[++index], 10);
    else if (arg === "--channel") options.channel = argv[++index];
    else if (arg === "--state") options.statePath = argv[++index];
    else if (arg === "--history-pages") options.historyPages = Number.parseInt(argv[++index], 10);
    else if (arg === "--threshold") options.threshold = Number.parseInt(argv[++index], 10);
    else if (arg === "--log") options.logPath = path.resolve(process.cwd(), argv[++index]);
    else if (arg === "--no-log") options.logPath = null;
  }

  if (!Number.isFinite(options.limit) || options.limit < 1) options.limit = 5;
  options.limit = Math.min(options.limit, 10);
  if (!Number.isFinite(options.historyPages) || options.historyPages < 1) options.historyPages = 6;
  options.historyPages = Math.min(options.historyPages, 20);
  if (!Number.isFinite(options.threshold)) options.threshold = HIGH_CONFIDENCE_THRESHOLD;
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

async function appendLog(logPath, event) {
  if (!logPath) return;
  await fs.mkdir(path.dirname(logPath), { recursive: true });
  await fs.appendFile(logPath, `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);
}

function decodeXml(value = "") {
  const named = {
    amp: "&",
    apos: "'",
    hellip: "...",
    gt: ">",
    lt: "<",
    mdash: "-",
    quot: "\""
  };

  return String(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal) => String.fromCodePoint(Number.parseInt(decimal, 10)))
    .replace(/&([a-z]+);/gi, (match, name) => named[name] ?? match)
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
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
      sourceType: "feed",
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
      sourceType: "feed",
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

  return items
    .map(normalizeCandidate)
    .filter((item) => item.title && item.url?.startsWith("http") && isProbablyArticleUrl(item.url));
}

function parseHtmlCandidates(html, source) {
  const candidates = [];
  const seen = new Set();
  const linkPattern = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = linkPattern.exec(html)) !== null) {
    const href = decodeXml(match[1]);
    const title = decodeXml(match[2]);
    if (!href || !title || title.length < 8) continue;

    let url;
    try {
      url = new URL(href, source.baseUrl || source.url).toString();
    } catch {
      continue;
    }

    const key = canonicalUrl(url);
    if (seen.has(key) || !isProbablyArticleUrl(url)) continue;
    seen.add(key);
    candidates.push(normalizeCandidate({
      source: source.name,
      sourceWeight: source.weight,
      sourceType: "page",
      title,
      url,
      summary: `${source.name} curated page candidate`,
      published: ""
    }));
  }

  return candidates.filter((candidate) => extractTopics(candidate).length > 0);
}

async function fetchText(url, fetchImpl = globalThis.fetch, timeoutMs = 12000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      headers: {
        "user-agent": "AISecHubDailyCurator/2.0"
      },
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
    return response.text();
  } catch (error) {
    if (error.name === "AbortError") throw new Error(`${url}: fetch timed out after ${timeoutMs}ms`);
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchFeedCandidates(fetchImpl = globalThis.fetch) {
  const results = await Promise.allSettled(
    FEED_SOURCES.map(async (source) => parseFeedItems(await fetchText(source.url, fetchImpl), source))
  );
  return {
    candidates: results.flatMap((result) => result.status === "fulfilled" ? result.value : []),
    errors: results
      .map((result, index) => result.status === "rejected" ? `${FEED_SOURCES[index].name}: ${result.reason.message}` : null)
      .filter(Boolean)
  };
}

async function fetchPageCandidates(fetchImpl = globalThis.fetch) {
  const results = await Promise.allSettled(
    PAGE_SOURCES.map(async (source) => parseHtmlCandidates(await fetchText(source.url, fetchImpl), source))
  );
  return {
    candidates: results.flatMap((result) => result.status === "fulfilled" ? result.value : []),
    errors: results
      .map((result, index) => result.status === "rejected" ? `${PAGE_SOURCES[index].name}: ${result.reason.message}` : null)
      .filter(Boolean)
  };
}

async function fetchArxivCandidates(fetchImpl = globalThis.fetch) {
  const sources = ARXIV_QUERIES.map((query) => ({
    name: "arXiv",
    weight: 18,
    url: `https://export.arxiv.org/api/query?search_query=${encodeURIComponent(query)}&start=0&max_results=8&sortBy=submittedDate&sortOrder=descending`
  }));

  const results = await Promise.allSettled(
    sources.map(async (source) => parseFeedItems(await fetchText(source.url, fetchImpl), source))
  );

  return {
    candidates: results
      .flatMap((result) => result.status === "fulfilled" ? result.value : [])
      .map((item) => normalizeCandidate({ ...item, source: "arXiv", url: item.url.replace(/^http:\/\//, "https://") })),
    errors: results
      .map((result, index) => result.status === "rejected" ? `${sources[index].url}: ${result.reason.message}` : null)
      .filter(Boolean)
  };
}

async function fetchAllCandidates(fetchImpl = globalThis.fetch) {
  const [feeds, pages, arxiv] = await Promise.all([
    fetchFeedCandidates(fetchImpl),
    fetchPageCandidates(fetchImpl),
    fetchArxivCandidates(fetchImpl)
  ]);

  return {
    candidates: [...feeds.candidates, ...pages.candidates, ...arxiv.candidates],
    sourceErrors: [...feeds.errors, ...pages.errors, ...arxiv.errors]
  };
}

async function fetchRecentChannelPosts({ channel, pages = 6, fetchImpl = globalThis.fetch } = {}) {
  const posts = [];
  const seen = new Set();
  let before;

  for (let page = 0; page < pages; page += 1) {
    const url = before ? `${publicChannelUrl(channel)}?before=${before}` : publicChannelUrl(channel);
    const html = await fetchText(url, fetchImpl);
    const pagePosts = parsePublicChannelPosts(html);
    if (!pagePosts.length) break;

    let minMessageId = null;
    for (const post of pagePosts) {
      if (seen.has(post.post)) continue;
      seen.add(post.post);
      posts.push(post);
      if (post.messageId) minMessageId = minMessageId === null ? post.messageId : Math.min(minMessageId, post.messageId);
    }

    if (!minMessageId || minMessageId === before) break;
    before = minMessageId;
  }

  return posts.sort((a, b) => (a.messageId || 0) - (b.messageId || 0));
}

function canonicalUrl(value = "") {
  if (!value) return "";
  try {
    const url = new URL(value);
    url.hash = "";
    for (const param of [...url.searchParams.keys()]) {
      if (/^utm_|^fbclid$|^gclid$|^mc_|^ref$/i.test(param)) url.searchParams.delete(param);
    }
    url.hostname = url.hostname.replace(/^www\./, "").toLowerCase();
    url.pathname = url.pathname.replace(/\/$/, "");
    url.pathname = url.pathname.replace(/\/abs\/(\d{4}\.\d+?)v\d+$/i, "/abs/$1");
    return url.toString().replace(/\/$/, "");
  } catch {
    return String(value).toLowerCase().replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "").trim();
  }
}

function normalize(value = "") {
  return canonicalUrl(value)
    .replace(/^https?:\/\//, "")
    .toLowerCase()
    .trim();
}

function domainOf(value = "") {
  try {
    return new URL(value).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

function isProbablyArticleUrl(url) {
  const lower = url.toLowerCase();
  if (/\/comments\/default|\/feeds\/|\/tag\/|\/category\/?$|\/author\/|\/page\/\d+/.test(lower)) return false;
  if (/\.(png|jpe?g|gif|svg|webp|zip|tar|gz)$/i.test(lower)) return false;
  return true;
}

function normalizeCandidate(candidate) {
  const rawTitle = decodeXml(candidate.title || "").replace(/\s+/g, " ").trim();
  const published = candidate.published || inferPublishedDate(rawTitle, candidate.url || "");
  return {
    ...candidate,
    title: cleanCandidateTitle(rawTitle),
    url: canonicalUrl(candidate.url || ""),
    summary: decodeXml(candidate.summary || "").replace(/\s+/g, " ").trim(),
    source: candidate.source || domainOf(candidate.url || ""),
    sourceWeight: candidate.sourceWeight || 0,
    published
  };
}

function cleanCandidateTitle(title) {
  return title
    .replace(/^\d{4}[-/]\d{2}[-/]\d{2}\s+/, "")
    .replace(/\s+This post is part.*$/i, "")
    .replace(/\s+\|\s*Blog\s+\|\s*.*$/i, "")
    .replace(/\s+We (have|showcase|found|discovered|analyze|present|demonstrate)\b.*$/i, "")
    .replace(/\s+Read More\s*$/i, "")
    .replace(/\s+Read More.*$/i, "")
    .replace(/\.\.\..*$/i, "")
    .replace(/\s+/g, " ")
    .trim();
}

function inferPublishedDate(title = "", url = "") {
  const text = `${title} ${url}`;
  const dashed = text.match(/\b(20\d{2})[-/](\d{2})[-/](\d{2})\b/);
  if (dashed) return `${dashed[1]}-${dashed[2]}-${dashed[3]}T00:00:00Z`;

  const urlDate = text.match(/\/(20\d{2})\/(\d{1,2})\/(\d{1,2})\//);
  if (urlDate) {
    const [, year, month, day] = urlDate;
    return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}T00:00:00Z`;
  }

  return "";
}

function parseViews(value) {
  if (typeof value === "number") return value;
  const text = String(value || "").trim().replace(/,/g, "");
  if (!text) return 0;
  const match = text.match(/^([\d.]+)\s*([kmb])?$/i);
  if (!match) return Number.parseInt(text, 10) || 0;
  const base = Number.parseFloat(match[1]);
  const suffix = match[2]?.toLowerCase();
  const multiplier = suffix === "b" ? 1000000000 : suffix === "m" ? 1000000 : suffix === "k" ? 1000 : 1;
  return Math.round(base * multiplier);
}

function firstExternalLink(post) {
  return (post.links || [])
    .map((link) => link.href || link)
    .find((href) => href && !href.startsWith("https://t.me/")) || "";
}

function firstTitleLine(text = "") {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line && !/^https?:\/\//i.test(line)) || "";
}

function channelPostToEngagementRecord(post, now = new Date()) {
  const url = firstExternalLink(post);
  const title = firstTitleLine(post.text) || post.documentTitle || post.serviceText || "";
  const postedAt = post.datetime || null;
  const views = parseViews(post.views);
  const ageHours = postedAt ? Math.max(0, (now.getTime() - Date.parse(postedAt)) / 3600000) : null;

  return {
    messageId: post.messageId,
    telegramUrl: post.url,
    title,
    url: canonicalUrl(url),
    sourceDomain: domainOf(url),
    postedAt,
    lastSeenAt: now.toISOString(),
    views,
    ageHours,
    normalizedViewsPerDay: normalizedViewsPerDay({ views, postedAt }, now),
    topics: extractTopics({ title, url, summary: post.text || post.documentTitle || "" }).map((topic) => topic.id)
  };
}

function normalizedViewsPerDay(record, now = new Date()) {
  if (!record?.postedAt || !Number.isFinite(Number(record.views))) return 0;
  const ageHours = Math.max(2, (now.getTime() - Date.parse(record.postedAt)) / 3600000);
  return Number(((Number(record.views) / ageHours) * 24).toFixed(2));
}

function updateEngagementState(state, recentPosts, now = new Date()) {
  const previous = new Map((state.engagement?.posts || []).map((post) => [engagementKey(post), post]));

  for (const post of recentPosts) {
    const record = channelPostToEngagementRecord(post, now);
    if (!record.messageId && !record.url) continue;

    const key = engagementKey(record);
    const existing = previous.get(key) || {};
    const merged = {
      ...existing,
      ...record,
      firstSeenAt: existing.firstSeenAt || now.toISOString()
    };

    if (record.ageHours >= 24 && !existing.performance24h) {
      merged.performance24h = {
        capturedAt: now.toISOString(),
        ageHours: Number(record.ageHours.toFixed(2)),
        views: record.views,
        normalizedViewsPerDay: record.normalizedViewsPerDay
      };
    }

    if (record.ageHours >= 48 && !existing.performance48h) {
      merged.performance48h = {
        capturedAt: now.toISOString(),
        ageHours: Number(record.ageHours.toFixed(2)),
        views: record.views,
        normalizedViewsPerDay: record.normalizedViewsPerDay
      };
    }

    previous.set(key, merged);
  }

  const posts = [...previous.values()]
    .sort((a, b) => Date.parse(b.postedAt || b.lastSeenAt || 0) - Date.parse(a.postedAt || a.lastSeenAt || 0))
    .slice(0, 500);

  return {
    ...state,
    engagement: {
      posts,
      updatedAt: now.toISOString()
    }
  };
}

function engagementKey(record) {
  return record.messageId ? `message:${record.messageId}` : `url:${normalize(record.url)}`;
}

function median(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function buildEngagementProfile(state, now = new Date()) {
  const records = (state.engagement?.posts || [])
    .map((record) => ({
      ...record,
      normalizedViewsPerDay: record.normalizedViewsPerDay || normalizedViewsPerDay(record, now)
    }))
    .filter((record) => Number.isFinite(record.normalizedViewsPerDay) && record.normalizedViewsPerDay > 0);

  const baseline = median(records.map((record) => record.normalizedViewsPerDay));
  if (!baseline) {
    return { baseline: 0, topicBoosts: {}, sourceBoosts: {}, sampleSize: 0 };
  }

  const topicScores = new Map();
  const sourceScores = new Map();
  for (const record of records) {
    const ratio = record.normalizedViewsPerDay / baseline;
    for (const topic of record.topics || []) {
      if (!topicScores.has(topic)) topicScores.set(topic, []);
      topicScores.get(topic).push(ratio);
    }
    if (record.sourceDomain) {
      if (!sourceScores.has(record.sourceDomain)) sourceScores.set(record.sourceDomain, []);
      sourceScores.get(record.sourceDomain).push(ratio);
    }
  }

  const topicBoosts = {};
  for (const [topic, ratios] of topicScores) {
    if (ratios.length < 2) continue;
    topicBoosts[topic] = Number(clamp((median(ratios) - 1) * 14, -10, 20).toFixed(2));
  }

  const sourceBoosts = {};
  for (const [source, ratios] of sourceScores) {
    if (ratios.length < 2) continue;
    sourceBoosts[source] = Number(clamp((median(ratios) - 1) * 8, -6, 12).toFixed(2));
  }

  return {
    baseline: Number(baseline.toFixed(2)),
    topicBoosts,
    sourceBoosts,
    sampleSize: records.length
  };
}

function buildPostedSet(posts, state) {
  const posted = new Set((state.postedUrls || []).map(normalize));
  for (const post of posts) {
    posted.add(normalize(post.url));
    posted.add(normalize(post.text?.split("\n")[0] || ""));
    const external = firstExternalLink(post);
    if (external) posted.add(normalize(external));
    for (const link of post.links || []) posted.add(normalize(link.href || link));
  }
  for (const record of state.engagement?.posts || []) {
    if (record.url) posted.add(normalize(record.url));
    if (record.title) posted.add(normalize(record.title));
  }
  return posted;
}

function extractTopics(candidate) {
  const text = `${candidate.title || ""} ${candidate.summary || ""} ${candidate.url || ""}`.toLowerCase();
  return TOPIC_RULES.filter((rule) => rule.pattern.test(text));
}

function sourceAuthority(candidate) {
  const domain = domainOf(candidate.url);
  let authority = candidate.sourceWeight || 0;

  if (DOMAIN_AUTHORITY.has(domain)) authority += DOMAIN_AUTHORITY.get(domain);
  else {
    for (const [known, value] of DOMAIN_AUTHORITY) {
      if (domain.endsWith(`.${known}`)) {
        authority += value;
        break;
      }
    }
  }

  if (candidate.sourceType === "page") authority -= 3;
  return authority;
}

function recencyScore(candidate, now = new Date()) {
  const publishedTime = Date.parse(candidate.published);
  if (!Number.isFinite(publishedTime)) return candidate.sourceType === "page" ? -4 : 3;
  const ageDays = (now.getTime() - publishedTime) / 86400000;
  if (ageDays <= 3) return 18;
  if (ageDays <= 7) return 14;
  if (ageDays <= 30) return 9;
  if (ageDays <= 120) return 2;
  return -10;
}

function technicalDepthScore(candidate) {
  const text = `${candidate.title || ""} ${candidate.summary || ""} ${candidate.url || ""}`;
  return TECHNICAL_DEPTH_PATTERNS.reduce((sum, [pattern, value]) => sum + (pattern.test(text) ? value : 0), 0);
}

function penaltyScore(candidate) {
  const text = `${candidate.title || ""} ${candidate.summary || ""}`;
  return PENALTY_PATTERNS.reduce((sum, [pattern, value]) => sum + (pattern.test(text) ? value : 0), 0);
}

function engagementScore(candidate, engagementProfile = {}) {
  const topics = extractTopics(candidate);
  const topicBoost = topics.reduce((sum, topic) => sum + (engagementProfile.topicBoosts?.[topic.id] || 0), 0);
  const sourceBoost = engagementProfile.sourceBoosts?.[domainOf(candidate.url)] || 0;
  return clamp(topicBoost + sourceBoost, -18, 28);
}

function scoreCandidate(candidate, { engagementProfile = {}, now = new Date() } = {}) {
  const normalized = normalizeCandidate(candidate);
  const primaryTopics = extractTopics({ ...normalized, summary: "" });
  if (!primaryTopics.length) {
    return {
      ...normalized,
      score: -100,
      topics: [],
      components: { topicFit: 0, sourceAuthority: sourceAuthority(normalized), technicalDepth: 0, recency: recencyScore(normalized, now), engagement: 0, penalty: 100 },
      decisionReason: "no technical AI security topic match in title or URL"
    };
  }

  const summaryTopics = extractTopics({ title: "", summary: normalized.summary, url: "" })
    .filter((topic) => !primaryTopics.some((primaryTopic) => primaryTopic.id === topic.id));
  const topics = [...primaryTopics, ...summaryTopics];
  const titleTopics = extractTopics({ ...normalized, summary: "", url: "" });
  const topicFit = primaryTopics.reduce((sum, topic) => sum + topic.weight, 0)
    + summaryTopics.reduce((sum, topic) => sum + Math.round(topic.weight * 0.25), 0)
    + (titleTopics.length ? 8 : -8);
  const components = {
    topicFit,
    sourceAuthority: sourceAuthority(normalized),
    technicalDepth: technicalDepthScore(normalized),
    recency: recencyScore(normalized, now),
    engagement: engagementScore(normalized, engagementProfile),
    penalty: penaltyScore(normalized)
  };

  const score = Object.entries(components).reduce(
    (sum, [key, value]) => key === "penalty" ? sum - value : sum + value,
    0
  );

  return {
    ...normalized,
    score: Number(score.toFixed(2)),
    topics: topics.map((topic) => topic.id),
    components,
    decisionReason: score >= HIGH_CONFIDENCE_THRESHOLD ? "high confidence" : "below high-confidence threshold"
  };
}

function rankCandidates(candidates, posted, { limit = 5, threshold = HIGH_CONFIDENCE_THRESHOLD, engagementProfile = {}, now = new Date() } = {}) {
  const byUrl = new Map();
  const rejected = [];

  for (const candidate of candidates.map(normalizeCandidate)) {
    const urlKey = normalize(candidate.url);
    const titleKey = normalize(candidate.title);

    if (!urlKey || posted.has(urlKey) || posted.has(titleKey)) {
      rejected.push({ ...candidate, score: -100, decisionReason: "duplicate title or URL" });
      continue;
    }

    if (!byUrl.has(urlKey)) byUrl.set(urlKey, candidate);
  }

  const ranked = [...byUrl.values()]
    .map((candidate) => scoreCandidate(candidate, { engagementProfile, now }))
    .sort((a, b) => b.score - a.score);

  const selected = ranked.filter((candidate) => candidate.score >= threshold).slice(0, limit);
  const selectedUrls = new Set(selected.map((candidate) => normalize(candidate.url)));

  for (const candidate of ranked) {
    if (!selectedUrls.has(normalize(candidate.url))) {
      rejected.push({
        ...candidate,
        decisionReason: candidate.score >= threshold ? "below selected limit" : candidate.decisionReason
      });
    }
  }

  return { selected, rejected };
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
  const now = new Date();

  const [recentPosts, state, candidateResult] = await Promise.all([
    fetchRecentChannelPosts({ channel: options.channel, pages: options.historyPages, fetchImpl }),
    readJson(options.statePath, { postedUrls: [], engagement: { posts: [] } }),
    fetchAllCandidates(fetchImpl)
  ]);

  const stateWithEngagement = updateEngagementState(state, recentPosts, now);
  const engagementProfile = buildEngagementProfile(stateWithEngagement, now);
  const posted = buildPostedSet(recentPosts, stateWithEngagement);
  const { selected, rejected } = rankCandidates(candidateResult.candidates, posted, {
    limit: options.limit,
    threshold: options.threshold,
    engagementProfile,
    now
  });

  await appendLog(options.logPath, {
    event: "curation_run",
    dryRun: options.dryRun,
    channel: options.channel,
    sourceErrors: candidateResult.sourceErrors,
    engagementProfile,
    selected: selected.map(logCandidate),
    rejected: rejected.slice(0, 40).map(logCandidate)
  });

  if (options.dryRun) {
    if (!selected.length) stdout.write("No new high-confidence AISecHub candidates found.\n");
    for (const candidate of selected) {
      stdout.write(`[${candidate.score}] ${formatPost(candidate)}\n`);
      stdout.write(`topics=${candidate.topics.join(",")} components=${JSON.stringify(candidate.components)}\n\n`);
    }
    return { exitCode: 0, posted: [] };
  }

  if (!selected.length) {
    await writeJson(options.statePath, stateWithEngagement);
    stdout.write("No new high-confidence AISecHub candidates found.\n");
    return { exitCode: 0, posted: [] };
  }

  if (!process.env.TELEGRAM_BOT_TOKEN) {
    await writeJson(options.statePath, stateWithEngagement);
    throw new Error("TELEGRAM_BOT_TOKEN is required in .env or the environment before posting.");
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
    await appendLog(options.logPath, { event: "posted", messageId: message.message_id, candidate: logCandidate(candidate) });
  }

  const nextState = {
    ...stateWithEngagement,
    postedUrls: [...new Set([...(stateWithEngagement.postedUrls || []), ...sent.map((item) => canonicalUrl(item.url))])].slice(-1000),
    updatedAt: now.toISOString()
  };
  await writeJson(options.statePath, nextState);

  try {
    const latest = await fetchRecentChannelPosts({ channel: options.channel, pages: 1, fetchImpl });
    const previewUrls = latest.slice(-sent.length).map((post) => post.url);
    for (const url of previewUrls) stdout.write(`${url}\n`);
    await appendLog(options.logPath, { event: "preview_verified", previewUrls });
  } catch (error) {
    stderr.write(`Preview verification failed: ${error.message}\n`);
    await appendLog(options.logPath, { event: "preview_failed", error: error.message });
  }

  return { exitCode: 0, posted: sent };
}

function logCandidate(candidate) {
  return {
    title: candidate.title,
    url: candidate.url,
    source: candidate.source,
    score: candidate.score,
    topics: candidate.topics,
    components: candidate.components,
    decisionReason: candidate.decisionReason
  };
}

export {
  buildEngagementProfile,
  buildPostedSet,
  canonicalUrl,
  extractTopics,
  fetchRecentChannelPosts,
  formatPost,
  normalizeCandidate,
  parseFeedItems,
  parseHtmlCandidates,
  parseViews,
  rankCandidates,
  scoreCandidate,
  updateEngagementState
};
