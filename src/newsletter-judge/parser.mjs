import fs from "node:fs/promises";
import path from "node:path";

const SECTION_ALIASES = new Map([
  ["insights", "Insights"],
  ["research", "Research"],
  ["tools", "Tools"],
  ["tools resources", "Tools & Resources"],
  ["tools and resources", "Tools & Resources"],
  ["tools resources", "Tools & Resources"],
  ["reports", "Reports"],
  ["cves", "CVEs"],
  ["cve", "CVEs"],
  ["videos", "Videos"],
  ["practitioner discussions", "Practitioner Discussions"],
  ["reddit conversations", "Practitioner Discussions"],
  ["reddit most interesting conversations", "Practitioner Discussions"],
  ["incidents", "Incidents"],
  ["governance", "Governance"],
  ["funding", "Funding"],
  ["notable reads", "Notable Reads"],
  ["upcoming conferences", "Upcoming Conferences"],
  ["conferences", "Upcoming Conferences"],
  ["llm application security", "LLM Application Security"],
  ["agent security", "Agent Security"],
  ["mcp security", "MCP Security"]
]);

const IGNORED_SECTION_NAMES = new Set([
  "lets connect",
  "let s connect",
  "about",
  "sponsor"
]);

export async function parseNewsletterFile(inputPath, options = {}) {
  const text = await fs.readFile(inputPath, "utf8");
  const format = resolveFormat(inputPath, options.format);
  if (format === "json") {
    return parseJsonNewsletter(text);
  }
  if (format === "markdown") {
    return parseMarkdownNewsletter(text);
  }
  throw new Error(`Unsupported newsletter format "${format}". Use markdown or json.`);
}

export function parseJsonNewsletter(text) {
  const warnings = [];
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid JSON newsletter input: ${error.message}`);
  }

  const rawItems = Array.isArray(parsed) ? parsed : parsed?.items;
  if (!Array.isArray(rawItems)) {
    throw new Error("JSON newsletter input must be an array or an object with an items array.");
  }

  const items = rawItems.map((item, index) => {
    const normalized = normalizeItem(item, index, warnings);
    return {
      ...normalized,
      raw: item
    };
  });

  if (items.length === 0) {
    warnings.push("JSON input contained no newsletter items.");
  }

  return {
    format: "json",
    items,
    warnings
  };
}

export function parseMarkdownNewsletter(text) {
  const warnings = [];
  const lines = text.split(/\r?\n/);
  const items = [];
  let currentSection = null;
  let ignoredSection = false;
  let currentItem = null;

  const flushItem = () => {
    if (!currentItem) return;
    currentItem.summary = currentItem.summaryLines.join("\n").trim();
    delete currentItem.summaryLines;
    if (!currentItem.url) {
      warnings.push(`Could not find a URL for item "${currentItem.title}".`);
    }
    if (!currentItem.summary) {
      warnings.push(`Could not find a summary for item "${currentItem.title}".`);
    }
    items.push(currentItem);
    currentItem = null;
  };

  lines.forEach((line, lineIndex) => {
    const heading = parseHeading(line);
    if (heading) {
      const headingName = canonicalHeading(heading.title);
      const normalized = normalizeHeadingKey(heading.title);
      if (/ai security newsletter/i.test(heading.title)) {
        flushItem();
        currentSection = null;
        ignoredSection = false;
        return;
      }
      if (IGNORED_SECTION_NAMES.has(normalized)) {
        flushItem();
        currentSection = headingName;
        ignoredSection = true;
        return;
      }
      if (SECTION_ALIASES.has(normalized)) {
        flushItem();
        currentSection = SECTION_ALIASES.get(normalized);
        ignoredSection = false;
        return;
      }
      if (currentSection === "Upcoming Conferences" && isMonthYearHeading(heading.title)) {
        flushItem();
        return;
      }
      if (currentSection && !ignoredSection) {
        flushItem();
        currentItem = {
          title: cleanTitle(heading.title),
          url: null,
          summary: "",
          summaryLines: [],
          section: currentSection,
          date: null,
          source: null,
          raw: line,
          line: lineIndex + 1
        };
      }
      return;
    }

    if (ignoredSection) return;
    const trimmed = line.trim();
    if (!trimmed || /^-{3,}$/.test(trimmed)) return;

    const itemStart = parseItemStart(trimmed);
    if (itemStart) {
      flushItem();
      currentItem = {
        title: itemStart.title,
        url: itemStart.url,
        summary: "",
        summaryLines: itemStart.trailing ? [itemStart.trailing] : [],
        section: currentSection,
        date: null,
        source: null,
        raw: line,
        line: lineIndex + 1
      };
      return;
    }

    if (currentItem) {
      if (!currentItem.url) {
        const link = extractFirstMarkdownLink(trimmed);
        if (link) {
          currentItem.url = link.url;
        }
      }
      currentItem.summaryLines.push(trimmed);
      return;
    }

    if (currentSection && /\[[^\]]+\]\([^)]+\)/.test(trimmed)) {
      warnings.push(`Ambiguous markdown link outside an item at line ${lineIndex + 1}.`);
    }
  });

  flushItem();

  if (items.length === 0) {
    warnings.push("Markdown parser did not extract any newsletter items.");
  }

  return {
    format: "markdown",
    items,
    warnings
  };
}

function normalizeItem(item, index, warnings) {
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    warnings.push(`JSON item ${index + 1} is not an object; using an empty placeholder.`);
    item = {};
  }
  const title = stringOrEmpty(item.title).trim() || `Untitled item ${index + 1}`;
  if (!item.title) {
    warnings.push(`JSON item ${index + 1} is missing a title.`);
  }
  return {
    title,
    url: nullableString(item.url),
    source: nullableString(item.source),
    summary: stringOrEmpty(item.summary).trim(),
    section: nullableString(item.section),
    date: nullableString(item.date)
  };
}

function resolveFormat(inputPath, explicitFormat) {
  if (explicitFormat && explicitFormat !== "auto") {
    if (["markdown", "md"].includes(explicitFormat)) return "markdown";
    if (explicitFormat === "json") return "json";
    return explicitFormat;
  }
  const ext = path.extname(inputPath).toLowerCase();
  if (ext === ".json") return "json";
  if (ext === ".md" || ext === ".markdown" || ext === "") return "markdown";
  return "markdown";
}

function parseHeading(line) {
  const match = line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
  if (!match) return null;
  return {
    level: match[1].length,
    title: cleanTitle(match[2])
  };
}

function parseItemStart(line) {
  const stripped = stripItemPrefix(line);
  const linkedBold = stripped.match(/^\*\*\[([^\]]+)\]\(([^)]+)\)\*\*(?:\s*(?:[-:–—]\s*)?(.*))?$/);
  if (linkedBold) {
    return itemStart(linkedBold[1], linkedBold[2], linkedBold[3]);
  }

  const linked = stripped.match(/^\[([^\]]+)\]\(([^)]+)\)(?:\s*(?:[-:–—]\s*)?(.*))?$/);
  if (linked) {
    return itemStart(linked[1], linked[2], linked[3]);
  }

  const boldTitle = stripped.match(/^\*\*([^*]+)\*\*(?:\s*(?:[-:–—]\s*)?(.*))?$/);
  if (boldTitle && hasItemPrefix(line)) {
    return itemStart(boldTitle[1], null, boldTitle[2]);
  }

  return null;
}

function itemStart(title, url, trailing) {
  return {
    title: cleanTitle(title),
    url: url || null,
    trailing: trailing ? trailing.trim() : ""
  };
}

function extractFirstMarkdownLink(line) {
  const match = line.match(/\[([^\]]+)\]\(([^)]+)\)/);
  if (!match) return null;
  return {
    title: match[1],
    url: match[2]
  };
}

function stripItemPrefix(line) {
  return line
    .trim()
    .replace(/^(?:[-*+]\s+|\d+[.)]\s+|(?:[0-9]\uFE0F?\u20E3)+\s+|[^\w\s#\[]+\s*)/u, "")
    .trim();
}

function hasItemPrefix(line) {
  return /^(?:[-*+]\s+|\d+[.)]\s+|(?:[0-9]\uFE0F?\u20E3)+\s+|[^\w\s#\[]+\s*)/u.test(line.trim());
}

function canonicalHeading(value) {
  return cleanTitle(value).replace(/\s+/g, " ").trim();
}

function normalizeHeadingKey(value) {
  return cleanTitle(value)
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function isMonthYearHeading(value) {
  return /^(january|february|march|april|may|june|july|august|september|october|november|december)\s+20\d{2}$/i.test(
    cleanTitle(value)
  );
}

function cleanTitle(value) {
  return stringOrEmpty(value)
    .replace(/\*\*/g, "")
    .replace(/^[-*+]\s+/, "")
    .replace(/^(?:[0-9]\uFE0F?\u20E3)+\s+/u, "")
    .replace(/^[^\w\s[]+\s*/u, "")
    .replace(/\s+/g, " ")
    .trim();
}

function nullableString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function stringOrEmpty(value) {
  return typeof value === "string" ? value : "";
}
