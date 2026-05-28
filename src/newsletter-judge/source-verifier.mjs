import { PDFParse } from "pdf-parse";

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_SOURCE_TEXT_CHARS = 20000;

export async function verifySourcesForItems(items, options = {}) {
  const verifySources = Boolean(options.verifySources);
  if (!verifySources) {
    return items.map((item) => ({
      url: item.url || null,
      source_verification_status: item.url ? "not_requested" : "no_url",
      source_title: "",
      source_text: "",
      error: null,
      final_url: item.url || null
    }));
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return items.map((item) => ({
      url: item.url || null,
      source_verification_status: item.url ? "unavailable" : "no_url",
      source_title: "",
      source_text: "",
      error: item.url ? "fetch is not available in this Node runtime" : null,
      final_url: item.url || null
    }));
  }

  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const results = [];
  for (const item of items) {
    results.push(await verifySingleSource(item, fetchImpl, timeoutMs, options));
  }
  return results;
}

async function verifySingleSource(item, fetchImpl, timeoutMs, options = {}) {
  if (!item.url) {
    return unavailable(item, "no_url", null);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(item.url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "newsletter-judge/1.0"
      }
    });
    clearTimeout(timer);

    if (!response || !response.ok) {
      return unavailable(item, "unavailable", `HTTP ${response?.status || "unknown"}`);
    }

    const contentType = response.headers?.get?.("content-type") || "";
    if (/pdf/i.test(contentType) || /\.pdf(?:$|[?#])/i.test(item.url)) {
      const raw = await response.arrayBuffer();
      const sourceText = await extractPdfText(raw, options).catch((error) => {
        throw new Error(`PDF text extraction failed: ${error instanceof Error ? error.message : String(error)}`);
      });
      if (!sourceText.trim()) {
        return unavailable(item, "unavailable", "PDF source fetched but no readable text was extracted");
      }
      return {
        url: item.url,
        source_verification_status: "verified",
        source_title: item.title || "",
        source_text: sourceText.slice(0, MAX_SOURCE_TEXT_CHARS),
        error: null,
        final_url: response.url || item.url
      };
    }

    const raw = await response.text();
    const sourceTitle = extractTitle(raw);
    const sourceText = htmlToText(raw).slice(0, MAX_SOURCE_TEXT_CHARS);
    if (!sourceText.trim()) {
      return unavailable(item, "unavailable", "No readable source text extracted");
    }

    return {
      url: item.url,
      source_verification_status: "verified",
      source_title: sourceTitle,
      source_text: sourceText,
      error: null,
      final_url: response.url || item.url
    };
  } catch (error) {
    clearTimeout(timer);
    return unavailable(item, "unavailable", error instanceof Error ? error.message : String(error));
  }
}

async function extractPdfText(raw, options = {}) {
  if (typeof options.pdfTextExtractor === "function") {
    return options.pdfTextExtractor(raw);
  }
  const parser = new PDFParse({ data: new Uint8Array(raw) });
  try {
    const result = await parser.getText();
    return result.text || "";
  } finally {
    await parser.destroy();
  }
}

function unavailable(item, status, error) {
  return {
    url: item.url || null,
    source_verification_status: status,
    source_title: "",
    source_text: "",
    error,
    final_url: item.url || null
  };
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? decodeHtml(match[1]).replace(/\s+/g, " ").trim() : "";
}

function htmlToText(html) {
  return decodeHtml(
    html
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
  ).trim();
}

function decodeHtml(value) {
  return value
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}
