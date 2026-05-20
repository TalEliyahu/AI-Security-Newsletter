function decodeHtml(value = "") {
  const named = {
    amp: "&",
    apos: "'",
    gt: ">",
    lt: "<",
    nbsp: " ",
    quot: "\""
  };

  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal) => String.fromCodePoint(Number.parseInt(decimal, 10)))
    .replace(/&([a-z]+);/gi, (match, name) => named[name] ?? match);
}

function stripTags(value = "") {
  return decodeHtml(
    value
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/p>/gi, "\n")
      .replace(/<[^>]+>/g, "")
      .replace(/\n{3,}/g, "\n\n")
      .trim()
  );
}

function extractFirst(block, pattern) {
  const match = block.match(pattern);
  return match ? decodeHtml(match[1].trim()) : "";
}

function extractLinks(block) {
  const links = [];
  const seen = new Set();
  const pattern = /<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = pattern.exec(block)) !== null) {
    const href = decodeHtml(match[1]);
    if (!href || seen.has(href)) continue;
    seen.add(href);
    links.push({
      href,
      label: stripTags(match[2])
    });
  }

  return links;
}

export function publicChannelUrl(channel) {
  const slug = String(channel || "AISecHub").replace(/^@/, "");
  return `https://t.me/s/${encodeURIComponent(slug)}`;
}

export function parsePublicChannelPosts(html) {
  const parts = String(html)
    .split(/<div class="tgme_widget_message_wrap\b/g)
    .slice(1)
    .map((part) => `<div class="tgme_widget_message_wrap${part}`);

  return parts
    .map((block) => {
      const post = extractFirst(block, /data-post="([^"]+)"/);
      if (!post) return null;

      const messageId = Number(post.split("/").at(-1));
      const textBlock = extractFirst(
        block,
        /<div class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)<\/div>/
      );
      const documentTitle = extractFirst(
        block,
        /<div class="tgme_widget_message_document_title"[^>]*>([\s\S]*?)<\/div>/
      );
      const serviceText = extractFirst(
        block,
        /<div class="tgme_widget_message_service_message"[^>]*>([\s\S]*?)<\/div>/
      );
      const viewsText = extractFirst(
        block,
        /<span class="tgme_widget_message_views"[^>]*>([\s\S]*?)<\/span>/
      );

      return {
        post,
        messageId: Number.isFinite(messageId) ? messageId : null,
        url: `https://t.me/${post}`,
        datetime: extractFirst(block, /<time[^>]*datetime="([^"]+)"/),
        views: viewsText,
        text: stripTags(textBlock),
        documentTitle: stripTags(documentTitle),
        serviceText: stripTags(serviceText),
        links: extractLinks(block)
          .filter((link) => !link.href.includes("telegram.org"))
          .filter((link) => !link.href.endsWith(`/${post.split("/").at(-1)}`) || link.label),
        media: {
          hasPhoto: block.includes("tgme_widget_message_photo_wrap"),
          hasVideo: block.includes("tgme_widget_message_video"),
          hasDocument: block.includes("tgme_widget_message_document")
        }
      };
    })
    .filter(Boolean);
}

export async function fetchPublicChannelPosts({
  channel = "AISecHub",
  fetchImpl = globalThis.fetch
} = {}) {
  const response = await fetchImpl(publicChannelUrl(channel), {
    headers: {
      "user-agent": "Mozilla/5.0 AISecHubBot/1.0"
    }
  });

  if (!response.ok) {
    throw new Error(`Public channel fetch failed: HTTP ${response.status}`);
  }

  return parsePublicChannelPosts(await response.text());
}

export function formatPublicChannelPost(post) {
  const pieces = [
    `${post.messageId ? `#${post.messageId}` : post.post} ${post.datetime || ""}`.trim(),
    post.url
  ];

  if (post.documentTitle) pieces.push(`Document: ${post.documentTitle}`);
  if (post.text) pieces.push(post.text);
  if (!post.text && !post.documentTitle && (post.media.hasPhoto || post.media.hasVideo)) {
    pieces.push("[media post with no visible caption]");
  }

  const externalLinks = post.links
    .map((link) => link.href)
    .filter((href) => !href.startsWith("https://t.me/"));
  if (externalLinks.length) {
    pieces.push(`Links: ${externalLinks.join(", ")}`);
  }
  if (post.views) pieces.push(`Views: ${post.views}`);

  return pieces.join("\n");
}

