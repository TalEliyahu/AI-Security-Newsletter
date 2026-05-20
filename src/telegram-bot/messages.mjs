export const UPDATE_MESSAGE_KEYS = [
  "channel_post",
  "edited_channel_post",
  "message",
  "edited_message"
];

const MEDIA_KEYS = [
  "animation",
  "audio",
  "document",
  "photo",
  "sticker",
  "video",
  "video_note",
  "voice"
];

export function extractUpdateMessage(update) {
  for (const key of UPDATE_MESSAGE_KEYS) {
    if (update?.[key]) {
      return {
        kind: key,
        updateId: update.update_id,
        message: update[key]
      };
    }
  }

  return null;
}

export function summarizeMessageUpdate(update) {
  const extracted = extractUpdateMessage(update);
  if (!extracted) return null;

  const { kind, updateId, message } = extracted;
  const chat = message.chat || {};
  const sender = message.from || message.sender_chat || {};
  const text = message.text || message.caption || "";
  const mediaTypes = MEDIA_KEYS.filter((key) => message[key]);

  return {
    updateId,
    kind,
    messageId: message.message_id,
    date: message.date ? new Date(message.date * 1000).toISOString() : null,
    editDate: message.edit_date ? new Date(message.edit_date * 1000).toISOString() : null,
    chatId: chat.id,
    chatTitle: chat.title || chat.username || chat.first_name || "",
    chatType: chat.type,
    senderId: sender.id,
    senderName: sender.title || sender.username || sender.first_name || "",
    authorSignature: message.author_signature || "",
    text,
    mediaTypes
  };
}

export function formatMessageSummary(summary) {
  if (!summary) return "[unsupported update]";

  const parts = [
    `#${summary.updateId}`,
    summary.kind,
    `chat=${summary.chatTitle || summary.chatId || "unknown"}`,
    `message=${summary.messageId || "unknown"}`
  ];

  if (summary.date) parts.push(summary.date);
  if (summary.mediaTypes.length) parts.push(`media=${summary.mediaTypes.join(",")}`);

  const header = parts.join(" | ");
  const body = summary.text ? `\n${summary.text}` : "\n[no text]";
  return `${header}${body}`;
}

export function truncateTelegramText(text, maxLength = 3900) {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 20).trimEnd()}\n...[truncated]`;
}

export function parseAllowedUserIds(value = "") {
  return new Set(
    String(value)
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => Number(item))
      .filter(Number.isSafeInteger)
  );
}

export function isAllowedUser(userId, allowedUserIds) {
  return allowedUserIds.size > 0 && allowedUserIds.has(Number(userId));
}

