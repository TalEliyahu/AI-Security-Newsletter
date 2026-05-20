# AISecHub Telegram Bot

This repo includes a small Telegram helper for `@AISECHUB_bot` and the `@AISecHub` channel.

It can:

- verify the bot is an admin in the channel
- read new Bot API updates with polling
- run a webhook receiver behind a public HTTPS URL
- send, edit, and delete channel messages
- register Telegram bot commands
- read the latest public channel preview posts from `https://t.me/s/AISecHub`

Telegram Bot API limitation: bots cannot fetch old channel history. For historical public posts, use `latest-public`, which reads Telegram's public channel preview page.

## Setup

Keep the bot token out of git:

```sh
cp .env.example .env
```

Then edit `.env` and set `TELEGRAM_BOT_TOKEN`.

The CLI auto-loads `.env` from the repo root. You can also export values directly in the shell if you prefer.

## Commands

If `npm` is not on PATH in this shell, replace `npm run telegram --` with:

```sh
node ./bin/aisechub-bot.mjs
```

Check admin and webhook status:

```sh
npm run telegram -- status
```

Read the latest 20 public visible posts:

```sh
npm run telegram -- latest-public --limit 20
```

Poll pending Bot API updates:

```sh
npm run telegram -- updates --limit 20 --timeout 10
```

Start a long-polling bot listener:

```sh
npm run telegram -- listen
```

Start listening from now and acknowledge any pending backlog:

```sh
npm run telegram -- listen --from-now
```

Send a channel message:

```sh
npm run telegram -- send --text "Message text"
```

Edit a channel message:

```sh
npm run telegram -- edit --message-id 123 --text "Updated text"
```

Delete a channel message:

```sh
npm run telegram -- delete --message-id 123
```

Register the bot command menu:

```sh
npm run telegram -- register-commands
```

## Private Bot Commands

When `listen` or `webhook serve` is running, the bot responds in private chat:

- `/help`
- `/whoami`
- `/status`
- `/latest 5`
- `/send message text`

The `/send` command is locked by default. Send `/whoami` to the bot, then add your Telegram user id to `.env`:

```sh
TELEGRAM_ALLOWED_USER_IDS=123456789
```

## Webhooks

For production, run the local webhook server behind a public HTTPS URL:

```sh
npm run telegram -- webhook serve --port 8787 --path /telegram/webhook
```

Then register the public URL with Telegram:

```sh
npm run telegram -- webhook set --url https://example.com/telegram/webhook
```

Check or remove the webhook:

```sh
npm run telegram -- webhook status
npm run telegram -- webhook delete
```

## Daily Curation

The curation profile is in `AISECHUB_CURATION.md`.

Preview the daily curator without posting:

```sh
npm run telegram:curate -- --dry-run --limit 5
```

Post selected items:

```sh
npm run telegram:curate -- --limit 5
```

The curator loads `.env`, reads recent `@AISecHub` history to avoid duplicates, pulls candidates from selected primary-source feeds and arXiv, ranks them against the channel profile, and posts each item separately as title plus URL.

Install the included macOS daily schedule:

```sh
mkdir -p ~/Library/LaunchAgents logs
cp launchd/com.aisechub.daily-curator.plist ~/Library/LaunchAgents/
launchctl unload ~/Library/LaunchAgents/com.aisechub.daily-curator.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.aisechub.daily-curator.plist
```

The schedule runs daily at 09:00 local time.
