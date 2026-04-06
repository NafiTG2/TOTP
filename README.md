# 🛡 BlockVeil Authenticator Bot

A Telegram bot that stores and generates TOTP codes (Google Authenticator compatible) with **AES-256-GCM encryption**.

## Features
- ➕ Add accounts via **QR code image**, **otpauth:// URI**, or **manual entry**
- 📋 List all accounts with **live OTP codes** and countdown timer
- 🗑 Delete accounts
- 🔒 All secrets encrypted with **AES-256-GCM + PBKDF2-SHA256 (310k iterations)**
- Each user's data is isolated by Telegram user ID

---

## Deploy on Railway

### 1. Fork / Clone this repo
```bash
git clone https://github.com/YOUR_USERNAME/blockveil-auth-bot
cd blockveil-auth-bot
```

### 2. Create Telegram Bot
- Open [@BotFather](https://t.me/BotFather) on Telegram
- Send `/newbot` and follow instructions
- Copy the **BOT_TOKEN**

### 3. Deploy to Railway
1. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
2. Select this repo
3. Add environment variables:

| Variable | Value |
|---|---|
| `BOT_TOKEN` | Your BotFather token |
| `ENCRYPTION_KEY` | A strong random string (32+ chars) |
| `DB_PATH` | `auth.db` |

4. Railway auto-detects `Procfile` and deploys as a **worker** (no port needed)

---

## Local Development
```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your values
python bot.py
```

---

## Security Notes
- `ENCRYPTION_KEY` is the master key — keep it secret and back it up
- If you lose `ENCRYPTION_KEY`, all stored secrets become unrecoverable
- SQLite DB is stored on Railway's ephemeral volume — consider upgrading to Railway's persistent volume or PostgreSQL for production

---

## Tech Stack
- `python-telegram-bot` 21.x
- `cryptography` (AES-256-GCM, PBKDF2)
- `pyzbar` + `Pillow` (QR code scanning)
- SQLite (storage)
- Railway (hosting)
