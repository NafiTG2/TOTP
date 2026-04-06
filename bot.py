import os
import re
import hmac
import time
import struct
import base64
import hashlib
import sqlite3
import logging
from io import BytesIO
from urllib.parse import urlparse, parse_qs, unquote

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler,
    MessageHandler, ConversationHandler, ContextTypes, filters
)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyzbar.pyzbar import decode as qr_decode
from PIL import Image

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ─── States ───────────────────────────────────────────────
WAITING_QR_OR_CODE = 1
WAITING_MANUAL_NAME = 2
WAITING_MANUAL_SECRET = 3

# ─── DB Setup ─────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "auth.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS totp_accounts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                name      TEXT NOT NULL,
                issuer    TEXT,
                secret_enc BLOB NOT NULL,
                salt      BLOB NOT NULL,
                iv        BLOB NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            )
        """)
        conn.commit()

# ─── Crypto ───────────────────────────────────────────────
MASTER_PASS = os.environ.get("ENCRYPTION_KEY", "blockveil_default_key_change_me")

def derive_key(salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310_000,
    )
    return kdf.derive(MASTER_PASS.encode())

def encrypt_secret(secret: str) -> tuple[bytes, bytes, bytes]:
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = derive_key(salt)
    ct   = AESGCM(key).encrypt(iv, secret.encode(), None)
    return ct, salt, iv

def decrypt_secret(ct: bytes, salt: bytes, iv: bytes) -> str:
    key = derive_key(salt)
    return AESGCM(key).decrypt(iv, ct, None).decode()

# ─── TOTP ─────────────────────────────────────────────────
def base32_decode(s: str) -> bytes:
    s = s.upper().strip().replace(' ', '')
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s + '=' * pad)

def generate_totp(secret: str) -> tuple[str, int]:
    key      = base32_decode(secret)
    ts       = int(time.time())
    counter  = ts // 30
    remain   = 30 - (ts % 30)
    msg      = struct.pack('>Q', counter)
    h        = hmac.new(key, msg, hashlib.sha1).digest()
    offset   = h[-1] & 0x0F
    code     = struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6), remain

def parse_otpauth(uri: str) -> dict | None:
    try:
        parsed  = urlparse(uri)
        if parsed.scheme != 'otpauth':
            return None
        label   = unquote(parsed.path.lstrip('/'))
        params  = parse_qs(parsed.query)
        secret  = params.get('secret', [None])[0]
        issuer  = params.get('issuer', [None])[0]
        if ':' in label:
            parts  = label.split(':', 1)
            issuer = issuer or parts[0].strip()
            name   = parts[1].strip()
        else:
            name = label.strip()
        if not secret:
            return None
        return {'name': name, 'issuer': issuer or '', 'secret': secret.upper()}
    except Exception:
        return None

# ─── Keyboards ────────────────────────────────────────────
def main_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add New TOTP", callback_data="add_totp")],
        [InlineKeyboardButton("📋 List of TOTP", callback_data="list_totp")],
    ])

def cancel_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Cancel", callback_data="cancel")]
    ])

# ─── Handlers ─────────────────────────────────────────────
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡 *BlockVeil Authenticator*\n\n"
        "Secure TOTP manager with AES\\-256\\-GCM encryption\\.\n"
        "Your secrets are encrypted before storage\\.\n\n"
        "Choose an option:",
        parse_mode="MarkdownV2",
        reply_markup=main_menu_keyboard()
    )

async def menu_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Show main menu from /menu command"""
    await update.message.reply_text(
        "Choose an option:",
        reply_markup=main_menu_keyboard()
    )

# ── ADD TOTP flow ──────────────────────────────────────────
async def add_totp_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "➕ *Add New TOTP Account*\n\n"
        "Send me one of the following:\n\n"
        "📷 *QR Code image* — screenshot from your authenticator app\n"
        "🔗 *otpauth:// URI* — paste the link directly\n"
        "⌨️ *Type* `manual` — enter name \\& secret manually\n\n"
        "_Supports Google Authenticator, Authy, and any RFC 6238 app_",
        parse_mode="MarkdownV2",
        reply_markup=cancel_keyboard()
    )
    return WAITING_QR_OR_CODE

async def handle_qr_or_code(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    # ── Photo / document (QR image) ──
    file_obj = None
    if update.message.photo:
        file_obj = await update.message.photo[-1].get_file()
    elif update.message.document and update.message.document.mime_type.startswith('image'):
        file_obj = await update.message.document.get_file()

    if file_obj:
        bio = BytesIO()
        await file_obj.download_to_memory(bio)
        bio.seek(0)
        try:
            img     = Image.open(bio)
            decoded = qr_decode(img)
            if not decoded:
                await update.message.reply_text(
                    "⚠️ No QR code found in image. Try a clearer screenshot.",
                    reply_markup=cancel_keyboard()
                )
                return WAITING_QR_OR_CODE
            uri  = decoded[0].data.decode('utf-8')
            data = parse_otpauth(uri)
            if not data:
                await update.message.reply_text(
                    "⚠️ QR code found but not a valid TOTP URI.",
                    reply_markup=cancel_keyboard()
                )
                return WAITING_QR_OR_CODE
            return await _save_account(update, ctx, user_id, data)
        except Exception as e:
            logger.error(f"QR decode error: {e}")
            await update.message.reply_text("⚠️ Could not read image. Try again.")
            return WAITING_QR_OR_CODE

    # ── Text input ──
    text = update.message.text.strip()

    if text.lower() == 'manual':
        await update.message.reply_text(
            "⌨️ *Manual Entry*\n\nEnter the *account name*:\n_Example: GitHub \\- john@example\\.com_",
            parse_mode="MarkdownV2",
            reply_markup=cancel_keyboard()
        )
        return WAITING_MANUAL_NAME

    if text.startswith('otpauth://'):
        data = parse_otpauth(text)
        if not data:
            await update.message.reply_text(
                "⚠️ Invalid otpauth URI. Check the format.",
                reply_markup=cancel_keyboard()
            )
            return WAITING_QR_OR_CODE
        return await _save_account(update, ctx, user_id, data)

    await update.message.reply_text(
        "⚠️ Send a *QR image*, an `otpauth://` URI, or type `manual`.",
        parse_mode="MarkdownV2",
        reply_markup=cancel_keyboard()
    )
    return WAITING_QR_OR_CODE

async def handle_manual_name(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    name = update.message.text.strip()
    if not name:
        await update.message.reply_text("⚠️ Name cannot be empty. Try again:")
        return WAITING_MANUAL_NAME
    ctx.user_data['pending_name'] = name
    await update.message.reply_text(
        f"✅ Name: *{name}*\n\nNow enter the *Base32 secret key*:\n"
        "_Example: JBSWY3DPEHPK3PXP_\n\n"
        "You can find this in your app's export or setup screen\\.",
        parse_mode="MarkdownV2",
        reply_markup=cancel_keyboard()
    )
    return WAITING_MANUAL_SECRET

async def handle_manual_secret(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    secret = update.message.text.strip().upper().replace(' ', '')
    user_id = update.effective_user.id

    # Validate base32
    if not re.match(r'^[A-Z2-7]+=*$', secret):
        await update.message.reply_text(
            "⚠️ Invalid Base32 secret. Only A-Z and 2-7 are allowed.",
            reply_markup=cancel_keyboard()
        )
        return WAITING_MANUAL_SECRET

    # Test TOTP
    try:
        generate_totp(secret)
    except Exception:
        await update.message.reply_text(
            "⚠️ Secret key is invalid. Cannot generate OTP.",
            reply_markup=cancel_keyboard()
        )
        return WAITING_MANUAL_SECRET

    name = ctx.user_data.pop('pending_name', 'Unknown')
    data = {'name': name, 'issuer': '', 'secret': secret}
    return await _save_account(update, ctx, user_id, data)

async def _save_account(update, ctx, user_id, data):
    """Encrypt and save, then show the first OTP."""
    secret = data['secret']
    ct, salt, iv = encrypt_secret(secret)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO totp_accounts (user_id, name, issuer, secret_enc, salt, iv) VALUES (?,?,?,?,?,?)",
            (user_id, data['name'], data['issuer'], ct, salt, iv)
        )
        conn.commit()

    code, remain = generate_totp(secret)
    issuer_line  = f"\n🏢 {data['issuer']}" if data['issuer'] else ""
    bar          = "▓" * int(remain / 3) + "░" * (10 - int(remain / 3))

    await update.message.reply_text(
        f"✅ *Account added successfully\\!*\n\n"
        f"👤 *{escape_md(data['name'])}*{escape_md(issuer_line)}\n\n"
        f"🔢 `{code[:3]} {code[3:]}`\n"
        f"⏱ {bar} {remain}s remaining\n\n"
        f"🔒 _Encrypted with AES\\-256\\-GCM_",
        parse_mode="MarkdownV2",
        reply_markup=main_menu_keyboard()
    )
    ctx.user_data.clear()
    return ConversationHandler.END

# ── LIST TOTP ──────────────────────────────────────────────
async def list_totp(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query   = update.callback_query
    await query.answer()
    user_id = update.effective_user.id

    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, issuer, secret_enc, salt, iv FROM totp_accounts WHERE user_id=? ORDER BY name",
            (user_id,)
        ).fetchall()

    if not rows:
        await query.edit_message_text(
            "📋 *Your TOTP Accounts*\n\nNo accounts yet\\. Tap *Add New TOTP* to get started\\.",
            parse_mode="MarkdownV2",
            reply_markup=main_menu_keyboard()
        )
        return

    lines = ["📋 *Your TOTP Accounts*\n"]
    kb    = []

    for row in rows:
        try:
            secret     = decrypt_secret(bytes(row['secret_enc']), bytes(row['salt']), bytes(row['iv']))
            code, remain = generate_totp(secret)
            bar        = "▓" * int(remain / 3) + "░" * (10 - int(remain / 3))
            issuer     = f" \\| {escape_md(row['issuer'])}" if row['issuer'] else ""
            lines.append(
                f"🔑 *{escape_md(row['name'])}*{issuer}\n"
                f"   `{code[:3]} {code[3:]}` ⏱ {bar} {remain}s\n"
            )
            kb.append([InlineKeyboardButton(
                f"🗑 Delete: {row['name']}", callback_data=f"del_{row['id']}"
            )])
        except Exception as e:
            logger.error(f"Decrypt error row {row['id']}: {e}")
            lines.append(f"⚠️ *{escape_md(row['name'])}* — decryption error\n")

    kb.append([InlineKeyboardButton("🔄 Refresh", callback_data="list_totp")])
    kb.append([InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")])

    await query.edit_message_text(
        "\n".join(lines),
        parse_mode="MarkdownV2",
        reply_markup=InlineKeyboardMarkup(kb)
    )

async def delete_account(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query   = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    acc_id  = int(query.data.split('_')[1])

    with get_db() as conn:
        row = conn.execute(
            "SELECT name FROM totp_accounts WHERE id=? AND user_id=?", (acc_id, user_id)
        ).fetchone()
        if row:
            conn.execute("DELETE FROM totp_accounts WHERE id=? AND user_id=?", (acc_id, user_id))
            conn.commit()
            name = row['name']
        else:
            name = None

    if name:
        await query.answer(f"✅ {name} deleted", show_alert=True)
    else:
        await query.answer("⚠️ Not found", show_alert=True)

    # Re-trigger list
    update.callback_query.data = "list_totp"
    await list_totp(update, ctx)

async def cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    ctx.user_data.clear()
    await query.edit_message_text("❌ Cancelled.", reply_markup=main_menu_keyboard())
    return ConversationHandler.END

async def main_menu_cb(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("Choose an option:", reply_markup=main_menu_keyboard())

# ─── Markdown escape ──────────────────────────────────────
def escape_md(text: str) -> str:
    if not text:
        return ''
    return re.sub(r'([_*\[\]()~`>#+\-=|{}.!\\])', r'\\\1', text)

# ─── Main ─────────────────────────────────────────────────
def main():
    init_db()
    token = os.environ["BOT_TOKEN"]
    app   = ApplicationBuilder().token(token).build()

    conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(add_totp_start, pattern="^add_totp$")],
        states={
            WAITING_QR_OR_CODE:   [
                MessageHandler(filters.PHOTO | filters.Document.IMAGE, handle_qr_or_code),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_qr_or_code),
            ],
            WAITING_MANUAL_NAME:   [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_manual_name)],
            WAITING_MANUAL_SECRET: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_manual_secret)],
        },
        fallbacks=[CallbackQueryHandler(cancel, pattern="^cancel$")],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("menu", menu_button))
    app.add_handler(conv)
    app.add_handler(CallbackQueryHandler(list_totp,       pattern="^list_totp$"))
    app.add_handler(CallbackQueryHandler(delete_account,  pattern="^del_\\d+$"))
    app.add_handler(CallbackQueryHandler(main_menu_cb,    pattern="^main_menu$"))

    logger.info("BlockVeil Authenticator Bot started.")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
