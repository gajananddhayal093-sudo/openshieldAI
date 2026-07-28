import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from config import BOT_TOKEN
from modules.security import generate_password, check_password_strength, get_hash

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ OpenShield AI Started Successfully!"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📚 OpenShield AI Help\n\n"
        "/start - Start the bot\n"
        "/help - Show help\n"
        "/about - About OpenShield AI"
    )


async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ OpenShield AI\n"
        "Cybersecurity platform\n"
        "Version 2.0 — Development"
    )
async def security(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = generate_password(16)

    await update.message.reply_text(
    "🔐 Security Tools\n\n"
    "1️⃣ Password Generator\n"
    "2️⃣ Password Strength\n"
    "3️⃣ MD5 Hash\n"
    "4️⃣ SHA256 Hash\n"
    "5️⃣ Base64\n"
    "6️⃣ URL Encode/Decode"
)
def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("security", security))
    print("OpenShield AI Bot Running...")
    app.run_polling()


if __name__ == "__main__":
    main()

