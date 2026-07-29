import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

from config import BOT_TOKEN
from modules.security import generate_password
from modules.analyzer.url_analyzer import analyze_url
from modules.analyzer.dns_analyzer import analyze_dns
from modules.analyzer.port_analyzer import analyze_ports
from modules.analyzer.tls_analyzer import analyze_tls
from modules.analyzer.network_risk import assess_network_risk
from modules.analyzer.network_pipeline import run_network_pipeline
from modules.analyzer.telegram_report import format_telegram_report
from modules.analyzer.report_writer import list_reports, load_report


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ OpenShield AI\n\n"
        "Cybersecurity assistant is online.\n\n"
        "Use /help to see available commands."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📚 OpenShield AI Commands\n\n"
        "/start - Start the bot\n"
        "/help - Show commands\n"
        "/about - About OpenShield AI\n"
        "/security - Security tools\n"
        "/analyze <URL> - Analyze a website"
    )


async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ OpenShield AI\n\n"
        "Defensive cybersecurity platform\n"
        "Version 2.0 — Phase 3"
    )


async def analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "🔎 URL Security Analyzer\\n\\n"
            "Usage:\\n"
            "/analyze https://example.com"
        )
        return

    url = context.args[0]

    try:
        from modules.analyzer.web_pipeline import run_web_pipeline

        result = run_web_pipeline(url)

        if result.get("error"):
            await update.message.reply_text(
                f"❌ Analysis failed\\n\\n{result['error']}"
            )
            return

        web = result["web"]
        pipeline = result["pipeline"]

        report = format_telegram_report(
            pipeline,
            "WEB"
        )

        await update.message.reply_text(report)

    except Exception as error:
        await update.message.reply_text(
            f"❌ Analyzer error:\\n{error}"
        )

async def security(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = generate_password(16)

    await update.message.reply_text(
        "🔐 Security Tools\n\n"
        f"🔑 Sample Generated Password:\n{password}\n\n"
        "Available tools:\n"
        "• Password Generator\n"
        "• Password Strength\n"
        "• MD5 / SHA Hashing\n"
        "• Base64 Encode/Decode\n"
        "• URL Encode/Decode"
    )



async def network(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "🌐 Network Security Analyzer\n\n"
            "Use:\n"
            "/network example.com"
        )
        return

    host = context.args[0]

    try:
        result = run_network_pipeline(host)

        report = format_telegram_report(
            result,
            "NETWORK"
        )

        dns = result.get("dns", {})
        ports = result.get("ports", {})
        tls = result.get("tls", {})

        addresses = dns.get("addresses", [])

        open_ports = [
            item for item in ports.get("ports", [])
            if item.get("status") == "open"
        ]

        lines = [
            report,
            "",
            "📡 NETWORK DETAILS",
            "",
            "DNS",
            "✅ Resolved" if addresses else "❌ Resolution failed",
            "",
            "🚪 Tested Ports",
        ]

        if open_ports:
            for item in open_ports:
                lines.append(
                    f"✅ {item.get('port')} — "
                    f"{item.get('service', 'unknown')}"
                )
        else:
            lines.append("No tested ports reported open.")

        lines.extend([
            "",
            "🔐 TLS",
            (
                f"✅ {tls.get('tls_version')} | "
                f"{tls.get('days_remaining')} days remaining"
            )
            if tls.get("valid")
            else "❌ TLS validation failed"
        ])

        await update.message.reply_text("\n".join(lines))

    except Exception as error:
        await update.message.reply_text(
            f"❌ Network analyzer error:\n{error}"
        )



async def reports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        report_files = list_reports(10)

        if not report_files:
            await update.message.reply_text(
                "📁 No saved security reports."
            )
            return

        lines = [
            "🛡️ OPENSHIELD AI",
            "📁 RECENT SECURITY REPORTS",
            "",
        ]

        for report in report_files:
            lines.append(f"• {report}")

        await update.message.reply_text("\n".join(lines))

    except Exception as error:
        await update.message.reply_text(
            f"❌ Report listing error:\n{error}"
        )


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        index = 1

        if context.args:
            try:
                index = int(context.args[0])
            except ValueError:
                await update.message.reply_text(
                    "❌ Usage: /report or /report 2"
                )
                return

        if index < 1 or index > 10:
            await update.message.reply_text(
                "❌ Report number must be between 1 and 10."
            )
            return

        saved = load_report(index)

        if not saved:
            await update.message.reply_text(
                "📁 Report not found."
            )
            return

        result = saved.get("result", {})
        report_type = saved.get("report_type", "SECURITY")

        message = format_telegram_report(
            result.get("pipeline", result),
            report_type,
        )

        await update.message.reply_text(message)

    except Exception as error:
        await update.message.reply_text(
            f"❌ Report loading error:\n{error}"
        )

def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("security", security))
    app.add_handler(CommandHandler("analyze", analyze))
    app.add_handler(CommandHandler("network", network))
    app.add_handler(CommandHandler("reports", reports))
    app.add_handler(CommandHandler("report", report))

    print("🛡️ OpenShield AI Bot Running...")
    app.run_polling()


if __name__ == "__main__":
    main()
