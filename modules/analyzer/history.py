from database.scan_history import get_history


def generate_history(limit=10):
    rows = get_history(limit)

    if not rows:
        return "📊 No scan history found."

    text = "📊 OPENSHIELD AI SCAN HISTORY\n\n"

    for row in rows:
        text += (
            f"🆔 {row[0]}\n"
            f"🎯 Target: {row[1]}\n"
            f"🔎 Type: {row[2]}\n"
            f"⚠️ Risk: {row[3]}\n"
            f"📈 Score: {row[4]}/100\n"
            f"🕒 {row[5]}\n\n"
        )

    return text
