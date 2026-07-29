import json
from datetime import datetime, timezone
from pathlib import Path


REPORT_DIR = Path("reports")


def save_report(result, report_type="SECURITY"):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    filename = (
        f"{report_type.lower()}_"
        f"{timestamp.strftime('%Y%m%d_%H%M%S_%f')}.json"
    )

    path = REPORT_DIR / filename

    payload = {
        "report_type": report_type,
        "generated_at": timestamp.isoformat(),
        "result": result,
    }

    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return str(path)

def list_reports(limit=10):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    reports = sorted(
        REPORT_DIR.glob("*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    return [str(report) for report in reports[:limit]]
