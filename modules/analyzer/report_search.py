import json
from pathlib import Path

REPORT_DIR = Path("reports")


def search_reports(keyword):
    results = []

    keyword = keyword.lower()

    if not REPORT_DIR.exists():
        return results

    for report in REPORT_DIR.glob("*.json"):
        try:
            data = json.loads(
                report.read_text(encoding="utf-8")
            )

            text = json.dumps(
                data,
                ensure_ascii=False
            ).lower()

            if keyword in text:
                results.append(str(report))

        except Exception:
            continue

    return results
