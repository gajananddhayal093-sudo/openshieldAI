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

def load_report(index=1):
    reports = list_reports(index)

    if len(reports) < index:
        return None

    report_path = Path(reports[index - 1])

    return json.loads(
        report_path.read_text(encoding="utf-8")
    )

def get_report_stats(limit=50):
    reports = list_reports(limit)

    stats = {
        "total": 0,
        "web": 0,
        "network": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
        "findings": 0,
    }

    for report in reports:
        try:
            data = json.loads(
                Path(report).read_text(encoding="utf-8")
            )

            stats["total"] += 1

            report_type = data.get(
                "report_type", ""
            ).lower()

            if report_type == "web":
                stats["web"] += 1
            elif report_type == "network":
                stats["network"] += 1

            result = data.get("result", {})
            pipeline = result.get("pipeline", result)
            risk = pipeline.get("risk", {})

            level = str(
                risk.get("risk", "")
            ).lower()

            if level in stats:
                stats[level] += 1

            stats["findings"] += len(
                pipeline.get("findings", [])
            )

        except (OSError, json.JSONDecodeError):
            continue

    return stats
