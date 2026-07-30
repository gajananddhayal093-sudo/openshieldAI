import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph
from modules.analyzer.intelligence import generate_intelligence



REPORT_DIR = Path("reports")


def build_report_summary(result):
    pipeline = result.get("pipeline", result)
    risk = pipeline.get("risk", {})

    findings = pipeline.get("findings", [])

    severity_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "")
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "risk": risk.get("risk", "UNKNOWN"),
        "score": risk.get("score", 0),
        "findings_count": len(findings),
        "highest_severity": risk.get("highest_severity"),
        "severity_counts": severity_counts,
    }


def save_report(result, report_type="SECURITY"):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    filename = (
        f"{report_type.lower()}_"
        f"{timestamp.strftime('%Y%m%d_%H%M%S_%f')}.json"
    )

    path = REPORT_DIR / filename

    payload = {
        "schema_version": "1.0",
        "report_type": report_type.upper(),
        "generated_at": timestamp.isoformat(),
        "summary": build_report_summary(result),
        "intelligence": generate_intelligence(
            build_report_summary(result)
        ),
        "result": result,
    }

    report_data = json.dumps(payload, indent=2, ensure_ascii=False)

    report_hash = hashlib.sha256(
        report_data.encode("utf-8")
    ).hexdigest()

    payload["sha256"] = report_hash

    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    try:
        generate_pdf_report(payload, path.with_suffix(".pdf"))
    except Exception as e:
        print(f"PDF generation failed: {e}")

    try:
        generate_html_report(payload, path.with_suffix(".html"))
    except Exception as e:
        print(f"HTML generation failed: {e}")

    return str(path)


def generate_pdf_report(payload, pdf_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(pdf_path))

    story = [
        Paragraph("<b>OpenShield AI Security Report</b>", styles["Heading1"]),
        Paragraph(f"Report Type: {payload.get('report_type', 'UNKNOWN')}", styles["BodyText"]),
        Paragraph(f"Generated: {payload.get('generated_at', '')}", styles["BodyText"]),
    ]

    summary = payload.get("summary", {})
    story.append(Paragraph(f"Risk: {summary.get('risk', 'UNKNOWN')}", styles["BodyText"]))
    story.append(Paragraph(f"Score: {summary.get('score', 0)}", styles["BodyText"]))
    story.append(Paragraph(f"Findings: {summary.get('findings_count', 0)}", styles["BodyText"]))

    doc.build(story)



def generate_html_report(payload, html_path):
    summary = payload.get("summary", {})

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>OpenShield AI Security Report</title>
<meta charset="utf-8">
</head>
<body>
<h1>🛡️ OpenShield AI Security Report</h1>

<h2>Report Information</h2>
<p>Type: {payload.get("report_type", "UNKNOWN")}</p>
<p>Generated: {payload.get("generated_at", "")}</p>

<h2>Risk Assessment</h2>
<p>Risk: {summary.get("risk", "UNKNOWN")}</p>
<p>Score: {summary.get("score", 0)}/100</p>
<p>Findings: {summary.get("findings_count", 0)}</p>

<h2>SHA-256 Integrity</h2>
<p>{payload.get("sha256", "Not available")}</p>

</body>
</html>
"""

    html_path.write_text(html, encoding="utf-8")


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
        "average_score": 0,
        "severity_percentages": {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        },
    }

    total_score = 0

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

            total_score += float(
                risk.get("score", 0) or 0
            )

            stats["findings"] += len(
                pipeline.get("findings", [])
            )

        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue

    if stats["total"]:
        stats["average_score"] = round(
            total_score / stats["total"],
            2,
        )

        for level in (
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ):
            stats["severity_percentages"][level] = round(
                stats[level.lower()] / stats["total"] * 100,
                2,
            )

    return stats


def verify_report(report_path):
    path = Path(report_path)

    if not path.exists():
        return {
            "valid": False,
            "error": "Report not found"
        }

    try:
        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        stored_hash = data.get("sha256")

        if not stored_hash:
            return {
                "valid": False,
                "error": "SHA-256 hash missing"
            }

        data_without_hash = dict(data)
        data_without_hash.pop("sha256", None)

        report_data = json.dumps(
            data_without_hash,
            indent=2,
            ensure_ascii=False
        )

        current_hash = hashlib.sha256(
            report_data.encode("utf-8")
        ).hexdigest()

        return {
            "valid": stored_hash == current_hash,
            "stored_hash": stored_hash,
            "current_hash": current_hash
        }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }
