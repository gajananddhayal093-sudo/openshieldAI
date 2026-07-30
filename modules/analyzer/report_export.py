import zipfile
from pathlib import Path


def export_report(report_path):
    report = Path(report_path)

    if not report.exists():
        return None

    export_file = report.with_suffix(".zip")

    files = [
        report,
        report.with_suffix(".pdf"),
        report.with_suffix(".html"),
    ]

    with zipfile.ZipFile(export_file, "w") as z:
        for file in files:
            if file.exists():
                z.write(file, file.name)

    return str(export_file)
