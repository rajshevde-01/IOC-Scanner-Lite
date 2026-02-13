from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from .scanner import generate_report, load_iocs, scan_files, scan_logs, write_csv, write_json

# Absolute path to project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DIST_DIR = PROJECT_ROOT / "web" / "dist"

# Flask app with static files from React build
app = Flask(__name__, static_folder=str(DIST_DIR), static_url_path="")


def _save_uploads(files, target_dir: Path) -> list[str]:
    saved: list[str] = []
    for uploaded in files:
        if not uploaded or not uploaded.filename:
            continue
        safe_name = Path(uploaded.filename).name
        destination = target_dir / safe_name
        uploaded.save(destination)
        saved.append(str(destination))
    return saved


def _parse_filters(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None

    types = payload.get("types") if isinstance(payload, dict) else None
    if not isinstance(types, list):
        return None
    return {str(item).lower() for item in types if item}


def _latest_report_dir() -> Path | None:
    reports_root = PROJECT_ROOT / "reports"
    if not reports_root.exists():
        return None
    report_dirs = [path for path in reports_root.iterdir() if path.is_dir()]
    if not report_dirs:
        return None
    return sorted(report_dirs, key=lambda path: path.name)[-1]


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/scan")
def scan():
    if "iocs" not in request.files:
        return jsonify({"error": "Missing IOC file"}), 400

    allowed_types = _parse_filters(request.form.get("filters"))

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        ioc_upload = request.files["iocs"]
        ioc_name = Path(ioc_upload.filename or "iocs.txt").name
        ioc_path = temp_path / ioc_name
        ioc_upload.save(ioc_path)

        file_paths = _save_uploads(request.files.getlist("files"), temp_path)
        log_paths = _save_uploads(request.files.getlist("logs"), temp_path)

        iocs = load_iocs(ioc_path)
        hits = scan_files(file_paths, iocs) + scan_logs(log_paths, iocs)

        if allowed_types:
            hits = [hit for hit in hits if hit.ioc_type.lower() in allowed_types]

        report = generate_report(ioc_path, hits)

        report_dir = PROJECT_ROOT / "reports" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_dir.mkdir(parents=True, exist_ok=True)
        json_path = report_dir / "report.json"
        csv_path = report_dir / "report.csv"
        write_json(json_path, report)
        write_csv(csv_path, hits)

    return jsonify(
        {
            "summary": report["summary"],
            "report_path": str(json_path),
            "csv_path": str(csv_path),
            "hits": report["hits"],
        }
    )


@app.get("/api/report/latest")
def download_latest():
    report_dir = _latest_report_dir()
    if not report_dir:
        abort(404, description="No reports available")

    report_type = (request.args.get("type") or "json").lower()
    if report_type not in {"json", "csv"}:
        abort(400, description="Unsupported report type")

    target = report_dir / f"report.{report_type}"
    if not target.exists():
        abort(404, description="Report file not found")

    return send_file(target, as_attachment=True)


@app.route("/")
def serve_index():
    """Serve the React app index.html"""
    return send_from_directory(str(DIST_DIR), "index.html")


@app.route("/<path:path>")
def serve_static(path):
    """Serve static files or fallback to index.html for SPA routing"""
    full_path = DIST_DIR / path
    if full_path.exists() and full_path.is_file():
        return send_from_directory(str(DIST_DIR), path)
    # Fallback to index.html for SPA routing
    return send_from_directory(str(DIST_DIR), "index.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
