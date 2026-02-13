import argparse
import sys
from pathlib import Path

from .scanner import generate_report, load_iocs, scan_files, scan_logs, write_csv, write_json


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan files and logs against IOC lists and generate reports."
    )
    parser.add_argument("--iocs", required=True, help="Path to IOC list (JSON or TXT).")
    parser.add_argument(
        "--files",
        nargs="*",
        default=[],
        help="File paths or directories to hash and scan.",
    )
    parser.add_argument(
        "--logs",
        nargs="*",
        default=[],
        help="Log file paths or directories to parse.",
    )
    parser.add_argument(
        "--out-json",
        default="report.json",
        help="Path to write JSON report.",
    )
    parser.add_argument(
        "--out-csv",
        default="report.csv",
        help="Path to write CSV export.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    ioc_path = Path(args.iocs)
    if not ioc_path.exists():
        print(f"IOC file not found: {ioc_path}", file=sys.stderr)
        return 2

    iocs = load_iocs(ioc_path)
    file_hits = scan_files(args.files, iocs)
    log_hits = scan_logs(args.logs, iocs)
    hits = file_hits + log_hits

    report = generate_report(ioc_path, hits)
    write_json(Path(args.out_json), report)
    write_csv(Path(args.out_csv), hits)

    summary = report["summary"]
    print("IOC Scan Summary")
    print(f"Total hits: {summary['total_hits']}")
    print("By severity:")
    for severity, count in summary["by_severity"].items():
        print(f"  {severity}: {count}")
    print("By type:")
    for ioc_type, count in summary["by_type"].items():
        print(f"  {ioc_type}: {count}")
    print(f"JSON report: {args.out_json}")
    print(f"CSV export: {args.out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
