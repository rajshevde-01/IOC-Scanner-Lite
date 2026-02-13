from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b")

DEFAULT_SEVERITY = "MEDIUM"


@dataclass(frozen=True)
class IOCItem:
    ioc_type: str
    value: str
    severity: str
    label: str


@dataclass
class Hit:
    ioc_type: str
    value: str
    severity: str
    label: str
    source: str
    path: str
    line_number: int | None
    context: str | None


IOCMap = Dict[str, Dict[str, List[IOCItem]]]


def normalize_value(ioc_type: str, value: str) -> str:
    if ioc_type in {"md5", "sha256", "domain", "url"}:
        return value.lower()
    return value


def infer_ioc_type(value: str) -> str:
    if MD5_RE.fullmatch(value):
        return "md5"
    if SHA256_RE.fullmatch(value):
        return "sha256"
    if IP_RE.fullmatch(value):
        return "ip"
    if URL_RE.fullmatch(value):
        return "url"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    return "unknown"


def normalize_iocs(items: Iterable[IOCItem]) -> IOCMap:
    normalized: IOCMap = {}
    for item in items:
        normalized.setdefault(item.ioc_type, {})
        key = normalize_value(item.ioc_type, item.value)
        normalized[item.ioc_type].setdefault(key, []).append(item)
    return normalized


def load_iocs(path: Path) -> IOCMap:
    if path.suffix.lower() == ".json":
        items = _load_iocs_json(path)
    else:
        items = _load_iocs_txt(path)
    return normalize_iocs(items)


def _load_iocs_json(path: Path) -> List[IOCItem]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items: List[IOCItem] = []

    if isinstance(raw, dict):
        for key, values in raw.items():
            items.extend(_parse_json_group(key, values))
    elif isinstance(raw, list):
        items.extend(_parse_json_group("hashes", raw))
    else:
        raise ValueError("Unsupported JSON IOC structure")

    return items


def _parse_json_group(group: str, values: Iterable) -> List[IOCItem]:
    items: List[IOCItem] = []
    group = group.lower()
    for entry in values:
        if isinstance(entry, str):
            value = entry
            severity = DEFAULT_SEVERITY
            label = ""
        elif isinstance(entry, dict):
            value = str(entry.get("value", "")).strip()
            severity = str(entry.get("severity", DEFAULT_SEVERITY)).upper()
            label = str(entry.get("label", "")).strip()
        else:
            continue

        if not value:
            continue

        if group in {"hashes", "hash", "hashes_md5", "hashes_sha256"}:
            inferred = infer_ioc_type(value)
            if inferred in {"md5", "sha256"}:
                ioc_type = inferred
            else:
                ioc_type = "hash"
        elif group in {"md5", "sha256", "ip", "domain", "url"}:
            ioc_type = group
        elif group in {"ips", "domains", "urls"}:
            ioc_type = group[:-1]
        else:
            ioc_type = infer_ioc_type(value)

        if ioc_type == "hash":
            ioc_type = infer_ioc_type(value)

        items.append(IOCItem(ioc_type=ioc_type, value=value, severity=severity, label=label))

    return items


def _load_iocs_txt(path: Path) -> List[IOCItem]:
    items: List[IOCItem] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [part.strip() for part in line.split("|")]
        if len(parts) == 1:
            value = parts[0]
            ioc_type = infer_ioc_type(value)
            severity = DEFAULT_SEVERITY
            label = ""
        else:
            ioc_type = parts[0].lower()
            value = parts[1] if len(parts) > 1 else ""
            severity = parts[2].upper() if len(parts) > 2 and parts[2] else DEFAULT_SEVERITY
            label = parts[3] if len(parts) > 3 else ""

        if not value:
            continue

        if ioc_type in {"hash", "hashes"}:
            ioc_type = infer_ioc_type(value)

        items.append(IOCItem(ioc_type=ioc_type, value=value, severity=severity, label=label))

    return items


def expand_paths(inputs: Iterable[str]) -> List[Path]:
    paths: List[Path] = []
    for item in inputs:
        candidate = Path(item)
        if candidate.exists():
            if candidate.is_dir():
                paths.extend([p for p in candidate.rglob("*") if p.is_file()])
            else:
                paths.append(candidate)
        else:
            for globbed in Path().glob(item):
                if globbed.is_dir():
                    paths.extend([p for p in globbed.rglob("*") if p.is_file()])
                else:
                    paths.append(globbed)
    return paths


def hash_file(path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def scan_files(inputs: Iterable[str], iocs: IOCMap) -> List[Hit]:
    hits: List[Hit] = []
    paths = expand_paths(inputs)
    for path in paths:
        hashes = hash_file(path)
        for hash_type, value in hashes.items():
            matches = iocs.get(hash_type, {}).get(value.lower(), [])
            for match in matches:
                hits.append(
                    Hit(
                        ioc_type=hash_type,
                        value=match.value,
                        severity=match.severity,
                        label=match.label,
                        source="file",
                        path=str(path),
                        line_number=None,
                        context=None,
                    )
                )
    return hits


def scan_logs(inputs: Iterable[str], iocs: IOCMap) -> List[Hit]:
    hits: List[Hit] = []
    paths = expand_paths(inputs)
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                line_hits = extract_log_hits(line, iocs, path, line_number)
                hits.extend(line_hits)
    return hits


def extract_log_hits(line: str, iocs: IOCMap, path: Path, line_number: int) -> List[Hit]:
    hits: List[Hit] = []
    seen: set[tuple[str, str]] = set()

    for value in MD5_RE.findall(line):
        hits.extend(_match_candidate("md5", value, iocs, path, line_number, line, seen))
    for value in SHA256_RE.findall(line):
        hits.extend(_match_candidate("sha256", value, iocs, path, line_number, line, seen))
    for value in IP_RE.findall(line):
        hits.extend(_match_candidate("ip", value, iocs, path, line_number, line, seen))
    for value in URL_RE.findall(line):
        cleaned = value.rstrip("].,)\"'\"")
        hits.extend(_match_candidate("url", cleaned, iocs, path, line_number, line, seen))
    for value in DOMAIN_RE.findall(line):
        hits.extend(_match_candidate("domain", value, iocs, path, line_number, line, seen))

    return hits


def _match_candidate(
    ioc_type: str,
    value: str,
    iocs: IOCMap,
    path: Path,
    line_number: int,
    line: str,
    seen: set[tuple[str, str]],
) -> List[Hit]:
    normalized = normalize_value(ioc_type, value)
    if (ioc_type, normalized) in seen:
        return []
    seen.add((ioc_type, normalized))

    matches = iocs.get(ioc_type, {}).get(normalized, [])
    results: List[Hit] = []
    for match in matches:
        results.append(
            Hit(
                ioc_type=ioc_type,
                value=match.value,
                severity=match.severity,
                label=match.label,
                source="log",
                path=str(path),
                line_number=line_number,
                context=line.strip(),
            )
        )
    return results


def generate_report(ioc_path: Path, hits: List[Hit]) -> Dict:
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for hit in hits:
        by_severity[hit.severity] = by_severity.get(hit.severity, 0) + 1
        by_type[hit.ioc_type] = by_type.get(hit.ioc_type, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ioc_source": str(ioc_path),
        "summary": {
            "total_hits": len(hits),
            "by_severity": dict(sorted(by_severity.items())),
            "by_type": dict(sorted(by_type.items())),
        },
        "hits": [hit.__dict__ for hit in hits],
    }


def write_json(path: Path, report: Dict) -> None:
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_csv(path: Path, hits: List[Hit]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ioc_type",
                "value",
                "severity",
                "label",
                "source",
                "path",
                "line_number",
                "context",
            ],
        )
        writer.writeheader()
        for hit in hits:
            writer.writerow(hit.__dict__)
