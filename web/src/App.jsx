import { useEffect, useMemo, useState } from "react";

const DEFAULT_STATUS = "Idle - ready to scan.";

const SEVERITY_LEVELS = ["HIGH", "MEDIUM", "LOW", "INFO"];
const SCAN_PHASES = [
  "Uploading inputs",
  "Hashing files",
  "Parsing logs",
  "Matching IOCs",
  "Writing report"
];
const MD5_RE = /^[a-fA-F0-9]{32}$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;
const IP_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const URL_RE = /^https?:\/\//i;
const DOMAIN_RE = /^(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})$/;

const initialFilters = {
  md5: true,
  sha256: true,
  ip: true,
  domain: true,
  url: true
};

const IOC_ACCEPT = ".json,.txt";
const TARGET_ACCEPT = ".exe,.dll,.sys,.bin";
const LOG_ACCEPT = ".log";

const CSV_SPLIT_RE = /,(?=(?:[^"]*"[^"]*")*[^"]*$)/;

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function summarizeIocs(iocItems) {
  const counts = { md5: 0, sha256: 0, ip: 0, domain: 0, url: 0, total: 0 };
  iocItems.forEach((item) => {
    if (counts[item.type] !== undefined) {
      counts[item.type] += 1;
      counts.total += 1;
    }
  });
  return counts;
}

function parseTxtIocs(text) {
  const lines = text.split(/\r?\n/).map((line) => line.trim());
  const items = [];
  lines.forEach((line) => {
    if (!line || line.startsWith("#")) return;
    const parts = line.split("|").map((part) => part.trim());
    if (parts.length === 1) {
      items.push({ type: "unknown", value: parts[0], severity: "MEDIUM" });
      return;
    }
    items.push({
      type: parts[0].toLowerCase(),
      value: parts[1] || "",
      severity: (parts[2] || "MEDIUM").toUpperCase(),
      label: parts[3] || ""
    });
  });
  return items;
}

function inferType(value) {
  if (MD5_RE.test(value)) return "md5";
  if (SHA256_RE.test(value)) return "sha256";
  if (IP_RE.test(value)) return "ip";
  if (URL_RE.test(value)) return "url";
  if (DOMAIN_RE.test(value)) return "domain";
  return "unknown";
}

function parseJsonIocs(text) {
  const raw = JSON.parse(text);
  const items = [];
  const normalizeGroup = (group, values) => {
    const groupKey = group.toLowerCase();
    const extractType = (value) => {
      if (groupKey === "hashes" || groupKey === "hash") {
        return inferType(value);
      }
      if (groupKey.endsWith("s")) {
        return groupKey.slice(0, -1);
      }
      return groupKey;
    };
    values.forEach((entry) => {
      if (typeof entry === "string") {
        items.push({
          type: extractType(entry),
          value: entry,
          severity: "MEDIUM"
        });
      } else if (entry && typeof entry === "object") {
        items.push({
          type: extractType(entry.value || ""),
          value: entry.value || "",
          severity: (entry.severity || "MEDIUM").toUpperCase(),
          label: entry.label || ""
        });
      }
    });
  };

  if (Array.isArray(raw)) {
    normalizeGroup("hashes", raw);
  } else if (raw && typeof raw === "object") {
    Object.keys(raw).forEach((key) => {
      const value = raw[key];
      if (Array.isArray(value)) {
        normalizeGroup(key, value);
      }
    });
  }

  return items;
}

function mapApiHits(apiHits = []) {
  return apiHits.map((hit, index) => ({
    id: `hit-${index}`,
    type: (hit.ioc_type || hit.type || "unknown").toLowerCase(),
    value: hit.value || "",
    severity: (hit.severity || "MEDIUM").toUpperCase(),
    label: hit.label || "",
    source: hit.source || "log",
    path: hit.path || "",
    context: hit.context || "",
    line: hit.line_number ? String(hit.line_number) : ""
  }));
}

export default function App() {
  const [status, setStatus] = useState(DEFAULT_STATUS);
  const [iocItems, setIocItems] = useState([]);
  const [iocFileName, setIocFileName] = useState("None");
  const [iocFile, setIocFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [logs, setLogs] = useState([]);
  const [filters, setFilters] = useState(initialFilters);
  const [hits, setHits] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanPhaseIndex, setScanPhaseIndex] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [sortBy, setSortBy] = useState("severity");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [consoleLines, setConsoleLines] = useState([
    "Welcome to IOC Scanner Lite.",
    "Load IOC lists to begin."
  ]);

  const counts = useMemo(() => summarizeIocs(iocItems), [iocItems]);

  useEffect(() => {
    if (!isScanning) return undefined;
    setScanProgress(8);
    setScanPhaseIndex(0);
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        const next = Math.min(prev + 7, 95);
        return next;
      });
      setScanPhaseIndex((prev) => (prev + 1) % SCAN_PHASES.length);
    }, 1200);
    return () => clearInterval(interval);
  }, [isScanning]);

  const appendConsole = (line) => {
    setConsoleLines((prev) => [line, ...prev].slice(0, 6));
  };

  const handleIocFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    let parsed = [];
    try {
      if (file.name.toLowerCase().endsWith(".json")) {
        parsed = parseJsonIocs(text);
      } else {
        parsed = parseTxtIocs(text);
      }
      setIocItems(parsed);
      setIocFileName(file.name);
      setIocFile(file);
      setStatus(`Loaded ${parsed.length} IOC entries.`);
      appendConsole(`IOC list loaded from ${file.name}`);
    } catch (error) {
      setStatus("Failed to parse IOC list. Check format.");
      appendConsole(`IOC parse error: ${error.message}`);
    }
  };

  const handleFiles = (event) => {
    const selected = Array.from(event.target.files || []);
    setFiles(selected);
    setStatus(`${selected.length} files selected for hashing.`);
    appendConsole(`Selected ${selected.length} files for hashing.`);
  };

  const handleLogs = (event) => {
    const selected = Array.from(event.target.files || []);
    setLogs(selected);
    setStatus(`${selected.length} log files ready for parsing.`);
    appendConsole(`Selected ${selected.length} log files.`);
  };

  const handleScan = async () => {
    if (!iocFile) {
      setStatus("Load an IOC list before running a scan.");
      appendConsole("Scan blocked: no IOC file loaded.");
      return;
    }
    setIsScanning(true);
    setStatus("Running scan against local API...");
    appendConsole("Scan started via API.");

    try {
      const formData = new FormData();
      formData.append("iocs", iocFile);
      files.forEach((file) => formData.append("files", file));
      logs.forEach((log) => formData.append("logs", log));
      formData.append(
        "filters",
        JSON.stringify({
          types: Object.keys(filters).filter((key) => filters[key])
        })
      );

      const response = await fetch("/api/scan", {
        method: "POST",
        body: formData
      });

      if (!response.ok) {
        const detail = await response.text();
        throw new Error(detail || "Scan request failed");
      }

      const data = await response.json();
      const mappedHits = mapApiHits(data.hits || []);
      setHits(mappedHits);
      setScanProgress(100);
      setStatus(`Scan complete. ${mappedHits.length} hits found.`);
      appendConsole(`Report saved to ${data.report_path}`);
    } catch (error) {
      setStatus("Scan failed. Check API status.");
      appendConsole(`Scan error: ${error.message}`);
    } finally {
      setIsScanning(false);
      setTimeout(() => setScanProgress(0), 1400);
    }
  };

  const handleClear = () => {
    setHits([]);
    setStatus(DEFAULT_STATUS);

    setSearchTerm("");
    setSeverityFilter("all");
    setTypeFilter("all");
    setSourceFilter("all");
    setPage(1);
    appendConsole("Cleared current hits.");
  };

  const handleFilterToggle = (key) => {
    setFilters((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  useEffect(() => {
    setPage(1);
  }, [searchTerm, severityFilter, typeFilter, sourceFilter, sortBy, sortDir, pageSize]);

  const filteredHits = useMemo(() => {
    const search = searchTerm.trim().toLowerCase();
    return hits.filter((hit) => {
      if (severityFilter !== "all" && hit.severity !== severityFilter) return false;
      if (typeFilter !== "all" && hit.type !== typeFilter) return false;
      if (sourceFilter !== "all" && hit.source !== sourceFilter) return false;
      if (!search) return true;
      const haystack = [hit.value, hit.path, hit.label, hit.context]
        .join(" ")
        .toLowerCase();
      return haystack.includes(search);
    });
  }, [hits, searchTerm, severityFilter, typeFilter, sourceFilter]);

  const sortedHits = useMemo(() => {
    const severityRank = {
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFO: 1
    };
    const sorted = [...filteredHits].sort((a, b) => {
      let aValue = a[sortBy] ?? "";
      let bValue = b[sortBy] ?? "";
      if (sortBy === "severity") {
        aValue = severityRank[a.severity] || 0;
        bValue = severityRank[b.severity] || 0;
      }
      if (typeof aValue === "string") aValue = aValue.toLowerCase();
      if (typeof bValue === "string") bValue = bValue.toLowerCase();
      if (aValue < bValue) return sortDir === "asc" ? -1 : 1;
      if (aValue > bValue) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [filteredHits, sortBy, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sortedHits.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * pageSize;
  const pagedHits = sortedHits.slice(pageStart, pageStart + pageSize);

  const severityStats = useMemo(() => {
    return SEVERITY_LEVELS.map((level) => ({
      label: level,
      value: filteredHits.filter((hit) => hit.severity === level).length
    }));
  }, [filteredHits]);

  const typeStats = useMemo(() => {
    const countsByType = filteredHits.reduce((acc, hit) => {
      acc[hit.type] = (acc[hit.type] || 0) + 1;
      return acc;
    }, {});
    return Object.keys(countsByType)
      .sort()
      .map((type) => ({ label: type.toUpperCase(), value: countsByType[type] }));
  }, [filteredHits]);

  const severityCounts = useMemo(() => {
    return hits.reduce(
      (acc, hit) => {
        acc[hit.severity] = (acc[hit.severity] || 0) + 1;
        return acc;
      },
      { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    );
  }, [hits]);

  const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);

  return (
    <div className="app">
      <header className="top-bar">
        <div className="brand-vertical">
          <svg
            className="brand-icon"
            viewBox="0 0 64 64"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* Shield outline */}
            <path
              d="M32 8L12 16V32C12 44 32 56 32 56C32 56 52 44 52 32V16L32 8Z"
              stroke="currentColor"
              strokeWidth="2"
              fill="none"
            />
            {/* Scan lines */}
            <line x1="24" y1="24" x2="40" y2="24" stroke="currentColor" strokeWidth="2" />
            <line x1="24" y1="32" x2="40" y2="32" stroke="currentColor" strokeWidth="2" />
            <line x1="24" y1="40" x2="40" y2="40" stroke="currentColor" strokeWidth="2" />
          </svg>
          <div className="brand-text">
            <div className="brand-title">SCANNER LITE</div>
            <div className="brand-sub">FILES + LOGS</div>
          </div>
        </div>
        <div className="top-meta">
          <div className="status">
            <span className="status-label">Status</span>
            <span className="status-value">{status}</span>
          </div>
          <div className="session-pill">
            <span className="dot" />
            Live session
          </div>
        </div>
      </header>

      <section className="page-head">
        <div>
          <div className="page-kicker">Threat intel console</div>
          <h1 className="page-title">IOC Scanner Dashboard</h1>
          <p className="page-sub">
            Load IOC lists, scan binaries and logs, and export verified reports.
          </p>
        </div>
        <div className="quick-stats">
          <div className="stat-pill">
            <span>Total IOCs</span>
            <strong>{counts.total}</strong>
          </div>
          <div className="stat-pill">
            <span>Files</span>
            <strong>{files.length}</strong>
          </div>
          <div className="stat-pill">
            <span>Logs</span>
            <strong>{logs.length}</strong>
          </div>
        </div>
      </section>

      <div className="layout">
        <aside className="sidebar">
          <section className="card">
            <h2>IOC Intake</h2>
            <p className="muted">Load JSON or TXT lists with severity tagging.</p>
            <div className="hint">Allowed: JSON, TXT</div>
            <label className="file-input">
              <input type="file" accept={IOC_ACCEPT} onChange={handleIocFile} />
              <span>Load IOC list</span>
            </label>
            <div className="meta">
              <div>Source: {iocFileName}</div>
              <div>Total IOCs: {counts.total}</div>
            </div>
          </section>

          <section className="card">
            <h2>Target Files</h2>
            <p className="muted">Hash files to compare MD5/SHA256.</p>
            <div className="hint">Allowed: EXE, DLL, SYS, BIN</div>
            <label className="file-input">
              <input type="file" multiple accept={TARGET_ACCEPT} onChange={handleFiles} />
              <span>Select files</span>
            </label>
            <div className="meta">
              <div>Files: {files.length}</div>
              <div>Total size: {formatBytes(totalFileSize)}</div>
            </div>
          </section>

          <section className="card">
            <h2>Log Sources</h2>
            <p className="muted">Parse logs and match IOCs via regex.</p>
            <div className="hint">Allowed: LOG</div>
            <label className="file-input">
              <input type="file" multiple accept={LOG_ACCEPT} onChange={handleLogs} />
              <span>Select logs</span>
            </label>
            <div className="meta">
              <div>Logs: {logs.length}</div>
              <div>Parser: regex pipeline</div>
            </div>
          </section>
        </aside>

        <main className="main">
          <section className="panel action-panel">
            <div>
              <h2>Scan Controls</h2>
              <p className="muted">Toggle IOC types and run a scan.</p>
              <div className="chip-row">
                {Object.keys(filters).map((key) => (
                  <button
                    key={key}
                    className={`chip ${filters[key] ? "active" : ""}`}
                    onClick={() => handleFilterToggle(key)}
                    type="button"
                  >
                    {key.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            <div className="actions">
              <button
                className="primary"
                onClick={handleScan}
                type="button"
                disabled={isScanning}
              >
                Run scan
              </button>
              <button onClick={handleClear} type="button" disabled={isScanning}>
                Clear hits
              </button>
            </div>
            <div className="meta">
              <div>Scan Results</div>
              <div className="progress">
                <div className="progress-bar" style={{ width: `${scanProgress}%` }} />
              </div>
              <div className="progress-meta">
                {isScanning
                  ? `Phase: ${SCAN_PHASES[scanPhaseIndex]}`
                  : "Idle - awaiting scan"}
              </div>
            </div>
          </section>

          <section className="panel grid">
            <div className="metric">
              <h3>IOC Coverage</h3>
              <div className="metric-value">{counts.total}</div>
              <div className="metric-sub">Total entries loaded</div>
              <div className="metric-tags">
                <span>MD5 {counts.md5}</span>
                <span>SHA256 {counts.sha256}</span>
                <span>IP {counts.ip}</span>
                <span>Domain {counts.domain}</span>
                <span>URL {counts.url}</span>
              </div>
            </div>
            <div className="metric">
              <h3>Current Hits</h3>
              <div className="metric-value">{hits.length}</div>
              <div className="metric-sub">Matches detected</div>
              <div className="metric-tags">
                <span className="pill high">HIGH {severityCounts.HIGH}</span>
                <span className="pill med">MEDIUM {severityCounts.MEDIUM}</span>
                <span className="pill low">LOW {severityCounts.LOW}</span>
                <span className="pill info">INFO {severityCounts.INFO}</span>
              </div>
            </div>
            <div className="metric">
              <h3>Session Notes</h3>
              <div className="console">
                {consoleLines.map((line, index) => (
                  <div key={index} className="console-line">
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="panel analytics">
            <div className="panel-header">
              <h2>Analytics</h2>
              <span className="muted">Live view from current results</span>
            </div>
            <div className="analytics-grid">
              <div className="chart">
                <h3>Severity Mix</h3>
                <div className="chart-body">
                  {severityStats.map((item) => (
                    <div key={item.label} className="chart-row">
                      <span>{item.label}</span>
                      <div className="chart-track">
                        <div
                          className={`chart-fill ${item.label.toLowerCase()}`}
                          style={{
                            width: `${
                              Math.max(
                                8,
                                (item.value / Math.max(filteredHits.length, 1)) * 100
                              )
                            }%`
                          }}
                        />
                      </div>
                      <strong>{item.value}</strong>
                    </div>
                  ))}
                </div>
              </div>
              <div className="chart">
                <h3>IOC Types</h3>
                <div className="chart-body">
                  {typeStats.length ? (
                    typeStats.map((item) => (
                      <div key={item.label} className="chart-row">
                        <span>{item.label}</span>
                        <div className="chart-track">
                          <div
                            className="chart-fill info"
                            style={{
                              width: `${
                                Math.max(
                                  8,
                                  (item.value / Math.max(filteredHits.length, 1)) * 100
                                )
                              }%`
                            }}
                          />
                        </div>
                        <strong>{item.value}</strong>
                      </div>
                    ))
                  ) : (
                    <div className="muted">No hits yet.</div>
                  )}
                </div>
              </div>
            </div>
          </section>

          <section className="panel table-panel">
            <div className="panel-header">
              <h2>Detection Results</h2>
              <span className="muted">Most recent hits</span>
            </div>
            <div className="table-controls">
              <input
                className="control-input"
                type="search"
                placeholder="Search value, path, label..."
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
              />
              <select
                className="control-select"
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value)}
              >
                <option value="all">All severities</option>
                {SEVERITY_LEVELS.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
              <select
                className="control-select"
                value={typeFilter}
                onChange={(event) => setTypeFilter(event.target.value)}
              >
                <option value="all">All types</option>
                {Object.keys(initialFilters).map((key) => (
                  <option key={key} value={key}>
                    {key.toUpperCase()}
                  </option>
                ))}
              </select>
              <select
                className="control-select"
                value={sourceFilter}
                onChange={(event) => setSourceFilter(event.target.value)}
              >
                <option value="all">All sources</option>
                <option value="file">File</option>
                <option value="log">Log</option>
              </select>
              <select
                className="control-select"
                value={sortBy}
                onChange={(event) => setSortBy(event.target.value)}
              >
                <option value="severity">Sort by severity</option>
                <option value="type">Sort by type</option>
                <option value="value">Sort by value</option>
                <option value="source">Sort by source</option>
                <option value="path">Sort by path</option>
              </select>
              <select
                className="control-select"
                value={sortDir}
                onChange={(event) => setSortDir(event.target.value)}
              >
                <option value="desc">Descending</option>
                <option value="asc">Ascending</option>
              </select>
              <select
                className="control-select"
                value={pageSize}
                onChange={(event) => setPageSize(Number(event.target.value))}
              >
                <option value={10}>10 rows</option>
                <option value={25}>25 rows</option>
                <option value={50}>50 rows</option>
              </select>
            </div>
            <div className="table">
              <div className="table-head">
                <span>Severity</span>
                <span>Type</span>
                <span>Value</span>
                <span>Source</span>
                <span>Location</span>
              </div>
              {pagedHits.length === 0 ? (
                <div className="table-empty">
                  No hits yet. Load IOCs and run a scan.
                </div>
              ) : (
                pagedHits.map((hit) => (
                  <div key={hit.id} className="table-row">
                    <span className={`pill ${hit.severity.toLowerCase()}`}>
                      {hit.severity}
                    </span>
                    <span>{hit.type.toUpperCase()}</span>
                    <span className="mono">{hit.value}</span>
                    <span>{hit.source}</span>
                    <span>{hit.path}</span>
                  </div>
                ))
              )}
            </div>
            <div className="table-footer">
              <span className="muted">
                Showing {pagedHits.length} of {sortedHits.length} hits
              </span>
              <div className="pagination">
                <button
                  type="button"
                  onClick={() => setPage(Math.max(currentPage - 1, 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </button>
                <span>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  type="button"
                  onClick={() => setPage(Math.min(currentPage + 1, totalPages))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          </section>


        </main>
      </div>

      <footer className="footer">
        <div>
          <strong>Scan Results</strong>
          <div className="muted">
            View and filter scan results using the controls above.
          </div>
        </div>
      </footer>
    </div>
  );
}
