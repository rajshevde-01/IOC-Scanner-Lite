# IOC Scanner Lite

> A comprehensive IOC (Indicator of Compromise) scanner with an interactive dashboard for scanning files and logs against threat intelligence lists.

[![Python 3.x](https://img.shields.io/badge/Python-3.8+-blue.svg?style=flat-square&logo=python)](https://www.python.org/)
[![React 18](https://img.shields.io/badge/React-18.2+-61dafb.svg?style=flat-square&logo=react)](https://reactjs.org/)
[![Flask 3](https://img.shields.io/badge/Flask-3.0+-000000.svg?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

## 🎯 Overview

IOC Scanner Lite is a threat intelligence tool that helps security teams quickly scan files and logs against IOC lists. Features include:

- **Interactive Web Dashboard** – Dark-themed React UI with real-time analytics
- **File Scanning** – Hash files (MD5/SHA256) and compare against IOCs
- **Log Parsing** – Regex-based IOC detection in log files
- **Multiple Formats** – Load IOCs from JSON or TXT
- **Rich Reports** – Generate JSON and CSV exports with severity tagging
- **RESTful API** – Flask backend for programmatic access

## 📸 Screenshots

### Dashboard Header & Controls
![Dashboard Header](docs/screenshots/screenshot-header.png)

### Scan Results & Analytics
![Dashboard Results](docs/screenshots/screenshot-results.png)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+ (for dashboard)
- pip and npm

### Installation

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd "IOC Scanner (Files + Logs)"
   ```

2. **Set up Python environment**
   ```bash
   python -m venv .venv
   # On Windows:
   .\.venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Build the dashboard**
   ```bash
   cd web
   npm install
   npm run build
   cd ..
   ```

### Running the Application

**With integrated Flask server (production):**
```bash
python -m ioc_scanner_lite.api
```
Access the dashboard at: **http://localhost:5000**

The server will:
- Serve the React dashboard on port 5000
- Provide API endpoints for scanning
- Generate and store reports in the `reports/` directory

## 📖 Usage

### Dashboard

1. **Load IOCs** – Upload a JSON or TXT file with IOC entries
2. **Select Files** – Choose binary files to hash (`.exe`, `.dll`, `.sys`, `.bin`)
3. **Select Logs** – Choose log files to parse (`.log`)
4. **Run Scan** – Click "Run scan" to execute
5. **View Results** – Filter, sort, and paginate through hits

### CLI

For headless scanning:

```bash
python -m ioc_scanner_lite --iocs examples/iocs.json \
  --files examples/malware.exe \
  --logs examples/sample.log \
  --out-json report.json \
  --out-csv report.csv
```

#### Options
- `--iocs <file>` – IOC list file (JSON or TXT) [required]
- `--files <paths...>` – Files to hash and scan
- `--logs <paths...>` – Log files to parse and scan
- `--out-json <path>` – Save JSON report
- `--out-csv <path>` – Save CSV report
- `--filter-types <type,...>` – Only scan specific IOC types (md5, sha256, ip, domain, url)

## 🔧 Configuration

### IOC File Formats

#### JSON Format
```json
{
  "hashes": [
    { "value": "9e107d9d372bb6826bd81d3542a419d6", "severity": "HIGH", "label": "malware.exe" }
  ],
  "ips": [
    { "value": "203.0.113.42", "severity": "MEDIUM", "label": "Known bad IP" }
  ],
  "domains": [
    "evil.example"
  ],
  "urls": [
    { "value": "http://evil.example/payload", "severity": "HIGH" }
  ]
}
```

#### TXT Format (Pipe-delimited)
```
type|value|severity|label

# Examples:
md5|9e107d9d372bb6826bd81d3542a419d6|HIGH|Trojan.exe
sha256|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|HIGH|Backdoor sample
ip|203.0.113.42|MEDIUM|C2 server
domain|evil.example|MEDIUM|Malicious domain
url|http://evil.example/payload|HIGH|Payload download
```

### File Restrictions

- **IOC Intake** – `.json`, `.txt` only
- **Target Files** – `.exe`, `.dll`, `.sys`, `.bin` only
- **Log Sources** – `.log` only

## 📊 API Endpoints

### Health Check
```bash
GET /api/health
```

### Run Scan
```bash
POST /api/scan
```

**Request (multipart/form-data):**
- `iocs` – IOC file (required)
- `files` – Target files to scan
- `logs` – Log files to parse
- `filters` – JSON string with `{"types": ["md5", "ip", ...]}` (optional)

**Response:**
```json
{
  "summary": {
    "total_hits": 2,
    "by_severity": {"HIGH": 1, "MEDIUM": 1},
    "by_type": {"md5": 1, "ip": 1}
  },
  "report_path": "reports/20260213T200000Z/report.json",
  "csv_path": "reports/20260213T200000Z/report.csv",
  "hits": [...]
}
```

### Download Latest Report
```bash
GET /api/report/latest?type=json|csv
```

## 🏗️ Project Structure

```
├── src/ioc_scanner_lite/
│   ├── __init__.py
│   ├── api.py              # Flask REST API & static file serving
│   ├── scanner.py          # Core scanning engine
│   └── cli.py              # Command-line interface
├── web/
│   ├── src/
│   │   ├── App.jsx         # React main component
│   │   └── styles.css      # Dark theme styling
│   ├── dist/               # Built static files (production)
│   └── package.json
├── examples/               # Sample IOCs and test files
├── reports/                # Generated scan reports (auto-created)
├── docs/screenshots/       # Documentation images
├── requirements.txt        # Python dependencies
└── README.md
```

## 🛠️ Development

### Build for Production

After modifying React code, rebuild the dashboard:

```bash
cd web
npm run build
# Static files output to web/dist/
cd ..
```

### Run Development

1. **Flask API (separate terminal):**
   ```bash
   python -m ioc_scanner_lite.api  # Port 5000
   ```

2. **Optional Vite Dev Server (for live reload):**
   ```bash
   cd web
   npm run dev  # Port 5173 (proxies /api to port 5000)
   ```

## 📋 Features

### Dashboard UI
- ✅ Dark theme with blue accent color
- ✅ Real-time scan progress indicator with phase tracking
- ✅ Analytics charts (severity distribution, IOC type breakdown)
- ✅ Advanced filtering (search, severity, type, source)
- ✅ Sorting by severity, type, value, source, or path
- ✅ Pagination (10/25/50 rows per page)
- ✅ Live session console for logging events
- ✅ Responsive design (desktop, tablet, mobile)
- ✅ Shield icon logo with monospace typography

### Scanner Engine
- ✅ MD5 and SHA256 file hashing
- ✅ Regex-based log parsing
- ✅ Multi-format IOC support (JSON, TXT)
- ✅ Severity tagging (HIGH, MEDIUM, LOW, INFO)
- ✅ Type inference (MD5, SHA256, IP, Domain, URL)
- ✅ Report generation (JSON, CSV)

## 🔐 Security Notes

- IOC Scanner processes files locally in memory
- No data is sent to external services
- Reports are stored in the `reports/` directory with timestamp-based filenames
- Sensitive files should be handled securely in production


## 🐛 Troubleshooting

### Flask API Port Already in Use
```powershell
# Kill the process using port 5000
Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess | Stop-Process -Force
```

### Dashboard Not Loading at localhost:5000
- Ensure Flask is running: `python -m ioc_scanner_lite.api`
- Check that `web/dist/` directory exists (run `npm run build` if not)
- Clear browser cache (Ctrl+Shift+Delete)

### API Returns "No reports available"
- Run a scan first to generate reports
- Check that `reports/` directory exists

### Python Venv Not Activating (Windows)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv\Scripts\Activate.ps1
```

## 📚 Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [React Documentation](https://react.dev/)
- [YARA Rules](https://yara.readthedocs.io/)
- [MISP Project](https://www.misp-project.org/)
- [AlienVault OTX](https://otx.alienvault.com/)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## 👤 Author

**Raj Shevde**  
SOC & VAPT Track | Blue Team | Defensive Security

[![LinkedIn](https://img.shields.io/badge/-LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/rajshevde)

Created for threat intelligence and security operations teams.

---

**Questions or issues?** Open a GitHub issue or contact the maintainers.
