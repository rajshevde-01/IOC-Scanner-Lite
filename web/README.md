# IOC Scanner Lite Dashboard

React/Vite dashboard for IOC Scanner Lite.

## Run

```bash
cd ..
python -m pip install -r requirements.txt
python -m ioc_scanner_lite.api
```

In a second terminal:

```bash
cd web
npm install
npm run dev
```

The dashboard runs at http://localhost:5173 and proxies /api to http://127.0.0.1:5000.
