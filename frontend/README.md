# FragGuard Runtime Viewer

This folder contains the modular runtime-backed viewer and local server.

## Run

From repo root:

```bash
python -m frontend.runtime_server --host 127.0.0.1 --port 8787
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787).

## Runtime data sources

- `seeds/*.json`
- `attacks/*.toml`
- `logs/session_*.jsonl`
- `mcp/logs/mcp_client_v1_*.log`

## API endpoints

- `GET /api/runs` - list discovered session logs
- `GET /api/run/latest` - normalized payload for newest session
- `GET /api/run/<session_file>` - normalized payload by session filename
- `POST /api/normalize_upload` - normalize uploaded arrays:
  - `seeds` (`list[dict]`)
  - `attacks` (`list[dict]`)
  - `session_events` (`list[dict]`)
