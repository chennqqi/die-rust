# died (die daemon) API Reference

died is the HTTP/JSON scan service for diec. It provides a REST API for
local and remote file identification, reusing the rule database across
requests to avoid repeated loading overhead.

## Quick Start

```sh
# Build and start the server
cargo build --release --package die-server
./target/release/died --db upstream/Detect-It-Easy/db --bind 127.0.0.1:18080
```

## API Endpoints

### `GET /health`

Returns service status and version information.

**Response** (`200 OK`):
```json
{
  "status": "ok",
  "programVersion": "0.3.0",
  "dbVersion": {
    "commit": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
    "ruleCount": 2037,
    "syncedAt": "2026-07-31T03:24:09Z"
  }
}
```

### `POST /scan/path`

Scan a local file by its path on the server filesystem.

**Request body** (`application/json`):
```json
{
  "path": "/path/to/file.exe",
  "flags": {
    "allTypes": false,
    "deep": false,
    "heuristic": false,
    "aggressive": false,
    "hideUnknown": false,
    "verbose": false
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | yes | File path on the server |
| `flags` | object | no | Scan flags (all default to `false`) |
| `flags.allTypes` | bool | no | Enable all file type rules (`--alltypes`) |
| `flags.deep` | bool | no | Deep scan mode |
| `flags.heuristic` | bool | no | Heuristic scan mode |
| `flags.aggressive` | bool | no | Aggressive scan mode |
| `flags.hideUnknown` | bool | no | Hide unknown detections |
| `flags.verbose` | bool | no | Verbose output |

**Response** (`200 OK`):
```json
{
  "path": "file.exe",
  "detections": [
    {
      "fileType": "PE",
      "type": "compiler",
      "name": "Microsoft Visual C/C++",
      "version": "19.44.35207",
      "options": "C"
    },
    {
      "fileType": "PE",
      "type": "linker",
      "name": "Microsoft Linker",
      "version": "14.44.35207",
      "options": null
    }
  ],
  "diagnostics": [],
  "programVersion": "0.3.0",
  "dbVersion": {
    "commit": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
    "ruleCount": 2037,
    "syncedAt": "2026-07-31T03:24:09Z"
  }
}
```

**Error responses**:
- `404` — file not found: `{"error": "not found: /path/to/file"}`
- `403` — path outside allowed root: `{"error": "path not allowed: ..."}`
- `413` — file too large: `{"error": "file too large: ... is N bytes (max M)"}`
- `500` — scan error: `{"error": "scan error: ..."}`

### `POST /scan/bytes`

Scan uploaded file content. The request body is the raw file bytes.

**URL query parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | no | File name hint (default: `uploaded.bin`) |
| `allTypes` | bool | no | Enable all file type rules |
| `deep` | bool | no | Deep scan mode |
| `heuristic` | bool | no | Heuristic scan mode |
| `aggressive` | bool | no | Aggressive scan mode |
| `hideUnknown` | bool | no | Hide unknown detections |
| `verbose` | bool | no | Verbose output |

**Request body**: raw file bytes (`application/octet-stream`)

**Response**: same as `/scan/path`

## Client Examples

### curl

```sh
# Health check
curl http://127.0.0.1:18080/health

# Scan local file by path
curl -X POST http://127.0.0.1:18080/scan/path \
  -H "Content-Type: application/json" \
  -d '{"path": "/usr/bin/ls", "flags": {"allTypes": true}}'

# Scan uploaded file content
curl -X POST "http://127.0.0.1:18080/scan/bytes?name=test.exe" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/path/to/file.exe

# Scan with hideUnknown flag
curl -X POST http://127.0.0.1:18080/scan/path \
  -H "Content-Type: application/json" \
  -d '{"path": "/usr/bin/ls", "flags": {"hideUnknown": true}}'
```

### PowerShell

```powershell
# Health check
Invoke-RestMethod -Uri "http://127.0.0.1:18080/health" -Method GET

# Scan local file by path
$body = @{ path = "C:\Windows\System32\notepad.exe"; flags = @{} } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:18080/scan/path" `
  -Method POST -ContentType "application/json" -Body $body

# Scan uploaded file content
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\file.exe")
Invoke-RestMethod -Uri "http://127.0.0.1:18080/scan/bytes?name=file.exe" `
  -Method POST -ContentType "application/octet-stream" -Body $bytes
```

### Python

```python
import requests

BASE = "http://127.0.0.1:18080"

# Health check
resp = requests.get(f"{BASE}/health")
print(resp.json())

# Scan local file by path
resp = requests.post(f"{BASE}/scan/path", json={
    "path": "/usr/bin/ls",
    "flags": {"allTypes": True}
})
for d in resp.json()["detections"]:
    print(f"  {d['type']}: {d['name']} {d.get('version', '')}")

# Scan uploaded file content
with open("file.exe", "rb") as f:
    resp = requests.post(
        f"{BASE}/scan/bytes?name=file.exe",
        data=f.read(),
        headers={"Content-Type": "application/octet-stream"}
    )
print(resp.json())
```

### Go

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	base := "http://127.0.0.1:18080"

	// Health check
	resp, _ := http.Get(base + "/health")
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Health:", string(body))
	resp.Body.Close()

	// Scan local file by path
	payload, _ := json.Marshal(map[string]any{
		"path":  "/usr/bin/ls",
		"flags": map[string]any{"allTypes": true},
	})
	resp, _ = http.Post(base+"/scan/path", "application/json", bytes.NewReader(payload))
	body, _ = io.ReadAll(resp.Body)
	fmt.Println("Scan:", string(body))
	resp.Body.Close()

	// Scan uploaded file content
	data, _ := os.ReadFile("file.exe")
	resp, _ = http.Post(base+"/scan/bytes?name=file.exe",
		"application/octet-stream", bytes.NewReader(data))
	body, _ = io.ReadAll(resp.Body)
	fmt.Println("Scan bytes:", string(body))
	resp.Body.Close()
}
```

### Batch scanning (Python)

```python
import requests
import os

BASE = "http://127.0.0.1:18080"

def scan_directory(dir_path):
    """Scan all files in a directory using the /scan/path endpoint."""
    results = []
    for name in os.listdir(dir_path):
        full = os.path.join(dir_path, name)
        if not os.path.isfile(full):
            continue
        resp = requests.post(f"{BASE}/scan/path", json={
            "path": full,
            "flags": {"hideUnknown": True}
        })
        if resp.status_code == 200:
            data = resp.json()
            results.append({
                "file": name,
                "detections": [
                    f"{d['type']}:{d['name']}" for d in data["detections"]
                ]
            })
    return results

for r in scan_directory("/usr/bin"):
    print(f"{r['file']}: {r['detections']}")
```

## Response Fields

### Detection

| Field | Type | Description |
|-------|------|-------------|
| `fileType` | string | Rule file type (e.g. `PE`, `ELF`, `Binary`) |
| `type` | string | Detection type (e.g. `compiler`, `linker`, `format`) |
| `name` | string | Detected name (e.g. `Microsoft Linker`) |
| `version` | string\|null | Detected version, or `null` |
| `options` | string\|null | Additional options (e.g. `dynamic`, `console`) |

### DatabaseVersion

| Field | Type | Description |
|-------|------|-------------|
| `commit` | string | Upstream rule database commit SHA |
| `ruleCount` | number | Number of loaded rules |
| `syncedAt` | string | ISO-8601 sync timestamp |

## Security Considerations

- **Default bind**: `127.0.0.1:0` (localhost only, random port). Use
  `--bind 127.0.0.1:18080` for a fixed port.
- **Path traversal**: `/scan/path` canonicalizes the path and checks
  against `--allow-root` if configured. Symlinks are resolved.
- **File size limit**: `--max-file-size` (default 256MB) limits
  `/scan/path` file size.
- **Request size limit**: `--max-request-size` (default 256MB) limits
  `/scan/bytes` body size.
- **Scan timeout**: `--scan-timeout` (default 30s) cancels long-running
  scans.
- **Remote access**: For cross-machine access, use a reverse proxy
  (nginx, caddy, Apache) with TLS and authentication.

## Server Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--db <path>` | required | Database directory path |
| `--bind <addr>` | `127.0.0.1:0` | Bind address and port |
| `--allow-root <dir>` | none | Restrict `/scan/path` to this directory |
| `--max-file-size <bytes>` | 268435456 | Max file size for `/scan/path` |
| `--max-request-size <bytes>` | 268435456 | Max body size for `/scan/bytes` |
| `--scan-timeout <secs>` | 30 | Scan timeout in seconds |

## Service Management

### Windows

```powershell
# Install as a Windows service (run as Administrator)
died install --db "C:\Program Files\died\db" --bind 127.0.0.1:18080

# Start/stop the service
sc start died
sc stop died

# Uninstall
died uninstall
```

### Linux (systemd)

```bash
# Generate a systemd unit template
died install --db /usr/share/die/db --bind 127.0.0.1:18080 > /tmp/died.service

# Install and start
sudo cp /tmp/died.service /etc/systemd/system/died.service
sudo systemctl daemon-reload
sudo systemctl enable --now died
```

### Packaging

See [packaging/README.md](../../crates/die-server/packaging/README.md) for
DEB, RPM, and MSI build instructions.
