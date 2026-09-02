## Plugins

Optional integrations that connect SecAutoMind with other tools.

### Burp Suite

- **Path**: `plugins/burp-suite/secautomindai-burp-extension/`
- **Build**: `bash build-mvn.sh` → `dist/secautomindai-burp-extension.jar`
- **Docs**: `README.md` / `README.zh-CN.md`

### Browser (Chrome / Edge)

- **Path**: `plugins/browser-extension/secautomindai-browser-extension/`
- **Version**: **0.3.8**
- **Install**: `chrome://extensions/` → Load unpacked → F12 → **SecAutoMind** tab
- **Package**: `bash package.sh` → `dist/secautomindai-browser-extension.zip`
- **Docs**: `README.zh-CN.md` (full) / `README.md` (summary)

#### Highlights (v0.3.x)

| Feature | Description |
|---------|-------------|
| Token expiry | Remaining time + 30s validate probe; detects server restart / unreachable |
| Capture pause | **● Capturing** / **○ Paused** — stop recording without closing DevTools |
| HTTP/1.1 display | Raw HAR in memory; UI + AI prompt normalized (no `:method` pseudo-headers) |
| Collapsible conn bar | Host/Port/Validate collapses after success |
| Popup | Read-only endpoint + connection status |
| Performance | XHR-only filter, no body read for static assets, rAF-throttled stream UI |
| Data caps | 200 captures/tab, 50 test runs, 512KB progress — all in-memory |
