"""Local governance dashboard HTTP server.

Uses only Python's built-in ``http.server`` module — no external web
framework dependency.  Serves a minimal HTML dashboard and a JSON REST API.

API routes:
    GET /               — HTML dashboard
    GET /api/audit      — recent audit entries
    GET /api/policies   — loaded policies
    GET /api/costs      — cost tracking summary
    GET /api/status     — governance health status
    GET /api/approvals  — pending approval requests

Example
-------
>>> from aumos_cowork_governance.dashboard.server import DashboardServer
>>> server = DashboardServer(api=api, host="127.0.0.1", port=8080)
>>> server.start()           # blocks
>>> # Or run in background:
>>> server.start_background()
>>> server.stop()
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aumos_cowork_governance.dashboard.api import DashboardApi

logger = logging.getLogger(__name__)

_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cowork Governance Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f4f5f7; color: #222; }
    header { background: #1a1a2e; color: #fff; padding: 16px 32px; }
    header h1 { font-size: 1.4rem; font-weight: 600; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px; padding: 24px 32px; }
    .card { background: #fff; border-radius: 8px; padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .card h2 { font-size: 0.85rem; text-transform: uppercase; color: #666;
               letter-spacing: .05em; margin-bottom: 8px; }
    .metric { font-size: 2rem; font-weight: 700; color: #1a1a2e; }
    .metric.warn { color: #d97706; }
    .metric.ok { color: #059669; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; }
    th { background: #f9f9f9; font-weight: 600; }
    #audit-table { margin: 0 32px 32px; background: #fff; border-radius: 8px;
                   padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    #audit-table h2 { margin-bottom: 12px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 0.78rem; font-weight: 600; }
    .badge-block { background: #fee2e2; color: #b91c1c; }
    .badge-warn  { background: #fef3c7; color: #92400e; }
    .badge-log   { background: #dbeafe; color: #1d4ed8; }
    .badge-ok    { background: #d1fae5; color: #065f46; }
    footer { text-align: center; padding: 24px; font-size: 0.8rem; color: #999; }
  </style>
</head>
<body>
  <header>
    <h1>Cowork Governance Dashboard</h1>
  </header>

  <div class="grid" id="metrics"></div>
  <div id="audit-table">
    <h2>Recent Audit Events</h2>
    <table id="audit-entries">
      <thead><tr><th>Timestamp</th><th>Event</th><th>Policy</th><th>Details</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
  <footer>aumos-cowork-governance &mdash; local governance dashboard</footer>

  <script>
    async function load() {
      const [status, audit, costs, approvals] = await Promise.all([
        fetch('/api/status').then(r => r.json()),
        fetch('/api/audit?n=50').then(r => r.json()),
        fetch('/api/costs').then(r => r.json()),
        fetch('/api/approvals').then(r => r.json()),
      ]);

      const metrics = document.getElementById('metrics');
      metrics.innerHTML = `
        <div class="card">
          <h2>Audit Events</h2>
          <div class="metric">${status.audit_count}</div>
        </div>
        <div class="card">
          <h2>Policies Loaded</h2>
          <div class="metric">${status.policy_count}</div>
        </div>
        <div class="card">
          <h2>Total Cost (USD)</h2>
          <div class="metric ${costs.total_cost_usd > 40 ? 'warn' : 'ok'}">
            $${Number(costs.total_cost_usd).toFixed(4)}
          </div>
        </div>
        <div class="card">
          <h2>Pending Approvals</h2>
          <div class="metric ${approvals.count > 0 ? 'warn' : 'ok'}">${approvals.count}</div>
        </div>
        <div class="card">
          <h2>Total Tokens</h2>
          <div class="metric">${costs.total_tokens.toLocaleString()}</div>
        </div>
        <div class="card">
          <h2>API Calls</h2>
          <div class="metric">${costs.call_count}</div>
        </div>
      `;

      const tbody = document.querySelector('#audit-entries tbody');
      tbody.innerHTML = '';
      for (const entry of (audit.entries || []).reverse()) {
        const ev = entry.event || '';
        let badge = `<span class="badge badge-log">${ev}</span>`;
        if (ev.includes('block')) badge = `<span class="badge badge-block">${ev}</span>`;
        else if (ev.includes('warn')) badge = `<span class="badge badge-warn">${ev}</span>`;
        const policy = entry.policy || '';
        const details = entry.message || JSON.stringify(entry.action_context || {}).slice(0, 80);
        tbody.innerHTML += `<tr>
          <td>${(entry.timestamp || '').replace('T', ' ').slice(0, 19)}</td>
          <td>${badge}</td>
          <td>${policy}</td>
          <td>${details}</td>
        </tr>`;
      }
    }
    load();
    setInterval(load, 10000);
  </script>
</body>
</html>
"""


class _DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the governance dashboard."""

    # Class-level reference to DashboardApi — set by DashboardServer.
    api: "DashboardApi"

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests."""
        path = self.path.split("?")[0]
        query = {}
        if "?" in self.path:
            for part in self.path.split("?", 1)[1].split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    query[k] = v

        if path == "/" or path == "/index.html":
            self._send_html(_DASHBOARD_HTML)
        elif path == "/api/status":
            self._send_json(self.api.get_status())
        elif path == "/api/audit":
            last_n = int(query.get("n", "100"))
            self._send_json(self.api.get_audit(last_n=last_n))
        elif path == "/api/policies":
            self._send_json(self.api.get_policies())
        elif path == "/api/costs":
            self._send_json(self.api.get_costs())
        elif path == "/api/approvals":
            self._send_json(self.api.get_approvals())
        else:
            self._send_404()

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: dict[str, object]) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_404(self) -> None:
        body = b'{"error": "Not found"}'
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # type: ignore[override]
        """Suppress default console request logging."""
        logger.debug(fmt, *args)


class DashboardServer:
    """Wraps an ``HTTPServer`` to serve the governance dashboard.

    Parameters
    ----------
    api:
        The :class:`DashboardApi` instance providing data to the frontend.
    host:
        Bind address (default: ``"127.0.0.1"``).
    port:
        Port to listen on (default: ``8080``).
    """

    def __init__(
        self,
        api: "DashboardApi",
        host: str = "127.0.0.1",
        port: int = 8080,
    ) -> None:
        self._api = api
        self._host = host
        self._port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the server and block until stopped (Ctrl-C)."""
        self._server = self._build_server()
        logger.info("Governance dashboard running at http://%s:%d/", self._host, self._port)
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._server.server_close()

    def start_background(self) -> None:
        """Start the server in a daemon background thread."""
        self._server = self._build_server()
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="governance-dashboard",
        )
        self._thread.start()
        logger.info(
            "Governance dashboard running (background) at http://%s:%d/",
            self._host,
            self._port,
        )

    def stop(self) -> None:
        """Stop the background server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def url(self) -> str:
        """The base URL the server listens on."""
        return f"http://{self._host}:{self._port}/"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_server(self) -> HTTPServer:
        """Create and configure the HTTPServer."""
        # Inject the API reference into the handler class.
        # We create a subclass per server instance to avoid sharing state.
        api = self._api

        class _Handler(_DashboardHandler):
            pass

        _Handler.api = api  # type: ignore[attr-defined]

        server = HTTPServer((self._host, self._port), _Handler)
        return server
