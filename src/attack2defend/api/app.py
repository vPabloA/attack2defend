"""Read-only REST API for Attack2Defend automation.

This module intentionally uses Python stdlib http.server to avoid making the API
surface a mandatory dependency. It is local/offline and reads only from bundle
and derived artifacts.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from attack2defend.automation.service import AutomationService


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class Attack2DefendHandler(BaseHTTPRequestHandler):
    service = AutomationService()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if path == "/api/v1/health" or path == "/health":
                return self.send_json(self.service.health())
            if path == "/api/v1/metadata":
                return self.send_json(self.service.metadata())
            if path.startswith("/api/v1/route/"):
                identifier = unquote(path.split("/api/v1/route/", 1)[1])
                return self.send_json(self.service.resolve_route(identifier))
            if path.startswith("/api/v1/soc-pack/"):
                identifier = unquote(path.split("/api/v1/soc-pack/", 1)[1])
                return self.send_json(self.service.build_soc_action_pack(identifier))
            if path.startswith("/api/v1/d3fend/") and path.endswith("/soc-actions"):
                identifier = unquote(path.removeprefix("/api/v1/d3fend/").removesuffix("/soc-actions"))
                return self.send_json(self.service.explain_d3fend_for_soc(identifier))
            if path == "/api/v1/factory/status":
                return self.send_json(self.service.get_factory_status())
            if path == "/api/v1/factory/candidates":
                return self.send_json(self.service.query_candidates(status=_first(query, "status"), run_id=_first(query, "run_id")))
            if path == "/api/v1/policy":
                return self.send_json(self.service.policy_inspect())
            if path == "/api/v1/golden/evaluation":
                return self.send_json(self.service.get_golden_evaluation())
            if path == "/api/v1/graph/quality":
                return self.send_json(self.service.get_graph_quality())
            if path == "/api/v1/search":
                return self.send_json(self.service.search_knowledge(_first(query, "q") or ""))
            if path.startswith("/api/v1/evidence-pack/"):
                identifier = unquote(path.split("/api/v1/evidence-pack/", 1)[1])
                return self.send_json(self.service.get_evidence_pack(identifier))
            return self.send_json({"status": "not_found", "blocking": False, "timeout_waited_for_human": False, "errors": [f"Unknown endpoint {path}"]}, status=404)
        except Exception as exc:
            return self.send_json({"status": "error", "blocking": False, "timeout_waited_for_human": False, "errors": [str(exc)]}, status=500)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            payload = json.loads(body or "{}")
            if path == "/api/v1/route/batch":
                ids = payload if isinstance(payload, list) else payload.get("ids", [])
                return self.send_json(self.service.batch_resolve_route([str(i) for i in ids]))
            return self.send_json({"status": "not_found", "blocking": False, "timeout_waited_for_human": False, "errors": [f"Unknown endpoint {path}"]}, status=404)
        except Exception as exc:
            return self.send_json({"status": "error", "blocking": False, "timeout_waited_for_human": False, "errors": [str(exc)]}, status=500)


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key) or []
    return values[0] if values else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the optional Attack2Defend read-only API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), Attack2DefendHandler)
    print(f"attack2defend-api: http://{args.host}:{args.port}/api/v1/health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
