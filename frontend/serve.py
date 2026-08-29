#!/usr/bin/env python3
"""Serve the site locally.

    python3 frontend/serve.py            # http://localhost:5173

The control plane is private, so for live scoring run this in another terminal:

    gcloud run services proxy interlock --region us-central1 --port 8080

Without it the page replays recorded output from real runs and labels itself
"recorded" rather than pretending to be live.
"""
from __future__ import annotations

import functools
import http.server
import pathlib
import socketserver

PORT = 5173
ROOT = pathlib.Path(__file__).resolve().parent


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        # The page fetches the proxied control plane from a different origin.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:  # quieter console
        return


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(Handler, directory=str(ROOT))
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"  Interlock site → http://localhost:{PORT}")
        print("  live scoring    → gcloud run services proxy interlock --region us-central1 --port 8080")
        httpd.serve_forever()
