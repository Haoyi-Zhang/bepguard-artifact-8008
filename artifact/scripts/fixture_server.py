#!/usr/bin/env python3
"""Local HTTP fixture server for scanner baselines.

The server maps each fixture id to a path of the form /fixture/<id> and emits
that fixture's response headers. It is intended only for local deterministic
baseline evaluation.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List


def load_fixtures(path: str) -> Dict[str, dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {str(item["id"]): item for item in data}


class FixtureHandler(BaseHTTPRequestHandler):
    fixtures: Dict[str, dict] = {}

    def do_GET(self) -> None:  # noqa: N802
        prefix = "/fixture/"
        if not self.path.startswith(prefix):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"unknown fixture\n")
            return
        fixture_id = self.path[len(prefix):].split("?", 1)[0]
        fixture = self.fixtures.get(fixture_id)
        if fixture is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"unknown fixture\n")
            return
        self.send_response(200)
        for header in fixture.get("headers", []):
            name = str(header.get("name", ""))
            value = str(header.get("value", ""))
            if name:
                self.send_header(name, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = f"<!doctype html><title>{fixture_id}</title><h1>{fixture_id}</h1>\n".encode("utf-8")
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve policy fixtures on localhost.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    FixtureHandler.fixtures = load_fixtures(args.fixtures)
    server = HTTPServer((args.host, args.port), FixtureHandler)
    print(json.dumps({"host": args.host, "port": args.port, "fixtures": len(FixtureHandler.fixtures)}, sort_keys=True))
    server.serve_forever()


if __name__ == "__main__":
    main()
