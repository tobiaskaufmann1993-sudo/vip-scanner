#!/usr/bin/env python3
"""Validate representative generated configs against the pinned Xray binary."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scanner  # noqa: E402


UUID = "11111111-1111-4111-8111-111111111111"


def vmess_uri() -> str:
    payload = {
        "v": "2",
        "ps": "schema-check",
        "add": "127.0.0.1",
        "port": "443",
        "id": UUID,
        "aid": "0",
        "scy": "auto",
        "net": "grpc",
        "type": "none",
        "host": "",
        "path": "grpc-service",
        "tls": "tls",
        "sni": "example.com",
        "fp": "chrome",
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return "vmess://" + encoded


def sample_uris() -> list[str]:
    ss_user = base64.urlsafe_b64encode(b"aes-256-gcm:password").decode("ascii").rstrip("=")
    return [
        (
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=tls"
            "&sni=example.com&type=ws&host=example.com&path=%2Fws#schema-vless"
        ),
        vmess_uri(),
        "trojan://password@127.0.0.1:443?security=tls&sni=example.com&type=tcp#schema-trojan",
        f"ss://{ss_user}@127.0.0.1:8388#schema-ss",
    ]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_xray_configs.py /path/to/xray", file=sys.stderr)
        return 2

    xray = Path(sys.argv[1]).resolve()
    if not xray.is_file():
        print(f"Xray binary not found: {xray}", file=sys.stderr)
        return 2

    for uri in sample_uris():
        node = scanner.parse_node(uri)
        config = scanner.build_xray_config(node, 19080)
        with tempfile.TemporaryDirectory(prefix="meza-schema-") as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            completed = subprocess.run(
                [str(xray), "run", "-test", "-config", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=15,
            )
        if completed.returncode != 0:
            print(f"Generated {node.protocol} config was rejected by Xray:", file=sys.stderr)
            print(completed.stdout[-3000:], file=sys.stderr)
            return 1
        print(f"Xray schema accepted: {node.protocol}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
