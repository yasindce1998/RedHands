#!/usr/bin/env python3
"""Harmless container smoke test: TCP-connect scan of one local listening port.

Run in the image with --network none; no external assessment targets are used.
"""

import json
import os
import socket
import subprocess
import tempfile


def main():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise RuntimeError("runtime image must run as non-root")
    with tempfile.TemporaryDirectory(prefix="redhands-smoke-") as tmp, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        request = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "nmap_port_scan", "arguments": {
                "target": "127.0.0.1", "ports": str(port), "scan_type": "connect"
            }},
        }
        env = os.environ.copy()
        env.update(REDHANDS_TRANSPORT="stdio", REDHANDS_AUTH="none", REDHANDS_TOOLSETS="nmap", REDHANDS_TIMEOUT="20s", REDHANDS_PLUGINS_DIR=tmp)
        result = subprocess.run(["redhands"], input=json.dumps(request) + "\n", text=True, capture_output=True, cwd=tmp, env=env, timeout=30, check=True)
        response = json.loads(result.stdout)
        if response.get("error") or response["result"].get("isError"):
            raise RuntimeError(f"nmap wrapper failed: {result.stdout} {result.stderr}")
        text = response["result"]["content"][0]["text"]
        if str(port) not in text or "open" not in text.lower():
            raise RuntimeError(f"nmap result missing local open port: {text}")
        subprocess.run(["redhands-cli", "version"], check=True)
        for binary in ("certipy", "secretsdump.py"):
            help_result = subprocess.run([binary, "-h"], text=True, capture_output=True, timeout=10, check=True)
            if "usage:" not in help_result.stdout.lower():
                raise RuntimeError(f"{binary} entry point did not start correctly")
        print("Non-root runtime and real nmap loopback smoke test passed")


if __name__ == "__main__":
    main()
