#!/usr/bin/env python3
"""Stand-in for aa-api-server: serves a controlled /api/v1/health on AA_API_ADDR.

STUB_MODE: ok:<version> | ctrl | big | nojson | noversion | slow | exit
"""
import json, os, socket, sys, time

mode = os.environ.get("STUB_MODE", "ok:0.0.1-rc.7")
if mode == "exit":
    sys.exit(1)
host, port = os.environ["AA_API_ADDR"].rsplit(":", 1)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host.strip("[]"), int(port))); srv.listen(8)

def body_for(mode):
    if mode.startswith("ok:"):
        return json.dumps({"status": "ok", "version": mode[3:], "api_version": "v1"}).encode()
    if mode == "ctrl":
        return json.dumps({"status": "ok", "version": "1.0\x1b[31mRED\nFAKE-LINE\u0007", "api_version": "v1"}).encode()
    if mode == "noversion":
        return json.dumps({"status": "ok", "api_version": "v1"}).encode()
    if mode == "nojson":
        return b"<html>not json</html>"
    return b"{}"

while True:
    c, _ = srv.accept()
    try:
        c.settimeout(3)
        c.recv(4096)
        if mode == "slow":
            time.sleep(3)
        if mode == "big":
            pad = b" " * (5 * 1024 * 1024)
            payload = b'{"status":"ok","version":"0.0.1-rc.7","api_version":"v1","pad":"' + pad + b'"}'
            c.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: %d\r\nconnection: close\r\n\r\n" % len(payload))
            c.sendall(payload)
        else:
            b = body_for(mode)
            c.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: %d\r\nconnection: close\r\n\r\n" % len(b) + b)
    except OSError:
        # The probe under test hangs up early on purpose (an oversized or slow body),
        # so a reset or broken pipe here is the expected outcome, not a stub failure.
        pass
    finally:
        c.close()
