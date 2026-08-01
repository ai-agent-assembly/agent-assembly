#!/usr/bin/env python3
"""AAASM-5269 research probe: measure a local Presidio Analyzer container.

Reproduces §3.4 and §4.5 of
`docs/src/research/AAASM-5269-sensitive-data-provider-architecture.md`: latency by
payload class, the large-payload failure threshold, Chinese-locale behavior, and
how Taiwan identifiers are labelled.

This is a **research** script. It is not wired into CI, it gates nothing, and it
is not part of the product. It exists so the numbers quoted in the Spike report
can be re-derived rather than taken on trust.

Usage
-----
Start the analyzer, pinned by digest (mutable tags are forbidden by ADR 0032):

    docker run -d --rm --name aaasm5269-presidio -p 15001:3000 --memory=4g \\
      ghcr.io/data-privacy-stack/presidio-analyzer@sha256:ae8f6f111ac2f04e3fec552f7f80edd0dcbfa2dd69ee1b9e030475be31669885

    python3 scripts/research/aaasm-5269-presidio-probe.py

To reproduce the egress-denied result instead, run it on an internal network and
exec the probe inside the container:

    docker network create --internal aaasm5269-noegress

Safety
------
Standard library only, so there is nothing to install. **Every fixture is
synthetic**: the Taiwan identifiers below are format-valid but are not issued to
any person, and no live credential is sent. Do not point this at anything but a
local container, and never feed it production data.
"""

from __future__ import annotations

import json
import statistics
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:15001"

BENIGN_EN = (
    "The quick brown fox jumps over the lazy dog. "
    "SELECT id, name FROM users WHERE active = true; "
    "2026-04-27T12:00:00Z info=processing request_id=abc123 "
)
BENIGN_ZH = (
    "使用者請求：請協助查詢訂單狀態，並將結果整理成報表。"
    "系統回應：查詢完成，共 12 筆資料，處理時間 340 毫秒。"
    "備註 (note): the retrieval step returned 12 rows from the orders table. "
)


def build(filler: str, target_bytes: int) -> str:
    out = ""
    while len(out.encode()) < target_bytes:
        out += filler
    return out


def analyze(text: str, language: str = "en", timeout: int = 300):
    body = json.dumps({"text": text, "language": language}).encode()
    req = urllib.request.Request(
        BASE + "/analyze", data=body, headers={"Content-Type": "application/json"}
    )
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read())
    return (time.perf_counter() - started) * 1000.0, payload


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int((p / 100.0) * len(ordered) + 0.5) - 1))
    return ordered[idx]


def bench(label: str, text: str, language: str = "en", n: int = 30) -> None:
    for _ in range(3):  # warm
        analyze(text, language)
    latencies, findings = [], 0
    for _ in range(n):
        ms, res = analyze(text, language)
        latencies.append(ms)
        findings = len(res)
    print(
        f"| `{label}` | {len(text.encode())} | {language} | {findings} | "
        f"{pct(latencies, 50):.2f} ms | {pct(latencies, 95):.2f} ms | "
        f"{pct(latencies, 99):.2f} ms | {statistics.mean(latencies):.2f} ms |"
    )


def main() -> None:
    print("## Presidio Analyzer — measured latency (local container, warm)\n")
    print("| case | bytes | lang | findings | p50 | p95 | p99 | mean |")
    print("|---|---:|---|---:|---:|---:|---:|---:|")
    bench("small_tool_call_~450B", build(BENIGN_EN, 450), "en")
    bench("medium_prompt_32KB", build(BENIGN_EN, 32 * 1024), "en", n=15)

    print("\n## Scaling and the large-payload failure threshold\n")
    print("| payload bytes | result | latency |")
    print("|---:|---|---:|")
    for kb in (64, 128, 256, 512, 768, 1024):
        text = build(BENIGN_EN, kb * 1024)
        try:
            ms, res = analyze(text)
            print(f"| {len(text.encode())} | OK, {len(res)} findings | {ms:.0f} ms |")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:90].replace("\n", " ")
            print(f"| {len(text.encode())} | **HTTP {exc.code}** {detail} | — |")

    print("\n## Chinese input\n")
    print("| case | bytes | lang | findings | p50 | p95 | p99 | mean |")
    print("|---|---:|---|---:|---:|---:|---:|---:|")
    zh = build(BENIGN_ZH, 450)
    for lang in ("zh", "zh-TW", "en"):
        try:
            bench(f"zh_text_as_lang_{lang}", zh, lang, n=5)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:120].replace("\n", " ")
            print(f"| `zh_text_as_lang_{lang}` | {len(zh.encode())} | {lang} | — | HTTP {exc.code}: {detail} | | | |")

    # Synthetic, format-valid Taiwan identifiers. Not issued to any person.
    print("\n## Taiwan identifier recognition (synthetic values)\n")
    print("| input | entities returned |")
    print("|---|---|")
    for label, text in (
        ("TW national ID in context", "身分證字號 A123456789 請確認"),
        ("TW national ID, bare", "A123456789"),
        ("TW business tax id", "統一編號 12345675"),
        ("TW mobile", "手機 0912345678"),
        ("TW mobile, intl form", "+886912345678"),
        ("English name + US SSN (control)", "John Smith SSN 123-45-6789"),
    ):
        try:
            _, res = analyze(text, "en")
            ents = ", ".join(f"{r['entity_type']}({r['score']:.2f})" for r in res) or "NONE"
        except Exception as exc:  # noqa: BLE001 - research script, report and continue
            ents = f"ERROR {exc}"
        print(f"| {label} | {ents} |")


if __name__ == "__main__":
    main()
