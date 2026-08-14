#!/usr/bin/env python3
"""Synthetic functional + resilience lab for HexStrike AI (local server).

Spins up a throwaway HTTP "target" on 127.0.0.1 and drives the running
HexStrike REST API (default http://127.0.0.1:8888) through the core pentest
workflows, checking that tools actually work end-to-end, plus a resilience
battery (injection probes, guardrails adversarial cases, robustness).

Usage:
    python3 scripts/synthetic_lab.py             # full run
    python3 scripts/synthetic_lab.py --quick     # skip slow scans (nikto/sqlmap/...)

Requires: hexstrike service running, standard Kali tools on PATH.
Everything targets 127.0.0.1 only — no external traffic.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

BASE = os.environ.get("HEXSTRIKE_URL", "http://127.0.0.1:8888")
MARKER = "HEXSTRIKE_INJ_MARKER"
RESULTS: list[tuple[str, bool, str]] = []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def api(path: str, payload=None, method="POST", timeout=360):
    url = f"{BASE}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode() or "{}")
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return -1, {"error": str(e)}


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    print(f"  {'✅' if ok else '❌'} {name}" + (f" — {detail}" if detail else ""))


def clear_cache():
    api("/api/cache/clear", method="POST")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# the synthetic target
# ---------------------------------------------------------------------------

class Lab:
    """Static-file HTTP server with pentest-bait content."""

    def __init__(self):
        self.port = free_port()
        self.root = tempfile.mkdtemp(prefix="hxs_lab_")
        files = {
            "index.html": (
                "<html><head><title>Synthetic Lab</title>"
                "<meta name='generator' content='WordPress 4.0'>"
                "<script src='https://code.jquery.com/jquery-1.2.6.js'></script>"
                "</head><body><a href='page2.html'>p2</a>"
                "<a href='admin/'>admin</a></body></html>"),
            "page2.html": "<html><body>deep page <a href='secret/'>s</a></body></html>",
            "admin/index.html": "<html><body>admin area</body></html>",
            "uploads/info.txt": "uploaded artifact",
            "secret/flag.txt": "flag{synthetic_lab_flag}",
            "vulnerable.php": "<html><body>result for id=1</body></html>",
            "robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /secret\n",
        }
        for rel, content in files.items():
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
        self.wordlist = os.path.join(self.root, "wl.txt")
        with open(self.wordlist, "w") as f:
            f.write("index\nadmin\nuploads\nsecret\npage2\nvulnerable\nnope1\nnope2\n")

        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(
            *a, directory=self.root, **kw)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# functional: core pentest workflows via REST
# ---------------------------------------------------------------------------

def test_functional(lab: Lab, quick: bool):
    print("\n━━━ Функциональные сценарии (полигон 127.0.0.1:%d) ━━━" % lab.port)

    # --- 1. bare command execution ------------------------------------
    st, r = api("/api/command", {"command": "printf 'cmd-ok'", "use_cache": False})
    check("execute_command: базовый вывод",
          st == 200 and r.get("stdout") == "cmd-ok", r.get("error", ""))
    st, r = api("/api/command",
                {"command": "echo a | tr a b", "use_cache": False})
    check("execute_command: пайплайн", st == 200 and r.get("stdout", "").strip() == "b")
    st, r = api("/api/command",
                {"command": "exit 7", "use_cache": False})
    check("execute_command: код возврата прокинулен",
          st == 200 and r.get("return_code") == 7)

    # --- 2. port scanning ---------------------------------------------
    st, r = api("/api/tools/nmap", {"target": "127.0.0.1",
                                    "ports": f"8888,{lab.port}",
                                    "scan_type": "-sV", "additional_args": "-Pn"})
    out = r.get("stdout", "")
    check("nmap: находит порты hexstrike и полигона",
          st == 200 and f"{lab.port}/tcp" in out and "8888/tcp" in out,
          f"rc={r.get('return_code')}")
    check("nmap: версия сервиса определена (-sV)", "HttpParser" in out or "http" in out.lower())

    st, r = api("/api/tools/rustscan", {"target": "127.0.0.1", "ports": str(lab.port)})
    check("rustscan: порт полигона открыт",
          st == 200 and str(lab.port) in r.get("stdout", ""),
          f"rc={r.get('return_code')}")

    st, r = api("/api/tools/nmap-advanced",
                {"target": "127.0.0.1", "scan_type": "-sV -sC",
                 "ports": str(lab.port)})
    out = r.get("stdout", "")
    check("nmap-advanced (full-режим глагола port_scan): отработал без таймаута",
          st == 200 and r.get("timed_out") is not True and f"{lab.port}/tcp" in out,
          f"exec={r.get('execution_time', 0):.0f}s")
    check("nmap-advanced: НЕТ broadcast/pre-scan утечек",
          "Pre-scan script results" not in out and "Sniffed" not in out)
    check("nmap-advanced: http-title из default,safe скриптов",
          "Synthetic Lab" in out or "http-title" in out)

    # --- 3. HTTP probing / tech detect --------------------------------
    st, r = api("/api/tools/httpx", {"target": lab.url, "mode": "probe"})
    body = json.dumps(r)
    check("httpx probe: статус полигона получен",
          st == 200 and ("200" in r.get("stdout", "") or "fallback" in r),
          r.get("fallback", "pd"))
    st, r = api("/api/tools/whatweb", {"target": lab.url})
    out = r.get("stdout", "")
    check("whatweb: технологический фингерпринт",
          st == 200 and ("WordPress" in out or "HTTPServer" in out or " JQuery" in out))

    # --- 4. directory brute -------------------------------------------
    st, r = api("/api/tools/gobuster", {"url": lab.url, "mode": "dir",
                                        "wordlist": lab.wordlist,
                                        "additional_args": "-q --no-error"})
    out = r.get("stdout", "")
    check("gobuster: находит /admin и /uploads",
          st == 200 and "/admin" in out and "/uploads" in out,
          f"rc={r.get('return_code')}")
    st, r = api("/api/tools/dirsearch", {"url": lab.url, "wordlist": lab.wordlist,
                                         "additional_args": "-q"})
    out = r.get("stdout", "")
    check("dirsearch: находит /secret",
          st == 200 and ("/secret" in out or "secret" in out))

    # --- 5. crawling ---------------------------------------------------
    st, r = api("/api/tools/katana", {"url": lab.url, "depth": 2,
                                      "js_crawl": False, "form_extraction": False})
    out = r.get("stdout", "")
    check("katana: краулит на page2.html",
          st == 200 and ("page2" in out or "secret" in out),
          f"rc={r.get('return_code')}")

    if not quick:
        # --- 6. vuln scanning (slow) -----------------------------------
        st, r = api("/api/tools/nikto", {"target": lab.url,
                                         "additional_args": "-Tuning 4 -nointeractive"})
        check("nikto: скан завершается со структурным выводом",
              st == 200 and r.get("return_code") is not None,
              f"rc={r.get('return_code')}, exec={r.get('execution_time', 0):.0f}s")

        # sqlmap = DESTRUCTIVE tier: проверяем и tier-гейт, и работу
        st, r = api("/api/tools/sqlmap",
                    {"url": f"{lab.url}/vulnerable.php?id=1"})
        check("sqlmap: DESTRUCTIVE без confirmed блокируется",
              st == 403, f"st={st}")
        st, r = api("/api/tools/sqlmap",
                    {"url": f"{lab.url}/vulnerable.php?id=1", "confirmed": True,
                     "additional_args": "--batch --random-agent --level=1"})
        check("sqlmap: с confirmed исполняется",
              st == 200 and r.get("return_code") is not None,
              f"rc={r.get('return_code')}")

    # --- 7. cloud audit graceful ---------------------------------------
    st, r = api("/api/tools/prowler", {"provider": "aws"})
    check("cloud_audit (prowler): без облачных кредов — структурированная ошибка, не 500",
          st in (200, 400, 503) and "Server error" not in json.dumps(r),
          f"st={st}")

    # --- 8. session workflow -------------------------------------------
    st, r = api("/api/session/create",
                {"target": "127.0.0.1", "scope_rules": ["127.0.0.1"]})
    sid = r.get("session_id", "")
    check("сессия: создана", st == 200 and sid)
    st, r = api(f"/api/session/{sid}/finding",
                {"tool": "nikto", "vuln_type": "info",
                 "title": "robots.txt reveals /admin", "endpoint": "/robots.txt"})
    check("сессия: находка добавлена, CVSS посчитан",
          st == 200 and "cvss_score" in r, str(r.get("cvss_score")))
    st, r = api(f"/api/session/{sid}/report?format=markdown", method="GET")
    rep = r.get("report", "") if isinstance(r, dict) else ""
    check("сессия: markdown-отчёт содержит находку",
          st == 200 and "robots.txt" in rep and "CVSS" in rep.upper())


def test_workflow_guardrails(lab: Lab):
    print("\n━━━ Guardrails workflow (scope/kill/async) ━━━")

    # scope allow / block
    api("/api/guardrails/scope", {"rules": ["127.0.0.1", "::1"]}, method="PUT")
    st, r = api("/api/tools/nmap", {"target": "127.0.0.1", "ports": "8888",
                                    "scan_type": "-sV", "additional_args": "-Pn"})
    check("scope: цель в scope — скан разрешён", st == 200)
    st, r = api("/api/tools/nmap", {"target": "192.0.2.1", "ports": "1"})
    reason = r.get("reason") or (r.get("guardrails") or {}).get("reason")
    check("scope: цель вне scope — блок 403",
          st == 403 and reason == "scope", f"st={st}")
    for variant in ["localhost", "0x7f000001", "2130706433", "127.1"]:
        st, r = api("/api/tools/nmap", {"target": variant, "ports": "1"})
        # безопасное направление = заблокировано (строка не совпала с правилом)
        check(f"scope-variant {variant!r}: не пропущен мимо правил",
              st == 403, f"st={st}")
    api("/api/guardrails/scope", {"rules": []}, method="PUT")

    # audit coverage for tool routes
    st, _ = api("/api/guardrails/audit?limit=50", method="GET")
    st, r = api("/api/guardrails/audit?limit=50", method="GET")
    tools_audited = {e.get("tool") for e in r.get("events", [])}
    check("audit: вызовы инструментов оставили след",
          {"nmap", "gobuster", "sqlmap"} <= tools_audited or "nmap" in tools_audited,
          str(sorted(tools_audited))[:120])

    # tier promotion gap probe
    st, r = api("/api/tools/nmap-advanced",
                {"target": "127.0.0.1", "scan_type": "-sV", "aggressive": True,
                 "ports": "8888"})
    check("tier: nmap-advanced aggressive=true требует подтверждения (nmap -A = DESTRUCTIVE)",
          st == 403, f"st={st} ← ГЭП, если не 403")

    # async process pool
    st, r = api("/api/process/execute-async",
                {"command": "echo async-ok", "use_cache": False})
    tid = r.get("task_id") or r.get("id")
    if tid:
        for _ in range(30):
            st, r = api(f"/api/process/get-task-result/{tid}", method="GET")
            res = r.get("result", {}) or {}
            if res.get("status") in ("completed", "failed", "lost"):
                break
            time.sleep(0.5)
        inner = (res.get("result") or {})
        check("async-задача: echo завершён, результат доступен",
              res.get("status") == "completed" and "async-ok" in (inner.get("stdout") or ""),
              f"status={res.get('status')}")
    else:
        check("async-задача: task_id получен", False, json.dumps(r)[:150])


INJECTION_PROBES = [
    # (name, path, payload) — параметр с метасимволом; маркер в stdout = RCE
    ("/api/tools/zap", {"host": "127.0.0.1", "port": f"8080; echo {MARKER}"}),
    ("/api/tools/gdb", {"binary": f"/bin/true; echo {MARKER}"}),
    ("/api/tools/radare2", {"binary": f"/bin/true; echo {MARKER}"}),
    ("/api/tools/autorecon", {"target": f"127.0.0.1; echo {MARKER}", "output_dir": "/tmp/hxs_atr"}),
    ("/api/tools/enum4linux-ng", {"target": f"127.0.0.1; echo {MARKER}"}),
    ("/api/tools/dalfox", {"url": f"http://127.0.0.1; echo {MARKER}"}),
    ("/api/tools/prowler", {"provider": f"aws; echo {MARKER}"}),
    ("/api/tools/pacu", {"module": f"ec2_enum; echo {MARKER}"}),
    ("/api/tools/jwt-analyzer", {"token": f"x; echo {MARKER}"}),
    ("/api/tools/wpscan", {"url": f"http://127.0.0.1:1; echo {MARKER}"}),
    ("/api/tools/nikto", {"target": f"127.0.0.1:1; echo {MARKER}"}),
    ("/api/tools/sqlmap", {"target": f"http://127.0.0.1:1; echo {MARKER}", "confirmed": True}),
]


def test_injection_battery():
    print("\n━━━ Инъекционная батарея (string-form роуты) ━━━")
    vulns = []
    for path, payload in INJECTION_PROBES:
        full = dict(payload)
        full["use_cache"] = False
        full.setdefault("additional_args", "")
        st, r = api(path, full, timeout=90)
        # RCE = marker in STDOUT (echo writes there). Marker in stderr may
        # be mere diagnostic reflection (recovery context echoes params),
        # and argv-form tools pass poisoned values as inert literals.
        out = r.get("stdout", "") or ""
        err = r.get("stderr", "") or ""
        if MARKER in out:
            vulns.append(path)
            check(f"инъекция {path}: УЯЗВИМ (RCE)", False)
        elif MARKER in err:
            check(f"инъекция {path}: пейлоад отражён в stderr (диагностика), shell-инъекции нет", True,
                  f"st={st}")
        else:
            check(f"инъекция {path}: метасимволы нейтрализованы/команда не исполнилась", True,
                  f"st={st}")
    if vulns:
        print(f"  ⚠️  УЯЗВИМЫХ РОУТОВ: {len(vulns)}")


ROBUSTNESS_PROBES = [
    ("не-JSON тело", {"raw": b"not json at all", "ct": "text/plain"}),
    ("JSON-массив вместо объекта", {"raw": b"[1,2,3]", "ct": "application/json"}),
    ("null в target", {"json": {"target": None}}),
    ("число в target", {"json": {"target": 42}}),
    ("пустая строка target", {"json": {"target": ""}}),
    ("юникод/нул-байт в target", {"json": {"target": "127.0.0.1\x00; id"}}),
    ("глубокая вложенность", {"json": {"target": "x" * 100000}}),
]


def test_robustness():
    print("\n━━━ Устойчивость к мусорному вводу (/api/tools/nmap) ━━━")
    for name, probe in ROBUSTNESS_PROBES:
        try:
            if "raw" in probe:
                req = urllib.request.Request(
                    f"{BASE}/api/tools/nmap", data=probe["raw"], method="POST",
                    headers={"Content-Type": probe["ct"]})
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        st = r.status
                except urllib.error.HTTPError as e:
                    st = e.code
            else:
                st, r = api("/api/tools/nmap", probe["json"], timeout=60)
            check(f"robustness: {name} → без 500/зависания", st < 500, f"st={st}")
        except Exception as e:
            check(f"robustness: {name} → без 500/зависания", False, str(e)[:80])


def test_rate_limit():
    """Informational: with the deployed sync gunicorn workers each worker
    handles one request at a time, so per-target in-flight concurrency never
    exceeds the worker count and the limiter's concurrency gate cannot fire
    (each check's acquire/release pair is strictly sequential per worker).
    The rps gate still applies in principle (~10/s per target)."""
    print("\n━━━ Rate limiter (информационно, sync-воркеры) ━━━")
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(api, "/api/command",
                          {"command": "sleep 1", "use_cache": False,
                           "target": "127.0.0.1"}) for _ in range(8)]
        codes = sorted(f.result()[0] for f in futs)
    check("rate: параллельные запросы не роняют сервер (все завершены)",
          all(c == 200 for c in codes), f"коды: {codes}")


def test_task_survival():
    """Submit a long async task, restart the service, expect honest 'lost'."""
    print("\n━━━ Выживание async-задач при рестарте сервиса ━━━")
    st, r = api("/api/process/execute-async", {"command": "sleep 20", "use_cache": False})
    tid = r.get("task_id") or r.get("id")
    if not tid:
        check("task-survival: задача отправлена", False, json.dumps(r)[:150])
        return
    check("task-survival: long-задача отправлена", True, f"id={tid}")
    rc = os.system("sudo -n systemctl restart hexstrike 2>/dev/null")
    if rc != 0:
        check("task-survival: рестарт сервиса", False, "sudo недоступен — пропуск")
        return
    for _ in range(40):
        st, r = api(f"/api/process/get-task-result/{tid}", method="GET")
        res = r.get("result", {}) or {}
        if res.get("status") in ("lost", "completed", "failed"):
            break
        time.sleep(1)
    check("task-survival: после recycle — честный статус вместо not_found",
          res.get("status") in ("lost", "completed", "failed"), f"status={res.get('status')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip slow scans")
    ap.add_argument("--skip-restart", action="store_true",
                    help="skip the service-restart survival test")
    args = ap.parse_args()

    print(f"HexStrike synthetic lab → {BASE}")
    st, r = api("/health?json", method="GET")
    if st != 200:
        print(f"❌ сервер не отвечает: {st} {r}")
        sys.exit(2)
    print(f"сервер: v{r.get('version')}")

    lab = Lab()
    lab.start()
    try:
        clear_cache()
        test_functional(lab, args.quick)
        test_workflow_guardrails(lab)
        test_injection_battery()
        test_robustness()
        test_rate_limit()
        if not args.skip_restart:
            test_task_survival()
    finally:
        lab.stop()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n━━━ ИТОГ: {passed}/{len(RESULTS)} проверок пройдено ━━━")
    for name, ok, detail in RESULTS:
        if not ok:
            print(f"  ❌ {name} {detail}")
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
