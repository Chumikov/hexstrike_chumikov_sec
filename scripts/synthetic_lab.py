#!/usr/bin/env python3
"""Synthetic functional + resilience lab for HexStrike AI (local server).

Spins up a disposable target range on 127.0.0.1 and drives the running
HexStrike REST API (default http://127.0.0.1:8888) through complete pentest
workflows, then fires resilience batteries at it.

Target range:
  * static web root (directories, linked pages, robots, binary file)
  * /login.php    — real SQLite-backed login with SQLi (string-concat query)
  * /search.php   — reflected parameter (XSS bait)
  * /redirect.php — 302 chain
  * /soft/*       — soft-404 zone (every path returns 200)
  * HTTPS server  — self-signed cert
  * blackhole     — accepts TCP, never answers
  * slow responder — answers after 25 s
  * closed port   — nothing listens

Batteries: functional verbs, findings pipeline (session/CVSS/report),
guardrails adversarial, injection probes, input robustness, hang matrix,
API-freeze probe, tool flag-drift smoke, kill-switch process semantics,
output fidelity (binary/ANSI/optimizer), MCP layer (stdio JSON-RPC),
auth-enabled instance, async-task survival across service restart.

Usage:
    python3 scripts/synthetic_lab.py             # full pedantic run
    python3 scripts/synthetic_lab.py --quick     # skip slow scans
    python3 scripts/synthetic_lab.py --skip-restart

Everything targets 127.0.0.1 only — no external traffic. Requires the
hexstrike service running and standard Kali tools on PATH.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import McpStdioClient  # noqa: E402

BASE = os.environ.get("HEXSTRIKE_URL", "http://127.0.0.1:8888")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARKER = "HEXSTRIKE_INJ_MARKER"
RESULTS: list[tuple[str, bool, str]] = []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def api(path: str, payload=None, method="POST", timeout=360, headers=None):
    url = f"{BASE}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
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


def pgrep(pattern: str) -> int:
    """Count processes whose FULL cmdline matches (pgrep -fc)."""
    r = subprocess.run(["pgrep", "-fc", pattern],
                       capture_output=True, text=True)
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return 0


def pgrep_name(name: str) -> int:
    """Count processes by exact NAME (pgrep -x).

    nmap on Kali execs as ``/usr/lib/nmap/nmap --privileged ...`` — a
    cmdline-anchored pattern misses it, the comm name does not.
    """
    r = subprocess.run(["pgrep", "-c", "-x", name],
                       capture_output=True, text=True)
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return 0


def wait_for_process(pattern: str, timeout: float = 15.0,
                     by_name: bool = False) -> int:
    """Poll until at least one matching process shows up (or timeout)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        n = pgrep_name(pattern) if by_name else pgrep(pattern)
        if n:
            return n
        time.sleep(0.5)
    return 0


# ---------------------------------------------------------------------------
# the synthetic target range
# ---------------------------------------------------------------------------

class LabHandler(http.server.SimpleHTTPRequestHandler):
    """Static files + dynamic pentest-bait endpoints."""

    lab: "Lab" = None  # injected

    def log_message(self, *a):  # silence
        pass

    def _dynamic_get(self):
        path = self.path.split("?")[0]
        if path == "/search.php":
            qs = self.path.split("?", 1)[1] if "?" in self.path else "q="
            params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
            q = urllib.parse.unquote_plus(params.get("q", ""))
            body = f"<html><body>results for: <b>{q}</b></body></html>"
            self._text(200, body)
            return True
        if path == "/redirect.php":
            self.send_response(302)
            self.send_header("Location", "/index.html")
            self.end_headers()
            return True
        if path.startswith("/soft/"):
            self._text(200, "<html><body>soft generic page</body></html>")
            return True
        if path == "/login.php":
            self._text(200, "<html><body><form method=POST>"
                            "user:<input name=user> pass:<input name=pass>"
                            "</form></body></html>")
            return True
        return False

    def _text(self, code, body, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self._dynamic_get():
            return
        super().do_GET()

    def do_POST(self):
        if self.path.split("?")[0] != "/login.php":
            self._text(404, "no")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        user = (form.get("user") or [""])[0]
        password = (form.get("pass") or [""])[0]
        db = sqlite3.connect(self.lab.db_path)
        try:
            # deliberately string-concatenated — this is the SQLi bait
            row = db.execute(
                f"SELECT user FROM users WHERE user='{user}' "
                f"AND pass='{password}'").fetchone()
        except sqlite3.OperationalError as e:
            db.close()
            self._text(500, f"sql error: {e}")
            return
        db.close()
        self._text(200, "<html><body>Login OK</body></html>" if row
                   else "<html><body>Login failed</body></html>")


class SlowHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        time.sleep(25)
        body = b"<html><body>finally</body></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Lab:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="hxs_lab_")
        self.port = free_port()
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
            "robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /secret\n",
        }
        for rel, content in files.items():
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
        shutil.copy("/bin/ls", os.path.join(self.root, "binary.bin"))
        self.wordlist = os.path.join(self.root, "wl.txt")
        with open(self.wordlist, "w") as f:
            f.write("index\nadmin\nuploads\nsecret\npage2\nnope1\nnope2\n")

        self.db_path = os.path.join(self.root, "lab.db")
        db = sqlite3.connect(self.db_path)
        db.execute("CREATE TABLE users (user TEXT, pass TEXT)")
        db.execute("INSERT INTO users VALUES ('admin','s3cr3t-pass')")
        db.commit()
        db.close()

        handler_cls = type("BoundLabHandler", (LabHandler,), {"lab": self})
        handler = lambda *a, **kw: handler_cls(*a, directory=self.root, **kw)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

        # HTTPS with self-signed cert
        self.https_port = free_port()
        self.httpd_tls = http.server.ThreadingHTTPServer(("127.0.0.1", self.https_port), handler)
        cert = os.path.join(self.root, "cert.pem")
        key = os.path.join(self.root, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-subj", "/CN=localhost", "-keyout", key,
                        "-out", cert], capture_output=True, timeout=60, check=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd_tls.socket = ctx.wrap_socket(self.httpd_tls.socket, server_side=True)
        self.tls_thread = threading.Thread(target=self.httpd_tls.serve_forever, daemon=True)

        # blackhole: accepts TCP and never speaks
        self.blackhole_port = free_port()
        self._bh_sock = socket.socket()
        self._bh_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._bh_sock.bind(("127.0.0.1", self.blackhole_port))
        self._bh_sock.listen(16)
        self._bh_conns = []
        self._bh_thread = threading.Thread(target=self._blackhole_loop, daemon=True)

        # slow responder
        self.slow_port = free_port()
        self.httpd_slow = http.server.ThreadingHTTPServer(("127.0.0.1", self.slow_port), SlowHandler)
        self.slow_thread = threading.Thread(target=self.httpd_slow.serve_forever, daemon=True)

        # closed port: reserved then released, nothing listens
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.closed_port = s.getsockname()[1]
        s.close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    @property
    def https_url(self):
        return f"https://127.0.0.1:{self.https_port}"

    def _blackhole_loop(self):
        while True:
            try:
                conn, _ = self._bh_sock.accept()
                self._bh_conns.append(conn)
            except OSError:
                return

    def start(self):
        self.thread.start()
        self.tls_thread.start()
        self._bh_thread.start()
        self.slow_thread.start()

    def stop(self):
        for srv in (self.httpd, self.httpd_tls, self.httpd_slow):
            try:
                srv.shutdown()
            except Exception:
                pass
        for c in self._bh_conns:
            try:
                c.close()
            except Exception:
                pass
        try:
            self._bh_sock.close()
        except Exception:
            pass
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# 1. functional: core pentest workflows via REST
# ---------------------------------------------------------------------------

def test_functional(lab: Lab, quick: bool):
    print("\n━━━ Функциональные сценарии (полигон :%d) ━━━" % lab.port)

    st, r = api("/api/command", {"command": "printf 'cmd-ok'", "use_cache": False})
    check("execute_command: базовый вывод",
          st == 200 and r.get("stdout") == "cmd-ok", r.get("error", ""))
    st, r = api("/api/command", {"command": "echo a | tr a b", "use_cache": False})
    check("execute_command: пайплайн", st == 200 and r.get("stdout", "").strip() == "b")
    st, r = api("/api/command", {"command": "exit 7", "use_cache": False})
    check("execute_command: код возврата прокинулен",
          st == 200 and r.get("return_code") == 7)

    st, r = api("/api/tools/nmap", {"target": "127.0.0.1",
                                    "ports": f"8888,{lab.port}",
                                    "scan_type": "-sV", "additional_args": "-Pn"})
    out = r.get("stdout", "")
    check("nmap: находит порты hexstrike и полигона",
          st == 200 and f"{lab.port}/tcp" in out and "8888/tcp" in out,
          f"rc={r.get('return_code')}")
    check("nmap: версия сервиса определена (-sV)", "http" in out.lower())

    st, r = api("/api/tools/rustscan", {"target": "127.0.0.1", "ports": str(lab.port)})
    check("rustscan: порт полигона открыт",
          st == 200 and str(lab.port) in r.get("stdout", ""),
          f"rc={r.get('return_code')}")

    st, r = api("/api/tools/nmap-advanced",
                {"target": "127.0.0.1", "scan_type": "-sV -sC",
                 "ports": str(lab.port)})
    out = r.get("stdout", "")
    check("nmap-advanced (full-режим port_scan): без таймаута",
          st == 200 and r.get("timed_out") is not True and f"{lab.port}/tcp" in out,
          f"exec={r.get('execution_time', 0):.0f}s")
    check("nmap-advanced: НЕТ broadcast/pre-scan утечек",
          "Pre-scan script results" not in out and "Sniffed" not in out)
    check("nmap-advanced: http-title из default,safe скриптов",
          "Synthetic Lab" in out or "http-title" in out)

    st, r = api("/api/tools/httpx", {"target": lab.url, "mode": "probe"})
    check("httpx probe: статус полигона получен",
          st == 200 and ("200" in r.get("stdout", "") or "fallback" in r),
          r.get("fallback", "pd"))
    st, r = api("/api/tools/whatweb", {"target": lab.url})
    out = r.get("stdout", "")
    check("whatweb: технологический фингерпринт",
          st == 200 and ("WordPress" in out or "HTTPServer" in out or " JQuery" in out))

    st, r = api("/api/tools/gobuster", {"url": lab.url, "mode": "dir",
                                        "wordlist": lab.wordlist,
                                        "additional_args": "-q --no-error"})
    out = r.get("stdout", "")
    check("gobuster: находит /admin и /uploads",
          st == 200 and "/admin" in out and "/uploads" in out,
          f"rc={r.get('return_code')}")
    st, r = api("/api/tools/dirsearch", {"url": lab.url, "wordlist": lab.wordlist})
    out = (r.get("stdout", "") or "") + (r.get("report", "") or "")
    check("dirsearch: находит /secret",
          st == 200 and "/secret" in out, f"rc={r.get('return_code')}")

    st, r = api("/api/tools/katana", {"url": lab.url, "depth": 2,
                                      "js_crawl": False, "form_extraction": False})
    out = r.get("stdout", "")
    check("katana: краулит на page2.html",
          st == 200 and ("page2" in out or "secret" in out),
          f"rc={r.get('return_code')}")

    # redirect chain
    st, r = api("/api/tools/whatweb",
                {"target": f"{lab.url}/redirect.php",
                 "additional_args": "--follow-redirect=transparent"})
    check("redirect-цепочка (301/302): инструмент отрабатывает без зависания",
          st == 200 and r.get("timed_out") is not True,
          f"rc={r.get('return_code')}")

    # soft-404 zone (informational)
    soft_wl = os.path.join(lab.root, "soft_wl.txt")
    with open(soft_wl, "w") as f:
        f.write("soft-aaa\nsoft-bbb\nsoft-ccc\n")
    st, r = api("/api/tools/gobuster", {"url": f"{lab.url}/soft/", "mode": "dir",
                                        "wordlist": soft_wl,
                                        "additional_args": "-q --no-error"})
    fp = sum(1 for w in ("soft-aaa", "soft-bbb", "soft-ccc")
             if w in r.get("stdout", ""))
    check("soft-404: инструмент возвращает статусы (агент обязан видеть 200-на-всё)",
          st == 200, f"ложных директорий в выводе: {fp}/3 (информационно)")

    # TLS target
    st, r = api("/api/tools/nmap",
                {"target": "127.0.0.1", "ports": str(lab.https_port),
                 "scan_type": "-sV", "additional_args": "-Pn --script ssl-cert"})
    out = r.get("stdout", "")
    check("TLS-цель: nmap снимает self-signed сертификат (ssl-cert)",
          st == 200 and ("ssl-cert" in out or "PEM" in out or "TLS" in out.upper()),
          f"rc={r.get('return_code')}")
    st, r = api("/api/tools/httpx", {"target": lab.https_url, "mode": "probe"})
    check("TLS-цель: httpx с self-signed — структурированный результат, не 500",
          st == 200, f"rc={r.get('return_code')}")

    if not quick:
        st, r = api("/api/tools/nikto", {"target": lab.url,
                                         "additional_args": "-Tuning 4 -nointeractive"})
        check("nikto: скан завершается со структурным выводом",
              st == 200 and r.get("return_code") is not None,
              f"rc={r.get('return_code')}, exec={r.get('execution_time', 0):.0f}s")

        # --- findings pipeline on the REAL vulnerable endpoint -----------
        st, r = api("/api/tools/sqlmap",
                    {"url": f"{lab.url}/login.php",
                     "data": "user=admin&pass=x",
                     "additional_args": "-p user --level=1 --risk=1 --threads=4 "
                                        "--timeout=5 --retries=1"})
        check("sqlmap: DESTRUCTIVE без confirmed блокируется", st == 403, f"st={st}")
        st, r = api("/api/tools/sqlmap",
                    {"url": f"{lab.url}/login.php",
                     "data": "user=admin&pass=x", "confirmed": True,
                     "additional_args": "-p user --level=1 --risk=1 --threads=4 "
                                        "--timeout=5 --retries=1"})
        out = r.get("stdout", "") + r.get("stderr", "")
        check("sqlmap: НАХОДИТ реальную SQLi (конвейер находок работает)",
              st == 200 and ("is vulnerable" in out or "back-end DBMS" in out),
              f"rc={r.get('return_code')}, exec={r.get('execution_time', 0):.0f}s")

        st, r = api("/api/tools/dalfox",
                    {"url": f"{lab.url}/search.php?q=LABXSSPROBE"})
        out = r.get("stdout", "")
        check("dalfox: находит reflected XSS",
              st == 200 and ("[V]" in out or "Reflect" in out or "found" in out.lower()),
              f"rc={r.get('return_code')}")

    st, r = api("/api/tools/prowler", {"provider": "aws"})
    check("cloud_audit (prowler): без облачных кредов — структурированная ошибка, не 500",
          st in (200, 400, 503) and "Server error" not in json.dumps(r),
          f"st={st}")


def test_workflow(lab: Lab):
    print("\n━━━ Workflow: сессии, отчёт, guardrails, async ━━━")

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
        check(f"scope-variant {variant!r}: не пропущен мимо правил", st == 403, f"st={st}")
    api("/api/guardrails/scope", {"rules": []}, method="PUT")

    st, r = api("/api/guardrails/audit?limit=50", method="GET")
    tools_audited = {e.get("tool") for e in r.get("events", [])}
    check("audit: вызовы инструментов оставили след",
          "nmap" in tools_audited, str(sorted(tools_audited))[:120])

    st, r = api("/api/tools/nmap-advanced",
                {"target": "127.0.0.1", "scan_type": "-sV", "aggressive": True,
                 "ports": "8888"})
    check("tier: nmap-advanced aggressive=true требует подтверждения", st == 403,
          f"st={st}")

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


# ---------------------------------------------------------------------------
# 2. injection battery + robustness
# ---------------------------------------------------------------------------

INJECTION_PROBES = [
    ("/api/tools/zap", {"host": "127.0.0.1", "port": f"8080; echo {MARKER}"}),
    ("/api/tools/gdb", {"binary": f"/bin/true; echo {MARKER}"}),
    ("/api/tools/radare2", {"binary": f"/bin/true; echo {MARKER}"}),
    ("/api/tools/autorecon", {"target": f"127.0.0.1; echo {MARKER}", "output_dir": "/tmp/hxs_atr"}),
    ("/api/tools/enum4linux-ng", {"target": f"127.0.0.1; echo {MARKER}"}),
    ("/api/tools/dalfox", {"url": f"http://127.0.0.1; echo {MARKER}"}),
    ("/api/tools/prowler", {"provider": f"aws; echo {MARKER}"}),
    ("/api/tools/pacu", {"module": f"ec2_enum; echo {MARKER}"}),
    ("/api/tools/wpscan", {"url": f"http://127.0.0.1:1; echo {MARKER}"}),
    ("/api/tools/nikto", {"target": f"127.0.0.1:1; echo {MARKER}"}),
    ("/api/tools/sqlmap", {"url": f"http://127.0.0.1:1; echo {MARKER}", "confirmed": True}),
    ("/api/tools/dirsearch", {"url": f"http://127.0.0.1:1; echo {MARKER}"}),
    ("/api/tools/whatweb", {"target": f"127.0.0.1:1; echo {MARKER}"}),
    ("/api/tools/gobuster", {"url": f"http://127.0.0.1:1; echo {MARKER}"}),
]


def test_injection_battery():
    print("\n━━━ Инъекционная батарея (string-form роуты) ━━━")
    vulns = []
    for path, payload in INJECTION_PROBES:
        full = dict(payload)
        full["use_cache"] = False
        full.setdefault("additional_args", "")
        st, r = api(path, full, timeout=90)
        out = r.get("stdout", "") or ""
        err = r.get("stderr", "") or ""
        if MARKER in out:
            vulns.append(path)
            check(f"инъекция {path}: УЯЗВИМ (RCE)", False)
        elif MARKER in err:
            check(f"инъекция {path}: пейлоад отражён в stderr (диагностика), shell-инъекции нет",
                  True, f"st={st}")
        else:
            check(f"инъекция {path}: метасимволы нейтрализованы", True, f"st={st}")
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


# ---------------------------------------------------------------------------
# 3. hang matrix + API freeze
# ---------------------------------------------------------------------------

def test_hang_matrix(lab: Lab):
    print("\n━━━ Матрица зависаний (чёрная дыра / медленная / закрытый порт) ━━━")

    cases = [
        ("чёрная дыра (accept+молчание)", f"http://127.0.0.1:{lab.blackhole_port}"),
        ("медленная цель (ответ через 25с)", f"http://127.0.0.1:{lab.slow_port}"),
        ("закрытый порт", f"http://127.0.0.1:{lab.closed_port}"),
    ]
    for name, url in cases:
        t0 = time.time()
        st, r = api("/api/tools/httpx", {"target": url, "mode": "probe"}, timeout=180)
        dt = time.time() - t0
        check(f"hang-matrix {name}: возврат за {dt:.0f}s (<120s), не 500",
              st == 200 and dt < 120 and r.get("return_code") is not None,
              f"st={st}, exec={r.get('execution_time', 0):.0f}s")

    t0 = time.time()
    st, r = api("/api/command",
                {"command": f"curl -s --max-time 5 http://127.0.0.1:{lab.blackhole_port}/ || echo curl-done",
                 "use_cache": False}, timeout=120)
    dt = time.time() - t0
    check("hang-matrix: curl к чёрной дыре — сервер вернулся структурно",
          st == 200 and dt < 120, f"за {dt:.0f}s")

    # BUG-5: infinite writer behind a finite reader (yes | head -c N, N > cap).
    # head blocks writing into the full pipe, yes blocks behind head; a
    # child-only SIGTERM deadlocks the executor and leaks both writers.
    t0 = time.time()
    st, r = api("/api/command",
                {"command": "yes 'BUG5MARK' | head -c 20971520",
                 "use_cache": False}, timeout=120)
    dt = time.time() - t0
    leaked = pgrep("yes .BUG5MARK.")
    check("BUG-5: yes|head поверх капа — быстрый возврат, писатели НЕ утекли",
          st == 200 and dt < 60 and r.get("output_truncated") is True and leaked == 0,
          f"за {dt:.0f}s, утекло {leaked}")


def test_api_freeze(lab: Lab, quick: bool):
    print("\n━━━ Заморозка API при параллельных долгих сканах ━━━")
    if quick:
        print("  (пропущено: --quick)")
        return
    import concurrent.futures
    scan = {"target": "127.0.0.1", "ports": str(lab.slow_port),
            "scan_type": "-sV",
            "additional_args": "-Pn --host-timeout 40s"}
    max_health_latency = 0.0
    stop = threading.Event()

    def poll_health():
        nonlocal max_health_latency
        while not stop.is_set():
            t0 = time.time()
            try:
                urllib.request.urlopen(f"{BASE}/health?json", timeout=60).read()
            except Exception:
                max_health_latency = 999  # health вообще не ответил
            max_health_latency = max(max_health_latency, time.time() - t0)
            time.sleep(0.5)

    poller = threading.Thread(target=poll_health, daemon=True)
    poller.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(api, "/api/tools/nmap", scan, timeout=180)
                for _ in range(2)]
        for f in futs:
            f.result()
    stop.set()
    poller.join(timeout=5)
    check(f"API не замерзает: max задержка /health {max_health_latency:.1f}s (<15s)",
          max_health_latency < 15,
          "gthread должен держать /health отзывчивым во время долгих сканов")


# ---------------------------------------------------------------------------
# 4. tool flag-drift smoke (BUG-1 class, systematic)
# ---------------------------------------------------------------------------

FLAG_SMOKE = [
    # (help argv, required substrings in combined help output)
    (["gobuster", "dir", "-h"], ["-u", "-w"]),
    (["nuclei", "-h"], ["-u", "-severity", "-tags"]),
    (["sqlmap", "-h"], ["-u", "--batch", "--data"]),
    (["nikto", "-h"], ["-h"]),
    (["wpscan", "--help"], ["--url", "--[no-]update", "--disable-tls-checks"]),
    (["dirsearch", "-h"], ["-u", "-w", "-o"]),
    (["ffuf", "-h"], ["-u", "-w"]),
    (["dalfox", "--help"], ["pipe", "--custom-payload", "--blind"]),
    (["enum4linux-ng", "-h"], ["-u", "-p", "-A"]),
    (["autorecon", "--help"], ["-o", "--heartbeat", "--timeout"]),
    (["masscan", "--help"], []),  # --help lists no options; existence only
    (["rustscan", "--help"], ["-a"]),
    (["r2", "-h"], ["-i", "-q"]),
    (["gdb", "--help"], ["-x", "-batch"]),
    (["whatweb", "--help"], []),
]


def test_flag_smoke():
    print("\n━━━ Дрейф флагов инструментов (BUG-1 класс) ━━━")
    for argv, required in FLAG_SMOKE:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            text = (r.stdout or "") + (r.stderr or "")
            if not required:
                check(f"{argv[0]}: запуск help без падения (rc={r.returncode})",
                      r.returncode in (0, 1, 2))
                continue
            missing = [f for f in required if f not in text]
            check(f"{argv[0]}: флаги {required} присутствуют в help",
                  not missing, f"отсутствуют: {missing}" if missing else "")
        except FileNotFoundError:
            check(f"{argv[0]}: флаги {required}", False, "бинарник не найден")
        except subprocess.TimeoutExpired:
            check(f"{argv[0]}: флаги {required}", False, "help завис (>20s)")

    # nmap: полный прогон с нашим выражением скриптов (реальная проверка)
    r = subprocess.run(
        ["nmap", "--host-timeout", "10s", "--script-timeout", "10s",
         "--script", "default,safe and not broadcast and not discovery and not external",
         "-p", "1", "127.0.0.1"], capture_output=True, text=True, timeout=60)
    check("nmap: микроскан с выражением скриптов проходит (rc=0, не rc=255)",
          r.returncode == 0 and "unrecognized" not in r.stderr,
          f"rc={r.returncode}")


# ---------------------------------------------------------------------------
# 5. kill-switch process semantics
# ---------------------------------------------------------------------------

def test_kill_semantics(lab: Lab, quick: bool):
    print("\n━━━ Kill switch: убивает ли РЕАЛЬНО запущенные процессы ━━━")

    # deterministic: async sleep task via the process pool
    st, r = api("/api/process/execute-async",
                {"command": "sleep 45", "use_cache": False})
    tid = r.get("task_id")
    running = False
    for _ in range(20):
        st, r = api(f"/api/process/get-task-result/{tid}", method="GET")
        if (r.get("result", {}) or {}).get("status") == "running":
            running = True
            break
        time.sleep(0.5)
    if not running:
        check("kill: sleep-задача успела запуститься", False, "задача не достигла running")
    else:
        before = wait_for_process("sleep 45", timeout=15)
        if before == 0:
            check("kill: процесс sleep 45 появился", False,
                  "воркер пометил running, но процесс не виден")
        else:
            for _ in range(3):  # попасть в оба воркера
                api("/api/guardrails/kill-all", {"reason": "lab-kill-test"})
            time.sleep(8)
            after = pgrep("sleep 45")
            api("/api/guardrails/reset")
            check("kill-all: процессы задач РЕАЛЬНО завершены (pgrep=0)",
                  after == 0, f"до={before}, после={after}")

    if not quick:
        # best-effort: long nmap against the slow responder
        def start_nmap():
            api("/api/tools/nmap",
                {"target": "127.0.0.1", "ports": str(lab.slow_port),
                 "scan_type": "-sV",
                 "additional_args": "-Pn --host-timeout 120s"}, timeout=300)
        t = threading.Thread(target=start_nmap, daemon=True)
        t.start()
        running_nmap = wait_for_process("nmap", timeout=20, by_name=True)
        if running_nmap == 0:
            check("kill-all: nmap успел запуститься", False, "процесс не пойман")
        else:
            for _ in range(3):
                api("/api/guardrails/kill-all", {"reason": "lab-kill-nmap"})
            time.sleep(12)
            after = pgrep_name("nmap")
            api("/api/guardrails/reset")
            t.join(timeout=5)
            check("kill-all: запущенный nmap РЕАЛЬНО убит (pgrep=0)",
                  after == 0, f"до={running_nmap}, после={after}")


# ---------------------------------------------------------------------------
# 6. output fidelity
# ---------------------------------------------------------------------------

def test_output_fidelity(lab: Lab):
    print("\n━━━ Достоверность вывода (бинарные данные / ANSI / /tmp) ━━━")

    before_tmp = len([n for n in os.listdir("/tmp") if n.startswith("hxs_dirsearch")])
    st, r = api("/api/tools/dirsearch", {"url": lab.url, "wordlist": lab.wordlist})
    after_tmp = len([n for n in os.listdir("/tmp") if n.startswith("hxs_dirsearch")])
    check("директории dirsearch в /tmp не копятся (утечка диска)",
          after_tmp <= before_tmp, f"до={before_tmp}, после={after_tmp}")

    st, r = api("/api/command",
                {"command": f"curl -s {lab.url}/binary.bin | wc -c",
                 "use_cache": False}, timeout=120)
    size = os.path.getsize("/bin/ls")
    check("бинарный файл через curl: размер совпал, декод не упал",
          st == 200 and r.get("stdout", "").strip().endswith(str(size)),
          f"stdout={r.get('stdout', '').strip()[-30:]!r}, ожидалось ~{size}")

    st, r = api("/api/command",
                {"command": "printf '\\033[31mRED\\033[0m plain\\n'",
                 "use_cache": False})
    check("ANSI-вывод: проходит без потерь и без 500",
          st == 200 and "RED" in r.get("stdout", ""))


# ---------------------------------------------------------------------------
# 7. MCP layer (stdio JSON-RPC)
# ---------------------------------------------------------------------------

def test_mcp_layer(lab: Lab):
    print("\n━━━ MCP-слой (stdio JSON-RPC, путь реального агента) ━━━")
    mcp_script = os.path.join(REPO, "hexstrike_mcp.py")

    try:
        client = McpStdioClient(mcp_script)
    except Exception as e:
        check("MCP: запуск stdio-сервера", False, str(e)[:100])
        return
    try:
        init = client.initialize(timeout=40)
        check("MCP: initialize", bool(init), str(init.get("serverInfo", ""))[:60])

        tools = client.list_tools(timeout=40)
        names = {t.get("name") for t in tools}
        core = {"port_scan", "subdomain_enum", "http_probe",
                "directory_brute", "web_vuln_scan", "cloud_audit"}
        check(f"MCP: tools/list ({len(names)} шт.), глаголы на месте",
              core <= names, f"нет: {sorted(core - names)}")

        exec_name = next(iter({"execute_command", "execute"} & names), None)
        if exec_name:
            res = client.call_tool(exec_name, {"command": "echo mcp-ok"},
                                   timeout=90)
            text = McpStdioClient.tool_text(res)
            check("MCP: execute → echo проходит сквозь весь стек",
                  "mcp-ok" in text and not res.get("isError"), text[:60])
            # optimizer fidelity: big structured output keeps head+tail+marker
            res = client.call_tool(
                exec_name,
                {"command": "python3 -c \"print('HEADMARK'+'X'*30000+'TAILMARK')\""},
                timeout=120)
            text = McpStdioClient.tool_text(res)
            check("MCP-оптимизатор: трюнкация сохраняет голову и хвост + маркер",
                  "HEADMARK" in text and "TAILMARK" in text and "truncated" in text,
                  f"len={len(text)}")
        else:
            check("MCP: execute-инструмент доступен", False, str(sorted(names))[:120])

        res = client.call_tool("port_scan",
                               {"target": "127.0.0.1", "ports": str(lab.port),
                                "mode": "fast"}, timeout=180)
        text = McpStdioClient.tool_text(res)
        check("MCP: port_scan(fast) видит порт полигона",
              str(lab.port) in text and not res.get("isError"), text[:60])

        res = client.call_tool("http_probe", {"url": lab.url, "mode": "probe"},
                               timeout=120)
        text = McpStdioClient.tool_text(res)
        check("MCP: http_probe(probe) — маппинг глагол→роут работает",
              not res.get("isError") and ("200" in text or "fallback" in text),
              text[:60])
    finally:
        client.close()

    # profile env: recon profile keeps recon verbs, hides exploit tools
    try:
        client2 = McpStdioClient(mcp_script,
                                 env_extra={"HEXSTRIKE_MCP_PROFILE": "recon"})
        client2.initialize(timeout=40)
        names2 = {t.get("name") for t in client2.list_tools(timeout=40)}
        client2.close()
        check("MCP-профиль recon: глаголы разведки есть, эксплойт-тулы скрыты",
              "port_scan" in names2 and "sqlmap" not in names2
              and "metasploit_run" not in names2,
              f"{len(names2)} инструментов")
    except Exception as e:
        check("MCP-профиль recon", False, str(e)[:100])


# ---------------------------------------------------------------------------
# 8. auth-enabled instance
# ---------------------------------------------------------------------------

def test_auth_mode():
    print("\n━━━ Режим аутентификации (отдельный инстанс :8889) ━━━")
    port = 8889
    env = dict(os.environ)
    env.update({"HEXSTRIKE_REQUIRE_AUTH": "true",
                "HEXSTRIKE_API_KEY": "lab-test-key",
                "HEXSTRIKE_PORT": str(port)})
    workdir = tempfile.mkdtemp(prefix="hxs_auth_")
    proc = subprocess.Popen(
        [os.environ.get("PYTHON", "python3"),
         os.path.join(REPO, "hexstrike_server.py"), "--port", str(port)],
        env=env, cwd=workdir,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        # Импорт 742КБ-модуля + init — под нагрузкой старта занимает ~10-30с
        up = False
        for _ in range(120):
            try:
                urllib.request.urlopen(f"{base}/health", timeout=2).read()
                up = True
                break
            except Exception:
                time.sleep(0.5)
        if not up:
            check("auth-инстанс: поднялся на :8889", False, "health не ответил за 60s")
            return

        def probe(path, method="GET", payload=None, key=None):
            req = urllib.request.Request(
                base + path,
                data=json.dumps(payload).encode() if payload else None,
                method=method,
                headers={"Content-Type": "application/json",
                         **({"X-API-Key": key} if key else {})})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code

        no_key = {
            "/api/tools/nmap": probe("/api/tools/nmap", "POST", {"target": "127.0.0.1"}),
            "/api/command": probe("/api/command", "POST", {"command": "echo x"}),
            "/api/guardrails/scope": probe("/api/guardrails/scope"),
            "/api/guardrails/audit": probe("/api/guardrails/audit"),
            "/api/session/create": probe("/api/session/create", "POST",
                                         {"target": "127.0.0.1"}),
            "/api/files/list": probe("/api/files/list"),
            "/api/process/pool-stats": probe("/api/process/pool-stats"),
        }
        leaked = [p for p, code in no_key.items() if code != 401]
        check("auth: все /api/* отвечают 401 без ключа (включая blueprints)",
              not leaked, f"утечки: {leaked}" if leaked else f"{len(no_key)} эндпоинтов")

        with_key = probe("/api/tools/nmap", "POST", {"target": "127.0.0.1"},
                         key="lab-test-key")
        check("auth: с корректным ключом доступ есть", with_key in (200, 400),
              f"st={with_key}")
        bad_key = probe("/api/command", "POST", {"command": "echo x"},
                        key="wrong-key")
        check("auth: неверный ключ отклоняется", bad_key == 401, f"st={bad_key}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 9. rate limiter + task survival
# ---------------------------------------------------------------------------

def test_rate_limit():
    print("\n━━━ Rate limiter (информационно) ━━━")
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(api, "/api/command",
                          {"command": "sleep 1", "use_cache": False,
                           "target": "127.0.0.1"}) for _ in range(8)]
        codes = sorted(f.result()[0] for f in futs)
    check("rate: параллельные запросы не роняют сервер", all(c == 200 for c in codes),
          f"коды: {codes}")


def test_task_survival():
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
    check("task-survival: после recycle — честный статус",
          res.get("status") in ("lost", "completed", "failed"), f"status={res.get('status')}")


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip slow scans")
    ap.add_argument("--skip-restart", action="store_true",
                    help="skip the service-restart survival test")
    args = ap.parse_args()

    print(f"HexStrike synthetic lab v2 → {BASE}")
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
        test_workflow(lab)
        test_injection_battery()
        test_robustness()
        test_hang_matrix(lab)
        test_flag_smoke()
        test_kill_semantics(lab, args.quick)
        test_output_fidelity(lab)
        test_api_freeze(lab, args.quick)
        test_mcp_layer(lab)
        test_auth_mode()
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
