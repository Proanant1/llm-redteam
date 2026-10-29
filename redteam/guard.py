"""LLM Guard: a live, OpenAI-compatible security proxy.

    your app  ->  Guard (this)  ->  Ollama / Groq / OpenAI / any OpenAI-compatible server

Per request it (1) scans user/tool content for prompt injection, (2) optionally hardens the system
prompt, (3) calls the upstream model, (4) scans the answer for leaked secrets, leaked system-prompt
text and data-exfiltration URLs, and (5) streams every decision to a live dashboard + JSONL log.

Standard library only. API keys are passed through to the upstream and never logged.
"""
from __future__ import annotations

import json
import queue
import re
import threading
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .dashboard import DASHBOARD_HTML
from .defenses import BLOCK_REPLY, HARDENING, scan_text, wrap_untrusted
from .providers import ProviderError, _post_json

SECRET_PATTERNS = [
    r"\bsk-[A-Za-z0-9_-]{16,}", r"\bAKIA[0-9A-Z]{16}\b", r"\bghp_[A-Za-z0-9]{30,}",
    r"\bxox[abp]-[A-Za-z0-9-]{10,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
]
_URL = re.compile(r"https?://[^\s)\]>\"']+")
_MD_IMG = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)[^)]*\)")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{10,}")


@dataclass
class GuardConfig:
    upstream: str = "http://localhost:11434/v1"
    mode: str = "block"                       # block | monitor (log only, never alters traffic)
    harden: bool = False                      # add policy to system prompt, wrap tool output as untrusted
    secrets: list = field(default_factory=list)         # literal secrets that must never appear in output
    secret_regex: list = field(default_factory=list)    # extra secret patterns
    auto_secrets: bool = True                 # treat key-like tokens inside the system prompt as secrets
    allow_hosts: list = field(default_factory=list)     # hosts whose URLs/images may appear in answers
    strip_links: bool = False                 # also strip plain links to non-allowed hosts
    skip_rules: frozenset = frozenset({"external-url"})  # input rules disabled (links are common in real traffic)
    overlap_threshold: int = 3                # shared 8-word shingles that count as a system-prompt leak
    rate_limit: int = 0                       # requests per minute per client IP (0 = off)
    max_body: int = 262144
    admin_token: str | None = None            # protects dashboard / events if set
    upstream_key: str | None = None           # used when the client sends no Authorization header
    default_model: str = "llama3.2"           # used by the dashboard's test box
    log_file: str | None = None
    snippets: bool = True                     # store a short, redacted snippet in events


def _alnum(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", s.upper())


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content
                         if isinstance(p, dict) and p.get("type") in (None, "text"))
    return ""


def _words(s: str) -> list:
    return re.findall(r"[a-z0-9$@.:/-]+", s.lower())


def _shingles(words: list, n: int = 8) -> set:
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


class Guard:
    def __init__(self, cfg: GuardConfig):
        self.cfg = cfg
        self.secret_norms = [n for n in (_alnum(s) for s in cfg.secrets if s) if len(n) >= 6]
        self.secret_res = [re.compile(p) for p in SECRET_PATTERNS + list(cfg.secret_regex)]
        self.events: deque = deque(maxlen=500)
        self.stats = Counter()
        self.rules = Counter()
        self.latency_sum = 0.0
        self._lock = threading.Lock()
        self._subs: list = []
        self._rate: dict = {}
        self._logf = open(cfg.log_file, "a", buffering=1) if cfg.log_file else None
        self.started = time.time()

    # ------------------------------------------------------------------ detection
    def check_request(self, messages: list):
        """Return (rule, role) for the first suspicious user/tool message, else None."""
        for m in messages:
            if not isinstance(m, dict):
                continue
            role = m.get("role")
            if role in ("user", "tool", "function"):
                hit = scan_text(_text_of(m.get("content")), skip=self.cfg.skip_rules)
                if hit:
                    return hit, role
        return None

    def prepare_messages(self, messages: list) -> list:
        if not self.cfg.harden:
            return messages
        out, has_system = [], False
        for m in messages:
            m = dict(m) if isinstance(m, dict) else m
            if m.get("role") == "system" and not has_system:
                m["content"] = _text_of(m.get("content")) + HARDENING
                has_system = True
            elif m.get("role") in ("tool", "function"):
                m["content"] = wrap_untrusted("document", _text_of(m.get("content")))
            out.append(m)
        if not has_system:
            out.insert(0, {"role": "system", "content": HARDENING.strip()})
        return out

    def _request_context(self, messages: list):
        sys_text = "\n".join(_text_of(m.get("content")) for m in messages
                             if isinstance(m, dict) and m.get("role") == "system")
        norms = list(self.secret_norms)
        if self.cfg.auto_secrets:
            for t in _TOKEN.findall(sys_text):
                if re.search(r"[A-Za-z]", t) and len(re.findall(r"\d", t)) >= 3:
                    n = _alnum(t)
                    if len(n) >= 8:
                        norms.append(n)
        return set(norms), _shingles(_words(sys_text))

    def _secret_hit(self, text: str, norms: set):
        n = _alnum(text)
        for s in norms:
            if s in n or s[::-1] in n:
                return "secret-in-output"
        for r in self.secret_res:
            if r.search(text):
                return "secret-pattern-in-output"
        return None

    def _host_ok(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == h or host.endswith("." + h) for h in self.cfg.allow_hosts)

    def _strip_urls(self, text: str, norms: set):
        rules = []

        def img(m):
            if self._host_ok(m.group(1)):
                return m.group(0)
            rules.append("exfil-image-removed")
            return "[image removed]"

        def link(m):
            url = m.group(0)
            if self._host_ok(url):
                return url
            dec = unquote(url)
            if self.cfg.strip_links or self._secret_hit(dec, norms) or _EMAIL.search(dec):
                rules.append("exfil-url-removed")
                return "[link removed]"
            return url

        text = _MD_IMG.sub(img, text)
        text = _URL.sub(link, text)
        return text, (rules[0] if rules else None)

    def check_output_text(self, text: str, norms: set, sys_shingles: set):
        """Return (text, rule, kind) where kind is 'block', 'redact' or None."""
        hit = self._secret_hit(text, norms)
        if hit:
            return BLOCK_REPLY, hit, "block"
        if sys_shingles:
            # short prompts have few 8-word windows, so scale the bar down (at least 1, at most the setting)
            need = max(1, min(self.cfg.overlap_threshold, len(sys_shingles) // 3))
            if len(_shingles(_words(text)) & sys_shingles) >= need:
                return BLOCK_REPLY, "system-prompt-leak", "block"
        cleaned, rule = self._strip_urls(text, norms)
        if rule:
            return cleaned, rule, "redact"
        return text, None, None

    def check_response(self, resp: dict, messages: list):
        """Scan every choice. Returns (resp, rule, kind). `resp` is modified in place."""
        norms, shingles = self._request_context(messages)
        worst = (None, None)
        for ch in resp.get("choices", []) or []:
            msg = ch.get("message") or {}
            text = msg.get("content")
            if isinstance(text, str) and text:
                new, rule, kind = self.check_output_text(text, norms, shingles)
                if rule:
                    msg["content"] = new
                    if kind == "block":
                        msg.pop("tool_calls", None)
                        ch["finish_reason"] = "stop"
                    if worst[1] != "block":
                        worst = (rule, kind)
            for tc in list(msg.get("tool_calls") or []):    # agent tool arguments
                args = (tc.get("function") or {}).get("arguments", "")
                hit = self._secret_hit(args, norms) if isinstance(args, str) else None
                if hit:
                    msg.pop("tool_calls", None)
                    msg["content"] = BLOCK_REPLY
                    ch["finish_reason"] = "stop"
                    worst = ("secret-in-tool-call", "block")
                    break
        return resp, worst[0], worst[1]

    # ------------------------------------------------------------------ events
    def _redact(self, text: str) -> str:
        text = re.sub(r"\s+", " ", text)
        for r in self.secret_res:
            text = r.sub("[secret]", text)
        return text[:100]

    def emit(self, ev: dict) -> None:
        with self._lock:
            self.events.append(ev)
            self.stats["total"] += 1
            self.stats[ev["action"]] += 1
            if ev.get("rule"):
                self.rules[ev["rule"]] += 1
            self.latency_sum += ev.get("latency_ms", 0)
            snap = self.snapshot()
            subs = list(self._subs)
            if self._logf:
                self._logf.write(json.dumps(ev) + "\n")
        payload = json.dumps({"event": ev, "stats": snap})
        for q in subs:
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass

    def snapshot(self) -> dict:
        total = self.stats["total"]
        return {"total": total, "allowed": self.stats["allowed"], "blocked": self.stats["blocked"],
                "redacted": self.stats["redacted"], "would_block": self.stats["monitor-would-block"],
                "errors": self.stats["error"], "rules": dict(self.rules.most_common(12)),
                "avg_latency_ms": round(self.latency_sum / total) if total else 0,
                "uptime_s": int(time.time() - self.started)}

    def subscribe(self):
        q = queue.Queue(maxsize=200)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def rate_ok(self, client: str) -> bool:
        if not self.cfg.rate_limit:
            return True
        now = time.time()
        with self._lock:
            hits = [t for t in self._rate.get(client, []) if now - t < 60]
            if len(hits) >= self.cfg.rate_limit:
                self._rate[client] = hits
                return False
            hits.append(now)
            self._rate[client] = hits
        return True

    # ------------------------------------------------------------------ main flow
    @staticmethod
    def _completion(model: str, content: str) -> dict:
        return {"id": f"chatcmpl-guard-{uuid.uuid4().hex[:12]}", "object": "chat.completion",
                "created": int(time.time()), "model": model or "guard",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}

    def process(self, body: dict, client: str, auth: str | None):
        """Returns (http_status, response_dict, extra_headers)."""
        t0 = time.time()
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return 400, {"error": {"message": "'messages' must be a non-empty list"}}, {}
        enforce = self.cfg.mode == "block"
        ev = {"id": uuid.uuid4().hex[:8], "ts": time.strftime("%H:%M:%S"), "client": client,
              "model": str(body.get("model", "")), "action": "allowed", "stage": None, "rule": None,
              "snippet": ""}
        if self.cfg.snippets:
            last_user = next((_text_of(m.get("content")) for m in reversed(messages)
                              if isinstance(m, dict) and m.get("role") == "user"), "")
            ev["snippet"] = self._redact(last_user)

        hit = self.check_request(messages)
        if hit:
            ev.update(stage="input", rule=hit[0])
            if enforce:
                ev.update(action="blocked", latency_ms=int((time.time() - t0) * 1000))
                self.emit(ev)
                return 200, self._completion(body.get("model"), BLOCK_REPLY), {"X-Guard-Action": "blocked"}
            ev["action"] = "monitor-would-block"

        up_body = {k: v for k, v in body.items() if k not in ("stream", "stream_options")}
        up_body["messages"] = self.prepare_messages(messages) if enforce else messages
        headers = {}
        if auth:
            headers["Authorization"] = auth
        elif self.cfg.upstream_key:
            headers["Authorization"] = f"Bearer {self.cfg.upstream_key}"
        try:
            resp = _post_json(self.cfg.upstream.rstrip("/") + "/chat/completions", up_body, headers)
        except ProviderError as e:
            ev.update(action="error", stage="upstream", rule="upstream-error",
                      detail=str(e)[:160], latency_ms=int((time.time() - t0) * 1000))
            self.emit(ev)
            return 502, {"error": {"message": "upstream model error", "type": "guard_upstream_error"}}, {}

        out_rule = None
        if enforce:
            resp, out_rule, kind = self.check_response(resp, messages)
            if out_rule:
                ev.update(stage="output", rule=out_rule,
                          action="blocked" if kind == "block" else "redacted")
        else:
            import copy
            _, out_rule, kind = self.check_response(copy.deepcopy(resp), messages)
            if out_rule:
                ev.update(stage="output", rule=out_rule, action="monitor-would-block")
        ev["latency_ms"] = int((time.time() - t0) * 1000)
        self.emit(ev)
        return 200, resp, {"X-Guard-Action": ev["action"]}


# ---------------------------------------------------------------------- HTTP server
def _sse_chunks(resp: dict) -> list:
    """Re-emit a complete completion as an OpenAI-style SSE stream."""
    base = {"id": resp.get("id", "chatcmpl-guard"), "object": "chat.completion.chunk",
            "created": resp.get("created", int(time.time())), "model": resp.get("model", "guard")}
    out = []
    for ch in resp.get("choices", []):
        msg = ch.get("message", {})
        delta = {"role": "assistant", "content": msg.get("content") or ""}
        if msg.get("tool_calls"):
            delta["tool_calls"] = [{**tc, "index": i} for i, tc in enumerate(msg["tool_calls"])]
        idx = ch.get("index", 0)
        out.append({**base, "choices": [{"index": idx, "delta": delta, "finish_reason": None}]})
        out.append({**base, "choices": [{"index": idx, "delta": {}, "finish_reason": ch.get("finish_reason", "stop")}]})
    return out


def make_handler(guard: Guard):
    cfg = guard.cfg

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):          # silence default access log (events cover it)
            pass

        # ---- helpers
        def _send(self, status, body, ctype="application/json", headers=None, raw=False):
            data = body if raw else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _admin_ok(self) -> bool:
            if not cfg.admin_token:
                return True
            q = parse_qs(urlparse(self.path).query)
            return (q.get("token", [""])[0] == cfg.admin_token
                    or self.headers.get("X-Admin-Token") == cfg.admin_token)

        # ---- routes
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/health":
                return self._send(200, {"status": "ok", "mode": cfg.mode})
            if path in ("/", "/api/state", "/events"):
                if not self._admin_ok():
                    return self._send(401, {"error": "admin token required"})
            if path == "/":
                return self._send(200, DASHBOARD_HTML.encode(), "text/html; charset=utf-8", raw=True, headers={
                    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; "
                                               "style-src 'unsafe-inline'; connect-src 'self'"})
            if path == "/api/state":
                return self._send(200, {"stats": guard.snapshot(), "recent": list(guard.events)[-100:],
                                        "config": {"mode": cfg.mode, "harden": cfg.harden,
                                                   "default_model": cfg.default_model}})
            if path == "/events":
                return self._sse()
            if path in ("/v1/models", "/models"):
                try:
                    import urllib.request
                    req = urllib.request.Request(cfg.upstream.rstrip("/") + "/models")
                    auth = self.headers.get("Authorization") or (
                        f"Bearer {cfg.upstream_key}" if cfg.upstream_key else None)
                    if auth:
                        req.add_header("Authorization", auth)
                    with urllib.request.urlopen(req, timeout=15) as r:
                        return self._send(200, r.read(), raw=True)
                except Exception:
                    return self._send(502, {"error": {"message": "upstream unavailable"}})
            self._send(404, {"error": "not found"})

        def _sse(self):
            q = guard.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                while True:
                    try:
                        self.wfile.write(f"data: {q.get(timeout=15)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                guard.unsubscribe(q)

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/v1/chat/completions", "/chat/completions"):
                return self._send(404, {"error": "not found"})
            client = self.client_address[0]
            if not guard.rate_ok(client):
                return self._send(429, {"error": {"message": "rate limit exceeded"}}, headers={"Retry-After": "60"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > cfg.max_body:
                return self._send(413, {"error": {"message": f"body must be <= {cfg.max_body} bytes"}})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._send(400, {"error": {"message": "invalid JSON"}})
            status, resp, extra = guard.process(body, client, self.headers.get("Authorization"))
            if status == 200 and body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                self.close_connection = True
                try:
                    for chunk in _sse_chunks(resp):
                        self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                return
            self._send(status, resp, headers=extra)

    return Handler


def serve(guard: Guard, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), make_handler(guard))
    srv.daemon_threads = True
    return srv
