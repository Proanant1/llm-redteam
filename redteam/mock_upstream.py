"""A fake OpenAI-compatible server backed by the simulator, so you can try the guard with zero setup.
It is deliberately gullible: it leaks the secret in the system prompt when it sees an injection."""
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .providers import MockProvider


def make_server(host: str = "127.0.0.1", port: int = 9000, level: str = "vulnerable") -> ThreadingHTTPServer:
    prov = MockProvider(level, seed=7)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send({"object": "list", "data": [{"id": "mock-model", "object": "model"}]})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            text = prov.chat(body.get("messages", []))
            self._send({"id": "chatcmpl-mock", "object": "chat.completion", "created": int(time.time()),
                        "model": body.get("model", "mock-model"),
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                     "finish_reason": "stop"}]})

    srv = ThreadingHTTPServer((host, port), H)
    srv.daemon_threads = True
    return srv
