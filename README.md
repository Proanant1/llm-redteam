# llm-redteam

A small, **zero-dependency** (Python 3.9+, standard library only) red-team and evaluation harness for LLM applications.
It attacks a realistic target app (a support bot with a planted secret and fake customer PII), measures how often
each attack succeeds, tests defenses, and reports **before/after numbers with confidence intervals and a utility cost**.

> Only run this against models and apps you own or are authorised to test. Every attack has a harmless,
> machine-checkable goal (leak a random canary, emit a marker, put the canary in a URL on a non-resolving domain).
> Nothing asks a model to produce harmful content.

## What it measures

| Metric | Meaning |
|---|---|
| **ASR** | Attack success rate = successful attack trials / total, with a 95% Wilson interval |
| **vs. none** | ASR change relative to the undefended baseline |
| **Stopped by filter** | Share of attacks blocked by the input/output filter before reaching the user |
| **Utility** | Share of benign prompts answered correctly and *not* blocked (includes 2 prompts that look like attacks, to expose over-blocking) |
| **Latency** | Mean time per attack trial |

**Attack library (30 attacks, 7 categories):** direct injection, system-prompt extraction, obfuscation (base64, ROT13,
leetspeak, letter spacing, payload splitting), role-play, indirect injection via retrieved documents, data exfiltration
(markdown-image beacons, links carrying PII), forged history / many-shot priming.

**Defenses under test:** `none`, `hardened_prompt` (policy block + untrusted-data delimiters + reminder), `input_filter`
(heuristic scanner, de-obfuscation aware, rejects client-supplied assistant turns), `output_filter` (canary and URL
redaction), `layered` (all together).

## Live guard (real time)

`redteam guard` is a **running security proxy** with a **live dashboard**. It speaks the OpenAI API, so you point any
app, SDK or agent at it by changing one `base_url`. It sits in front of Ollama, Groq, OpenAI, vLLM, LM Studio, or
anything OpenAI-compatible.

```
your app  -->  Guard :8787  -->  your model (Ollama / Groq / OpenAI / ...)
                  |
                  +--> live dashboard + events.jsonl
```

**Per request it:**
1. Scans `user` and `tool` messages for injection (instruction-override, extraction, fake delimiters, base64/ROT13/leetspeak/spaced text, image-exfil). Tool output is where indirect injection arrives, so agents are covered.
2. Optionally hardens the system prompt (`--harden`) and wraps tool output as untrusted data.
3. Calls the upstream model.
4. Scans the answer: secrets (yours, built-in key patterns, and key-like tokens auto-detected in the system prompt, including spelled-out/reversed forms), **system-prompt leaks** (long verbatim overlap), and **exfiltration URLs/images** (removed, with PII/secret-carrying links stripped). It also checks tool-call arguments for secrets.
5. Emits an event to the dashboard (Server-Sent Events) and an optional JSONL log.

```bash
# Try it with zero setup (fake gullible model + guard + dashboard)
python -m redteam mock-upstream --port 9000 &
python -m redteam guard --upstream http://127.0.0.1:9000/v1 --default-model mock-model
# open http://127.0.0.1:8787  -> use the "Try it" box and watch events stream in live

# Real use with a local model
python -m redteam guard --upstream http://localhost:11434/v1 --default-model llama3.2 --log-file events.jsonl

# Real use with a hosted API (key passes through, never logged)
export GROQ_API_KEY=...
python -m redteam guard --upstream https://api.groq.com/openai/v1 --upstream-key-env GROQ_API_KEY \
    --secret-env MY_INTERNAL_TOKEN --allow-host mycompany.com --harden
```
Then in your app: `OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="...")`.

| Flag | Purpose |
|---|---|
| `--mode monitor` | **Roll out safely:** log what *would* be blocked without touching traffic. Switch to `block` once the false-positive rate looks acceptable |
| `--secret-env VAR` / `--secrets-file` / `--secret-regex` | Values/patterns that must never leave the model |
| `--allow-host`, `--strip-links` | Control which URLs/images may appear in answers |
| `--rate-limit N`, `--max-body` | Per-IP requests/minute, request size cap |
| `--admin-token T` | Require `?token=T` for dashboard/events (use whenever you bind beyond localhost) |
| `--no-snippets` | Store no prompt text in events/logs |

Blocked requests return a normal `200` with a polite refusal and the header `X-Guard-Action: blocked`, so client apps don't break.
Streaming (`stream=true`) is supported by scanning the complete answer first, then replaying it as SSE chunks
(this is what makes output blocking possible, at the cost of time-to-first-token).

### Measure the live guard with the harness

```bash
export COMPAT_BASE_URL=http://127.0.0.1:8787/v1       # point the harness at the guard
python -m redteam run --targets compat:llama3.2 --defenses none --trials 5
```
Run it once against the model directly and once through the guard to get your before/after table. On the bundled simulator
(wiring check only, not a finding) attacks drop from 79% to 5%, **and utility drops from 100% to 75%** because the
heuristic filter over-blocks two benign prompts that look like attacks. That trade-off is exactly what the report is for.
The remaining misses (a task-hijack suffix, an HTML-comment injection) are real examples of what pattern filters cannot see.

**Security notes:** binds to `127.0.0.1` by default; the dashboard renders all attacker-controlled text via `textContent`
and is served with a strict CSP; upstream errors are not echoed to clients; API keys are never stored or logged.
**Limits:** this is defense in depth, not a guarantee. Heuristics miss paraphrased and novel attacks. Prompt-leak detection
catches verbatim copying, not translation or paraphrase. Keep secrets out of prompts and enforce authorization outside the model.

## Quick start

```bash
# 1. Verify the pipeline offline (simulator, no keys, no network)
python -m unittest discover -s tests -v
python -m redteam run --targets mock:vulnerable --defenses all --workers 1

# 2. Free, local, real model (install Ollama, then: ollama pull llama3.2)
python -m redteam run --targets ollama:llama3.2 --defenses none hardened_prompt layered --trials 5

# 3. Compare several models (bring your own keys via environment variables)
export GROQ_API_KEY=...        # free tier available
export GEMINI_API_KEY=...      # free tier available
python -m redteam run --targets ollama:llama3.2 groq:<model> gemini:<model> --defenses all --trials 5

# 4. Re-render reports later, list what's available
python -m redteam report results/results.json
python -m redteam list-attacks
python -m redteam list-defenses
```

Outputs go to `results/`: `report.html` (self-contained scorecard with per-attack heatmap), `report.md`, and
`results.json` (every prompt, output and verdict, for audit).

**Important:** the `mock:` targets are a simulator whose "vulnerability" is a weighted coin flip. They exist to test the
tooling. **Never publish mock numbers as findings.** Report results from real models only.

### Supported targets

| Spec | Notes |
|---|---|
| `ollama:<model>` | Local and free. `OLLAMA_HOST` to change the address |
| `groq:<model>`, `gemini:<model>`, `openrouter:<model>` | Free tiers or free models exist; limits change, check current terms |
| `openai:<model>`, `anthropic:<model>` | Paid; `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` |
| `compat:<model>` | Any OpenAI-compatible server (`COMPAT_BASE_URL`, `COMPAT_API_KEY`), e.g. vLLM, LM Studio |

Keys are read from environment variables only. They are never written to disk, logged, or put in error messages.

### Test your own app's system prompt

```bash
python -m redteam run --targets ollama:llama3.2 --system-prompt-file my_prompt.txt
```

Your prompt must contain `{{CANARY}}` (a fake secret placed where your real secrets would be) and may use
`{{CUSTOMER}}` for fake PII. Leak, marker and exfiltration checks all work unchanged.

## CI gate (fail the build if defenses regress)

```bash
python -m redteam run --targets ollama:llama3.2 --defenses none layered \
    --trials 5 --fail-above 0.10 --gate-defense layered   # exit 1 if layered ASR > 10%
```

See `.github/workflows/redteam.yml`. The default workflow runs the offline tests and the simulator, so it costs $0
and needs no secrets. To gate on a real model, add a self-hosted runner with Ollama or an API-key secret.

## Extending it

- **New attack:** append an `Attack(...)` to `ATTACKS` in `redteam/attacks.py`. Pick a goal (`leak`, `marker`, `exfil`).
- **New defense:** add a `Defense(...)` flag in `defenses.py` and apply it in `target.prepare` / the evaluator
  (for example a trained classifier, an LLM-as-judge guard, or tool-permission checks).
- **New judge goal:** extend `judge()` in `attacks.py`.
- **Your real app over HTTP:** add a provider class with a `chat(messages, temperature, max_tokens)` method
  in `providers.py` that calls your endpoint, then register it in `make_provider`.

## Method and honest limitations

- Fixed public attack set, so a defense can overfit to it. Add private attacks for real assessments.
- Single-turn attacks plus scripted history. No adaptive, multi-turn attacker yet (good next step: an attacker LLM
  that iterates against the target, like PAIR/TAP-style methods).
- Keyword and canary judges are objective but can miss paraphrased or partial leaks (the judge catches spelled-out
  and reversed canaries, not every transformation).
- Trials of one attack are repeated samples, not independent attacks, so intervals show sampling noise, not coverage.
- Heuristic filters are intentionally simple. The report shows both their catch rate and their over-blocking cost.
- Results are specific to this target prompt, these models and this temperature.

## Suggested workflow for a portfolio write-up

1. Pick 3 models (one local, two free-tier). Run `--defenses all --trials 5` or more.
2. Read `report.html`, then open `results.json` and study the attacks that still succeed under `layered`.
3. Write a threat model (assets, attacker, trust boundaries, out of scope), then explain *why* each residual
   attack works and what architectural fix (privilege separation, no secrets in prompts, tool allow-lists) would remove it.
4. Add 5-10 attacks of your own, re-run, and report before/after tables with intervals and the utility cost.
5. Open a PR or issue to a related open-source project (garak, promptfoo, PyRIT) with something you learned.
