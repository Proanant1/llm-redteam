"""Command line interface:  python -m redteam <run|report|list-attacks|list-defenses> ..."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .attacks import ATTACKS, BENIGN, CATEGORIES
from .defenses import DEFENSES
from .evaluator import RunConfig, run
from .providers import ProviderError
from .report import render_html, render_markdown
from .target import DEFAULT_SYSTEM


def _write_reports(res: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(res, indent=2))
    (out / "report.md").write_text(render_markdown(res))
    (out / "report.html").write_text(render_html(res))
    print(f"\nWrote {out}/results.json, report.md, report.html", file=sys.stderr)


def cmd_run(a) -> int:
    template = Path(a.system_prompt_file).read_text() if a.system_prompt_file else DEFAULT_SYSTEM
    defenses = list(DEFENSES) if a.defenses == ["all"] else a.defenses
    cfg = RunConfig(targets=a.targets, defenses=defenses, categories=a.categories, trials=a.trials,
                    workers=a.workers, temperature=a.temperature, max_tokens=a.max_tokens,
                    seed=a.seed, system_template=template, include_benign=not a.no_benign)
    try:
        res = run(cfg)
    except (ProviderError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    _write_reports(res, Path(a.out))
    print(render_markdown(res))

    total_err = sum(c["errors"] for t in res["summary"].values() for c in t.values())
    if total_err:
        print(f"warning: {total_err} request(s) failed and were excluded from the stats", file=sys.stderr)
    if all(c["n"] == 0 for t in res["summary"].values() for c in t.values()):
        print("error: every request failed. Is the model running / API key valid?", file=sys.stderr)
        return 2

    if a.fail_above is not None:                     # CI gate
        gate = a.gate_defense or defenses[-1]
        bad = [(t, c[gate]["asr"]) for t, c in res["summary"].items()
               if gate in c and c[gate]["asr"] is not None and c[gate]["asr"] > a.fail_above]
        if bad:
            for t, v in bad:
                print(f"GATE FAILED: {t} ASR {v:.0%} > {a.fail_above:.0%} under '{gate}'", file=sys.stderr)
            return 1
    return 0


def cmd_report(a) -> int:
    res = json.loads(Path(a.results).read_text())
    _write_reports(res, Path(a.out))
    return 0


def cmd_list_attacks(_a) -> int:
    for x in ATTACKS:
        print(f"{x.id:6} {x.category:20} goal={x.goal:7} sev={x.severity}  {x.name}")
    print(f"\n{len(ATTACKS)} attacks, {len(BENIGN)} benign prompts. Categories: {', '.join(CATEGORIES)}")
    return 0


def cmd_list_defenses(_a) -> int:
    for d in DEFENSES.values():
        print(f"{d.name:16} {d.description}")
    return 0


def cmd_guard(a) -> int:
    from .guard import Guard, GuardConfig, serve
    secrets = []
    for name in a.secret_env or []:
        if os.environ.get(name):
            secrets.append(os.environ[name])
        else:
            print(f"warning: env var {name} is not set; ignoring", file=sys.stderr)
    if a.secrets_file:
        secrets += [ln.strip() for ln in Path(a.secrets_file).read_text().splitlines() if ln.strip()]
    cfg = GuardConfig(
        upstream=a.upstream, mode=a.mode, harden=a.harden, secrets=secrets,
        secret_regex=a.secret_regex or [], auto_secrets=not a.no_auto_secrets,
        allow_hosts=a.allow_host or [], strip_links=a.strip_links, rate_limit=a.rate_limit,
        max_body=a.max_body, admin_token=a.admin_token,
        upstream_key=os.environ.get(a.upstream_key_env) if a.upstream_key_env else None,
        default_model=a.default_model, log_file=a.log_file, snippets=not a.no_snippets)
    try:
        srv = serve(Guard(cfg), a.host, a.port)
    except OSError as e:
        print(f"error: cannot bind {a.host}:{a.port}: {e}", file=sys.stderr)
        return 2
    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.admin_token:
        print("warning: listening on a non-local address without --admin-token; the dashboard is open to the network",
              file=sys.stderr)
    token_q = f"?token={a.admin_token}" if a.admin_token else ""
    print(f"LLM Guard running  mode={a.mode}  harden={a.harden}\n"
          f"  proxy     http://{a.host}:{a.port}/v1   (point your app's base_url here)\n"
          f"  upstream  {a.upstream}\n"
          f"  dashboard http://{a.host}:{a.port}/{token_q}\n"
          f"  Ctrl+C to stop", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    return 0


def cmd_mock_upstream(a) -> int:
    from .mock_upstream import make_server
    srv = make_server(a.host, a.port, a.level)
    print(f"Mock upstream (gullible simulator) on http://{a.host}:{a.port}/v1 - Ctrl+C to stop", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="redteam", description="Red-team and evaluate LLM apps.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run attacks against targets and defenses")
    r.add_argument("--targets", nargs="+", default=["mock:vulnerable"],
                   help="e.g. ollama:llama3.2 groq:<model> openai:<model> anthropic:<model> mock:vulnerable")
    r.add_argument("--defenses", nargs="+", default=["none", "hardened_prompt", "layered"],
                   help=f"any of {list(DEFENSES)} or 'all'")
    r.add_argument("--categories", nargs="+", choices=CATEGORIES, default=None)
    r.add_argument("--trials", type=int, default=3)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--temperature", type=float, default=0.7)
    r.add_argument("--max-tokens", type=int, default=300)
    r.add_argument("--seed", type=int, default=1337)
    r.add_argument("--system-prompt-file", help="your own system prompt; must contain {{CANARY}}")
    r.add_argument("--no-benign", action="store_true", help="skip the utility (benign) prompts")
    r.add_argument("--out", default="results")
    r.add_argument("--fail-above", type=float, default=None, metavar="ASR",
                   help="exit 1 if ASR (0-1) under the gate defense exceeds this (for CI)")
    r.add_argument("--gate-defense", default=None, help="defense used for the gate (default: last listed)")
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="re-render reports from a results.json")
    rp.add_argument("results")
    rp.add_argument("--out", default="results")
    rp.set_defaults(fn=cmd_report)

    g = sub.add_parser("guard", help="run the live security proxy + dashboard")
    g.add_argument("--upstream", default="http://localhost:11434/v1",
                   help="OpenAI-compatible base URL (Ollama default; e.g. https://api.groq.com/openai/v1)")
    g.add_argument("--host", default="127.0.0.1")
    g.add_argument("--port", type=int, default=8787)
    g.add_argument("--mode", choices=["block", "monitor"], default="block",
                   help="monitor = log what would be blocked but never change traffic")
    g.add_argument("--harden", action="store_true", help="inject a security policy into the system prompt")
    g.add_argument("--secret-env", nargs="+", metavar="VAR", help="env vars whose values must never appear in output")
    g.add_argument("--secrets-file", help="file with one secret per line")
    g.add_argument("--secret-regex", nargs="+", metavar="REGEX", help="extra secret patterns")
    g.add_argument("--no-auto-secrets", action="store_true",
                   help="don't treat key-like tokens in the system prompt as secrets")
    g.add_argument("--allow-host", nargs="+", metavar="HOST", help="hosts allowed in answer URLs/images")
    g.add_argument("--strip-links", action="store_true", help="also strip plain links to non-allowed hosts")
    g.add_argument("--rate-limit", type=int, default=0, metavar="N", help="max requests/minute per client IP")
    g.add_argument("--max-body", type=int, default=262144)
    g.add_argument("--admin-token", default=None, help="require ?token=... for dashboard and events")
    g.add_argument("--upstream-key-env", metavar="VAR", help="env var holding the upstream API key")
    g.add_argument("--default-model", default="llama3.2", help="model used by the dashboard test box")
    g.add_argument("--log-file", default=None, help="append events as JSON lines")
    g.add_argument("--no-snippets", action="store_true", help="don't store any prompt text in events")
    g.set_defaults(fn=cmd_guard)

    m = sub.add_parser("mock-upstream", help="fake gullible OpenAI-compatible server for demos/tests")
    m.add_argument("--host", default="127.0.0.1")
    m.add_argument("--port", type=int, default=9000)
    m.add_argument("--level", choices=["vulnerable", "robust"], default="vulnerable")
    m.set_defaults(fn=cmd_mock_upstream)

    sub.add_parser("list-attacks").set_defaults(fn=cmd_list_attacks)
    sub.add_parser("list-defenses").set_defaults(fn=cmd_list_defenses)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
