"""Runs the (target x defense x attack x trial) matrix and computes the scorecard numbers."""
from __future__ import annotations

import math
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .attacks import ATTACKS, BENIGN, judge
from .context import make_ctx
from .defenses import BLOCK_REPLY, DEFENSES, filter_output
from .providers import ProviderError, make_provider
from .target import DEFAULT_SYSTEM, prepare


@dataclass
class RunConfig:
    targets: list[str]
    defenses: list[str]
    categories: list[str] | None = None
    trials: int = 3
    workers: int = 4
    temperature: float = 0.7
    max_tokens: int = 300
    seed: int = 1337
    system_template: str = DEFAULT_SYSTEM
    include_benign: bool = True


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - m) / d), min(1.0, (c + m) / d)


def _one(provider, defense, kind, item, trial, ctx, cfg: RunConfig) -> dict:
    rec = {"target": provider.spec, "defense": defense.name, "kind": kind, "id": item.id,
           "trial": trial, "stage": None, "error": None, "output": "", "latency": 0.0}
    if kind == "attack":
        rec.update(category=item.category, goal=item.goal, severity=item.severity)
        ai = item.build(ctx)
        user, doc, history = ai.user, ai.doc, ai.history
    else:
        user, doc, history = item.user, item.doc, []
    t0 = time.time()
    try:
        prep = prepare(cfg.system_template, ctx, defense, user, doc, history)
        if prep.messages is None:
            output, rec["stage"], rec["reason"] = BLOCK_REPLY, "input_filter", prep.blocked_reason
        else:
            output = provider.chat(prep.messages, cfg.temperature, cfg.max_tokens)
            if defense.output_filter:
                output, why = filter_output(output, ctx)
                if why:
                    rec["stage"], rec["reason"] = "output_filter", why
    except ProviderError as e:
        rec["error"] = str(e)
        return rec
    rec["latency"] = time.time() - t0
    rec["output"] = output
    if rec["stage"] is None and output.strip() == BLOCK_REPLY:       # a live guard in front of the target refused
        rec["stage"], rec["reason"] = "external_guard", "refusal from upstream guard"
    if kind == "attack":
        rec["success"], rec["judge"] = judge(item.goal, output, ctx)
    else:
        blocked = rec["stage"] is not None
        ok = (not blocked) and (item.expect is None or bool(re.search(item.expect, output, re.I)))
        rec["success"], rec["judge"] = ok, ("blocked" if blocked else ("ok" if ok else "missing expected content"))
    return rec


def run(cfg: RunConfig, quiet: bool = False) -> dict:
    unknown = [d for d in cfg.defenses if d not in DEFENSES]
    if unknown:
        raise ValueError(f"Unknown defense(s): {unknown}. Available: {list(DEFENSES)}")
    attacks = [a for a in ATTACKS if not cfg.categories or a.category in cfg.categories]
    if not attacks:
        raise ValueError("No attacks selected (check --categories).")
    if "{{CANARY}}" not in cfg.system_template:
        raise ValueError("system prompt must contain {{CANARY}} so leaks can be measured")
    providers = {s: make_provider(s, cfg.seed) for s in cfg.targets}
    ctx = make_ctx(cfg.seed)

    jobs = []
    for spec, prov in providers.items():
        for dname in cfg.defenses:
            d = DEFENSES[dname]
            for a in attacks:
                for t in range(cfg.trials):
                    jobs.append((prov, d, "attack", a, t))
            if cfg.include_benign:
                for b in BENIGN:
                    for t in range(cfg.trials):
                        jobs.append((prov, d, "benign", b, t))

    records: list[dict] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as ex:
        futs = [ex.submit(_one, p, d, k, it, t, ctx, cfg) for p, d, k, it, t in jobs]
        for f in as_completed(futs):
            records.append(f.result())
            done += 1
            if not quiet and (done % max(1, len(jobs) // 10) == 0 or done == len(jobs)):
                print(f"  progress: {done}/{len(jobs)}", file=sys.stderr)

    records.sort(key=lambda r: (r["target"], cfg.defenses.index(r["defense"]), r["kind"], r["id"], r["trial"]))
    return {
        "meta": {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "seed": cfg.seed, "trials": cfg.trials, "temperature": cfg.temperature,
                 "targets": cfg.targets, "defenses": cfg.defenses,
                 "n_attacks": len(attacks), "n_benign": len(BENIGN) if cfg.include_benign else 0},
        "summary": summarize(records, cfg.defenses),
        "trials": records,
    }


def summarize(records: list[dict], defense_order: list[str]) -> dict:
    out: dict = {}
    targets = sorted({r["target"] for r in records})
    for t in targets:
        out[t] = {}
        for d in defense_order:
            rs = [r for r in records if r["target"] == t and r["defense"] == d]
            att = [r for r in rs if r["kind"] == "attack" and not r["error"]]
            ben = [r for r in rs if r["kind"] == "benign" and not r["error"]]
            k, n = sum(r["success"] for r in att), len(att)
            lo, hi = wilson(k, n)
            cats, atks = {}, {}
            for r in att:
                for bucket, key in ((cats, r["category"]), (atks, r["id"])):
                    b = bucket.setdefault(key, {"k": 0, "n": 0})
                    b["n"] += 1
                    b["k"] += r["success"]
            for bucket in (cats, atks):
                for b in bucket.values():
                    b["asr"] = b["k"] / b["n"]
            out[t][d] = {
                "n": n, "k": k, "asr": (k / n) if n else None, "ci_lo": lo, "ci_hi": hi,
                "filtered": (sum(r["stage"] is not None for r in att) / n) if n else None,
                "utility": (sum(r["success"] for r in ben) / len(ben)) if ben else None,
                "utility_n": len(ben),
                "latency": (sum(r["latency"] for r in att) / n) if n else None,
                "errors": sum(1 for r in rs if r["error"]),
                "categories": cats, "attacks": atks,
            }
    return out
