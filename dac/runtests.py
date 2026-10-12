"""For every rule: all tp.jsonl events must match, no fp.jsonl event may match. Prints a coverage table."""
import json, sys
from pathlib import Path
import yaml
from .engine import evaluate

ROOT = Path(__file__).resolve().parents[1]


def run():
    rows = []
    for p in sorted((ROOT / "rules").rglob("*.yml")):
        r = yaml.safe_load(open(p))
        res = {}
        for kind in ("tp", "fp"):
            evs = [json.loads(l) for l in open(ROOT / "tests/samples" / p.stem / f"{kind}.jsonl") if l.strip()]
            res[kind] = (sum(evaluate(r, e) for e in evs), len(evs))
        ok = res["tp"][0] == res["tp"][1] and res["fp"][0] == 0
        rows.append((p.stem, r["level"], [t for t in r["tags"] if t.startswith("attack.t")], res, ok))
    return rows


def main():
    rows = run()
    print(f"{'rule':45s} {'level':8s} {'TP hit':8s} {'FP hit':8s} result")
    for n, lvl, tags, res, ok in rows:
        print(f"{n:45s} {lvl:8s} {res['tp'][0]}/{res['tp'][1]:<6} {res['fp'][0]}/{res['fp'][1]:<6} {'PASS' if ok else 'FAIL'}  {','.join(tags)}")
    bad = sum(not r[-1] for r in rows)
    print(f"{len(rows)} rules, {bad} failing")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
