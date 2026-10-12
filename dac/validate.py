"""Lint every rule: schema, unique UUIDs, ATT&CK tags, level, test samples present,
condition references, and (optional) pySigma conversion to Splunk SPL."""
import re, sys, uuid
from pathlib import Path
import yaml

REQ = ["title", "id", "status", "description", "author", "date", "tags", "logsource", "detection", "falsepositives", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUS = {"experimental", "test", "stable"}
ROOT = Path(__file__).resolve().parents[1]


def lint(path, seen_ids):
    errs = []
    r = yaml.safe_load(open(path))
    for k in REQ:
        if k not in r:
            errs.append(f"missing {k}")
    try:
        uuid.UUID(str(r.get("id")))
    except ValueError:
        errs.append("id not a UUID")
    if r.get("id") in seen_ids:
        errs.append(f"duplicate id with {seen_ids[r['id']]}")
    seen_ids[r.get("id")] = path.name
    if r.get("level") not in LEVELS: errs.append("bad level")
    if r.get("status") not in STATUS: errs.append("bad status")
    if not any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in r.get("tags", [])):
        errs.append("no attack.tXXXX technique tag")
    if not re.fullmatch(r"\d{4}[/-]\d{2}[/-]\d{2}", str(r.get("date", ""))): errs.append("bad date")
    det = r.get("detection", {})
    cond = det.get("condition", "")
    if "|" in cond.replace("1 of", "").replace("all of", ""):
        errs.append("aggregation in condition (deprecated; use correlation rules)")
    for w in re.findall(r"[A-Za-z_][\w*]*", cond):
        if w in ("and", "or", "not", "of", "them", "all"): continue
        if "*" in w:
            continue
        if w not in det: errs.append(f"condition references unknown selection '{w}'")
    stem = path.stem
    for kind in ("tp", "fp"):
        if not (ROOT / "tests/samples" / stem / f"{kind}.jsonl").exists():
            errs.append(f"missing tests/samples/{stem}/{kind}.jsonl")
    return r, errs


def convert_all(rules):
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    out, fails = {}, {}
    be = SplunkBackend()
    for p, text in rules:
        try:
            out[p.stem] = be.convert(SigmaCollection.from_yaml(text))
        except Exception as e:
            fails[p.stem] = f"{type(e).__name__}: {e}"
    return out, fails


def main():
    paths = sorted((ROOT / "rules").rglob("*.yml"))
    seen, bad = {}, 0
    for p in paths:
        _, errs = lint(p, seen)
        print(("FAIL " if errs else "ok   ") + str(p.relative_to(ROOT)) + ("  " + "; ".join(errs) if errs else ""))
        bad += bool(errs)
    try:
        spl, fails = convert_all([(p, p.read_text()) for p in paths])
        outd = ROOT / "results/splunk"; outd.mkdir(parents=True, exist_ok=True)
        for k, v in spl.items(): (outd / f"{k}.spl").write_text("\n".join(v) + "\n")
        print(f"pySigma -> Splunk: {len(spl)} converted, {len(fails)} failed")
        for k, v in fails.items(): print(f"  convert FAIL {k}: {v}"); bad += 1
    except ImportError:
        print("pySigma not installed: skipping conversion")
    print(f"{len(paths)} rules, {bad} with errors")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
