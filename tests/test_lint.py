from pathlib import Path
from dac.validate import lint, ROOT


def test_all_rules_lint_clean():
    seen = {}
    for p in sorted((ROOT / "rules").rglob("*.yml")):
        _, errs = lint(p, seen)
        assert not errs, f"{p.name}: {errs}"


def test_linter_catches_bad_rule(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("title: x\nid: not-a-uuid\nlevel: urgent\ntags: [attack.execution]\ndetection: {sel: {a: 1}, condition: 'sel and missing | count() > 5'}\n")
    _, errs = lint(p, {})
    joined = " ".join(errs)
    for want in ("id not a UUID", "bad level", "technique tag", "unknown selection 'missing'", "aggregation", "missing tests/samples"):
        assert want in joined
