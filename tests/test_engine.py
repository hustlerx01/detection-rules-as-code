import pytest
from dac.engine import evaluate
from dac.runtests import run

R = {"detection": {"sel": {"Image|endswith": "\\cmd.exe", "CommandLine|contains|all": ["/c", "whoami"]},
                   "filter": {"User": "SYSTEM"}, "condition": "sel and not filter"}}


def test_modifiers_and_not():
    assert evaluate(R, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami", "User": "bob"})
    assert not evaluate(R, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami", "User": "SYSTEM"})
    assert not evaluate(R, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c dir", "User": "bob"})


def test_one_of_and_case_insensitive():
    r = {"detection": {"s1": {"a": "X"}, "s2": {"b|startswith": "pre"}, "condition": "1 of s*"}}
    assert evaluate(r, {"b": "PREfix"}) and not evaluate(r, {"a": "y"})


def test_wildcards_and_lists():
    r = {"detection": {"s": {"EventID": [4720, 4732], "TargetUserName": "*$"}, "condition": "s"}}
    assert evaluate(r, {"EventID": 4720, "TargetUserName": "FAKE$"}) and not evaluate(r, {"EventID": 4720, "TargetUserName": "bob"})


def test_bad_condition_raises():
    with pytest.raises(Exception):
        evaluate({"detection": {"s": {"a": 1}, "condition": "s and"}}, {"a": 1})


@pytest.mark.parametrize("row", run(), ids=lambda r: r[0])
def test_every_rule_hits_tp_and_not_fp(row):
    name, _, _, res, ok = row
    assert ok, f"{name}: {res}"
