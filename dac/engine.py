"""Minimal Sigma evaluator for testing rules against JSON log events.
Supports: field|contains|startswith|endswith|re|all modifiers, lists (OR),
keyword lists, conditions with and/or/not/parentheses, '1 of x*', 'all of x*', '1 of them'.
Not supported (by design): aggregations/correlations, |base64offset, |cidr, |windash."""
import fnmatch, re


def _match_value(val, pattern, mods):
    if val is None:
        return False
    if isinstance(pattern, int) or isinstance(val, int):
        return str(val) == str(pattern)
    v, p = str(val), str(pattern)
    if "re" in mods:
        return re.search(p, v) is not None
    v, p = v.lower(), p.lower()
    if "contains" in mods:
        return p in v
    if "startswith" in mods:
        return v.startswith(p)
    if "endswith" in mods:
        return v.endswith(p)
    if "*" in p or "?" in p:
        return fnmatch.fnmatchcase(v, p)
    return v == p


def _match_map(event, sel):
    for key, pat in sel.items():
        field, *mods = key.split("|")
        pats = pat if isinstance(pat, list) else [pat]
        val = event.get(field)
        hits = [_match_value(val, p, mods) for p in pats]
        if not (all(hits) if "all" in mods else any(hits)):
            return False
    return True


def match_selection(event, sel):
    if isinstance(sel, dict):
        return _match_map(event, sel)
    if isinstance(sel, list):  # list of maps (OR) or keywords
        if all(isinstance(x, dict) for x in sel):
            return any(_match_map(event, x) for x in sel)
        blob = " ".join(str(v) for v in event.values()).lower()
        return any(str(k).lower() in blob for k in sel)
    raise ValueError(f"bad selection {sel!r}")


TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of \S+|\ball of \S+|[A-Za-z_][\w*]*")


def evaluate(rule, event):
    det = rule["detection"]
    names = [k for k in det if k not in ("condition", "timeframe")]
    toks = TOKEN.findall(det["condition"])
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos; pos += 1; return toks[pos - 1]

    def atom():
        t = take()
        if t == "(":
            v = expr(); assert take() == ")"; return v
        if t == "not":
            return not atom()
        if t.startswith(("1 of ", "all of ")):
            q, pat = t.split(" of ")
            pat = "*" if pat == "them" else pat
            sels = [match_selection(event, det[n]) for n in names if fnmatch.fnmatch(n, pat)]
            return any(sels) if q == "1" else (all(sels) and bool(sels))
        return match_selection(event, det[t])

    def term():
        v = atom()
        while peek() == "and":
            take(); r = atom(); v = v and r
        return v

    def expr():
        v = term()
        while peek() == "or":
            take(); r = term(); v = v or r
        return v

    out = expr()
    if pos != len(toks):
        raise ValueError(f"unparsed condition tail: {toks[pos:]}")
    return out
