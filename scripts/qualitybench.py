#!/usr/bin/env python3
"""strata-jetson: GSM8K-mini quality probe (20 fixed problems, stdlib only).

Sends each of 20 hardcoded GSM8K-style word problems to an OpenAI-compatible
/v1/chat/completions endpoint (/no_think prefix, max_tokens 512, temperature 0),
extracts the LAST number in the reply and scores it against the hardcoded gold
answer (numeric exact match) — the primary metric, objective under restating
models that echo the problem statement (their echoed numbers land first).
First-number accuracy is still extracted and recorded per item as a
DIAGNOSTIC (the old primary).  Fraction/ratio spellings ("1/2", "2:3") are
normalised to their decimal value before extraction.  Outputs accuracy + a
per-item table (JSON + MD).  --selftest pins the scoring contract offline.

Two transports:
  direct     (default) plain /v1/chat/completions against --llm-url
             -> record honestly marked "未经权限层" (bypasses the permission layer)
  bicameral  --permission-layer --control-url http://h:18100 --agent-url http://h:18101
             issues a capability token (agent-ro / llm.complete) and invokes
             through POST /agent/invoke -> "经权限层" (subject to the instance's
             llm_max_tokens cap, e.g. 64 on the running Jetson instance)

Usage:
  qualitybench.py --llm-url http://127.0.0.1:8960/v1 --model qwen3.8-27b \
      --tag bi150-27b --out results/2026-10-17-perf-depth/gsm8k-bi150-27b.json
"""
import argparse
import datetime
import json
import re
import ssl
import time
import urllib.request

# ---------------------------------------------------------------------------
# GSM8K-mini: 20 fixed problems, gold answers computed by hand and verified by
# script (scripts/__pycache__ excluded; see results README for the check).
# Coverage: 1/2-digit multiplication-addition (g1..g9,g16,g18), ratios and
# fractions (g3,g12,g17), percentages (g4,g5,g10,g19,g20).
# ---------------------------------------------------------------------------
GSM8K_MINI = [
    ("g01", "A bakery sells 24 cupcakes per tray. It bakes 5 trays in the morning and 3 trays in the afternoon. How many cupcakes does it bake in total?", 192),
    ("g02", "Tom has 4 boxes of pencils with 12 pencils in each box. He buys 15 more pencils. How many pencils does he have now?", 63),
    ("g03", "A recipe uses flour and sugar in a ratio of 2 to 3. If a baker uses 8 cups of flour, how many cups of sugar does he need?", 12),
    ("g04", "A jacket costs $80. During a sale the price is reduced by 25%. What is the sale price in dollars?", 60),
    ("g05", "A restaurant bill is $45. Sam leaves a 20% tip on top of the bill. What is the total amount he pays in dollars?", 54),
    ("g06", "A train travels at 60 kilometers per hour for 3 hours, then at 80 kilometers per hour for 2 hours. How many kilometers does it travel in total?", 340),
    ("g07", "Sara reads 15 pages every day. After 12 days she wants to know how much of her 250-page book remains. How many pages does she still have left to read?", 70),
    ("g08", "A fruit stand has 3 bags of apples. Each bag contains 8 red apples and 4 green apples. How many apples are there in total?", 36),
    ("g09", "Movie tickets cost $12 for an adult and $7 for a child. A family buys 4 adult tickets and 5 child tickets. What is the total cost in dollars?", 83),
    ("g10", "A store has 90 shirts. In one week it sells 30% of them. How many shirts did it sell?", 27),
    ("g11", "Mike saves $8 every week. After 9 weeks he buys a video game that costs $40. How many dollars does he have left?", 32),
    ("g12", "In a factory the ratio of men to women is 5 to 3. There are 24 women working there. How many men work there?", 40),
    ("g13", "A car uses 8 liters of fuel for every 100 kilometers. How many liters does it need for a trip of 450 kilometers?", 36),
    ("g14", "John runs 3 kilometers every morning. How many kilometers does he run in 14 days?", 42),
    ("g15", "A toy machine makes 45 toys per hour and runs 7 hours per day. How many toys does it make in 4 days?", 1260),
    ("g16", "A pack of 6 pens costs $9. How much do 4 packs cost in dollars?", 36),
    ("g17", "Lisa has 50 marbles. She gives one fifth of them to Ben, and then gives one quarter of her remaining marbles to Sara. How many marbles does Lisa have left?", 30),
    ("g18", "A printer prints 17 pages per minute. It runs for 6 minutes, jams, is repaired, and then prints 23 pages per minute for 4 more minutes. How many pages did it print in total?", 194),
    ("g19", "Nina deposits $200 in a bank account that pays 5% simple interest per year. What is the total amount in the account after 3 years, in dollars?", 230),
    ("g20", "A shop orders 12 boxes of candles with 25 candles in each box. 20% of the candles arrive broken and are thrown away. How many good candles remain?", 240),
]

NUM_RE = re.compile(r"-?\d[\d,]*(?:\.\d+)?")
# "a/b" (fraction) and "a:b" (ratio) spellings: normalised to the decimal
# value of a/b BEFORE extraction, so a reply like "the answer is 1/2" scores
# as 0.5 instead of 1 (or 2). Division by zero is left untouched.
FRAC_RE = re.compile(
    r"(-?\d[\d,]*(?:\.\d+)?)\s*([/:])\s*(-?\d[\d,]*(?:\.\d+)?)")


def normalize_frac(text):
    """Substitute every "a/b" / "a:b" occurrence with its decimal quotient
    ("1/2" -> "0.5", "2:3" -> "0.666666666667"). Pure; selftest-pinned."""
    def repl(m):
        try:
            num = float(m.group(1).replace(",", ""))
            den = float(m.group(3).replace(",", ""))
        except ValueError:
            return m.group(0)
        if den == 0:
            return m.group(0)
        return "%.12g" % (num / den)
    return FRAC_RE.sub(repl, text or "")


def extract_first_number(text):
    """Diagnostic metric: the first number in the reply (the old primary —
    under restating models it usually lands on an echoed problem digit)."""
    m = NUM_RE.search(normalize_frac(text))
    if not m:
        return None
    try:
        return float(m.group(0).replace(",", ""))
    except ValueError:
        return None


def extract_last_number(text):
    """PRIMARY metric: the last number in the reply. Restating models put
    the final answer last; the echoed problem digits all precede it."""
    ms = list(NUM_RE.finditer(normalize_frac(text)))
    if not ms:
        return None
    try:
        return float(ms[-1].group(0).replace(",", ""))
    except ValueError:
        return None


def chat_completion(base_url, model, prompt, max_tokens, timeout):
    url = base_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url = url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    ctx = ssl._create_unverified_context()  # noqa: SLF001 - local endpoints only
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        payload = json.loads(r.read().decode())
    dt = time.perf_counter() - t0
    msg = (payload.get("choices") or [{}])[0].get("message", {})
    usage = payload.get("usage") or {}
    return {
        "content": msg.get("content") or "",
        "reasoning_content": msg.get("reasoning_content") or "",
        "latency_s": dt,
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "finish_reason": (payload.get("choices") or [{}])[0].get("finish_reason"),
    }


class BicameralClient:
    """Permission-layer transport: /issue on the control plane, /agent/invoke
    on the agent plane with the capability token (open control instance)."""

    def __init__(self, control_url, agent_url, task_id, max_tokens, timeout):
        self.control_url = control_url.rstrip("/")
        self.agent_url = agent_url.rstrip("/")
        self.task_id = task_id
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.token = None
        self.issue = None
        self.max_tokens_effective = None

    def _post(self, url, body, headers=None):
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **(headers or {})})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def issue_token(self):
        self.issue = self._post(self.control_url + "/issue", {
            "agent": "agent-ro",
            "task_id": self.task_id,
            "tools": ["llm.complete"],
            "ttl_s": 3600,
            "budget": {"max_calls": 40, "max_llm_calls": 40},
        })
        self.token = self.issue["token"]
        return self.issue

    def complete(self, prompt):
        nonce = "q-%d" % time.time_ns()
        res = self._post(self.agent_url + "/agent/invoke", {
            "nonce": nonce,
            "tool": "llm.complete",
            "params": {"prompt": prompt, "max_tokens": self.max_tokens},
        }, headers={"X-Capability-Token": self.token})
        out = res.get("result") or {}
        text = out.get("content")
        if text is None and isinstance(out, dict):
            text = out.get("content_summary") or out.get("text")
        usage = out.get("usage") or {}
        return {
            "content": text if isinstance(text, str) else json.dumps(out)[:2000],
            "reasoning_content": "",
            "latency_s": None,
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "finish_reason": res.get("reason_code") or ("ok" if res.get("ok") else "deny"),
            "envelope": {k: res[k] for k in ("ok", "reason_code", "tool", "audit_ref")
                         if k in res},
        }


def score(items, client, timeout):
    rows = []
    for qid, question, gold in items:
        prompt = "/no_think " + question + " Answer with only the final numeric result."
        try:
            r = client.complete(prompt)
            err = None
        except Exception as e:  # noqa: BLE001 - record the failure, keep going
            r, err = {"content": "", "reasoning_content": "", "latency_s": None,
                      "prompt_tokens": None, "completion_tokens": None,
                      "finish_reason": "exception"}, repr(e)
        # PRIMARY: last number (robust under restating models); the
        # first number is kept per item as a diagnostic (old primary).
        got = extract_last_number(r["content"])
        ok = got is not None and abs(got - float(gold)) < 1e-6
        got_first = extract_first_number(r["content"])
        ok_first = got_first is not None and abs(got_first - float(gold)) < 1e-6
        rows.append({
            "id": qid, "gold": gold, "extracted": got, "correct": bool(ok),
            "extracted_first": got_first, "correct_first": bool(ok_first),
            "latency_s": r.get("latency_s"),
            "completion_tokens": r.get("completion_tokens"),
            "finish_reason": r.get("finish_reason"),
            "error": err,
            "content_preview": (r.get("content") or "")[:300],
        })
        print("  %s gold=%s got=%s %s (first=%s %s)"
              % (qid, gold, got, "OK" if ok else "WRONG", got_first,
                 "ok" if ok_first else "diag-wrong"), flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm-url", default="http://127.0.0.1:8960/v1")
    ap.add_argument("--model", default="")
    ap.add_argument("--max-tokens", type=int, default=512)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--tag", default="gsm8k-mini")
    ap.add_argument("--out", default=None,
                    help="output JSON path (.md written alongside)")
    ap.add_argument("--permission-layer", action="store_true",
                    help="route through the bicameral permission layer instead of direct")
    ap.add_argument("--control-url", default="http://127.0.0.1:18100")
    ap.add_argument("--agent-url", default="http://127.0.0.1:18101")
    ap.add_argument("--selftest", action="store_true",
                    help="run the offline scoring self-test (no network) and exit")
    args = ap.parse_args()

    if args.selftest:
        return cmd_selftest()
    if not args.out:
        ap.error("--out is required (or use --selftest)")

    if args.permission_layer:
        client = BicameralClient(args.control_url, args.agent_url,
                                 "gsm8k-mini-" + args.tag, args.max_tokens,
                                 args.timeout)
        issue = client.issue_token()
        transport = "bicameral permission layer (经权限层: /issue -> /agent/invoke llm.complete)"
        model_id = issue.get("agent", "agent-ro")
        notes = ["issued jti=%s budget=%s" % (issue.get("jti"), issue.get("budget")),
                 "instance llm_max_tokens cap applies (server LIMITS['llm_max_tokens'], "
                 "default 64); requested max_tokens=%d may be clamped" % args.max_tokens]
    else:
        client = _DirectClient(args.llm_url, args.model, args.max_tokens,
                               args.timeout)
        transport = "direct /v1/chat/completions (未经权限层, bypasses permission layer)"
        model_id = args.model
        notes = []

    print("scoring %d items against %s (%s)" % (len(GSM8K_MINI), args.tag, transport))
    rows = score(GSM8K_MINI, client, args.timeout)
    n_ok = sum(1 for r in rows if r["correct"])
    n_ok_first = sum(1 for r in rows if r["correct_first"])
    rec = {
        "schema": "quality/1",
        "suite": "GSM8K-mini (20 fixed problems, hardcoded gold answers)",
        "tag": args.tag,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "transport": transport,
        "protocol": {"/no_think prefix": True, "max_tokens": args.max_tokens,
                     "temperature": 0,
                     "scoring": "LAST number in reply vs gold, numeric exact "
                                "match (primary; robust under restating "
                                "models — echoed problem digits land first); "
                                "fraction/ratio spellings (a/b, a:b) "
                                "normalised to their decimal value first; "
                                "first-number accuracy recorded per item as "
                                "a diagnostic (the old primary)"},
        "target": {"llm_url": args.llm_url if not args.permission_layer else args.agent_url,
                   "model": model_id},
        "accuracy": n_ok / len(rows),
        "n_correct": n_ok,
        "n_total": len(rows),
        "accuracy_first_number": n_ok_first / len(rows),
        "n_correct_first_number": n_ok_first,
        "per_item": rows,
        "notes": notes,
    }
    with open(args.out, "w") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)

    md = args.out[:-5] + ".md" if args.out.endswith(".json") else args.out + ".md"
    with open(md, "w") as f:
        f.write("# GSM8K-mini — %s\n\n" % args.tag)
        f.write("- transport: %s\n- accuracy (last number, primary): **%d/%d = %.1f%%**\n"
                % (transport, n_ok, len(rows), 100.0 * n_ok / len(rows)))
        f.write("- accuracy (first number, diagnostic): %d/%d = %.1f%%\n\n"
                % (n_ok_first, len(rows), 100.0 * n_ok_first / len(rows)))
        f.write("| id | gold | last# (primary) | ok | first# | ok_first | finish | preview |\n"
                "|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            prev = (r["content_preview"] or "").replace("|", "\\|").replace("\n", " ")[:80]
            f.write("| %s | %s | %s | %s | %s | %s | %s | %s |\n" %
                    (r["id"], r["gold"], r["extracted"],
                     "Y" if r["correct"] else "N", r["extracted_first"],
                     "Y" if r["correct_first"] else "N", r["finish_reason"], prev))
    print("accuracy: %d/%d = %.1f%% -> %s" % (n_ok, len(rows),
                                              100.0 * n_ok / len(rows), args.out))
    return 0


class _StubClient:
    """Offline transport for the selftest fixture: canned replies, prompts
    captured. Never touches the network."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        i = len(self.prompts) - 1
        return {"content": self.replies[min(i, len(self.replies) - 1)],
                "reasoning_content": "", "latency_s": 0.0,
                "prompt_tokens": 1, "completion_tokens": 1,
                "finish_reason": "stop"}


def cmd_selftest() -> int:
    """Offline scoring contract: restating replies score via the LAST
    number (primary); fraction/ratio spellings normalise before
    extraction; the first number survives as a diagnostic."""
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    # --- fraction / ratio normalisation before extraction --- #
    check("norm.one_half_is_decimal",
          normalize_frac("one fifth: 1/2 of them") == "one fifth: 0.5 of them",
          repr(normalize_frac("one fifth: 1/2 of them")))
    check("norm.extract_half", extract_first_number("the answer is 1/2") == 0.5
          and extract_last_number("the answer is 1/2") == 0.5)
    check("norm.extract_ratio_two_three",
          abs(extract_last_number("the ratio 2:3 gives 0.666666666667") - 0.666666666667) < 1e-9)
    check("norm.ratio_last_number_extraction",
          abs(extract_last_number("sugar/flour is 3/2, so 12 cups") - 12.0) < 1e-9,
          repr(extract_last_number("sugar/flour is 3/2, so 12 cups")))
    check("norm.division_by_zero_untouched",
          extract_first_number("it is 10/0 cases") == 10.0
          and extract_last_number("it is 10/0 cases") == 0.0)
    check("norm.thousands_commas_kept",
          extract_last_number("it costs 1,260 dollars") == 1260.0)
    check("norm.plain_text_untouched",
          normalize_frac("24 x 8 = 192") == "24 x 8 = 192")

    # --- primary = LAST number: the restating-model fixture --- #
    restate_g01 = ("A bakery sells 24 cupcakes per tray. It bakes 5 trays in "
                   "the morning and 3 trays in the afternoon, so 24 times 8. "
                   "The bakery bakes 192 cupcakes in total.")
    check("score.restatement_primary_last_number",
          extract_last_number(restate_g01) == 192.0
          and extract_first_number(restate_g01) == 24.0)
    check("score.answer_only_still_correct",
          extract_last_number("192") == 192.0
          and extract_first_number("192") == 192.0)

    # --- end-to-end fixture through score() with the stub transport --- #
    items = GSM8K_MINI[:3]                      # g01 gold 192, g02 gold 63, g03 gold 12
    stub = _StubClient([
        restate_g01,                            # restates; answer last -> primary OK
        "Tom has 48 pencils, buys 15 more, so he has 63 pencils now.",   # answer last
        "The recipe uses flour and sugar in a ratio of 2 to 3. "         # fraction answer
        "8 cups of flour means 8x3/2 = 12 cups of sugar.",
    ])
    rows = score(items, stub, 5)
    check("score.fixture_restating_model_all_correct",
          [r["correct"] for r in rows] == [True, True, True]
          and all(r["correct"] for r in rows),
          str([(r["id"], r["extracted"]) for r in rows]))
    check("score.fixture_first_number_diagnostic_degrades",
          [r["correct_first"] for r in rows] == [False, False, False],
          str([(r["id"], r["extracted_first"]) for r in rows]))
    check("score.fixture_prompt_shape",
          all(p.startswith("/no_think ") and p.endswith(
              "Answer with only the final numeric result.") for p in stub.prompts))
    # a wrong LAST number must stay wrong under the primary metric
    rows2 = score(items[:1], _StubClient(
        ["24 per tray, 8 trays, so 24 x 8. The bakery bakes 100 cupcakes in total."]), 5)
    check("score.fixture_wrong_last_number_is_wrong",
          rows2[0]["correct"] is False and rows2[0]["extracted"] == 100.0)

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


class _DirectClient:
    """chat.completions transport (direct, no permission layer)."""

    def __init__(self, base_url, model, max_tokens, timeout):
        self.base_url, self.model = base_url, model
        self.max_tokens, self.timeout = max_tokens, timeout

    def complete(self, prompt):
        return chat_completion(self.base_url, self.model, prompt,
                               self.max_tokens, self.timeout)


if __name__ == "__main__":
    main()
