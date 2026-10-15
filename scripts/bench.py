#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral throughput/latency benchmark against a RUNNING instance.

Closes the README section 6 boundary "Throughput is unmeasured": measures req/s
and p50/p95/p99 latency of permission-layer tool calls at several concurrency
levels, plus a separate average-decode stat for llm.complete levels. Standard
library only; the script touches nothing except --base and --agent.

Per concurrency level:
    1. warm-up (unrecorded): one probe call, then a short measured burst to
       estimate achievable qps at that concurrency (llm: probe call only).
    2. pre-issue agent-ro tokens sized `duration x est_qps x 2` with canonical
       budget keys (calls / llm_calls / bytes). The server clamps every token
       to BUDGET_CAPS, so enough tokens are pre-issued — with per-token client
       budget accounting — that the level never starves; on-demand refill
       covers any estimation error.
    3. N worker threads loop until the deadline: pick a random pre-written
       4 KiB file and fs.read it through POST /agent/invoke (full deny-chain),
       recording every latency. Errors = non-2xx responses + transport
       failures (breakdown in the JSON).

For kind=llm the loop calls llm.complete instead; decode tok/s is completion
tokens / full round-trip (the layer only sees OpenAI `usage`).

Usage:
    python3 scripts/bench.py --admin-token $TOKEN \
        --concurrency 1,4,16 --duration 15 --kind fs \
        --out results/2026-10-16-bench-throughput
    python3 scripts/bench.py --selftest    # pure functions only, no instance
"""

import argparse
import http.client
import json
import math
import os
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

FILE_BYTES = 4096               # == server LIMITS["file_read"]: reads untruncated
DEFAULT_OUT = "results/2026-10-16-bench-throughput"
DEFAULT_LLM_PROMPT = "Reply with exactly: ok"
LLM_PROMPT_MAX = 8 * 1024       # server llm_prompt limit; over it -> D9 413
MAX_TOKENS_PER_THREAD = 64      # pre-issue cap per thread; refill covers more
TOKEN_WARN_TOTAL = 800          # server nonce table caps at 1024 live jtis


def fail(msg):
    sys.exit("bench: " + msg)


# --------------------------------------------------------------------------- #
# pure functions (covered by --selftest; no I/O, no clocks, no network)
# --------------------------------------------------------------------------- #

def percentile(sorted_values, pct):
    """Nearest-rank percentile of an ASCENDING list. Empty input raises."""
    if not sorted_values:
        raise ValueError("percentile of empty list")
    if not 0.0 <= pct <= 100.0:
        raise ValueError("pct out of range: %r" % (pct,))
    n = len(sorted_values)
    idx = min(n - 1, max(0, math.ceil(pct / 100.0 * n) - 1))
    return sorted_values[idx]


def token_budget(duration_s, est_qps, bytes_per_call, llm=False):
    """Budget for one level (canonical keys): calls = duration x est_qps x 2.

    bytes_per_call is the server's own debit unit (fs.read: constant 4096;
    llm.complete: prompt length). llm=True also grants llm_calls, else 0.
    """
    calls = max(1, int(math.ceil(float(duration_s) * float(est_qps) * 2.0)))
    return {
        "calls": calls,
        "llm_calls": calls if llm else 0,
        "bytes": calls * int(bytes_per_call),
    }


def plan_tokens(needed, clamped, cap=MAX_TOKENS_PER_THREAD):
    """How many tokens to pre-issue so one thread never starves.

    `needed` / `clamped` are budget dicts under canonical keys; `clamped` is
    the budget echoed back by /issue after the server-side BUDGET_CAPS clamp.
    Returns max over dimensions of ceil(needed/clamped), capped at `cap`
    (on-demand refill covers a capped plan).
    """
    n = 1
    for dim in ("calls", "llm_calls", "bytes"):
        need = int(needed.get(dim, 0))
        have = int(clamped.get(dim, 0))
        if need <= 0:
            continue
        if have <= 0:
            raise ValueError("budget dim %s unusable (clamped to 0)" % dim)
        n = max(n, -(-need // have))            # ceil division
    return min(n, cap)


def _fmt(v, nd=2, na="-"):
    if v is None:
        return na
    return ("%." + str(nd) + "f") % v


def render_markdown(meta, levels):
    """Human-readable bench report (the .md written next to the JSON)."""
    is_llm = meta.get("kind") == "llm"
    cols = ["concurrency", "req/s", "p50 ms", "p95 ms", "p99 ms", "mean ms",
            "errors", "non2xx", "conn", "tokens"]
    if is_llm:
        cols.append("decode tok/s")
    out = []
    out.append("# Bicameral bench - kind=%s" % meta.get("kind"))
    out.append("")
    out.append("- run: %s (runid %s)" % (meta.get("ts"), meta.get("runid")))
    out.append("- base: %s (build_sha %s) / agent: %s / strata_state: %s"
               % (meta.get("base"), meta.get("build_sha"), meta.get("agent"),
                  meta.get("strata_state")))
    out.append("- window: %s s per level; client: %s"
               % (_fmt(meta.get("duration_s"), 1), meta.get("client")))
    if not is_llm and meta.get("files"):
        f = meta["files"]
        out.append("- corpus: %s file(s) x %s B pre-written via agent-rw "
                   "fs.write; every read is fs.read through /agent/invoke"
                   % (f.get("count"), f.get("bytes_each")))
    if is_llm and meta.get("llm"):
        l = meta["llm"]
        out.append("- llm.complete: prompt %s B, max_tokens %s; decode tok/s = "
                   "completion_tokens / full round-trip (e2e, from usage)"
                   % (l.get("prompt_bytes"), l.get("max_tokens")))
    out.append("- errors = non-2xx responses + transport failures; req/s = "
               "requests started within the window / window length")
    out.append("")
    out.append("| " + " | ".join(cols) + " |")
    out.append("|" + "|".join(["---:"] * len(cols)) + "|")
    for lv in levels:
        lat = lv.get("latency_ms") or {}
        tok = lv.get("tokens") or {}
        cells = [str(lv.get("concurrency")),
                 _fmt(lv.get("req_per_s"), 1),
                 _fmt(lat.get("p50")), _fmt(lat.get("p95")),
                 _fmt(lat.get("p99")), _fmt(lat.get("mean")),
                 str(lv.get("errors", 0)), str(lv.get("non2xx", 0)),
                 str(lv.get("conn_errors", 0)),
                 str((tok.get("preissued", 0)) + (tok.get("on_demand", 0)))]
        if is_llm:
            cells.append(_fmt((lv.get("llm") or {}).get("decode_tok_per_s_mean"), 1))
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    return "\n".join(out)


def selftest():
    """Assert the pure-function layer; exit 0/1. No instance needed."""
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name
              + ("" if cond else " | " + str(detail)))
        if not cond:
            ok = False

    # percentile (nearest-rank on an ascending list)
    seq100 = list(range(1, 101))
    check("percentile p50 of 1..100", percentile(seq100, 50) == 50)
    check("percentile p95 of 1..100", percentile(seq100, 95) == 95)
    check("percentile p99 of 1..100", percentile(seq100, 99) == 99)
    check("percentile p0/p100 ends", percentile(seq100, 0) == 1
          and percentile(seq100, 100) == 100)
    check("percentile single element", percentile([7.5], 95) == 7.5)
    check("percentile requires ascending input",
          percentile(sorted([3, 1, 2]), 50) == 2)
    try:
        percentile([], 50)
        check("percentile empty raises", False, "no exception")
    except ValueError:
        check("percentile empty raises", True)
    try:
        percentile(seq100, 101)
        check("percentile pct>100 raises", False, "no exception")
    except ValueError:
        check("percentile pct>100 raises", True)

    # token_budget: duration x est_qps x 2, canonical keys, llm dimension
    b = token_budget(15, 100, FILE_BYTES)
    check("token_budget fs canonical keys",
          b == {"calls": 3000, "llm_calls": 0, "bytes": 3000 * FILE_BYTES}, b)
    bl = token_budget(15, 100, 25, llm=True)
    check("token_budget llm grants llm_calls",
          bl["llm_calls"] == 3000 and bl["bytes"] == 3000 * 25, bl)
    check("token_budget ceil", token_budget(2.5, 3.3, 10)["calls"] == 17)
    check("token_budget min 1 call",
          token_budget(0.001, 0.1, FILE_BYTES)["calls"] == 1)
    check("token_budget exact ceil boundary",
          token_budget(10, 0.05, 10)["calls"] == 1)

    # plan_tokens: server-clamped budget -> how many tokens to pre-issue
    caps = {"calls": 1000, "llm_calls": 100, "bytes": 1024 * 1024}
    check("plan_tokens bytes dimension dominates (256 reads/token)",
          plan_tokens({"calls": 6000, "llm_calls": 0,
                       "bytes": 6000 * FILE_BYTES}, caps) == 24)
    check("plan_tokens one token is enough",
          plan_tokens({"calls": 5, "llm_calls": 0,
                       "bytes": 5 * FILE_BYTES}, caps) == 1)
    check("plan_tokens llm_calls dimension",
          plan_tokens({"calls": 500, "llm_calls": 500, "bytes": 500 * 25},
                      caps) == 5)
    check("plan_tokens honours cap",
          plan_tokens({"calls": 10 ** 9, "llm_calls": 0,
                       "bytes": 10 ** 9 * FILE_BYTES}, caps, cap=7) == 7)
    try:
        plan_tokens({"calls": 5, "llm_calls": 0, "bytes": 5 * FILE_BYTES},
                    {"calls": 1000, "llm_calls": 0, "bytes": 0})
        check("plan_tokens zero-clamped dim raises", False, "no exception")
    except ValueError:
        check("plan_tokens zero-clamped dim raises", True)

    # render_markdown: table header, rows, llm decode column
    meta = {"kind": "fs", "ts": "2026-10-16T00:00:00Z", "runid": "t",
            "base": "http://127.0.0.1:18000", "agent": "http://127.0.0.1:18001",
            "build_sha": "abcdef0123456789", "strata_state": "ok",
            "duration_s": 15.0, "client": "1 process",
            "files": {"count": 32, "bytes_each": FILE_BYTES}}
    lv = {"concurrency": 4, "req_per_s": 123.4,
          "latency_ms": {"p50": 1.0, "p95": 2.0, "p99": 3.0, "mean": 1.2},
          "errors": 0, "non2xx": 0, "conn_errors": 0,
          "tokens": {"preissued": 8, "on_demand": 0}}
    md = render_markdown(meta, [lv])
    for frag in ("| concurrency |", "req/s", "p99 ms", "| 4 |", "123.4",
                 "| 8 |", "kind=fs"):
        check("render_markdown contains %r" % frag, frag in md)
    meta_llm = dict(meta, kind="llm", files=None,
                    llm={"prompt_bytes": 25, "max_tokens": 64})
    lv_llm = dict(lv, llm={"decode_tok_per_s_mean": 2.5,
                           "completion_tokens_mean": 60.0, "samples": 3})
    md_llm = render_markdown(meta_llm, [lv_llm])
    check("render_markdown llm decode column",
          "decode tok/s" in md_llm and "| 2.5 |" in md_llm)

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# HTTP plumbing
# --------------------------------------------------------------------------- #

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_post_json(url, body, headers=None, timeout=15):
    """One-shot POST; returns (status, parsed-body-or-{"raw": ...})."""
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:200]}


def http_get_json(url, timeout=5):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:200]}
    except Exception as e:
        return None, {"raw": "%s: %s" % (type(e).__name__, e)}


def url_target(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        fail("bad url %r (need scheme://host:port)" % url)
    return u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)


def issue_token(base, admin_token, task_id, budget, ttl,
                agent="agent-ro", tools=None, strict=True):
    """POST /issue with the X-Admin-Token header (control plane now requires
    it; missing -> 401 CTL/AUTH_REQUIRED). Returns (token, clamped_budget)
    or (None, error) when strict=False. Never returns a token on failure."""
    body = {"agent": agent, "task_id": task_id,
            "tools": tools if tools is not None else ["fs.read"],
            "ttl_s": int(ttl), "budget": budget}
    headers = {}
    if admin_token:
        headers["X-Admin-Token"] = admin_token
    status, resp = http_post_json(base + "/issue", body, headers)
    if status == 200 and isinstance(resp, dict) and resp.get("ok"):
        return resp["token"], resp.get("budget") or {}
    err = "status=%s body=%s" % (status, resp)
    if status == 401:
        err = ("401 CTL/AUTH_REQUIRED - the control plane requires "
               "X-Admin-Token; pass --admin-token (or set BICAMERAL_ADMIN_TOKEN)")
    if strict:
        fail("/issue failed: " + err)
    return None, err


class InvokeClient:
    """Keep-alive agent-plane client owned by ONE thread."""

    def __init__(self, scheme, host, port, timeout):
        self.scheme, self.host, self.port, self.timeout = scheme, host, port, timeout
        self.conn = None

    def _connect(self):
        cls = (http.client.HTTPSConnection if self.scheme == "https"
               else http.client.HTTPConnection)
        self.conn = cls(self.host, self.port, timeout=self.timeout)
        self.conn.connect()
        try:    # latency bench: never let client Nagle eat a 40 ms delayed-ACK
            self.conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def invoke(self, token, nonce, tool, params):
        """One /agent/invoke round-trip -> (status, body, transport_error).

        One automatic retry on a fresh connection for transport errors (the
        server closes idle keep-alive connections after 30 s). status is None
        iff a transport error survived the retry.
        """
        payload = json.dumps({"nonce": nonce, "tool": tool,
                              "params": params}).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "X-Capability-Token": token}
        last_err = None
        for attempt in (0, 1):
            if self.conn is None:
                self._connect()
            try:
                self.conn.request("POST", "/agent/invoke", body=payload,
                                  headers=headers)
                try:    # the layer never sees it otherwise: server Nagle holds
                        # each response for the client's delayed ACK (~40 ms);
                        # prompt ACKs measure the gate, not the TCP stack
                    self.conn.sock.setsockopt(socket.IPPROTO_TCP,
                                              socket.TCP_QUICKACK, 1)
                except (OSError, AttributeError):
                    pass
                rsp = self.conn.getresponse()
                raw = rsp.read()
                try:
                    body = json.loads(raw.decode("utf-8", "replace"))
                except Exception:
                    body = {"raw": raw[:200].decode("utf-8", "replace")}
                return rsp.status, body, None
            except Exception as e:
                last_err = "%s: %s" % (type(e).__name__, e)
                self.close()
        return None, None, last_err


# --------------------------------------------------------------------------- #
# corpus pre-write (through the permission layer, like the README quick start)
# --------------------------------------------------------------------------- #

def file_content(idx):
    """Exactly 4 KiB of injection-clean filler (no braces/quotes/keywords)."""
    row = "bicameral-bench f%04d 0123456789 abcdefghijklmnopqrstuvwxyz " % idx
    return (row * (FILE_BYTES // len(row) + 2))[:FILE_BYTES]


def prewrite_files(base, agent_url, admin, scheme, host, port, scope, runid,
                   n_files, ttl):
    """Pre-write n x 4 KiB files via agent-rw fs.write (never direct disk I/O)."""
    budget = token_budget(n_files, 1.0, FILE_BYTES)     # calls=2n: x2 headroom
    task_id = "bench-prewrite-%s" % runid
    tok, clamped = issue_token(base, admin, task_id, budget, ttl,
                               agent="agent-rw", tools=["fs.write"])
    stack = [tok]
    for _ in range(plan_tokens(budget, clamped) - 1):
        t, _ = issue_token(base, admin, task_id, budget, ttl,
                           agent="agent-rw", tools=["fs.write"])
        stack.append(t)
    left = {"calls": clamped.get("calls", 0), "bytes": clamped.get("bytes", 0)}
    cl = InvokeClient(scheme, host, port, 30.0)
    paths = []
    try:
        for i in range(n_files):
            if left["calls"] <= 0 or left["bytes"] < FILE_BYTES:
                if not stack:
                    fail("pre-write ran out of tokens")
                stack.pop()
                left = {"calls": clamped.get("calls", 0),
                        "bytes": clamped.get("bytes", 0)}
            path = "%s/bench/%s/f%04d.txt" % (scope.rstrip("/"), runid, i)
            status, body, err = cl.invoke(
                stack[-1], "bw-%s-%d" % (runid, i), "fs.write",
                {"path": path, "content": file_content(i),
                 "idem_key": "bw-%s-%d" % (runid, i)})
            if err is not None or status != 200:
                fail("pre-write fs.write failed: status=%s err=%s body=%s"
                     % (status, err, body))
            left["calls"] -= 1
            left["bytes"] -= FILE_BYTES
            paths.append(path)
    finally:
        cl.close()
    return paths


# --------------------------------------------------------------------------- #
# the measured loop
# --------------------------------------------------------------------------- #

def new_worker_out():
    return {"latencies": [], "decode": [], "ctok": [], "by_status": {},
            "by_reason": {}, "non2xx": 0, "conn_errors": 0, "conn_samples": [],
            "switch429": 0, "on_demand": 0, "od_fail": 0, "crash": None}


def bench_worker(tidx, ctx, out):
    """Loop invoke until the deadline, recording every latency into `out`."""
    cl = InvokeClient(ctx["scheme"], ctx["host"], ctx["port"], ctx["timeout"])
    state = {"tok": None, "calls": 0, "bytes": 0, "llm": 0}
    seq = 0
    rnd = random.Random()
    files, bpc, is_llm = ctx["files"], ctx["bytes_per_call"], ctx["llm"]

    def take_token():
        """Next pre-issued token of this thread's stack, else issue on demand."""
        st = ctx["stacks"][tidx]
        if st:
            b = ctx["clamped"]
            state["tok"] = st.pop()
            state["calls"] = b.get("calls", 0)
            state["bytes"] = b.get("bytes", 0)
            state["llm"] = b.get("llm_calls", 0)
            return True
        with ctx["od_lock"]:
            ctx["on_demand"] += 1
        tok, _ = issue_token(ctx["base"], ctx["admin"], ctx["issue_task"],
                             ctx["issue_budget"], ctx["ttl"],
                             agent="agent-ro", tools=[ctx["tool"]], strict=False)
        if tok is None:
            with ctx["od_lock"]:
                ctx["od_fail"] += 1
            return False
        b = ctx["clamped"]
        state["tok"] = tok
        state["calls"] = b.get("calls", 0)
        state["bytes"] = b.get("bytes", 0)
        state["llm"] = b.get("llm_calls", 0)
        return True

    try:
        while time.perf_counter() < ctx["deadline"]:
            if (state["tok"] is None or state["calls"] <= 0
                    or state["bytes"] < bpc or (is_llm and state["llm"] <= 0)):
                if not take_token():
                    break                       # cannot issue: stop this thread
            seq += 1
            nonce = "b%s-%s%d-%d" % (ctx["runid"], ctx["phase"], tidx, seq)
            if is_llm:
                params = {"prompt": ctx["prompt"],
                          "max_tokens": ctx["llm_max_tokens"]}
            else:
                params = {"path": files[rnd.randrange(len(files))]}
            t0 = time.perf_counter()
            status, body, err = cl.invoke(state["tok"], nonce, ctx["tool"], params)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            if err is not None:
                out["conn_errors"] += 1
                if len(out["conn_samples"]) < 5:
                    out["conn_samples"].append(err)
                continue
            # Debit what the server debits: budget_take runs after the deny
            # checks, so 200 / 5xx (handler ran) / 413 consumed budget while
            # early denials (D1..D12) and D10 did not. Drift is corrected by
            # forcing a token switch on the next D10.
            if status == 200 or status >= 500 or status == 413:
                state["calls"] -= 1
                state["bytes"] -= bpc
                if is_llm:
                    state["llm"] -= 1
            key = str(status)
            out["by_status"][key] = out["by_status"].get(key, 0) + 1
            out["latencies"].append(dt_ms)
            if status != 200:
                out["non2xx"] += 1
                rc = ""
                if isinstance(body, dict):
                    rc = body.get("reason_code") or body.get("error") or ""
                out["by_reason"][rc or "?"] = out["by_reason"].get(rc or "?", 0) + 1
                if status == 429 and rc.startswith("D10"):
                    out["switch429"] += 1
                    state["calls"] = state["bytes"] = state["llm"] = 0
            elif is_llm:
                u = (body.get("result") or {}).get("usage") or {}
                ct = u.get("completion_tokens")
                if (isinstance(ct, (int, float)) and not isinstance(ct, bool)
                        and dt_ms > 0):
                    out["decode"].append(ct / (dt_ms / 1000.0))
                    out["ctok"].append(ct)
    except Exception as e:                          # one worker must not kill the level
        out["crash"] = "%s: %s" % (type(e).__name__, e)
    finally:
        cl.close()


def run_threads(conc, ctx):
    outs = [new_worker_out() for _ in range(conc)]
    threads = [threading.Thread(target=bench_worker, args=(i, ctx, outs[i]),
                                daemon=True)
               for i in range(conc)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return outs


def build_stacks(conc, budget, task_id, base, admin, ttl, tool):
    """Pre-issue conc x per_thread tokens, dealt round-robin to per-thread
    stacks. Returns (stacks, clamped, per_thread)."""
    tok, clamped = issue_token(base, admin, task_id, budget, ttl,
                               agent="agent-ro", tools=[tool])
    per_thread = plan_tokens(budget, clamped)
    stacks = [[] for _ in range(conc)]
    stacks[0].append(tok)
    for i in range(1, conc * per_thread):
        t, _ = issue_token(base, admin, task_id, budget, ttl,
                           agent="agent-ro", tools=[tool])
        stacks[i % conc].append(t)
    return stacks, clamped, per_thread


def aggregate_level(conc, window_s, elapsed_s, est_qps_thread, outs,
                    preissued, on_demand):
    lats, decode, ctok = [], [], []
    by_status, by_reason = {}, {}
    non2xx = conn = od = odfail = sw = 0
    crashes = []
    for w in outs:
        lats.extend(w["latencies"])
        decode.extend(w["decode"])
        ctok.extend(w["ctok"])
        non2xx += w["non2xx"]
        conn += w["conn_errors"]
        sw += w["switch429"]
        od += w["on_demand"]
        odfail += w["od_fail"]
        for k, v in w["by_status"].items():
            by_status[k] = by_status.get(k, 0) + v
        for k, v in w["by_reason"].items():
            by_reason[k] = by_reason.get(k, 0) + v
        crashes.extend(w["conn_samples"])
        if w["crash"]:
            crashes.append("worker crash: " + w["crash"])
    lats.sort()
    completed = len(lats)
    started = completed + conn
    lat = None
    if lats:
        lat = {"mean": round(sum(lats) / len(lats), 3),
               "min": round(lats[0], 3),
               "p50": round(percentile(lats, 50), 3),
               "p95": round(percentile(lats, 95), 3),
               "p99": round(percentile(lats, 99), 3),
               "max": round(lats[-1], 3)}
    level = {
        "concurrency": conc,
        "window_s": round(window_s, 3),
        "elapsed_s": round(elapsed_s, 3),
        "est_qps_per_thread": round(est_qps_thread, 1),
        "requests": completed,
        "req_per_s": round(completed / window_s, 2) if window_s > 0 else None,
        "latency_ms": lat,
        "errors": non2xx + conn,
        "non2xx": non2xx,
        "conn_errors": conn,
        "error_rate_pct": round(100.0 * (non2xx + conn) / started, 3) if started else None,
        "by_status": by_status,
        "by_reason": by_reason,
        "budget_429_switches": sw,
        "tokens": {"preissued": preissued, "on_demand": od + odfail},
    }
    if crashes:
        level["samples_of_failures"] = crashes[:5]
    if decode:
        level["llm"] = {
            "decode_tok_per_s_mean": round(sum(decode) / len(decode), 1),
            "completion_tokens_mean": round(sum(ctok) / len(ctok), 1),
            "samples": len(decode),
        }
    return level


def run_level(base, agent_url, admin, scheme, host, port, conc, duration,
              kind, files, runid, level_idx, timeout, ttl, llm_prompt,
              llm_max_tokens, warmup_s):
    tool = "llm.complete" if kind == "llm" else "fs.read"
    is_llm = kind == "llm"
    bytes_per_call = (len(llm_prompt.encode("utf-8")) if is_llm else FILE_BYTES)
    task_id = "bench-%s-c%d-%s" % (kind, conc, runid)

    # 1) unrecorded probe call: instance sanity + per-call latency estimate
    probe_budget = {"calls": 4, "llm_calls": 4,
                    "bytes": 4 * max(bytes_per_call, FILE_BYTES)}
    ptok, _ = issue_token(base, admin, task_id + "-probe", probe_budget, ttl,
                          agent="agent-ro", tools=[tool])
    probe_params = ({"prompt": llm_prompt, "max_tokens": llm_max_tokens}
                    if is_llm else
                    {"path": files[0] if files else "/dev/null-nonread"})
    pcl = InvokeClient(scheme, host, port, timeout)
    t0 = time.perf_counter()
    status, body, err = pcl.invoke(ptok, "b%s-p%d-0" % (runid, level_idx),
                                   tool, probe_params)
    probe_s = time.perf_counter() - t0
    pcl.close()
    if err is not None or status != 200:
        fail("warm-up probe call failed (instance unhealthy?): status=%s "
             "err=%s body=%s" % (status, err, body))

    # 2) estimate qps at this concurrency: short unrecorded burst (fs only;
    #    an llm call is far longer than any sensible burst window)
    if is_llm:
        est_qps_thread = 1.0 / max(probe_s, 1e-6)
        used_warmup = 0.0
    else:
        wu = warmup_s if warmup_s > 0 else max(0.3, min(2.0, duration / 10.0))
        wu_calls = min(2000, int(math.ceil(wu / max(probe_s, 1e-6) * 4)) + 8)
        wu_budget = {"calls": wu_calls, "llm_calls": 0,
                     "bytes": wu_calls * bytes_per_call}
        stacks, clamped, _ = build_stacks(conc, wu_budget, task_id + "-wu",
                                          base, admin, ttl, tool)
        ctx = {"scheme": scheme, "host": host, "port": port, "timeout": timeout,
               "tool": tool, "llm": is_llm, "files": files,
               "bytes_per_call": bytes_per_call, "prompt": llm_prompt,
               "llm_max_tokens": llm_max_tokens, "runid": runid, "phase": "w",
               "deadline": time.perf_counter() + wu, "stacks": stacks,
               "clamped": clamped, "base": base, "admin": admin,
               "issue_task": task_id + "-wu", "issue_budget": wu_budget,
               "ttl": ttl, "od_lock": threading.Lock(), "on_demand": 0}
        wouts = run_threads(conc, ctx)
        wu_done = sum(len(o["latencies"]) + o["conn_errors"] for o in wouts)
        est_qps_thread = ((wu_done / wu) / conc) if wu_done else 1.0 / max(probe_s, 1e-6)
        used_warmup = wu

    # 3) budget  duration x est_qps x 2  (canonical keys) -> pre-issue tokens
    budget = token_budget(duration, est_qps_thread, bytes_per_call, llm=is_llm)
    stacks, clamped, per_thread = build_stacks(conc, budget, task_id,
                                               base, admin, ttl, tool)
    total_tokens = conc * per_thread
    if per_thread >= MAX_TOKENS_PER_THREAD:
        print("bench:   note: plan hit the %d-token/thread cap; on-demand "
              "refill will cover the rest" % MAX_TOKENS_PER_THREAD)
    if total_tokens > TOKEN_WARN_TOTAL:
        print("bench:   note: %d live tokens planned (server nonce table caps "
              "at 1024 jtis; older tokens' slots may be evicted - harmless for "
              "the bench, but consider a shorter duration)"
              % total_tokens)
    print("bench:   est %.1f req/s/thread -> budget calls=%d llm_calls=%d "
          "bytes=%d -> %d token(s)/thread, %d total, warmup %.1fs"
          % (est_qps_thread, budget["calls"], budget["llm_calls"],
             budget["bytes"], per_thread, total_tokens, used_warmup))

    # 4) the recorded window
    ctx = {"scheme": scheme, "host": host, "port": port, "timeout": timeout,
           "tool": tool, "llm": is_llm, "files": files,
           "bytes_per_call": bytes_per_call, "prompt": llm_prompt,
           "llm_max_tokens": llm_max_tokens, "runid": runid, "phase": "r",
           "deadline": time.perf_counter() + duration, "stacks": stacks,
           "clamped": clamped, "base": base, "admin": admin,
           "issue_task": task_id, "issue_budget": budget, "ttl": ttl,
           "od_lock": threading.Lock(), "on_demand": 0}
    win_start = time.perf_counter()
    outs = run_threads(conc, ctx)
    elapsed = time.perf_counter() - win_start
    return aggregate_level(conc, duration, elapsed, est_qps_thread, outs,
                           total_tokens, ctx["on_demand"])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args():
    ap = argparse.ArgumentParser(
        description="bicameral throughput/latency bench (README section 6: "
                    "throughput) - hits only --base and --agent")
    ap.add_argument("--base", default="http://127.0.0.1:18000",
                    help="control plane (/issue, /healthz)")
    ap.add_argument("--agent", default="http://127.0.0.1:18001",
                    help="agent plane (/agent/invoke)")
    ap.add_argument("--admin-token",
                    default=os.environ.get("BICAMERAL_ADMIN_TOKEN", ""),
                    help="control-plane token, sent as X-Admin-Token "
                         "(env BICAMERAL_ADMIN_TOKEN)")
    ap.add_argument("--concurrency", default="1,4,16",
                    help="comma-separated concurrency levels")
    ap.add_argument("--duration", type=float, default=15.0,
                    help="seconds per level")
    ap.add_argument("--kind", choices=("fs", "llm"), default="fs",
                    help="fs: fs.read of pre-written 4 KiB files; "
                         "llm: llm.complete (decode reported separately)")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="output directory for bench-<kind>.json/.md")
    ap.add_argument("--files", type=int, default=32,
                    help="fs kind: corpus size (files pre-written via agent-rw)")
    ap.add_argument("--scope", default="/tmp/bicameral/data",
                    help="server data scope the corpus is written under")
    ap.add_argument("--warmup-s", type=float, default=0.0,
                    help="fs warm-up burst seconds (0 = auto: min(2, duration/10))")
    ap.add_argument("--llm-max-tokens", type=int, default=64)
    ap.add_argument("--llm-prompt", default=DEFAULT_LLM_PROMPT)
    ap.add_argument("--timeout", type=float, default=0.0,
                    help="per-request timeout s (0 = auto: fs 30, llm 150)")
    ap.add_argument("--ttl", type=int, default=3600,
                    help="capability token ttl_s (server clamps to 3600)")
    ap.add_argument("--selftest", action="store_true",
                    help="run pure-function assertions and exit (no instance)")
    return ap.parse_args()


def main():
    args = parse_args()
    if args.selftest:
        return selftest()

    base, agent_url = args.base.rstrip("/"), args.agent.rstrip("/")
    try:
        levels = [int(x) for x in args.concurrency.split(",") if x.strip()]
    except ValueError:
        fail("--concurrency must be comma-separated ints, got %r"
             % args.concurrency)
    if not levels or any(c <= 0 for c in levels):
        fail("--concurrency must be positive ints, got %r" % args.concurrency)
    if args.duration <= 0:
        fail("--duration must be > 0")
    if args.kind == "fs" and args.files <= 0:
        fail("--files must be > 0")
    prompt_bytes = len(args.llm_prompt.encode("utf-8"))
    if args.kind == "llm" and prompt_bytes > LLM_PROMPT_MAX:
        fail("llm prompt is %d B; server rejects > %d B (D9)"
             % (prompt_bytes, LLM_PROMPT_MAX))
    timeout = args.timeout or (150.0 if args.kind == "llm" else 30.0)
    runid = time.strftime("%Y%m%d-%H%M%S")

    # preflight: only ever --base and --agent from here on
    status, h = http_get_json(base + "/healthz")
    if status != 200 or not isinstance(h, dict):
        fail("control plane %s unhealthy: status=%s body=%s (is the instance "
             "running?)" % (base, status, h))
    build_sha, strata = h.get("build_sha", "?"), h.get("strata_state", "?")
    scheme, host, port = url_target(agent_url)
    print("bench: base=%s (build_sha=%s strata_state=%s) agent=%s kind=%s "
          "levels=%s duration=%ss"
          % (base, build_sha, strata, agent_url, args.kind, levels, args.duration))
    if args.kind == "llm" and strata != "ok":
        print("bench: WARNING strata_state=%s - llm.complete will 503 (D13); "
              "those count as errors" % strata)

    files = []
    if args.kind == "fs":
        files = prewrite_files(base, agent_url, args.admin_token, scheme, host,
                               port, args.scope, runid, args.files, args.ttl)
        print("bench: pre-wrote %d x %d B via agent-rw fs.write under %s/bench/%s"
              % (len(files), FILE_BYTES, args.scope, runid))

    meta = {
        "tool": "scripts/bench.py",
        "ts": now_iso(),
        "runid": runid,
        "base": base,
        "agent": agent_url,
        "build_sha": build_sha,
        "strata_state": strata,
        "kind": args.kind,
        "duration_s": args.duration,
        "concurrency_levels": levels,
        "scope": args.scope,
        "files": {"count": len(files), "bytes_each": FILE_BYTES} if files else None,
        "llm": ({"prompt_bytes": prompt_bytes, "max_tokens": args.llm_max_tokens}
                if args.kind == "llm" else None),
        "admin_token_used": bool(args.admin_token),
        "client": "1 process, keep-alive HTTP, %d worker threads per level"
                  % max(levels),
    }

    all_levels = []
    try:
        for i, conc in enumerate(levels):
            print("bench: level %d/%d conc=%d" % (i + 1, len(levels), conc))
            lv = run_level(base, agent_url, args.admin_token, scheme, host,
                           port, conc, args.duration, args.kind, files, runid,
                           i, timeout, args.ttl, args.llm_prompt,
                           args.llm_max_tokens, args.warmup_s)
            all_levels.append(lv)
            lat = lv.get("latency_ms") or {}
            print("bench:   -> req/s=%s p50=%sms p95=%sms p99=%sms errors=%s"
                  % (_fmt(lv.get("req_per_s"), 1), _fmt(lat.get("p50")),
                     _fmt(lat.get("p95")), _fmt(lat.get("p99")), lv["errors"]))
            if lv.get("llm"):
                print("bench:   -> decode %s tok/s (mean, e2e; %s completion "
                      "tokens mean)" % (_fmt(lv["llm"]["decode_tok_per_s_mean"], 1),
                                        _fmt(lv["llm"]["completion_tokens_mean"], 1)))
    except KeyboardInterrupt:
        print("bench: interrupted", file=sys.stderr)
        return 130

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "bench-%s.json" % args.kind)
    md_path = os.path.join(args.out, "bench-%s.md" % args.kind)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "levels": all_levels}, f,
                  ensure_ascii=False, indent=2)
        f.write("\n")
    md = render_markdown(meta, all_levels)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md + "\n")
    print(md)
    print("bench: wrote %s and %s" % (json_path, md_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
