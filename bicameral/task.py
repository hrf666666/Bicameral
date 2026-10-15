#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral task.py — task/1 unified task schema + on-device executor.

Implements docs/paradigm.md §3.5 (统一任务): one task schema that any device
can validate, and one result envelope that any device produces — so a result
is always delivered together with the facts that produced it (engine, perf
reference, audit reference). 与 server.py/install.py 同一工程哲学: stdlib
single file, fail-closed validation (unknown fields are errors, never
silently ignored), bounded fields, diagnostics on stderr / data on stdout.

Subcommands:
    validate <task.json>    validate a task/1 file, print it back normalized
    execute-local <task|->  RUNS ON A DEVICE: read task (path or "-" for
                            stdin), ask the LOCAL permission layer for a
                            token (POST control-plane /issue, subject
                            agent-ro, tools=[llm.complete], 1-call budget),
                            invoke POST agent-plane /agent/invoke with a
                            fresh nonce, normalize the outcome into the
                            result/1 envelope and print EXACTLY ONE JSON line
                            (the envelope) to stdout — the master reads it
                            back over ssh stdout (scp is the alternate
                            transport and is not needed for the PoC)
    selftest / --selftest   pure-function self-test (schema validation,
                            dual-machine envelope normalization)

Result envelope (result/1) — identical shape no matter which device ran:
    {"schema":"result/1","task_id":...,"device":...,
     "engine":{"model_id":...,"backend":...},
     "perf_ref":...,"audit_ref":...,
     "device_audit_digest":...,
     "result":{"content_summary":...,"usage":{...}},"latency_ms":...}
per paradigm §3.5: 调用方拿到的不仅是答案，还有「这个答案是在什么能力的
设备上、以什么实测性能产生的」。model_id comes from the local layer's
GET /capabilities (the layer's live Strata state); backend and the refs are
supplied by whoever ships the task (the router passes the PerfRecord facts).

device_audit_digest (red-team A9 hardening): sha256_16 of THIS run's ALLOW
row in the device-side audit (the row the local permission layer wrote when
the jti from /issue was spent). A fabricated envelope cannot carry a digest
that resolves to a real ALLOW row for its task_id — bicameral/
verify_result.py cross-checks exactly that at archival time. null means the
executor could not read its audit (envelope stays valid; the cross-check
will reject it — fail-loud downstream, never silent).

Exit codes: 0 ok · 2 usage/schema error · 3 permission-layer DENY (reason
code on stderr) · 4 control-plane /issue failure · 5 envelope failure.
Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.request

TASK_SCHEMA = "task/1"
RESULT_SCHEMA = "result/1"

# §3.5 names "qa|extract|code|…" — a closed set today, extended by editing
# this tuple (fail-closed: an unseen type is a schema error, not a fallback).
TASK_TYPES = ("qa", "extract", "code")
LATENCY_CLASSES = ("interactive", "batch")
EGRESS_VALUES = ("none",)          # only "none" is named by §3.5 so far

# llm.complete bounds mirror server.py LIMITS (schema rejects early what the
# permission layer would deny later: llm_prompt 8 KiB, max_tokens 1..64).
LLM_PROMPT_MAX = 8 * 1024
LLM_MAX_TOKENS_CAP = 64
DEFAULT_TTL_S = 300

DEFAULT_DEVICE_AUDIT = "/tmp/bicameral/audit.jsonl"   # server.py AUDIT_PATH default
SHA16_RE = re.compile(r"^[0-9a-f]{16}$")              # sha256_16 fingerprint

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
QUALITY_BAR_KEY_RE = re.compile(r"^min_[a-z0-9_]+$")
FORBIDDEN_KEYS = ("actions", "tool_calls")     # D8 parity: never at any depth

SUBJECT = "agent-ro"               # SUBJECTS["agent-ro"] ⊇ {llm.complete} (server.py)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _has_forbidden_key(obj):
    """True if key 'actions'/'tool_calls' appears at ANY depth (server.py D8)."""
    if isinstance(obj, dict):
        return any(k in FORBIDDEN_KEYS or _has_forbidden_key(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_forbidden_key(v) for v in obj)
    return False


def _is_num(v):
    return not isinstance(v, bool) and isinstance(v, (int, float))


# --------------------------------------------------------------------------- #
# task/1 schema — fail-closed, unknown fields rejected
# --------------------------------------------------------------------------- #

def validate_task(raw):
    """Strict task/1 validation. Returns (task, None) or (None, error string).

    Unknown top-level and nested fields are errors (same contract as
    server.py /issue D8 and install.py validate_appspec), values are
    type-and-range checked, and the qa input shape is verified against the
    server-side llm.complete bounds so a task that passes here cannot fail
    there on size.
    """
    if not isinstance(raw, dict):
        return None, "task must be a JSON object"
    if raw.get("schema") != TASK_SCHEMA:
        return None, "schema must be %r" % TASK_SCHEMA
    unknown = sorted(set(raw) - {"schema", "task_id", "type", "input",
                                 "quality_bar", "latency_class", "constraints"})
    if unknown:
        return None, "unknown field(s): %s" % ", ".join(unknown)
    for name in ("task_id", "type", "input", "latency_class"):
        if name not in raw:
            return None, "missing field: " + name

    task_id = raw["task_id"]
    if not isinstance(task_id, str) or not TASK_ID_RE.match(task_id):
        return None, "task_id must match %s" % TASK_ID_RE.pattern

    if raw["type"] not in TASK_TYPES:
        return None, "type must be one of %s" % "|".join(TASK_TYPES)

    inp = raw["input"]
    if not isinstance(inp, dict) or not inp:
        return None, "input must be a non-empty object"
    if _has_forbidden_key(inp):
        return None, "forbidden key (actions/tool_calls) at some depth"
    if raw["type"] == "qa":
        prompt = inp.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            return None, "input.prompt must be a non-empty string for type qa"
        if len(prompt.encode("utf-8")) > LLM_PROMPT_MAX:
            return None, "input.prompt exceeds %d bytes" % LLM_PROMPT_MAX

    lc = raw["latency_class"]
    if lc not in LATENCY_CLASSES:
        return None, "latency_class must be one of %s" % "|".join(LATENCY_CLASSES)

    qb = raw.get("quality_bar")
    if qb is not None:
        if not isinstance(qb, dict):
            return None, "quality_bar must be an object"
        for k, v in qb.items():
            if not QUALITY_BAR_KEY_RE.match(k):
                return None, "quality_bar key must match %s: %s" % (
                    QUALITY_BAR_KEY_RE.pattern, k)
            if not _is_num(v) or not (0.0 <= float(v) <= 1.0):
                return None, "quality_bar.%s must be a number in 0..1" % k

    cons = raw.get("constraints")
    if cons is not None:
        if not isinstance(cons, dict):
            return None, "constraints must be an object"
        unknown = sorted(set(cons) - {"data_scope", "egress"})
        if unknown:
            return None, "unknown constraints field(s): %s" % ", ".join(unknown)
        ds = cons.get("data_scope")
        if ds is not None and (not isinstance(ds, str)
                               or not ds.startswith("/")):
            return None, "constraints.data_scope must be an absolute path"
        eg = cons.get("egress")
        if eg is not None and eg not in EGRESS_VALUES:
            return None, "constraints.egress must be one of %s" % "|".join(EGRESS_VALUES)

    task = {
        "schema": TASK_SCHEMA,
        "task_id": task_id,
        "type": raw["type"],
        "input": inp,
        "latency_class": lc,
        "quality_bar": dict(qb) if qb else {},
        "constraints": dict(cons) if cons else {},
    }
    return task, None


def load_task(path):
    """Read a task/1 from a file path or "-" (stdin). Returns (task, err)."""
    try:
        if path == "-":
            raw = json.loads(sys.stdin.read())
        else:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
    except OSError as e:
        return None, "cannot read task: %s" % e.strerror
    except Exception as e:
        return None, "task is not valid JSON: %s" % type(e).__name__
    return validate_task(raw)


# --------------------------------------------------------------------------- #
# result/1 envelope — normalization + validation
# --------------------------------------------------------------------------- #

def normalize_result(task_id, device, raw, engine, perf_ref, audit_ref,
                     latency_ms, device_audit_digest=None):
    """Normalize any device's execution outcome into one result/1 envelope.

    raw is either the agent-plane response {"ok":true,"result":{...}} or the
    inner result {"content_summary":...,"usage":{...}} directly — the caller
    does not need to know which shape came back. engine is coerced to exactly
    {model_id, backend}. device_audit_digest pins the run to its device-side
    ALLOW audit row (A9; see module docstring). Returns the envelope dict
    (key order is normative for readability; consumers must not depend on it).
    """
    if isinstance(raw, dict) and raw.get("ok") is True and isinstance(raw.get("result"), dict):
        raw = raw["result"]
    if not isinstance(raw, dict):
        raw = {}
    summary = raw.get("content_summary")
    usage = raw.get("usage")
    eng = engine if isinstance(engine, dict) else {}
    return {
        "schema": RESULT_SCHEMA,
        "task_id": task_id,
        "device": device,
        "engine": {"model_id": eng.get("model_id"),
                   "backend": eng.get("backend")},
        "perf_ref": perf_ref,
        "audit_ref": audit_ref,
        "device_audit_digest": device_audit_digest,
        "result": {"content_summary": summary if isinstance(summary, str) else None,
                   "usage": usage if isinstance(usage, dict) else {}},
        "latency_ms": round(float(latency_ms), 1) if _is_num(latency_ms) else None,
    }


def extract_allow_digest(audit_path, jti, task_id):
    """A9: sha256_16 of THIS run's ALLOW row in the device-side audit.

    Scans the audit for the last line whose event is ALLOW with this jti +
    task_id and hashes that line's exact raw bytes. The digest ties the
    envelope to a permission event a forger cannot produce for a run that
    never happened (bicameral/verify_result.py resolves it at archival).
    Returns (digest_or_None, detail) — None is honest "could not extract",
    never a fabricated value.
    """
    if not isinstance(jti, str) or not jti:
        return None, "no jti (issue response lacked one)"
    try:
        with open(audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        return None, "cannot read device audit %s: %s" % (audit_path, e.strerror)
    for raw_line in reversed(lines):
        line = raw_line.rstrip("\n")
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("event") == "ALLOW" \
                and obj.get("jti") == jti and obj.get("task_id") == task_id:
            return hashlib.sha256(line.encode("utf-8")).hexdigest()[:16], "ok"
    return None, "no ALLOW row for jti=%s task_id=%s in %s" % (
        jti, task_id, audit_path)


def validate_result(env):
    """Strict result/1 shape check. Returns None if ok, else error string.

    device_audit_digest must be present (A9): null is legal at shape level
    (the executor could not read its audit — envelope survives, the archival
    cross-check will not), anything set must be 16 lowercase hex chars.
    """
    if not isinstance(env, dict):
        return "envelope must be a JSON object"
    if env.get("schema") != RESULT_SCHEMA:
        return "schema must be %r" % RESULT_SCHEMA
    want = {"schema", "task_id", "device", "engine", "perf_ref", "audit_ref",
            "device_audit_digest", "result", "latency_ms"}
    missing = sorted(want - set(env))
    unknown = sorted(set(env) - want)
    if missing:
        return "missing field(s): %s" % ", ".join(missing)
    if unknown:
        return "unknown field(s): %s" % ", ".join(unknown)
    for name in ("task_id", "device", "perf_ref", "audit_ref"):
        if not isinstance(env.get(name), str) or not env[name]:
            return "%s must be a non-empty string" % name
    dad = env.get("device_audit_digest")
    if dad is not None and (not isinstance(dad, str) or not SHA16_RE.match(dad)):
        return "device_audit_digest must be null or 16 lowercase hex chars"
    eng = env.get("engine")
    if not isinstance(eng, dict) or set(eng) != {"model_id", "backend"}:
        return "engine must be exactly {model_id, backend}"
    if eng["model_id"] is not None and not isinstance(eng["model_id"], str):
        return "engine.model_id must be a string or null"
    if eng["backend"] is not None and not isinstance(eng["backend"], str):
        return "engine.backend must be a string or null"
    res = env.get("result")
    if not isinstance(res, dict) or set(res) != {"content_summary", "usage"}:
        return "result must be exactly {content_summary, usage}"
    if not isinstance(res["content_summary"], str):
        return "result.content_summary must be a string"
    if not isinstance(res["usage"], dict):
        return "result.usage must be an object"
    if not _is_num(env.get("latency_ms")) or env["latency_ms"] < 0:
        return "latency_ms must be a non-negative number"
    return None


# --------------------------------------------------------------------------- #
# permission-layer client (runs on the device)
# --------------------------------------------------------------------------- #

def _post_json(url, body, timeout, headers=None):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as rsp:
        return rsp.status, json.loads(rsp.read().decode("utf-8", "replace"))


def get_model_id(control_url, timeout=5):
    """Live engine fact: GET control-plane /capabilities -> model_id (or None)."""
    try:
        with urllib.request.urlopen(control_url + "/capabilities",
                                    timeout=timeout) as rsp:
            caps = json.loads(rsp.read().decode("utf-8", "replace"))
        mid = caps.get("model_id")
        return mid if isinstance(mid, str) and mid else None
    except Exception:
        return None


def issue_token(control_url, task_id, timeout=10, ttl_s=DEFAULT_TTL_S):
    """POST /issue: least-privilege token — agent-ro, llm.complete, 1 call.

    Returns (token, jti, err); jti comes from the /issue response and feeds
    extract_allow_digest after the invocation (A9)."""
    status, body = _post_json(control_url + "/issue", {
        "agent": SUBJECT,
        "task_id": task_id,
        "tools": ["llm.complete"],
        "ttl_s": int(ttl_s),
        "budget": {"max_calls": 1, "max_llm_calls": 1},
    }, timeout)
    if status != 200 or not body.get("ok"):
        return None, None, "issue failed: HTTP %s %s" % (status, body.get("error"))
    jti = body.get("jti")
    return body["token"], (jti if isinstance(jti, str) else None), None


def invoke(agent_url, token, prompt, max_tokens, timeout=120):
    """POST /agent/invoke with a fresh nonce; returns (result_raw, latency_ms, err).

    A non-200 IS a denial with a reason body (server.py always sends
    {reason_code}), not a transport failure — the code is surfaced so the
    operator sees D13/CAPABILITY_DEGRADED rather than a bare HTTPError.
    """
    t0 = time.monotonic()
    try:
        status, body = _post_json(agent_url + "/agent/invoke", {
            "nonce": secrets.token_hex(8),
            "tool": "llm.complete",
            "params": {"prompt": prompt, "max_tokens": int(max_tokens)},
        }, timeout, headers={"X-Capability-Token": token})
    except urllib.error.HTTPError as e:
        latency_ms = (time.monotonic() - t0) * 1000.0
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
            reason = body.get("reason_code") or body.get("error") or ("HTTP %s" % e.code)
        except Exception:
            reason = "HTTP %s" % e.code
        return None, latency_ms, "DENY %s" % reason
    except Exception as e:
        return None, (time.monotonic() - t0) * 1000.0, \
            "invoke transport failure: %s" % type(e).__name__
    latency_ms = (time.monotonic() - t0) * 1000.0
    if status != 200 or not body.get("ok"):
        return None, latency_ms, "DENY %s" % body.get("reason_code", "HTTP %s" % status)
    return body, latency_ms, None


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def cmd_validate(args) -> int:
    task, err = load_task(args.task)
    if err:
        print("task: invalid: %s" % err, file=sys.stderr)
        return 2
    print(json.dumps(task, ensure_ascii=False, indent=2))
    return 0


def cmd_execute_local(args) -> int:
    """On-device executor: /issue -> /agent/invoke -> one JSON line envelope."""
    task, err = load_task(args.task)
    if err:
        print("task: invalid: %s" % err, file=sys.stderr)
        return 2
    if task["type"] != "qa":
        print("task: execute-local implements type qa only (got %r); "
              "extend TASK executor types deliberately" % task["type"],
              file=sys.stderr)
        return 2

    token, jti, err = issue_token(args.control_url, task["task_id"],
                                  timeout=args.http_timeout, ttl_s=args.ttl_s)
    if err:
        print("task: %s" % err, file=sys.stderr)
        return 4

    model_id = args.model_id or get_model_id(args.control_url,
                                             timeout=args.http_timeout)
    raw, latency_ms, err = invoke(args.agent_url, token,
                                  task["input"]["prompt"], args.max_tokens,
                                  timeout=args.llm_timeout)
    if err:
        print("task: %s" % err, file=sys.stderr)
        return 3

    # A9: pin this run to its device-side ALLOW audit row. A null digest is
    # recorded honestly (stderr note) — the envelope stays valid, but the
    # archival cross-check (bicameral/verify_result.py) will reject it.
    digest, detail = extract_allow_digest(args.audit_path, jti,
                                          task["task_id"])
    if digest is None:
        print("task: note: device_audit_digest unavailable: %s "
              "(archival cross-check will reject this envelope)" % detail,
              file=sys.stderr)

    env = normalize_result(
        task_id=task["task_id"], device=args.device, raw=raw,
        engine={"model_id": model_id, "backend": args.backend},
        perf_ref=args.perf_ref, audit_ref=args.audit_ref,
        latency_ms=latency_ms if latency_ms is not None else 0.0,
        device_audit_digest=digest)
    err = validate_result(env)
    if err:
        print("task: envelope invalid: %s" % err, file=sys.stderr)
        return 5
    # stdout is the transport: exactly one JSON line, nothing else on it.
    print(json.dumps(env, ensure_ascii=False))
    print("task: envelope for %s on %s (%.1f ms, model_id=%s)"
          % (task["task_id"], args.device, env["latency_ms"], model_id),
          file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# selftest — pure functions only (no network, no filesystem writes)
# --------------------------------------------------------------------------- #

def cmd_selftest(_args) -> int:
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    good = {
        "schema": "task/1", "task_id": "qa-ability-token-001", "type": "qa",
        "input": {"prompt": "用一句话说明什么是能力令牌"},
        "latency_class": "interactive",
        "constraints": {"egress": "none"},
    }
    task, err = validate_task(good)
    check("schema.accepts_good", task is not None and err is None, err or "")
    if task:
        check("schema.defaults_fillin",
              task["quality_bar"] == {} and task["constraints"] == {"egress": "none"})

    def bad(mutate, label):
        obj = json.loads(json.dumps(good))
        mutate(obj)
        t, e = validate_task(obj)
        check("schema.rejects_" + label, t is None and bool(e), e or "accepted")

    bad(lambda o: o.update(extra=1), "unknown_top_field")
    bad(lambda o: o["constraints"].update(proxy="x"), "unknown_constraints_field")
    bad(lambda o: o.update(quality_bar={"max_gsm8k": 0.9}), "unknown_quality_bar_key")
    bad(lambda o: o.pop("type"), "missing_type")
    bad(lambda o: o.pop("input"), "missing_input")
    bad(lambda o: o.pop("latency_class"), "missing_latency_class")
    bad(lambda o: o.update(schema="task/2"), "wrong_schema")
    bad(lambda o: o.update(type="summarize"), "unknown_type")
    bad(lambda o: o.update(latency_class="whenever"), "unknown_latency_class")
    bad(lambda o: o.update(task_id=""), "empty_task_id")
    bad(lambda o: o.update(task_id="../evil"), "traversal_task_id")
    bad(lambda o: o.update(task_id=7), "nonstring_task_id")
    bad(lambda o: o["input"].pop("prompt"), "qa_without_prompt")
    bad(lambda o: o["input"].update(prompt="   "), "qa_blank_prompt")
    bad(lambda o: o["input"].update(prompt="x" * (LLM_PROMPT_MAX + 1)),
        "prompt_too_long")
    bad(lambda o: o["input"].update({"actions": []}), "forbidden_key")
    bad(lambda o: o.update(quality_bar={"min_gsm8k": 1.5}), "quality_bar_out_of_range")
    bad(lambda o: o.update(quality_bar={"min_gsm8k": True}), "quality_bar_bool")
    bad(lambda o: o["constraints"].update(egress="direct"), "unknown_egress_value")
    bad(lambda o: o["constraints"].update(data_scope="relative/path"),
        "relative_data_scope")

    # --- normalize: two machines, one shape (the ask's 双机信封归一一致) --- #
    jetson = normalize_result(
        task_id="qa-ability-token-001", device="jetson",
        raw={"ok": True, "result": {"content_summary": "能力令牌是一次授权的签名凭据…",
                                    "usage": {"completion_tokens": 42}},
             "jti": "should-not-leak"},
        engine={"model_id": "Qwen3-0.6B-Q8_0",
                "backend": "CUDA (libggml-cuda.so.0.24.0)"},
        perf_ref="results/2026-10-14-probe-bench/perf-jetson.json",
        audit_ref="/tmp/bicameral/audit.jsonl", latency_ms=1883.27,
        device_audit_digest="b7c9e2a41d3f5068")
    bi150 = normalize_result(
        task_id="qa-ability-token-001", device="bi150",
        raw={"content_summary": "能力令牌是…（bi150 的回答）",
             "usage": {"completion_tokens": 51}},
        engine={"model_id": "Qwen3-0.6B-Q8_0", "backend": "CPU only"},
        perf_ref="results/2026-10-14-probe-bench/perf-bi150.json",
        audit_ref="/root/bicameral-sandbox/audit.jsonl", latency_ms=986.4,
        device_audit_digest="0123456789abcdef")

    e1, e2 = validate_result(jetson), validate_result(bi150)
    check("normalize.dual_machine_valid", e1 is None and e2 is None,
          "%s / %s" % (e1, e2))
    check("normalize.dual_machine_same_shape",
          sorted(jetson) == sorted(bi150)
          and sorted(jetson["engine"]) == sorted(bi150["engine"])
          and sorted(jetson["result"]) == sorted(bi150["result"])
          and jetson["schema"] == bi150["schema"] == RESULT_SCHEMA)
    check("normalize.dual_machine_values_differ",
          jetson["device"] != bi150["device"]
          and jetson["engine"]["backend"] != bi150["engine"]["backend"])
    check("normalize.invoke_wrapper_stripped",
          "jti" not in jetson and "ok" not in jetson
          and jetson["result"]["usage"] == {"completion_tokens": 42})
    check("normalize.latency_rounded",
          jetson["latency_ms"] == 1883.3 and bi150["latency_ms"] == 986.4)
    check("normalize.digest_passthrough",
          jetson["device_audit_digest"] == "b7c9e2a41d3f5068"
          and bi150["device_audit_digest"] == "0123456789abcdef")
    no_dig = normalize_result("t", "d", raw={"content_summary": "s", "usage": {}},
                              engine={"model_id": "m", "backend": "b"},
                              perf_ref="p", audit_ref="a", latency_ms=1.0)
    check("normalize.digest_defaults_null",
          no_dig["device_audit_digest"] is None
          and validate_result(no_dig) is None)   # shape-valid; cross-check
          # (verify_result.py) is what rejects null — fail-loud, not here

    bad_raw = normalize_result("t", "d", raw="not-a-dict",
                               engine="nope", perf_ref="p", audit_ref="a",
                               latency_ms=None)
    check("normalize.garbage_defaults",
          bad_raw["result"]["content_summary"] is None
          and bad_raw["result"]["usage"] == {}
          and bad_raw["engine"] == {"model_id": None, "backend": None}
          and validate_result(bad_raw) is not None)
    no_lat = normalize_result("t", "d", raw={"content_summary": "s", "usage": {}},
                              engine={"model_id": "m", "backend": "b"},
                              perf_ref="p", audit_ref="a", latency_ms=None)
    check("normalize.missing_latency_invalid",
          validate_result(no_lat) == "latency_ms must be a non-negative number",
          validate_result(no_lat) or "accepted")

    def bad_env(mutate, label):
        env = json.loads(json.dumps(jetson))
        mutate(env)
        e = validate_result(env)
        check("result.rejects_" + label, bool(e), e or "accepted")

    bad_env(lambda o: o.update(extra=1), "unknown_top_field")
    bad_env(lambda o: o.pop("device_audit_digest"), "missing_digest_field")
    bad_env(lambda o: o.update(device_audit_digest="ABCDEF0123456789"),
            "digest_uppercase")
    bad_env(lambda o: o.update(device_audit_digest="0123456789abcde"),
            "digest_too_short")
    bad_env(lambda o: o.update(device_audit_digest="f" * 64),
            "digest_full_sha256_not_16")
    bad_env(lambda o: o.update(device_audit_digest="g" * 16),
            "digest_not_hex")
    bad_env(lambda o: o.pop("audit_ref"), "missing_audit_ref")
    bad_env(lambda o: o.update(schema="result/2"), "wrong_schema")
    bad_env(lambda o: o.update(device=""), "empty_device")
    bad_env(lambda o: o["engine"].pop("backend"), "engine_missing_backend")
    bad_env(lambda o: o["engine"].update(extra=None), "engine_unknown_field")
    bad_env(lambda o: o["result"].update(content_summary=5), "summary_not_str")
    bad_env(lambda o: o["result"].pop("usage"), "missing_usage")
    bad_env(lambda o: o.update(latency_ms=-1), "negative_latency")

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="task.py",
        description="Bicameral task/1 — unified task schema + on-device "
                    "executor (docs/paradigm.md §3.5). Stdlib-only, "
                    "fail-closed, diagnostics on stderr / data on stdout.")
    ap.add_argument("--selftest", action="store_true",
                    help="run the pure-function self-test and exit")
    sub = ap.add_subparsers(dest="cmd")

    ap_v = sub.add_parser("validate", help="validate a task/1 file")
    ap_v.add_argument("task", help="task/1 JSON file")

    ap_x = sub.add_parser("execute-local",
                          help="RUN ON A DEVICE: /issue -> /agent/invoke -> "
                               "result/1 envelope on stdout")
    ap_x.add_argument("task", help='task/1 JSON file, or "-" for stdin')
    ap_x.add_argument("--device", required=True,
                      help="device name recorded in the envelope")
    ap_x.add_argument("--control-url", default="http://127.0.0.1:18000")
    ap_x.add_argument("--agent-url", default="http://127.0.0.1:18001")
    ap_x.add_argument("--model-id", default=None,
                      help="default: GET /capabilities model_id")
    ap_x.add_argument("--backend", default=None,
                      help="engine backend string (router passes the "
                           "PerfRecord fact)")
    ap_x.add_argument("--perf-ref", default="unknown",
                      help="PerfRecord reference recorded in the envelope")
    ap_x.add_argument("--audit-ref", default="unknown",
                      help="device-side audit trail reference")
    ap_x.add_argument("--audit-path", default=DEFAULT_DEVICE_AUDIT,
                      help="device-side audit JSONL read back for the A9 "
                           "ALLOW-row digest (default: %s)" % DEFAULT_DEVICE_AUDIT)
    ap_x.add_argument("--max-tokens", type=int, default=LLM_MAX_TOKENS_CAP)
    ap_x.add_argument("--ttl-s", type=int, default=DEFAULT_TTL_S)
    ap_x.add_argument("--http-timeout", type=float, default=10)
    ap_x.add_argument("--llm-timeout", type=float, default=120)

    sub.add_parser("selftest", help="pure-function self-test")

    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "execute-local":
        args.max_tokens = max(1, min(int(args.max_tokens), LLM_MAX_TOKENS_CAP))
        args.ttl_s = max(1, min(int(args.ttl_s), 3600))
        return cmd_execute_local(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
