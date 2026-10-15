#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral verify_result.py — archival cross-check for result/1 envelopes.

Red-team A9 hardening: a fabricated envelope used to pass every shape check
because nothing tied it to a real permission grant on the device. The
executor now stamps each envelope with device_audit_digest = sha256_16 of
THIS run's ALLOW row in the device-side audit (bicameral/task.py
extract_allow_digest); this script resolves that digest at archival time:

    1. envelope shape          — task.validate_result (imported, not mirrored:
                                 this checker runs master-side, deployability
                                 does not demand a third copy of the contract)
    2. digest present and 16 lowercase hex — null = "cannot cross-check" = FAIL
    3. digest resolves         — exactly one ALLOW line in the device audit
                                 hashes to it (exact raw bytes)
    4. task_id binding         — that ALLOW row's task_id == envelope.task_id
    5. ISSUE/ALLOW pair        — an ISSUE row with the same jti + task_id exists
                                 (an ALLOW without its ISSUE is an incomplete
                                 audit, not a verified grant)

Usage:
    verify_result.py <envelope.json|-> [--device-audit <audit.jsonl>]
        --device-audit defaults to the envelope's audit_ref when that is a
        readable path. Exit: 0 verified · 1 cross-check FAILED · 2 usage.

An attacker who can also rewrite the device audit can forge a matching pair
— stated honestly: this raises fabrication from "zero checks" to "requires
device-side audit write access"; the audit itself is hash-chained upstream
(server-side) and router-side (route-audit seq/prev chain).
Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from task import SHA16_RE, validate_result     # authority, not a third mirror


def sha16(line):
    """sha256_16 of one audit line's exact bytes (trailing newline excluded)."""
    return hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()[:16]


def load_audit_rows(path):
    """Read the device audit into [(raw_line, obj_or_None)]. (None, err) on
    unreadable file — a missing audit is a hard failure, never a pass."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        return None, "cannot read device audit %s: %s" % (path, e.strerror)
    rows = []
    for raw in lines:
        line = raw.rstrip("\n")
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            obj = None
        rows.append((line, obj if isinstance(obj, dict) else None))
    return rows, None


def check_envelope(env, rows):
    """Pure cross-check. rows: [(raw_line, obj_or_None)]. Returns (ok, reasons).

    All reasons are collected (not fail-first) so one run reports everything
    an operator must look at.
    """
    reasons = []
    err = validate_result(env)
    if err:
        return False, ["envelope invalid: %s" % err]
    digest = env.get("device_audit_digest")
    if not isinstance(digest, str) or not SHA16_RE.match(digest):
        return False, ["device_audit_digest is %r — envelope cannot be "
                       "cross-checked against the device audit (null/absent/"
                       "malformed digest is a hard archival failure)" % (digest,)]
    allow = [(line, obj) for line, obj in rows
             if obj and obj.get("event") == "ALLOW" and sha16(line) == digest]
    if not allow:
        return False, ["no ALLOW row in the device audit hashes to %s — "
                       "envelope corresponds to no recorded permission grant"
                       % digest]
    if len(allow) > 1:
        reasons.append("digest %s matches %d ALLOW rows (hash collision or "
                       "duplicated audit) — manual review required"
                       % (digest, len(allow)))
    _, aobj = allow[0]
    if aobj.get("task_id") != env.get("task_id"):
        reasons.append("ALLOW row task_id %r != envelope task_id %r"
                       % (aobj.get("task_id"), env.get("task_id")))
    jti = aobj.get("jti")
    if not any(obj.get("event") == "ISSUE" and obj.get("jti") == jti
               and obj.get("task_id") == env.get("task_id")
               for _, obj in rows):
        reasons.append("no ISSUE row for jti=%s with task_id=%s — ALLOW "
                       "without its ISSUE pair" % (jti, env.get("task_id")))
    return not reasons, reasons


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="verify_result.py",
        description="Cross-check a result/1 envelope's device_audit_digest "
                    "against the device-side permission audit (A9). "
                    "Exit 0 verified · 1 FAILED · 2 usage.")
    ap.add_argument("envelope", nargs="?", default=None,
                    help="result/1 JSON file, or '-' for stdin")
    ap.add_argument("--device-audit", default=None,
                    help="device-side audit JSONL (default: the envelope's "
                         "audit_ref if it is a readable path)")
    ap.add_argument("--selftest", action="store_true",
                    help="run the pure-function self-test and exit")
    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest()
    if not args.envelope:
        ap.print_usage(sys.stderr)
        return 2

    try:
        if args.envelope == "-":
            env = json.loads(sys.stdin.read())
        else:
            with open(args.envelope, "r", encoding="utf-8") as f:
                env = json.load(f)
    except OSError as e:
        print("verify_result: cannot read envelope: %s" % e.strerror,
              file=sys.stderr)
        return 2
    except Exception as e:
        print("verify_result: envelope is not valid JSON: %s"
              % type(e).__name__, file=sys.stderr)
        return 2

    path = args.device_audit
    if path is None:
        ref = env.get("audit_ref") if isinstance(env, dict) else None
        if isinstance(ref, str) and os.path.isfile(ref):
            path = ref
        else:
            print("verify_result: no --device-audit given and audit_ref %r "
                  "is not a readable path" % (ref,), file=sys.stderr)
            return 2
    rows, err = load_audit_rows(path)
    if err:
        print("verify_result: %s" % err, file=sys.stderr)
        return 2
    ok, reasons = check_envelope(env, rows)
    for r in reasons:
        print("verify_result: FAILED: %s" % r, file=sys.stderr)
    if ok:
        print("verify_result: VERIFIED: envelope task_id=%s device=%s "
              "digest=%s resolves to its device-side ISSUE/ALLOW pair"
              % (env.get("task_id"), env.get("device"),
                 env.get("device_audit_digest")), file=sys.stderr)
        return 0
    return 1


def cmd_selftest() -> int:
    """Pure-function self-test of the cross-check (no files, no network)."""
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    def line(**kw):
        return json.dumps(kw, ensure_ascii=False, separators=(",", ":"))

    jti = "cafebabe12345678"
    issue = line(ts=1.0, event="ISSUE", jti=jti, task_id="t1", agent="agent-ro")
    allow = line(ts=2.0, event="ALLOW", jti=jti, task_id="t1",
                 agent="agent-ro", tool="llm.complete",
                 result_keys=["content_summary", "usage"], est_bytes=64)
    other_allow = line(ts=3.0, event="ALLOW", jti="deadbeefdeadbeef",
                       task_id="t2", agent="agent-ro", tool="llm.complete",
                       result_keys=["content_summary"], est_bytes=8)
    rows = [(issue, json.loads(issue)), (allow, json.loads(allow)),
            (other_allow, json.loads(other_allow))]

    def envelope(task_id="t1", digest="AUTO", **extra):
        env = {"schema": "result/1", "task_id": task_id, "device": "jetson",
               "engine": {"model_id": "m", "backend": "b"},
               "perf_ref": "p", "audit_ref": "a",
               "device_audit_digest": sha16(allow) if digest == "AUTO" else digest,
               "result": {"content_summary": "s", "usage": {}},
               "latency_ms": 12.5}
        env.update(extra)
        return env

    ok, why = check_envelope(envelope(), rows)
    check("crosscheck.verifies_real_pair", ok, why)
    ok, why = check_envelope(envelope(digest="0" * 16), rows)
    check("crosscheck.rejects_unresolvable_digest",
          not ok and any("no ALLOW row" in r for r in why), why)
    ok, why = check_envelope(envelope(digest=None), rows)
    check("crosscheck.rejects_null_digest",
          not ok and any("cannot be cross-checked" in r for r in why), why)
    ok, why = check_envelope(envelope(task_id="t2"), rows)
    check("crosscheck.rejects_task_id_mismatch",
          not ok and any("task_id" in r for r in why), why)
    lone_allow = [(allow, json.loads(allow))]      # ISSUE row missing
    ok, why = check_envelope(envelope(), lone_allow)
    check("crosscheck.rejects_allow_without_issue",
          not ok and any("ISSUE" in r for r in why), why)
    bad_env = envelope()
    bad_env.pop("latency_ms")
    ok, why = check_envelope(bad_env, rows)
    check("crosscheck.rejects_shape_violation",
          not ok and any("envelope invalid" in r for r in why), why)
    ok, why = check_envelope(envelope(digest="G" * 16), rows)
    check("crosscheck.rejects_malformed_digest",
          not ok and any("device_audit_digest" in r for r in why), why)
    dup = rows + [(allow, json.loads(allow))]      # same line twice
    ok, why = check_envelope(envelope(), dup)
    check("crosscheck.flags_duplicate_allow",
          not ok and any("matches 2 ALLOW rows" in r for r in why), why)
    legacy_rows = [(other_allow, json.loads(other_allow))]   # unrelated only
    ok, why = check_envelope(envelope(), legacy_rows)
    check("crosscheck.legacy_audit_no_pass",
          not ok and any("no ALLOW row" in r for r in why), why)

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
