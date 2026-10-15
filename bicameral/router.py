#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral router.py — minimal AUDITABLE task router (task/1 -> device).

Implements the routing half of docs/paradigm.md §3.5: 主控路由 =
capability × performance × permission × load, and — normatively — 「路由
必须可复审」: every decision appends one ROUTE event (JSONL) with the
candidate list, each candidate's decode_tps, the selection and its reason.
PoC scope (stated, not hidden): performance comes from the archived
bench/1 PerfRecords; permission = the device offers a run method (its
permission layer is the only execution path, see task.py execute-local);
load is not sampled yet and is recorded as null in the event rather than
invented. 与 server.py/install.py 同一工程哲学: stdlib single file,
fail-closed validation, diagnostics on stderr / data on stdout.

Subcommands:
    route <task.json>           score candidates, append ROUTE, print decision
    execute <task.json>         route, then run task.py execute-local on the
                                selected device (local subprocess, or ssh with
                                the task JSON on stdin) and read the result/1
                                envelope back from stdout; appends RESULT
    selftest / --selftest       pure-function self-test (scoring policy,
                                devices/perf schema validation, envelope
                                shape mirror)

Inputs (paths are CWD-relative; defaults match the paradigm stage-2/4 layout):
    --devices   examples/devices.json                     devices/1 manifest:
                                                          name / ssh / local /
                                                          run (执行方式) per device
    --bench-dir results/2026-10-14-probe-bench            perf-<name>.json
                                                          bench/1 PerfRecords
                                                          (per-device "perf"
                                                          override honoured)
    --audit     results/2026-10-15-stage4-task/route-audit.jsonl

Policy (latency_class -> score, tiebreak, both recorded in the event):
    interactive: min ttft_ms.mean, then max decode_tps.mean
    batch:       max decode_tps.mean, then min ttft_ms.mean
A candidate is viable only with a run method and a readable PerfRecord;
non-viable candidates stay in the event with the reason (可复审 includes
the ones that lost for lack of facts).

router.py does NOT import task.py (single-file deployability, same rule as
install.py not importing probe.py): the result/1 shape check is mirrored
below and both selftests pin the same contract.

Exit codes: 0 ok · 2 usage/schema error · 3 no viable candidate ·
4 execution failure (device run failed or envelope invalid).
Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time

DEVICES_SCHEMA = "devices/1"
BENCH_SCHEMA = "bench/1"
RESULT_SCHEMA = "result/1"                       # mirror of task.py

DEFAULT_DEVICES = "examples/devices.json"
DEFAULT_BENCH_DIR = "results/2026-10-14-probe-bench"
DEFAULT_AUDIT = "results/2026-10-15-stage4-task/route-audit.jsonl"

POLICY = {"interactive": "min ttft_ms.mean, then max decode_tps.mean",
          "batch": "max decode_tps.mean, then min ttft_ms.mean"}

EXECUTE_TIMEOUT_S = 180

TASK_ID_RE_STR = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"


# --------------------------------------------------------------------------- #
# schema validation (fail-closed)
# --------------------------------------------------------------------------- #

TASK_ID_RE = re.compile(TASK_ID_RE_STR)


def validate_devices(raw):
    """Strict devices/1 validation. Returns (devices, None) or (None, err)."""
    if not isinstance(raw, dict) or raw.get("schema") != DEVICES_SCHEMA:
        return None, "schema must be %r" % DEVICES_SCHEMA
    unknown = sorted(set(raw) - {"schema", "devices"})
    if unknown:
        return None, "unknown field(s): %s" % ", ".join(unknown)
    devs = raw.get("devices")
    if not isinstance(devs, list) or not devs:
        return None, "devices must be a non-empty list"
    out, seen = [], set()
    for d in devs:
        if not isinstance(d, dict):
            return None, "device entry must be an object"
        unknown = sorted(set(d) - {"name", "local", "ssh", "run",
                                   "perf", "audit_ref"})
        if unknown:
            return None, "unknown device field(s): %s" % ", ".join(unknown)
        for name in ("name", "local", "run"):
            if name not in d:
                return None, "device missing field: " + name
        name = d["name"]
        if not isinstance(name, str) or not TASK_ID_RE.match(name):
            return None, "device name must match %s" % TASK_ID_RE_STR
        if name in seen:
            return None, "duplicate device name: %s" % name
        seen.add(name)
        if not isinstance(d["local"], bool):
            return None, "device %s: local must be a bool" % name
        if not isinstance(d["run"], str) or not d["run"].strip():
            return None, "device %s: run must be a non-empty command" % name
        ssh = d.get("ssh")
        if ssh is not None and (not isinstance(ssh, str) or not ssh.strip()):
            return None, "device %s: ssh must be a non-empty string or null" % name
        if not d["local"] and not ssh:
            return None, "device %s: remote device needs ssh" % name
        for k in ("perf", "audit_ref"):
            v = d.get(k)
            if v is not None and (not isinstance(v, str) or not v.strip()):
                return None, "device %s: %s must be a non-empty string or null" % (name, k)
        out.append(d)
    return out, None


def load_devices(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except OSError as e:
        return None, "cannot read devices: %s" % e.strerror
    except Exception as e:
        return None, "devices is not valid JSON: %s" % type(e).__name__
    return validate_devices(raw)


def load_perf(path, expect_name):
    """Read one bench/1 PerfRecord, extract the routing facts.

    Returns (facts, None) or (None, err). facts = {decode_tps, ttft_ms,
    backend, engine, model}. A record that fails validation makes its
    candidate non-viable — the loss is recorded in the ROUTE event, never
    silent.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except OSError as e:
        return None, "cannot read perf: %s" % e.strerror
    except Exception as e:
        return None, "perf is not valid JSON: %s" % type(e).__name__
    if not isinstance(rec, dict) or rec.get("schema") != BENCH_SCHEMA:
        return None, "perf schema must be %r" % BENCH_SCHEMA
    if rec.get("device") != expect_name:
        return None, "perf device %r does not match candidate %r" % (
            rec.get("device"), expect_name)
    summary = rec.get("summary")
    if not isinstance(summary, dict):
        return None, "perf missing summary"
    dt = (summary.get("decode_tps") or {}).get("mean")
    tt = (summary.get("ttft_ms") or {}).get("mean")
    if not isinstance(dt, (int, float)) or isinstance(dt, bool) \
            or not isinstance(tt, (int, float)) or isinstance(tt, bool):
        return None, "perf summary needs numeric decode_tps.mean and ttft_ms.mean"
    eng = rec.get("engine") or {}
    model = rec.get("model") or {}
    return {"decode_tps": float(dt), "ttft_ms": float(tt),
            "backend": eng.get("backend"),
            "engine": eng.get("name"),
            "model": model.get("name")}, None


# --------------------------------------------------------------------------- #
# scoring — pure, auditable
# --------------------------------------------------------------------------- #

def decide(latency_class, cands):
    """Order candidates by the class policy. Returns (ordered, reason).

    cands: [{device, viable, why, perf, perf_ref, ...}] — non-viable entries
    sort last and can never be selected. Pure: no I/O, selftest-covered.
    """
    def key(c):
        p = c.get("perf") or {}
        dt = p.get("decode_tps", float("-inf"))
        tt = p.get("ttft_ms", float("inf"))
        if latency_class == "interactive":
            return (0 if c["viable"] else 1, tt, -dt)
        return (0 if c["viable"] else 1, -dt, tt)

    ordered = sorted(cands, key=key)
    top = ordered[0] if ordered and ordered[0]["viable"] else None
    parts = ["%s decode_tps=%.2f tok/s ttft=%.2f ms" % (
        c["device"], (c.get("perf") or {}).get("decode_tps", float("nan")),
        (c.get("perf") or {}).get("ttft_ms", float("nan")))
        if c["viable"] else "%s NOT_VIABLE (%s)" % (c["device"], c.get("why"))
        for c in ordered]
    if top is None:
        return ordered, "no viable candidate among: %s" % "; ".join(parts)
    metric = ("min ttft_ms.mean" if latency_class == "interactive"
              else "max decode_tps.mean")
    return ordered, "%s: %s -> %s [%s]" % (latency_class, metric,
                                           top["device"], "; ".join(parts))


def route_event(task_id, latency_class, ordered, selected, reason):
    """One redacted ROUTE record: candidates + decode_tps + choice + why."""
    return {
        "ts": round(time.time(), 3),
        "event": "ROUTE",
        "task_id": task_id,
        "latency_class": latency_class,
        "policy": POLICY[latency_class],
        "load": None,                    # not sampled in the PoC — stated,
                                         # not invented (paradigm §7 spirit)
        "candidates": [{"device": c["device"],
                        "viable": c["viable"],
                        "decode_tps": (c.get("perf") or {}).get("decode_tps"),
                        "ttft_ms": (c.get("perf") or {}).get("ttft_ms"),
                        "score": (c.get("perf") or {}).get(
                            "ttft_ms" if latency_class == "interactive"
                            else "decode_tps"),
                        "perf_ref": c.get("perf_ref"),
                        "why": c.get("why") if not c["viable"] else None}
                       for c in ordered],
        "selected": selected,
        "reason": reason,
    }


def append_audit(path, rec):
    """Append one JSONL event (open-append-flush-close: crash-safe for a CLI)."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


# --------------------------------------------------------------------------- #
# result/1 shape — MIRROR of task.py validate_result (no import, by design)
# --------------------------------------------------------------------------- #

def validate_result(env):
    """Mirror of task.py validate_result; both selftests pin the contract."""
    if not isinstance(env, dict):
        return "envelope must be a JSON object"
    if env.get("schema") != RESULT_SCHEMA:
        return "schema must be %r" % RESULT_SCHEMA
    want = {"schema", "task_id", "device", "engine", "perf_ref", "audit_ref",
            "result", "latency_ms"}
    missing = sorted(want - set(env))
    unknown = sorted(set(env) - want)
    if missing:
        return "missing field(s): %s" % ", ".join(missing)
    if unknown:
        return "unknown field(s): %s" % ", ".join(unknown)
    for name in ("task_id", "device", "perf_ref", "audit_ref"):
        if not isinstance(env.get(name), str) or not env[name]:
            return "%s must be a non-empty string" % name
    eng = env.get("engine")
    if not isinstance(eng, dict) or set(eng) != {"model_id", "backend"}:
        return "engine must be exactly {model_id, backend}"
    res = env.get("result")
    if not isinstance(res, dict) or set(res) != {"content_summary", "usage"}:
        return "result must be exactly {content_summary, usage}"
    if not isinstance(res["content_summary"], str):
        return "result.content_summary must be a string"
    if not isinstance(env.get("latency_ms"), (int, float)) \
            or isinstance(env.get("latency_ms"), bool) or env["latency_ms"] < 0:
        return "latency_ms must be a non-negative number"
    return None


# --------------------------------------------------------------------------- #
# candidate assembly
# --------------------------------------------------------------------------- #

def build_candidates(devices, bench_dir):
    """devices/1 entries + PerfRecord facts -> scored candidate list."""
    cands = []
    for d in devices:
        name = d["name"]
        perf_ref = d.get("perf") or os.path.join(bench_dir, "perf-%s.json" % name)
        c = {"device": name, "run": d["run"], "ssh": d.get("ssh"),
             "local": d["local"], "perf_ref": perf_ref,
             "audit_ref": d.get("audit_ref") or "unknown",
             "perf": None, "viable": False, "why": None}
        if not d["local"] and not (d.get("ssh") or "").strip():
            c["why"] = "no run path (remote without ssh)"
        else:
            perf, err = load_perf(perf_ref, name)
            if err:
                c["why"] = err
            else:
                c["perf"], c["viable"] = perf, True
        cands.append(c)
    return cands


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def _route_once(args, task):
    """Validate inputs, score, append ROUTE. Returns (selected, cands, err)."""
    devices, err = load_devices(args.devices)
    if err:
        return None, None, "devices: %s" % err
    cands = build_candidates(devices, args.bench_dir)
    ordered, reason = decide(task["latency_class"], cands)
    selected = ordered[0]["device"] if ordered and ordered[0]["viable"] else None
    append_audit(args.audit, route_event(task["task_id"],
                                         task["latency_class"],
                                         ordered, selected, reason))
    return selected, ordered, (None if selected else "no viable candidate: %s" % reason)


def cmd_route(args) -> int:
    task, err = load_task(args.task)
    if err:
        print("router: task: %s" % err, file=sys.stderr)
        return 2
    selected, ordered, err = _route_once(args, task)
    if err:
        print("router: %s" % err, file=sys.stderr)
        return 3
    decision = route_event(task["task_id"], task["latency_class"],
                           ordered, selected,
                           decide(task["latency_class"], ordered)[1])
    print(json.dumps(decision, ensure_ascii=False, indent=2))
    print("router: ROUTE appended to %s" % args.audit, file=sys.stderr)
    return 0


def _run_on_device(cand, task, args):
    """Run execute-local on the candidate; returns (envelope, err).

    Transport: the task JSON goes in on stdin, the result/1 envelope comes
    back as exactly one JSON line on stdout (the ask's「stdout JSON」; scp is
    the alternate channel and is deliberately not needed here).
    """
    argv = shlex.split(cand["run"]) + [
        "-", "--device", cand["device"],
        "--perf-ref", cand["perf_ref"],
        "--audit-ref", cand["audit_ref"],
    ]
    backend = (cand.get("perf") or {}).get("backend")
    if backend:
        argv += ["--backend", backend]
    if cand["local"]:
        cmd = argv
    else:
        cmd = ["ssh"] + shlex.split(cand["ssh"]) + [" ".join(shlex.quote(a) for a in argv)]
    try:
        proc = subprocess.run(
            cmd, input=json.dumps(task, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return None, "device run timed out after %ss" % args.timeout
    except OSError as e:
        return None, "device run failed to start: %s" % e
    if proc.returncode != 0:
        return None, "device run exit %d: %s" % (
            proc.returncode, proc.stderr.decode("utf-8", "replace").strip()[:200])
    try:
        env = json.loads(proc.stdout.decode("utf-8", "replace").strip())
    except Exception:
        return None, "device stdout is not a JSON envelope"
    err = validate_result(env)
    if err:
        return None, "envelope invalid: %s" % err
    return env, None


def cmd_execute(args) -> int:
    task, err = load_task(args.task)
    if err:
        print("router: task: %s" % err, file=sys.stderr)
        return 2
    selected, ordered, err = _route_once(args, task)
    if err:
        print("router: %s" % err, file=sys.stderr)
        return 3
    cand = next(c for c in ordered if c["device"] == selected)
    print("router: selected %s (%s)" % (selected, POLICY[task["latency_class"]]),
          file=sys.stderr)
    env, err = _run_on_device(cand, task, args)
    if err:
        append_audit(args.audit, {"ts": round(time.time(), 3), "event": "EXECUTE_FAIL",
                                  "task_id": task["task_id"], "device": selected,
                                  "detail": err})
        print("router: execute failed: %s" % err, file=sys.stderr)
        return 4
    append_audit(args.audit, {
        "ts": round(time.time(), 3), "event": "RESULT",
        "task_id": task["task_id"], "device": env["device"],
        "latency_ms": env["latency_ms"],
        "model_id": env["engine"]["model_id"],
        "envelope_sha256_16": hashlib.sha256(
            json.dumps(env, ensure_ascii=False, sort_keys=True)
            .encode("utf-8")).hexdigest()[:16],
    })  # redaction: answer text never enters the audit (server.py promise)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(env, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("router: envelope written to %s" % args.out, file=sys.stderr)
    print(json.dumps(env, ensure_ascii=False, indent=2))
    return 0


def load_task(path):
    """Mirror of task.py load_task (router stays single-file)."""
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
    return validate_task_mirror(raw)


def validate_task_mirror(raw):
    """Minimal task/1 check (full authority lives in task.py validate_task).

    The router only needs: it IS a task/1 with a safe task_id and a
    latency_class it can score. Deep input/constraints validation is not
    duplicated here — the device-side executor re-validates with full
    authority before anything runs.
    """
    if not isinstance(raw, dict):
        return None, "task must be a JSON object"
    if raw.get("schema") != "task/1":
        return None, "schema must be 'task/1'"
    for name in ("task_id", "type", "input", "latency_class"):
        if name not in raw:
            return None, "missing field: " + name
    if not isinstance(raw["task_id"], str) or not TASK_ID_RE.match(raw["task_id"]):
        return None, "task_id must match %s" % TASK_ID_RE_STR
    if raw["latency_class"] not in POLICY:
        return None, "latency_class must be one of %s" % "|".join(sorted(POLICY))
    return raw, None


# --------------------------------------------------------------------------- #
# selftest — pure functions only (no network, no ssh, no files)
# --------------------------------------------------------------------------- #

def cmd_selftest(_args) -> int:
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    perf_jet = {"decode_tps": 67.48, "ttft_ms": 29.77, "backend": "CUDA"}
    perf_bi = {"decode_tps": 100.55, "ttft_ms": 23.57, "backend": "CPU"}

    def cand(name, perf, viable=True, why=None, local=False):
        return {"device": name, "run": "python3 task.py execute-local",
                "ssh": None if local else "-p 1 host", "local": local,
                "perf_ref": "perf-%s.json" % name, "audit_ref": "a",
                "perf": perf if viable else None,
                "viable": viable, "why": why}

    jet, bi = cand("jetson", perf_jet, local=True), cand("bi150", perf_bi)

    ordered, reason = decide("batch", [jet, bi])
    check("decide.batch_max_decode_tps",
          ordered[0]["device"] == "bi150" and "100.55" in reason, reason)
    ordered, _ = decide("interactive", [jet, bi])
    check("decide.interactive_min_ttft",
          ordered[0]["device"] == "bi150")          # 23.57 ms < 29.77 ms
    faster_ttft = cand("fast", {"decode_tps": 10.0, "ttft_ms": 5.0})
    check("decide.batch_ignores_ttft",
          decide("batch", [faster_ttft, bi])[0][0]["device"] == "bi150")
    check("decide.interactive_prefers_ttft_over_tps",
          decide("interactive", [faster_ttft, bi])[0][0]["device"] == "fast")

    dead = cand("ghost", None, viable=False, why="perf missing")
    ordered, reason = decide("batch", [dead, jet])
    check("decide.nonviable_never_selected",
          ordered[0]["device"] == "jetson" and "NOT_VIABLE" in reason, reason)
    ordered, reason = decide("batch", [dead])
    check("decide.none_viable", ordered[0]["device"] == "ghost"
          and "no viable" in reason, reason)

    ev = route_event("t1", "batch", decide("batch", [jet, bi])[0], "bi150", "r")
    check("route.event_shape",
          ev["event"] == "ROUTE" and ev["task_id"] == "t1"
          and ev["load"] is None
          and [c["device"] for c in ev["candidates"]] == ["bi150", "jetson"]
          and ev["candidates"][0]["decode_tps"] == 100.55
          and ev["selected"] == "bi150" and ev["reason"] == "r"
          and isinstance(ev["ts"], float))

    good_dev = {"schema": "devices/1", "devices": [
        {"name": "jetson", "local": True, "ssh": None, "run": "python3 t.py"},
        {"name": "bi150", "local": False, "ssh": "-p 1 h", "run": "python3 t.py"},
    ]}
    devs, err = validate_devices(good_dev)
    check("devices.accepts_good", devs is not None and err is None, err or "")

    def bad_dev(mutate, label):
        obj = json.loads(json.dumps(good_dev))
        mutate(obj)
        d, e = validate_devices(obj)
        check("devices.rejects_" + label, d is None and bool(e), e or "accepted")

    bad_dev(lambda o: o.update(extra=1), "unknown_top_field")
    bad_dev(lambda o: o["devices"][0].update(user="x"), "unknown_device_field")
    bad_dev(lambda o: o["devices"][0].pop("run"), "missing_run")
    bad_dev(lambda o: o["devices"][0].update(local="yes"), "local_not_bool")
    bad_dev(lambda o: o["devices"][0].update(run=""), "empty_run")
    bad_dev(lambda o: o["devices"][0].update(ssh=3), "ssh_not_str")
    bad_dev(lambda o: o["devices"][1].update(ssh=None), "remote_without_ssh")
    bad_dev(lambda o: o["devices"][1].update(name="a/b"), "bad_name")
    bad_dev(lambda o: o["devices"][1].__setitem__("name", "jetson"), "duplicate_name")

    ok_perf = {"schema": "bench/1", "device": "jetson",
               "summary": {"decode_tps": {"mean": 67.48},
                           "ttft_ms": {"mean": 29.77}},
               "engine": {"backend": "CUDA"}, "model": {"name": "Qwen3-0.6B"}}
    # load_perf reads a path (no filesystem in the pure selftest), so the
    # record-facts contract is pinned via decide() above; here we pin the
    # schema gate name and the negative path on a missing file:
    check("perf.schema_gate_mirror", ok_perf["schema"] == BENCH_SCHEMA)
    _, err = load_perf("definitely-missing-perf.json", "jetson")
    check("perf.missing_file_is_error", bool(err), err or "accepted")

    env = {"schema": "result/1", "task_id": "t1", "device": "bi150",
           "engine": {"model_id": "m", "backend": "CPU"},
           "perf_ref": "p", "audit_ref": "a",
           "result": {"content_summary": "s", "usage": {}},
           "latency_ms": 12.5}
    check("result.accepts_canonical", validate_result(env) is None,
          validate_result(env) or "")
    bad = json.loads(json.dumps(env)); bad.pop("audit_ref")
    check("result.rejects_missing_field", validate_result(bad) is not None)
    bad = json.loads(json.dumps(env)); bad["engine"]["extra"] = 1
    check("result.rejects_engine_extra", validate_result(bad) is not None)
    bad = json.loads(json.dumps(env)); bad["latency_ms"] = -1
    check("result.rejects_negative_latency", validate_result(bad) is not None)
    check("result.rejects_non_object", validate_result([]) is not None)

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="router.py",
        description="Bicameral task router — auditable task/1 -> device "
                    "selection (docs/paradigm.md §3.5). Stdlib-only, every "
                    "decision lands in the ROUTE audit.")
    ap.add_argument("--selftest", action="store_true",
                    help="run the pure-function self-test and exit")
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("task", help='task/1 JSON file, or "-" for stdin')
        p.add_argument("--devices", default=DEFAULT_DEVICES,
                       help="devices/1 manifest (default: %s)" % DEFAULT_DEVICES)
        p.add_argument("--bench-dir", default=DEFAULT_BENCH_DIR,
                       help="dir with perf-<name>.json (default: %s)"
                            % DEFAULT_BENCH_DIR)
        p.add_argument("--audit", default=DEFAULT_AUDIT,
                       help="ROUTE audit JSONL (default: %s)" % DEFAULT_AUDIT)

    ap_r = sub.add_parser("route", help="score candidates, print the decision")
    common(ap_r)

    ap_e = sub.add_parser("execute",
                          help="route, run execute-local on the winner, "
                               "read the envelope back")
    common(ap_e)
    ap_e.add_argument("--out", default=None,
                      help="also write the envelope JSON here")
    ap_e.add_argument("--timeout", type=float, default=EXECUTE_TIMEOUT_S,
                      help="device run timeout in seconds")

    sub.add_parser("selftest", help="pure-function self-test")

    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if args.cmd == "route":
        return cmd_route(args)
    if args.cmd == "execute":
        return cmd_execute(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
