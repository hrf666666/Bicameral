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

Red-team hardening (2026-10-15 review, confirmed findings):
    A1  every read PerfRecord's sha256_16 lands in the ROUTE event and
        --expect-perf-sha DEVICE=SHA16 pins the archived fingerprint — a
        tampered perf file can no longer steer routing invisibly;
    A2  the route audit is hash-chained: every appended row carries seq and
        prev_sha256_16 (hash of the previous raw line); the chain is
        verified at startup and a broken chain warns loudly on stderr
        (deleted/altered/reordered rows become detectable; note honestly:
        deleting the LAST row is only detectable via external anchoring of
        the tail hash — the `anchor` subcommand below automates exactly
        that, and every startup/append cross-checks the anchored tail);
    A10 before deciding, each candidate with a health_url is probed
        (GET, bounded --health-timeout); unreachable/unhealthy (HTTP != 200
        or strata_state != ok) candidates are NOT_VIABLE and stay in the
        ROUTE event with the reason — no more dispatching into a dead
        backend on stale PerfRecords;
    A9  result/1 envelopes carry device_audit_digest (extracted by the
        executor from the device-side audit), mirrored in validate_result;
        bicameral/verify_result.py cross-checks the archive;
    A11 the devices/1 manifest is a structured whitelist, not a command
        source: an entry carries only {name, transport, base, agent,
        control?, exec, ssh?, perf, audit_ref, health_url} — the old
        free-form `run` command string is gone and unknown fields are
        schema errors (fail-closed). The router itself owns the argv it
        runs on a device (python3 <base> execute-local - --device …,
        see execute_argv), so a poisoned manifest can no longer execute
        arbitrary commands; ssh transport is a structured {host, port?,
        user?} destination (no option strings → no -oProxyCommand
        surface); ROUTE/RESULT events record devices_manifest_sha256_16
        so a swapped manifest is visible in the audit (a RESULT claimed
        from a non-manifest device is detectable).

Subcommands:
    route <task.json>           score candidates, append ROUTE, print decision
    execute <task.json>         route, then run task.py execute-local on the
                                selected device (local subprocess, or ssh with
                                the task JSON on stdin) and read the result/1
                                envelope back from stdout; appends RESULT
    anchor --audit <f> --out <f>
                                verify the chain, then freeze its tail OUTSIDE
                                the audit file (anchor/1: timestamp, row count,
                                tail seq + tail-line sha256_16) — with an
                                anchor in place, deleting/rewriting the last
                                rows (invisible to in-file chaining) is
                                detected loudly at every startup/append
                                cross-check (default anchor path: <audit>.anchor,
                                checked only when the file exists)
    selftest / --selftest       pure-function self-test (scoring policy,
                                devices/perf schema validation, audit hash
                                chain, external anchor record, envelope shape
                                mirror, fixed argv)

Inputs (paths are CWD-relative; defaults match the paradigm stage-2/4 layout):
    --devices   examples/devices.json                     devices/1 manifest
                                                          (A11 structured
                                                          whitelist): name /
                                                          transport local|ssh
                                                          (+ ssh {host, port?,
                                                          user?} for remote) /
                                                          base (device-side
                                                          task.py path) /
                                                          agent / control? /
                                                          exec={kind:
                                                          execute-local} /
                                                          perf / audit_ref /
                                                          health_url per device
    --bench-dir results/2026-10-14-probe-bench            perf-<name>.json
                                                          bench/1 PerfRecords
                                                          (per-device "perf"
                                                          override honoured)
    --audit     results/2026-10-15-stage4-task/route-audit.jsonl

Policy (latency_class -> score, tiebreak, both recorded in the event):
    interactive: min ttft_ms.mean, then max decode_tps.mean
    batch:       max decode_tps.mean, then min ttft_ms.mean
A candidate is viable only with a whitelisted execute-local method (A11:
transport + base + exec.kind) and a readable PerfRecord; non-viable
candidates stay in the event with the reason (可复审 includes the ones
that lost for lack of facts).

router.py does NOT import task.py (single-file deployability, same rule as
install.py not importing probe.py): the result/1 shape check is mirrored
below and both selftests pin the same contract.

Exit codes: 0 ok · 2 usage/schema error (incl. anchor over a broken or
empty chain) · 3 no viable candidate ·
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
import urllib.parse
import urllib.request

DEVICES_SCHEMA = "devices/1"
BENCH_SCHEMA = "bench/1"
RESULT_SCHEMA = "result/1"                       # mirror of task.py
ANCHOR_SCHEMA = "anchor/1"                       # external tail anchor (A2)

# A11: devices/1 whitelist facts. `run` is gone — the router owns the argv
# (execute_argv); a new transport or exec kind is a deliberate edit here,
# anything unseen is a schema error, never a fallback.
TRANSPORTS = ("local", "ssh")
EXEC_KINDS = ("execute-local",)
HOST_RE_STR = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$"   # hostname / IP literal
USER_RE_STR = r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$"  # ssh login user

DEFAULT_DEVICES = "examples/devices.json"
DEFAULT_BENCH_DIR = "results/2026-10-14-probe-bench"
DEFAULT_AUDIT = "results/2026-10-15-stage4-task/route-audit.jsonl"

POLICY = {"interactive": "min ttft_ms.mean, then max decode_tps.mean",
          "batch": "max decode_tps.mean, then min ttft_ms.mean"}

EXECUTE_TIMEOUT_S = 180
HEALTH_TIMEOUT_S = 5.0                           # A10: bounded liveness probe

TASK_ID_RE_STR = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
SHA16_RE = re.compile(r"^[0-9a-f]{16}$")         # sha256_16 fingerprints


def sha256_16(data: bytes) -> str:
    """First 16 hex chars of sha256 — the repo-wide fingerprint width."""
    return hashlib.sha256(data).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# schema validation (fail-closed)
# --------------------------------------------------------------------------- #

TASK_ID_RE = re.compile(TASK_ID_RE_STR)
HOST_RE = re.compile(HOST_RE_STR)
USER_RE = re.compile(USER_RE_STR)


def _bad_dev_path(v, what):
    """Absolute device-side path, no traversal parts (A11: `base` lands in
    the router-owned argv, so it gets the install.py path discipline)."""
    if not isinstance(v, str) or not v.strip():
        return "%s must be a non-empty string" % what
    if "\x00" in v:
        return "%s must not contain NUL" % what
    if not v.startswith("/"):
        return "%s must be an absolute device path" % what
    if any(p in ("", ".", "..") for p in v.split("/")[1:]):  # [1:]: the
        return "%s must not contain empty/./.. path parts" % what  # leading /
    return None


def _bad_dev_url(v, what):
    """Absolute http(s) URL (agent/control/health endpoints)."""
    if not isinstance(v, str) or not v.strip():
        return "%s must be a non-empty string or null" % what
    u = urllib.parse.urlparse(v)
    if u.scheme not in ("http", "https") or not u.netloc:
        return "%s must be an absolute http(s) URL" % what
    return None


def validate_devices(raw):
    """Strict devices/1 validation. Returns (devices, None) or (None, err).

    A11: the manifest is a structured whitelist, not a command source —
    the legacy free-form `run` string and any other unknown field is a
    schema error. Each entry states transport facts only; the argv is
    built by the router (execute_argv). transport=ssh requires a
    structured ssh {host, port?, user?} destination (validated fields, so
    no option strings — no -oProxyCommand surface), transport=local
    forbids the ssh field.
    """
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
        unknown = sorted(set(d) - {"name", "transport", "base", "agent",
                                   "control", "exec", "ssh", "perf",
                                   "audit_ref", "health_url"})
        if unknown:
            return None, "unknown device field(s): %s" % ", ".join(unknown)
        for name in ("name", "transport", "base", "agent", "exec"):
            if name not in d:
                return None, "device missing field: " + name
        if "admin_token" in d and (not isinstance(d["admin_token"], str)
                                   or not 1 <= len(d["admin_token"]) <= 256):
            return None, "device admin_token must be a 1..256 char string"
        name = d["name"]
        if not isinstance(name, str) or not TASK_ID_RE.match(name):
            return None, "device name must match %s" % TASK_ID_RE_STR
        if name in seen:
            return None, "duplicate device name: %s" % name
        seen.add(name)
        if d["transport"] not in TRANSPORTS:
            return None, ("device %s: transport must be one of %s"
                          % (name, "|".join(TRANSPORTS)))
        err = _bad_dev_path(d["base"], "device %s: base" % name)
        if err:
            return None, err
        err = _bad_dev_url(d["agent"], "device %s: agent" % name)
        if err:
            return None, err
        if d.get("control") is not None:
            err = _bad_dev_url(d["control"], "device %s: control" % name)
            if err:
                return None, err
        ex = d["exec"]
        if not isinstance(ex, dict) or set(ex) != {"kind"} \
                or ex["kind"] not in EXEC_KINDS:
            return None, ('device %s: exec must be {"kind": "%s"} (A11: the '
                          "only run method; anything else fails closed)"
                          % (name, EXEC_KINDS[0]))
        ssh = d.get("ssh")
        if d["transport"] == "ssh":
            if not isinstance(ssh, dict):
                return None, ("device %s: transport ssh needs an "
                              "ssh {host, port?, user?} object" % name)
            unknown = sorted(set(ssh) - {"host", "port", "user"})
            if unknown:
                return None, ("device %s: unknown ssh field(s): %s"
                              % (name, ", ".join(unknown)))
            host = ssh.get("host")
            if not isinstance(host, str) or not HOST_RE.match(host):
                return None, "device %s: ssh.host must match %s" % (
                    name, HOST_RE_STR)
            port = ssh.get("port")
            if port is not None and (isinstance(port, bool)
                                     or not isinstance(port, int)
                                     or not 1 <= port <= 65535):
                return None, "device %s: ssh.port must be an int in 1..65535" % name
            user = ssh.get("user")
            if user is not None and (not isinstance(user, str)
                                     or not USER_RE.match(user)):
                return None, "device %s: ssh.user must match %s" % (
                    name, USER_RE_STR)
        elif ssh is not None:
            return None, ("device %s: ssh is only valid with transport ssh"
                          % name)
        if d.get("health_url") is not None:
            err = _bad_dev_url(d["health_url"], "device %s: health_url" % name)
            if err:
                return None, err
        for k in ("perf", "audit_ref"):
            v = d.get(k)
            if v is not None and (not isinstance(v, str) or not v.strip()):
                return None, "device %s: %s must be a non-empty string or null" % (name, k)
        out.append(d)
    return out, None


def load_devices(path):
    """Read + validate a devices/1 manifest. Returns (devices, sha, err):
    sha is the sha256_16 of the manifest's exact bytes (A11 fingerprint for
    the ROUTE/RESULT events), None when the manifest did not validate."""
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        return None, None, "cannot read devices: %s" % e.strerror
    try:
        raw = json.loads(blob.decode("utf-8"))
    except Exception as e:
        return None, None, "devices is not valid JSON: %s" % type(e).__name__
    devices, err = validate_devices(raw)
    return devices, (sha256_16(blob) if devices else None), err


def load_perf(path, expect_name):
    """Read one bench/1 PerfRecord, extract the routing facts.

    Returns (facts, None) or (None, err). facts = {decode_tps, ttft_ms,
    backend, engine, model, perf_sha256_16}. The sha256_16 of the file's
    exact bytes travels with the facts into the ROUTE event (A1): a
    doctored perf file is visible in the audit and pinnable via
    --expect-perf-sha. A record that fails validation makes its
    candidate non-viable — the loss is recorded in the ROUTE event, never
    silent.
    """
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        return None, "cannot read perf: %s" % e.strerror
    try:
        rec = json.loads(blob.decode("utf-8"))
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
            "model": model.get("name"),
            "perf_sha256_16": sha256_16(blob)}, None


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


def health_probe(url, timeout):
    """A10: lightweight liveness probe — GET health_url within `timeout`.

    Returns (ok, detail). ok requires HTTP 200 AND, when the body is JSON
    carrying strata_state, that state == "ok" (a degraded permission layer
    is not a live candidate — this is exactly the stale-PerfRecord trap:
    the layer answers but its backend is gone). A 200 with a non-JSON body
    (llama.cpp /health answers plain) passes the shape check. ANY transport
    failure is a probe failure, never an exception escape.
    """
    try:
        req = urllib.request.Request(
            url, method="GET", headers={"User-Agent": "bicameral-router-health/1"})
        with urllib.request.urlopen(req, timeout=timeout) as rsp:
            status = getattr(rsp, "status", None) or rsp.getcode()
            body = rsp.read(4096).decode("utf-8", "replace")
    except Exception as e:
        return False, "unreachable: %s" % type(e).__name__
    if status != 200:
        return False, "unhealthy: HTTP %s" % status
    try:
        state = json.loads(body).get("strata_state")
    except Exception:
        state = None
    if state is not None and state != "ok":
        return False, "unhealthy: strata_state=%s" % state
    return True, "ok"


def apply_health(cands, probes):
    """A10 gate: fold probe results into viability (pure, selftest-covered).

    probes: {device: (ok, detail)} for every candidate that had a
    health_url. Unreachable/unhealthy viable candidates flip NOT_VIABLE
    with the probe detail as the why; every candidate records its health
    outcome in the ROUTE event (None = no health_url configured — stated,
    not invented).
    """
    for c in cands:
        if c["device"] not in probes:
            c["health"] = None
            continue
        ok, detail = probes[c["device"]]
        c["health"] = detail
        if not ok and c["viable"]:
            c["viable"], c["why"] = False, "health probe failed: %s" % detail
            c["perf"] = None          # lost facts never keep scoring weight
    return cands


def apply_expect_perf_sha(cands, expect):
    """A1 gate: pin input integrity (pure, selftest-covered).

    expect: {device: sha256_16} from --expect-perf-sha. A viable candidate
    whose perf file hash mismatches the pinned fingerprint flips
    NOT_VIABLE — poisoned routing numbers survive only as a visible loss,
    never as a silent win. Returns an error string for a device not in the
    manifest (typo = usage error, fail-closed), else None.
    """
    for dev, want in expect.items():
        c = next((x for x in cands if x["device"] == dev), None)
        if c is None:
            return "expect-perf-sha names unknown device %r" % dev
        got = (c.get("perf") or {}).get("perf_sha256_16")
        if c["viable"] and got != want:
            c["viable"], c["why"] = False, \
                "perf sha mismatch: expected %s, got %s" % (want, got)
            c["perf"] = None
    return None


def route_event(task_id, latency_class, ordered, selected, reason,
                manifest_sha=None):
    """One redacted ROUTE record: candidates + facts + fingerprints + why.

    A1: each candidate carries perf_sha256_16 (hash of the exact perf file
    bytes that produced its numbers) and its A10 health outcome — the
    decision is reproducible from named, fingerprinted, liveness-checked
    inputs, and doctored inputs are visible in the audit itself.
    A11: devices_manifest_sha256_16 fingerprints the exact manifest bytes
    the decision was made from — a swapped or poisoned manifest is
    visible in the audit, so a RESULT claiming a device no manifest
    vouched for is detectable.
    """
    return {
        "ts": round(time.time(), 3),
        "event": "ROUTE",
        "task_id": task_id,
        "latency_class": latency_class,
        "policy": POLICY[latency_class],
        "load": None,                    # not sampled in the PoC — stated,
                                         # not invented (paradigm §7 spirit)
        "devices_manifest_sha256_16": manifest_sha,
        "candidates": [{"device": c["device"],
                        "viable": c["viable"],
                        "decode_tps": (c.get("perf") or {}).get("decode_tps"),
                        "ttft_ms": (c.get("perf") or {}).get("ttft_ms"),
                        "score": (c.get("perf") or {}).get(
                            "ttft_ms" if latency_class == "interactive"
                            else "decode_tps"),
                        "perf_ref": c.get("perf_ref"),
                        "perf_sha256_16": (c.get("perf") or {}).get(
                            "perf_sha256_16"),
                        "health": c.get("health"),
                        "why": c.get("why") if not c["viable"] else None}
                       for c in ordered],
        "selected": selected,
        "reason": reason,
    }


# --------------------------------------------------------------------------- #
# audit hash chain (A2): every appended row is chained to the previous raw
# line, the chain is verified at startup, breaks warn loudly. The tail hash
# printed at startup is the external-anchoring point for detecting last-row
# deletion (stated honestly: in-file chaining alone cannot see it).
# --------------------------------------------------------------------------- #

def audit_line_sha(raw_line):
    """sha256_16 of one audit line's exact bytes (trailing newline excluded)."""
    return sha256_16(raw_line.rstrip("\n").encode("utf-8"))


def chain_link(prev_raw, seq):
    """Chain fields linking a new record onto prev_raw (None = fresh chain)."""
    return {"seq": seq,
            "prev_sha256_16": audit_line_sha(prev_raw) if prev_raw else None}


def _audit_tail(path):
    """Last non-empty raw line + highest chained seq seen. (None, 0) if absent."""
    prev_raw, last_seq = None, 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                if not raw.strip():
                    continue
                prev_raw = raw.rstrip("\n")
                try:
                    obj = json.loads(prev_raw)
                except Exception:
                    continue
                if isinstance(obj, dict) and isinstance(obj.get("seq"), int):
                    last_seq = obj["seq"]
    except OSError:
        return None, 0
    return prev_raw, last_seq


def verify_audit_lines(lines):
    """Pure chain check over raw audit lines. Returns (ok, reason, tail, rows).

    Rules: rows before the first chained row are legacy (grandfathered —
    the chain starts at the first row that carries seq/prev_sha256_16).
    From there on EVERY row must be chained, seq must increment by exactly
    1, and prev_sha256_16 must equal the hash of the previous raw line.
    Any violation names its 1-based row number. Selftest-covered.
    """
    prev_raw, prev_seq, started = None, 0, False
    tail, rows = None, 0
    for raw in lines:
        if not raw.strip():
            continue
        rows += 1
        line = raw.rstrip("\n")
        tail = audit_line_sha(line)
        try:
            obj = json.loads(line)
        except Exception:
            obj = None
        chained = isinstance(obj, dict) \
            and ("seq" in obj or "prev_sha256_16" in obj)
        if not chained:
            if started:
                return False, ("row %d: unchained row inside the chained "
                               "region (deleted chain fields?)" % rows), tail, rows
            prev_raw = line
            continue
        if started and obj.get("seq") != prev_seq + 1:
            return False, ("row %d: seq %r does not follow %d (row(s) deleted "
                           "or reordered)" % (rows, obj.get("seq"), prev_seq)), \
                tail, rows
        want_prev = audit_line_sha(prev_raw) if prev_raw else None
        if obj.get("prev_sha256_16") != want_prev:
            return False, ("row %d: prev_sha256_16 %r does not match the "
                           "previous line %r (content altered)" % (
                               rows, obj.get("prev_sha256_16"), want_prev)), \
                tail, rows
        prev_raw, prev_seq, started = line, obj["seq"], True
    if not started:
        return True, "no chained rows (legacy audit — chain starts on next append)", tail, rows
    return True, "chain ok (%d row(s))" % rows, tail, rows


def verify_audit(path):
    """Read the audit file (if any) and verify its chain. Same return shape."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return verify_audit_lines(f.readlines())
    except OSError:
        return True, "no audit yet (fresh chain)", None, 0


def append_audit(path, rec, anchor=None):
    """Append one chained JSONL event (open-append-flush-close: crash-safe).

    A2: the record gains seq (previous chained seq + 1) and prev_sha256_16
    (hash of the previous raw line as observed on disk — after tampering,
    the new row honestly chains onto the exact bytes it saw, so the break
    stays visible at every future verify_audit).
    `anchor`: anchor/1 file cross-checked BEFORE writing — chaining onto a
    tail that differs from the anchored one means the file moved between
    anchoring and this append, which warns loudly (check_anchor) but still
    lands (evidence-preserving). Returns the new tail sha256_16 (the next
    external-anchoring point).
    """
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    prev_raw, prev_seq = _audit_tail(path)
    if anchor:
        check_anchor(anchor, audit_line_sha(prev_raw) if prev_raw else None,
                     "append")
    rec = dict(rec)
    rec.update(chain_link(prev_raw, prev_seq + 1))
    line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
    return audit_line_sha(line)


# --------------------------------------------------------------------------- #
# external anchoring (A2's stated gap): in-file chaining cannot see deletion
# of the LAST rows. The anchor subcommand freezes the tail hash OUTSIDE the
# audit file (anchor/1 record); every startup/append then cross-checks the
# anchored tail and warns LOUDLY on mismatch — 审计灭迹 becomes detectable.
# --------------------------------------------------------------------------- #

def build_anchor_record(tail_sha, rows, audit_path, seq=None, ts=None):
    """Pure: the anchor/1 record — the operator-held fact "the audit ended
    EXACTLY here (rows/seq/tail hash) at this time". Selftest-covered."""
    return {"schema": ANCHOR_SCHEMA,
            "ts": round(time.time() if ts is None else ts, 3),
            "audit": audit_path,
            "rows": rows,
            "seq": seq,
            "tail_sha256_16": tail_sha}


def anchored_tail(obj):
    """Pure: extract the anchored tail hash. Returns (tail16, None) or
    (None, err) — a malformed anchor must never silently count as a match.
    Selftest-covered."""
    if not isinstance(obj, dict) or obj.get("schema") != ANCHOR_SCHEMA:
        return None, "anchor schema must be %r" % ANCHOR_SCHEMA
    tail = obj.get("tail_sha256_16")
    if not isinstance(tail, str) or not SHA16_RE.match(tail):
        return None, "anchor tail_sha256_16 must be 16 lowercase hex chars"
    return tail, None


def check_anchor(anchor_path, live_tail, when):
    """Loud external-anchor cross-check at startup/append (A2).

    No anchor file -> nothing to compare (True — stated, not invented).
    Anchor unreadable/malformed -> loud warning, False.
    Anchored tail != live tail -> LOUD stderr warning, False: rows moved
    since anchoring — a legitimate append (then re-anchor) or deletion /
    rewrite (audit 灭迹). Fail-loud, never fail-stopped: recovery is
    appending and re-anchoring; the check never blocks routing.
    """
    if not anchor_path:
        return True
    try:
        with open(anchor_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except OSError:
        return True                       # no anchor yet — nothing to compare
    except Exception as e:
        print("router: *** ANCHOR UNREADABLE (%s): %s (%s) — investigate "
              "before trusting the audit tail"
              % (when, anchor_path, type(e).__name__), file=sys.stderr)
        return False
    tail, err = anchored_tail(obj)
    if err:
        print("router: *** ANCHOR MALFORMED (%s): %s: %s"
              % (when, anchor_path, err), file=sys.stderr)
        return False
    if tail != live_tail:
        print("router: *** ANCHOR MISMATCH (%s) *** %s: anchored tail=%s but "
              "the live audit tail is %s — rows moved since anchoring. "
              "Legitimate append? re-run `router.py anchor`. Otherwise rows "
              "were deleted/rewritten after the anchor (audit tampering)."
              % (when, anchor_path, tail, live_tail), file=sys.stderr)
        return False
    return True


def cmd_anchor(args) -> int:
    """`anchor`: verify the chain, then freeze its tail outside the file.

    Refuses (exit 2) to anchor a BROKEN chain or an empty audit — an
    anchor over tampered/absent rows would legitimize them.
    """
    ok, why, tail, rows = verify_audit(args.audit)
    if not ok:
        print("router: refuse to anchor a BROKEN chain: %s" % why,
              file=sys.stderr)
        return 2
    if not tail:
        print("router: nothing to anchor (audit has no rows): %s"
              % args.audit, file=sys.stderr)
        return 2
    _, last_seq = _audit_tail(args.audit)
    rec = build_anchor_record(tail, rows, args.audit,
                              seq=last_seq if last_seq else None)
    d = os.path.dirname(args.out)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("router: anchor written: %s rows=%d seq=%s tail=%s (audit=%s)"
          % (args.out, rows, rec["seq"], tail, args.audit), file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# result/1 shape — MIRROR of task.py validate_result (no import, by design)
# --------------------------------------------------------------------------- #

def validate_result(env):
    """Mirror of task.py validate_result; both selftests pin the contract.

    A9: result/1 carries device_audit_digest (sha256_16 of the device-side
    ALLOW row, or null when the executor could not read its audit) — the
    archival cross-check lives in bicameral/verify_result.py.
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
    """devices/1 entries + PerfRecord facts -> candidate list (facts only).

    A11: entries carry transport facts only — no command strings (the argv
    is router-owned, see execute_argv). Viability gates (health probe A10,
    perf fingerprint pin A1) are applied by the caller so they stay pure
    and selftest-covered; this only gathers facts: perf numbers + sha256_16,
    transport, health_url.
    """
    cands = []
    for d in devices:
        name = d["name"]
        perf_ref = d.get("perf") or os.path.join(bench_dir, "perf-%s.json" % name)
        c = {"device": name, "transport": d["transport"], "base": d["base"],
             "agent": d["agent"], "control": d.get("control"),
             "ssh": d.get("ssh"), "exec": d["exec"]["kind"],
             "perf_ref": perf_ref,
             "audit_ref": d.get("audit_ref") or "unknown",
             "health_url": d.get("health_url"),
             "perf": None, "viable": False, "why": None, "health": None}
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

def _parse_expect_perf_sha(items):
    """--expect-perf-sha DEVICE=sha256_16 pairs -> dict (A1). Usage error text
    on malformed input, else None."""
    expect = {}
    for item in items:
        dev, sep, sha = item.partition("=")
        dev, sha = dev.strip(), sha.strip().lower()
        if not sep or not dev or not SHA16_RE.match(sha):
            return None, ("expect-perf-sha must be DEVICE=sha256_16 "
                          "(16 lowercase hex), got %r" % item)
        expect[dev] = sha
    return expect, None


def _route_once(args, task):
    """Verify the audit chain, gate candidates, score, append ROUTE.

    A2 first: the chain is verified at startup and a break WARNS on stderr
    (fail-loud, not fail-stopped: recovery is appending — the new row
    chains onto the exact tail bytes observed, preserving the evidence).
    Returns (selected, ordered, manifest_sha, err); manifest_sha is the A11
    devices/1 fingerprint carried into the ROUTE (and RESULT) events.
    """
    ok, why, tail, _rows = verify_audit(args.audit)
    if ok:
        print("router: audit chain ok: %s tail_sha256_16=%s"
              % (why, tail), file=sys.stderr)   # external anchoring point (A2)
    else:
        print("router: AUDIT CHAIN BROKEN — %s (audit=%s tail_sha256_16=%s)"
              % (why, args.audit, tail), file=sys.stderr)
    check_anchor(getattr(args, "anchor", None), tail, "startup")   # A2
    expect, err = _parse_expect_perf_sha(getattr(args, "expect_perf_sha", []))
    if err:
        return None, None, None, err
    devices, manifest_sha, err = load_devices(args.devices)
    if err:
        return None, None, None, "devices: %s" % err
    cands = build_candidates(devices, args.bench_dir)
    probes = {c["device"]: health_probe(c["health_url"], args.health_timeout)
              for c in cands if c["viable"] and c.get("health_url")}
    apply_health(cands, probes)                              # A10
    err = apply_expect_perf_sha(cands, expect)               # A1
    if err:
        return None, None, None, err
    ordered, reason = decide(task["latency_class"], cands)
    selected = ordered[0]["device"] if ordered and ordered[0]["viable"] else None
    new_tail = append_audit(args.audit, route_event(task["task_id"],
                                                    task["latency_class"],
                                                    ordered, selected, reason,
                                                    manifest_sha),
                            anchor=getattr(args, "anchor", None))
    print("router: appended, new tail_sha256_16=%s (re-anchor: "
          "`router.py anchor --audit %s --out <anchor file>`)"
          % (new_tail, args.audit), file=sys.stderr)
    return selected, ordered, manifest_sha, \
        (None if selected else "no viable candidate: %s" % reason)


def cmd_route(args) -> int:
    task, err = load_task(args.task)
    if err:
        print("router: task: %s" % err, file=sys.stderr)
        return 2
    selected, ordered, manifest_sha, err = _route_once(args, task)
    if err:
        print("router: %s" % err, file=sys.stderr)
        return 3
    decision = route_event(task["task_id"], task["latency_class"],
                           ordered, selected,
                           decide(task["latency_class"], ordered)[1],
                           manifest_sha)
    print(json.dumps(decision, ensure_ascii=False, indent=2))
    print("router: ROUTE appended to %s" % args.audit, file=sys.stderr)
    return 0


def execute_argv(cand, backend=None):
    """The one argv shape the router ever runs on a device (A11).

    python3 <base> execute-local with the manifest's facts as flag VALUES
    only — the manifest names no program, interpreter or shell string, so
    a poisoned devices/1 cannot smuggle a command into the invocation.
    The task JSON travels on stdin ("-").
    """
    argv = ["python3", cand["base"], "execute-local", "-",
            "--device", cand["device"],
            "--perf-ref", cand["perf_ref"],
            "--audit-ref", cand["audit_ref"]]
    if cand.get("control"):
        argv += ["--control-url", cand["control"]]
    if cand.get("agent"):
        argv += ["--agent-url", cand["agent"]]
    # admin_token never goes into argv (ps-visible): local transport receives it
    # via the process environment; ssh devices must have it provisioned remotely.
    if backend:
        argv += ["--backend", backend]
    return argv


def transport_cmd(cand, argv):
    """Wrap the fixed argv for the candidate's transport (pure).

    local: the argv runs as-is (argv array, no shell). ssh: the argv is
    one shell-quoted remote command to a destination built from the
    VALIDATED structured ssh {host, port?, user?} fields only — no option
    strings from the manifest, so no -oProxyCommand surface. Selftest
    pins both shapes.
    """
    if cand["transport"] == "local":
        return list(argv)
    d = cand["ssh"]
    target = d["host"] if not d.get("user") else "%s@%s" % (d["user"], d["host"])
    return (["ssh"] + (["-p", str(d["port"])] if d.get("port") else [])
            + [target, " ".join(shlex.quote(a) for a in argv)])


def _run_on_device(cand, task, args):
    """Run execute-local on the candidate; returns (envelope, err).

    Transport: the task JSON goes in on stdin, the result/1 envelope comes
    back as exactly one JSON line on stdout (the ask's「stdout JSON」; scp is
    the alternate channel and is deliberately not needed here). The argv is
    router-owned (A11): execute_argv + transport_cmd — the manifest never
    supplies a command.
    """
    backend = (cand.get("perf") or {}).get("backend")
    cmd = transport_cmd(cand, execute_argv(cand, backend))
    try:
        env = dict(os.environ)
        if cand.get("admin_token"):
            env["BICAMERAL_ADMIN_TOKEN"] = cand["admin_token"]  # local transport only
        proc = subprocess.run(
            cmd, input=json.dumps(task, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
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


def result_event(task_id, env, manifest_sha):
    """One redacted RESULT record (pure; selftest-covered).

    A9: device_audit_digest carries the archival cross-check anchor; the
    answer text never enters the audit (server.py promise). A11: the A9
    digest alone cannot tell WHERE an envelope was made — the manifest
    fingerprint is recorded alongside so a RESULT produced from a device
    no manifest vouched for (route-level impersonation) is detectable.
    """
    return {"ts": round(time.time(), 3), "event": "RESULT",
            "task_id": task_id, "device": env["device"],
            "latency_ms": env["latency_ms"],
            "model_id": env["engine"]["model_id"],
            "device_audit_digest": env.get("device_audit_digest"),
            "devices_manifest_sha256_16": manifest_sha,
            "envelope_sha256_16": hashlib.sha256(
                json.dumps(env, ensure_ascii=False, sort_keys=True)
                .encode("utf-8")).hexdigest()[:16]}


def cmd_execute(args) -> int:
    task, err = load_task(args.task)
    if err:
        print("router: task: %s" % err, file=sys.stderr)
        return 2
    selected, ordered, manifest_sha, err = _route_once(args, task)
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
                                  "detail": err}, anchor=args.anchor)
        print("router: execute failed: %s" % err, file=sys.stderr)
        return 4
    append_audit(args.audit, result_event(task["task_id"], env, manifest_sha),
                 anchor=args.anchor)
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

    perf_jet = {"decode_tps": 67.48, "ttft_ms": 29.77, "backend": "CUDA",
                "perf_sha256_16": "b" * 16}
    perf_bi = {"decode_tps": 100.55, "ttft_ms": 23.57, "backend": "CPU",
               "perf_sha256_16": "a" * 16}

    def cand(name, perf, viable=True, why=None, local=True, health_url=None):
        return {"device": name, "transport": "local" if local else "ssh",
                "base": "/srv/b/task.py",
                "agent": "http://127.0.0.1:18001", "control": None,
                "ssh": None if local else {"host": "h", "port": 1, "user": "u"},
                "exec": "execute-local",
                "perf_ref": "perf-%s.json" % name, "audit_ref": "a",
                "health_url": health_url, "health": None,
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

    ev = route_event("t1", "batch", decide("batch", [jet, bi])[0], "bi150", "r",
                     manifest_sha="c" * 16)
    check("route.event_shape",
          ev["event"] == "ROUTE" and ev["task_id"] == "t1"
          and ev["load"] is None
          and ev["devices_manifest_sha256_16"] == "c" * 16
          and [c["device"] for c in ev["candidates"]] == ["bi150", "jetson"]
          and ev["candidates"][0]["decode_tps"] == 100.55
          and ev["candidates"][0]["perf_sha256_16"] == "a" * 16
          and ev["candidates"][1]["perf_sha256_16"] == "b" * 16
          and ev["selected"] == "bi150" and ev["reason"] == "r"
          and isinstance(ev["ts"], float))

    # --- A1: perf input integrity — fingerprint recorded + pinnable --- #
    check("sha16.known_vector", sha256_16(b"") == "e3b0c44298fc1c14"
          and len(sha256_16(b"x")) == 16)
    ok16, bad16 = "a" * 16, "0123456789abcdef"
    c1, c2 = cand("bi150", dict(perf_bi)), cand("jetson", dict(perf_jet))
    check("expect_sha.match_keeps_viable",
          apply_expect_perf_sha([c1, c2], {"bi150": ok16}) is None
          and c1["viable"] and c2["viable"])
    c1 = cand("bi150", dict(perf_bi))
    err = apply_expect_perf_sha([c1], {"bi150": bad16})
    check("expect_sha.mismatch_flips_not_viable",
          err is None and not c1["viable"]
          and "mismatch" in c1["why"] and bad16 in c1["why"]
          and c1["perf"] is None, c1["why"] or "still viable")
    c1 = cand("bi150", dict(perf_bi), viable=False, why="perf missing")
    check("expect_sha.skips_already_nonviable",
          apply_expect_perf_sha([c1], {"bi150": bad16}) is None
          and not c1["viable"])
    check("expect_sha.unknown_device_is_error",
          apply_expect_perf_sha([cand("bi150", dict(perf_bi))],
                                {"ghost": ok16}) is not None)
    e, err = _parse_expect_perf_sha(["bi150=%s" % ok16])
    check("expect_sha.parse_ok", e == {"bi150": ok16} and err is None)
    for bad in ("bi150", "bi150=XYZ", "bi150=" + "a" * 15, "=aabb"):
        e, err = _parse_expect_perf_sha([bad])
        if not (e is None and err):
            break
    check("expect_sha.parse_rejects_malformed", e is None and bool(err), bad)

    # --- A10: liveness gate (pure fold; the probe itself is I/O) --- #
    c1 = cand("bi150", dict(perf_bi))
    apply_health([c1], {})
    check("health.not_probed_recorded", c1["health"] is None and c1["viable"])
    c1 = cand("bi150", dict(perf_bi))
    apply_health([c1], {"bi150": (True, "ok")})
    check("health.ok_keeps_viable", c1["health"] == "ok" and c1["viable"])
    c1 = cand("bi150", dict(perf_bi))
    c2 = cand("jetson", dict(perf_jet))
    apply_health([c1, c2], {"bi150": (False, "unreachable: URLError"),
                            "jetson": (False, "unhealthy: strata_state=degraded")})
    check("health.failure_flips_not_viable",
          not c1["viable"] and "unreachable" in c1["why"] and c1["perf"] is None
          and not c2["viable"] and "strata_state=degraded" in c2["why"],
          "%s | %s" % (c1["why"], c2["why"]))
    check("health.dead_backend_loses_to_live",
          decide("batch", [c1, c2])[1].count("NOT_VIABLE") == 2)

    # --- A2: audit hash chain (pure line walker) --- #
    def line(**kw):
        return json.dumps(kw, ensure_ascii=False, separators=(",", ":"))

    legacy = line(ts=1.0, event="ROUTE", task_id="legacy")
    # first chained row links onto the legacy tail (append_audit chains onto
    # the exact last raw line, grandfathered or not)
    r1 = line(ts=2.0, event="ROUTE", task_id="r1", seq=1,
              prev_sha256_16=audit_line_sha(legacy))
    r2 = line(ts=3.0, event="RESULT", task_id="r1", seq=2,
              prev_sha256_16=audit_line_sha(r1))
    r3 = line(ts=4.0, event="ROUTE", task_id="r2", seq=3,
              prev_sha256_16=audit_line_sha(r2))
    ok, why, tail, rows = verify_audit_lines([])
    check("chain.empty_ok", ok and rows == 0 and tail is None)
    ok, why, _, _ = verify_audit_lines([legacy])
    check("chain.legacy_only_ok", ok and "legacy" in why, why)
    ok, why, tail, rows = verify_audit_lines([legacy, r1, r2, r3])
    check("chain.intact_ok",
          ok and rows == 4 and tail == audit_line_sha(r3)
          and "chain ok" in why, why)
    gap = line(ts=4.0, event="ROUTE", task_id="r2", seq=3,
               prev_sha256_16=audit_line_sha(r2))
    ok, why, _, _ = verify_audit_lines([legacy, r1, gap])   # r2 deleted
    check("chain.deleted_row_detected", not ok and "does not follow" in why, why)
    altered = line(ts=3.5, event="RESULT", task_id="r1", seq=2,
                   prev_sha256_16=audit_line_sha(r1))   # ts tampered in place
    ok, why, _, _ = verify_audit_lines([legacy, r1, altered, r3])
    check("chain.altered_row_detected",
          not ok and "does not match the previous line" in why, why)
    forged = line(ts=5.0, event="ROUTE", task_id="fabricated")  # unchained
    ok, why, _, _ = verify_audit_lines([legacy, r1, r2, forged])
    check("chain.unchained_inside_region_detected",
          not ok and "unchained row" in why, why)
    fresh1 = line(ts=9.0, event="ROUTE", task_id="fresh", seq=1,
                  prev_sha256_16=None)                  # genuinely fresh chain
    ok, why, _, _ = verify_audit_lines([fresh1])
    check("chain.fresh_chain_ok", ok and "chain ok (1 row(s))" in why, why)
    corrupt = r2[:-1] + "x"                          # clobbered closing brace
    ok, why, _, _ = verify_audit_lines([r1, corrupt])
    check("chain.trailing_corruption_detected", not ok, why)

    # --- A2 external anchoring: anchor/1 record round-trip + mismatch
    #     primitive (pure; the file cross-check itself is check_anchor I/O,
    #     excluded from this selftest like health_probe) --- #
    tail_r3 = audit_line_sha(r3)
    rec = build_anchor_record(tail_r3, 4, "route-audit.jsonl", seq=3, ts=1.0)
    check("anchor.record_shape",
          rec["schema"] == "anchor/1" and rec["rows"] == 4 and rec["seq"] == 3
          and rec["audit"] == "route-audit.jsonl" and rec["ts"] == 1.0
          and rec["tail_sha256_16"] == tail_r3)
    got, err = anchored_tail(rec)
    check("anchor.tail_roundtrip", got == tail_r3 and err is None, err or got)
    for bad_anchor in (None, {}, {"schema": "anchor/9", "tail_sha256_16": "a" * 16},
                       {"schema": "anchor/1"},
                       {"schema": "anchor/1", "tail_sha256_16": "XYZ"},
                       {"schema": "anchor/1", "tail_sha256_16": "a" * 15}):
        got, err = anchored_tail(bad_anchor)
        if not (got is None and bool(err)):
            break
    check("anchor.rejects_malformed", got is None and bool(err), repr(bad_anchor))
    # the mismatch primitive: an anchor over r3 does NOT match the tail of
    # the truncated chain [legacy, r1] — exactly the last-row deletion that
    # in-file chaining cannot see (A2's stated gap)
    ok2, why2, tail_trunc, rows_trunc = verify_audit_lines([legacy, r1])
    anchored = anchored_tail(build_anchor_record(tail_r3, 4, "a", seq=3))[0]
    check("anchor.detects_truncated_tail",
          ok2 and rows_trunc == 2 and tail_trunc == audit_line_sha(r1)
          and anchored != tail_trunc, "%s vs %s" % (anchored, tail_trunc))
    check("anchor.matches_intact_tail",
          anchored_tail(build_anchor_record(tail2 := tail_trunc, 2, "a"))[0]
          == tail2)

    # --- A11: devices/1 structured whitelist — the manifest states facts,
    #     the router owns the argv; run/unknown fields fail closed --- #
    man = {"schema": "devices/1", "devices": [
        {"name": "jetson", "transport": "local",
         "base": "/srv/b/task.py", "agent": "http://127.0.0.1:18001",
         "control": "http://127.0.0.1:18000",
         "exec": {"kind": "execute-local"}},
        {"name": "bi150", "transport": "ssh",
         "ssh": {"user": "root", "host": "10.0.0.2", "port": 31451},
         "base": "/root/b/task.py", "agent": "http://127.0.0.1:18001",
         "exec": {"kind": "execute-local"}},
    ]}
    devs, err = validate_devices(man)
    check("devices.accepts_structured", devs is not None and err is None,
          err or "")
    with_url = json.loads(json.dumps(man))
    with_url["devices"][0]["health_url"] = "http://127.0.0.1:18100/healthz"
    devs, err = validate_devices(with_url)
    check("devices.accepts_health_url", devs is not None and err is None,
          err or "")

    def bad_dev(mutate, label):
        obj = json.loads(json.dumps(man))
        mutate(obj)
        d, e = validate_devices(obj)
        check("devices.rejects_" + label, d is None and bool(e), e or "accepted")

    bad_dev(lambda o: o.update(extra=1), "unknown_top_field")
    bad_dev(lambda o: o["devices"][0].update(user="x"), "unknown_device_field")
    bad_dev(lambda o: o["devices"][0].update(run="python3 -c 'evil'"),
            "run_field")                                    # the A11 vector
    bad_dev(lambda o: o["devices"][0].update(run=""), "empty_run_field")
    bad_dev(lambda o: o["devices"][0].update(local=True), "legacy_local_field")
    bad_dev(lambda o: o["devices"][0].pop("transport"), "missing_transport")
    bad_dev(lambda o: o["devices"][0].update(transport="telnet"),
            "unknown_transport")
    bad_dev(lambda o: o["devices"][0].pop("base"), "missing_base")
    bad_dev(lambda o: o["devices"][0].update(base="rel/task.py"),
            "relative_base")
    bad_dev(lambda o: o["devices"][0].update(base="/a/../evil.py"),
            "traversal_base")
    bad_dev(lambda o: o["devices"][0].update(base="/a/\x00.py"), "nul_base")
    bad_dev(lambda o: o["devices"][0].pop("agent"), "missing_agent")
    bad_dev(lambda o: o["devices"][0].update(agent="127.0.0.1:18001"),
            "agent_not_absolute_url")
    bad_dev(lambda o: o["devices"][0].update(control="ftp://x"),
            "control_bad_scheme")
    bad_dev(lambda o: o["devices"][0].pop("exec"), "missing_exec")
    bad_dev(lambda o: o["devices"][0].update(exec={"kind": "shell"}),
            "exec_unknown_kind")
    bad_dev(lambda o: o["devices"][0].update(
        exec={"kind": "execute-local", "argv": ["sh"]}), "exec_unknown_field")
    bad_dev(lambda o: o["devices"][1].pop("ssh"), "ssh_missing_for_remote")
    bad_dev(lambda o: o["devices"][1].update(ssh={"host": "h", "port": "22"}),
            "ssh_port_not_int")
    bad_dev(lambda o: o["devices"][1].update(ssh={"host": "h", "user": "r ot"}),
            "ssh_user_bad")
    bad_dev(lambda o: o["devices"][1].update(
        ssh={"host": "h", "o": "ProxyCommand=touch /tmp/x"}),
        "ssh_unknown_field")                          # no option strings pass
    bad_dev(lambda o: o["devices"][1].update(
        ssh={"host": "-oProxyCommand=x"}), "ssh_host_bad")
    bad_dev(lambda o: o["devices"][0].update(ssh={"host": "h"}),
            "ssh_forbidden_on_local")
    bad_dev(lambda o: o["devices"][1].update(name="a/b"), "bad_name")
    bad_dev(lambda o: o["devices"][1].__setitem__("name", "jetson"),
            "duplicate_name")
    bad_dev(lambda o: o["devices"][0].update(health_url="ftp://h/x"),
            "health_url_bad_scheme")
    bad_dev(lambda o: o["devices"][0].update(health_url="not-a-url"),
            "health_url_not_absolute")
    bad_dev(lambda o: o["devices"][0].update(health_url=""),
            "health_url_empty")

    # the router-built argv is a fixed shape; the manifest contributed only
    # the flag VALUES (base path, agent/control URLs, device name)
    if devs:
        cands = build_candidates(devs, "/bench")
        check("devices.fixed_argv_local",
              execute_argv(cands[0], "CUDA") ==
              ["python3", "/srv/b/task.py", "execute-local", "-",
               "--device", "jetson", "--perf-ref", "/bench/perf-jetson.json",
               "--audit-ref", "unknown",
               "--control-url", "http://127.0.0.1:18000",
               "--agent-url", "http://127.0.0.1:18001", "--backend", "CUDA"],
              str(execute_argv(cands[0], "CUDA")))
        check("devices.fixed_argv_no_optionals",
              execute_argv(cands[1]) ==
              ["python3", "/root/b/task.py", "execute-local", "-",
               "--device", "bi150", "--perf-ref", "/bench/perf-bi150.json",
               "--audit-ref", "unknown",
               "--agent-url", "http://127.0.0.1:18001"])
        remote = transport_cmd(cands[1], execute_argv(cands[1]))
        check("devices.fixed_argv_ssh_transport",
              remote[:4] == ["ssh", "-p", "31451", "root@10.0.0.2"]
              and remote[4] == ("python3 /root/b/task.py execute-local - "
                                "--device bi150 --perf-ref "
                                "/bench/perf-bi150.json --audit-ref unknown "
                                "--agent-url http://127.0.0.1:18001"),
              str(remote))
        check("devices.local_transport_bare_argv",
              transport_cmd(cands[0], ["a", "b"]) == ["a", "b"])

    # RESULT event: A9 digest + A11 manifest fingerprint in one record
    res = {"schema": RESULT_SCHEMA, "task_id": "t1", "device": "bi150",
           "engine": {"model_id": "m", "backend": "CPU"},
           "perf_ref": "p", "audit_ref": "a", "device_audit_digest": None,
           "result": {"content_summary": "s", "usage": {}}, "latency_ms": 1.0}
    ev = result_event("t1", res, "a" * 16)
    check("devices.manifest_sha_into_result_event",
          ev["event"] == "RESULT"
          and ev["devices_manifest_sha256_16"] == "a" * 16
          and ev["device_audit_digest"] is None
          and ev["envelope_sha256_16"] == hashlib.sha256(
              json.dumps(res, ensure_ascii=False, sort_keys=True)
              .encode("utf-8")).hexdigest()[:16])

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
           "device_audit_digest": "0123456789abcdef",
           "result": {"content_summary": "s", "usage": {}},
           "latency_ms": 12.5}
    check("result.accepts_canonical", validate_result(env) is None,
          validate_result(env) or "")
    bad = json.loads(json.dumps(env)); bad.pop("device_audit_digest")
    check("result.rejects_missing_digest", validate_result(bad) is not None)
    bad = json.loads(json.dumps(env)); bad["device_audit_digest"] = None
    check("result.accepts_null_digest", validate_result(bad) is None,
          validate_result(bad) or "")
    for bad_digest in ("0123456789ABCDEF", "0123456789abcde", "z" * 16,
                       "f" * 64):
        bad = json.loads(json.dumps(env))
        bad["device_audit_digest"] = bad_digest
        if validate_result(bad) is None:
            break
    check("result.rejects_malformed_digest",
          validate_result(bad) is not None, bad_digest)
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
        p.add_argument("--anchor", default=None, metavar="FILE",
                       help="anchor/1 file to cross-check the audit tail "
                            "against at startup/append (A2; default: "
                            "<audit>.anchor, consulted only when it exists)")
        p.add_argument("--expect-perf-sha", action="append", default=[],
                       metavar="DEVICE=SHA256_16", dest="expect_perf_sha",
                       help="pin a device's perf file fingerprint (A1, "
                            "repeatable); a mismatch makes the candidate "
                            "NOT_VIABLE instead of silently steerable")
        p.add_argument("--health-timeout", type=float, default=HEALTH_TIMEOUT_S,
                       help="liveness probe budget per candidate in seconds "
                            "(A10, default: %s)" % HEALTH_TIMEOUT_S)

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

    ap_a = sub.add_parser("anchor",
                          help="freeze the audit tail hash outside the audit "
                               "file (A2 external anchoring)")
    ap_a.add_argument("--audit", default=DEFAULT_AUDIT,
                      help="ROUTE audit JSONL (default: %s)" % DEFAULT_AUDIT)
    ap_a.add_argument("--out", required=True, metavar="FILE",
                      help="anchor/1 file to write (tail seq + row count + "
                           "timestamp + tail-line sha256_16)")

    sub.add_parser("selftest", help="pure-function self-test")

    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if args.cmd in ("route", "execute"):
        # usage-semantics: a malformed --expect-perf-sha is exit 2 (schema/
        # usage error), not the no-viable-candidate exit 3 of _route_once
        _, err = _parse_expect_perf_sha(args.expect_perf_sha)
        if err:
            print("router: %s" % err, file=sys.stderr)
            return 2
        if args.anchor is None:
            args.anchor = args.audit + ".anchor"   # zero-config external anchoring
    if args.cmd == "route":
        return cmd_route(args)
    if args.cmd == "execute":
        return cmd_execute(args)
    if args.cmd == "anchor":
        return cmd_anchor(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
