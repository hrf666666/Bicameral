#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral fleet.py — device heartbeat / offline awareness (pull mode).

Implements device-level liveness for the fleet (docs/paradigm.md §3.1
probe/1 reports): the master knows, per device, whether it is reachable
NOW, or when it was last seen. 与 server.py/probe.py 同一工程哲学:
stdlib single file, diagnostics on stderr / data on stdout, fail-closed
validation, pure decision logic pinned by --selftest.

Why PULL and not push (网络现实 §1): devices cannot be assumed to accept
inbound connections — bi150 is reachable from outside ONLY via a mapped
ssh port (31451). So the heartbeat is master-initiated: the master runs
the probe ON each device through that device's transport and pulls the
probe/1 report back.
    local  -> python3 probe.py -o <tmp>   (direct subprocess)
    ssh    -> scp probe.py up, ssh-run it into <sandbox>/report.json,
              scp the report back           (the only channel guaranteed
                                              to exist)
A push model would need every device to hold a route/credential back to
the master and would silently invert trust (each device writes its own
liveness); pull keeps one writer (the master), one evidence chain (the
registry), and works through exactly the transport the manifest already
declares.

States (pure function classify, selftest-pinned):
    ONLINE   this check's probe succeeded — fresh report on disk
    STALE    this check's probe/ssh failed, but the registry holds a
             last-known-good report younger than --stale-s
    OFFLINE  probe failed and no fresh report exists (includes the
             first-ever probe failing: nothing was ever seen)

Registry (fleet-registry/1, one JSON file, master-owned): per device
{name, last_seen_ts, last_report_path, report_sha256_16}. Corruption is
tolerated, never fatal: bad entries are dropped with a stderr warning
and the file is rebuilt on the next successful check.

Daemon (resident mode): re-runs the exact check round every --interval,
prints a loud "*** STATE device: A -> B ***" event line on every state
transition (ONLINE/STALE/OFFLINE, "new" on first sighting, GONE when a
device leaves the manifest), appends each round to the daemon-owned hash
chain <registry_dir>/audit.jsonl (A2: seq + prev_sha256_16, mirror of
router.py) and writes the chain tail sha256_16 into the anchor file
(--anchor, default <registry_dir>/audit.anchor). The anchor is
deliberately a SEPARATE file from the audit: copy it off-host (see
deploy/systemd/README.md for a one-line cron) and deleting the LAST audit
row on the host becomes externally visible — the anchored tail no longer
matches the audit's actual tail. This closes the A2 residual (last-row
deletion is invisible to in-file chaining) by automating the external
anchoring the red-team review left as a manual ops action. SIGTERM/SIGINT
finish the current round and exit gracefully (exit 0).

Red line: every external invocation (python3 probe / ssh / scp) goes
through an injected runner callable — selftest exercises the ssh path
with a stub runner and never touches a real device.

Usage:
    python3 bicameral/fleet.py check --devices examples/devices.json \
            [--registry results/fleet/registry.json] [--stale-s 300]
    python3 bicameral/fleet.py status --registry results/fleet/registry.json
    python3 bicameral/fleet.py daemon --devices examples/devices.json \
            --registry results/fleet/registry.json --interval 300 \
            [--anchor results/fleet/audit.anchor]
    python3 bicameral/fleet.py selftest        # pure functions only
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time

PROBE_SCHEMA = "probe/1"
DEVICES_SCHEMA = "devices/1"
REGISTRY_SCHEMA = "fleet-registry/1"

ONLINE, STALE, OFFLINE = "ONLINE", "STALE", "OFFLINE"

DEFAULT_REGISTRY = "results/fleet/registry.json"
DEFAULT_STALE_S = 300.0
DEFAULT_INTERVAL_S = 300.0          # daemon round period
FLEET_AUDIT_NAME = "audit.jsonl"    # daemon-owned round chain, beside registry
FLEET_ANCHOR_NAME = "audit.anchor"  # anchor: a SEPARATE file, external anchor
ANCHOR_SCHEMA = "fleet-anchor/1"
ROUND_EVENT = "FLEET_ROUND"
DEFAULT_TIMEOUT_S = 120.0          # per subprocess step, per device
REMOTE_SANDBOX = "/tmp/bicameral-fleet"   # fleet-owned remote scratch dir
STDERR_EXCERPT = 200               # max chars of a child's stderr kept

TRANSPORTS = ("local", "ssh")
DEVICE_FIELDS = {"name", "transport", "base", "agent", "control", "exec",
                 "ssh", "perf", "audit_ref", "health_url"}  # devices/1 whitelist
SSH_FIELDS = {"host", "port", "user"}

NAME_RE_STR = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
HOST_RE_STR = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$"   # hostname / IP literal
USER_RE_STR = r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$"  # ssh login user
NAME_RE = re.compile(NAME_RE_STR)
HOST_RE = re.compile(HOST_RE_STR)
USER_RE = re.compile(USER_RE_STR)
SHA16_RE = re.compile(r"^[0-9a-f]{16}$")             # sha256_16 fingerprints

# ssh/scp hardening flags — fleet-owned constants, never manifest data
# (A11 lesson: structured destinations only, no option strings from the
# devices/1 file, so no -oProxyCommand surface). BatchMode fails instead
# of hanging on a password prompt; accept-new absorbs first-contact host
# keys without weakening known-host revocation.
SSH_OPTS = ["-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new"]

RunResult = type("RunResult", (), {})  # placeholder replaced below


# --------------------------------------------------------------------------- #
# pure decision core — classify + registry parsing (selftest-pinned)
# --------------------------------------------------------------------------- #

def classify(last_seen_age_s, probe_ok, stale_s):
    """Tri-state heartbeat decision. Pure; the one function the states mean.

    probe_ok True wins outright -> ONLINE (age is irrelevant, a fresh report
    was just pulled). Otherwise the registry's last-known-good age decides:
    never seen (None) -> OFFLINE (first probe failed), age <= stale_s ->
    STALE (report still fresh enough to trust), beyond -> OFFLINE. A
    negative age (master clock moved back / skew) clamps to 0. stale_s
    must be a positive number; last_seen_age_s a number or None; probe_ok
    strictly bool — violations raise, never silently decide.
    """
    if not isinstance(probe_ok, bool):
        raise TypeError("probe_ok must be bool, got %r" % (probe_ok,))
    if isinstance(stale_s, bool) or not isinstance(stale_s, (int, float)) \
            or not stale_s > 0:
        raise ValueError("stale_s must be a positive number, got %r" % (stale_s,))
    if probe_ok:
        return ONLINE
    if last_seen_age_s is None:
        return OFFLINE
    if isinstance(last_seen_age_s, bool) \
            or not isinstance(last_seen_age_s, (int, float)):
        raise TypeError("last_seen_age_s must be a number or None, got %r"
                        % (last_seen_age_s,))
    age = max(0.0, float(last_seen_age_s))
    return STALE if age <= stale_s else OFFLINE


def _good_entry(entry):
    """One registry device entry is well-formed (pure)."""
    if not isinstance(entry, dict):
        return False
    ts = entry.get("last_seen_ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return False
    path = entry.get("last_report_path")
    if not isinstance(path, str) or not path:
        return False
    sha = entry.get("report_sha256_16")
    return isinstance(sha, str) and bool(SHA16_RE.match(sha))


def parse_registry(text):
    """Pure: registry file text -> (registry dict | None, problems).

    Corruption tolerance contract: structurally unusable files (bad JSON,
    wrong schema, devices not an object) yield (None, problems) — the
    caller warns loudly and rebuilds. Per-entry rot (missing fields,
    non-numeric last_seen_ts, malformed sha) drops just that entry and
    reports it, keeping the healthy ones. Unknown top-level fields are
    ignored: the registry is master-owned and forward-compatible.
    """
    try:
        raw = json.loads(text)
    except (TypeError, ValueError) as e:
        return None, ["not valid JSON: %s" % type(e).__name__]
    if not isinstance(raw, dict) or raw.get("schema") != REGISTRY_SCHEMA:
        return None, ["schema must be %r" % REGISTRY_SCHEMA]
    devs = raw.get("devices")
    if not isinstance(devs, dict):
        return None, ["devices must be an object keyed by device name"]
    out, problems = {}, []
    for name, entry in devs.items():
        if _good_entry(entry):
            out[name] = {"last_seen_ts": entry["last_seen_ts"],
                         "last_report_path": entry["last_report_path"],
                         "report_sha256_16": entry["report_sha256_16"]}
        else:
            problems.append("dropped corrupt device entry %r" % name)
    sha = raw.get("manifest_sha256_16")
    return {"schema": REGISTRY_SCHEMA,
            "updated_ts": raw.get("updated_ts"),
            "manifest_sha256_16":
                sha if isinstance(sha, str) and SHA16_RE.match(sha) else None,
            "devices": out}, problems


def entry_age(registry, name, now):
    """Seconds since the device's last-known-good probe, or None (pure)."""
    entry = registry["devices"].get(name)
    if not entry:
        return None
    return max(0.0, now - entry["last_seen_ts"])


# --------------------------------------------------------------------------- #
# pure transport planning — the only places "ssh"/"scp" appear as argv[0]
# --------------------------------------------------------------------------- #

def _ssh_target(ssh_cfg):
    """user@host or bare host, from VALIDATED structured fields only."""
    return "%s@%s" % (ssh_cfg["user"], ssh_cfg["host"]) if ssh_cfg.get("user") \
        else ssh_cfg["host"]


def _ssh_port_flags(ssh_cfg):
    """-p for ssh, -P for scp (they really do differ)."""
    port = ssh_cfg.get("port")
    return (["-p", str(port)] if port else [])


def _scp_port_flags(ssh_cfg):
    port = ssh_cfg.get("port")
    return (["-P", str(port)] if port else [])


def probe_run_argv(probe_path, out_path):
    """local transport: the probe writes its report to a temp file."""
    return ["python3", probe_path, "-o", out_path]


def plan_ssh_probe(ssh_cfg, probe_path, remote_dir, local_report_path):
    """Pure. One ssh device's probe as three argv plans (A11: fleet-owned
    argv, structured destination, shell-quoted remote paths — a devices/1
    file contributes user/host/port values only, never command text).

    Returns [(label, argv), ...]: scp the probe up, run it remotely into
    <remote_dir>/report.json, scp the report back down.
    """
    target = _ssh_target(ssh_cfg)
    remote_probe = remote_dir + "/probe.py"
    remote_report = remote_dir + "/report.json"
    scp_up = (["scp"] + SSH_OPTS + _scp_port_flags(ssh_cfg)
              + [probe_path, "%s:%s" % (target, remote_probe)])
    ssh_mkdir = (["ssh"] + SSH_OPTS + _ssh_port_flags(ssh_cfg)
                 + [target, "mkdir -p %s" % shlex.quote(remote_dir)])
    remote_cmd = "python3 %s -o %s" % (
        shlex.quote(remote_probe), shlex.quote(remote_report))
    ssh_run = (["ssh"] + SSH_OPTS + _ssh_port_flags(ssh_cfg)
               + [target, remote_cmd])
    scp_down = (["scp"] + SSH_OPTS + _scp_port_flags(ssh_cfg)
                + ["%s:%s" % (target, remote_report), local_report_path])
    # mkdir must precede scp-up: scp does not create remote directories
    return [("ssh-mkdir", ssh_mkdir), ("scp-up", scp_up),
            ("ssh-run", ssh_run), ("scp-down", scp_down)]


def run_steps(steps, runner, timeout_s):
    """Execute planned argv steps through the INJECTED runner, stopping at
    the first failure. Pure given a pure runner — selftest drives ssh
    plans with a stub, so no real device is ever touched. Returns
    (failed_label | None, detail)."""
    for label, argv in steps:
        res = runner(argv, timeout_s)
        if res.rc != 0:
            err = res.stderr.decode("utf-8", "replace").strip()[:STDERR_EXCERPT]
            return label, "%s exit %d: %s" % (label, res.rc, err or "(no stderr)")
    return None, "ok"


# --------------------------------------------------------------------------- #
# pure report validation + formatting
# --------------------------------------------------------------------------- #

def validate_report_blob(blob):
    """Bytes pulled off a device -> (report dict | None, err). Fail-closed:
    only a real probe/1 object counts as evidence."""
    try:
        report = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return None, "report is not valid JSON: %s" % type(e).__name__
    if not isinstance(report, dict) or report.get("schema") != PROBE_SCHEMA:
        return None, "report schema must be %r" % PROBE_SCHEMA
    return report, None


def iso_utc(ts):
    return datetime.datetime.fromtimestamp(
        ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_age(age_s):
    return "-" if age_s is None else "%.1fs" % age_s


# --------------------------------------------------------------------------- #
# devices/1 manifest — heartbeat subset of router.validate_devices (mirror,
# both selftests pin the same structured-ssh contract)
# --------------------------------------------------------------------------- #

def validate_devices(raw):
    """Strict devices/1 validation for heartbeat use. Returns
    (devices, None) or (None, err).

    Same fail-closed philosophy as router.py: unknown fields rejected, ssh
    destinations strictly structured {host, port?, user?} — no option
    strings, so no -oProxyCommand surface. Heartbeat consumes only
    name/transport/ssh, so base/agent/exec are tolerated but not required
    (a fleet-only manifest stays valid; the router's own validator still
    governs task execution).
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
        unknown = sorted(set(d) - DEVICE_FIELDS)
        if unknown:
            return None, "unknown device field(s): %s" % ", ".join(unknown)
        name = d.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            return None, "device name must match %s" % NAME_RE_STR
        if name in seen:
            return None, "duplicate device name: %s" % name
        seen.add(name)
        if d.get("transport") not in TRANSPORTS:
            return None, ("device %s: transport must be one of %s"
                          % (name, "|".join(TRANSPORTS)))
        ssh = d.get("ssh")
        if d["transport"] == "ssh":
            if not isinstance(ssh, dict):
                return None, ("device %s: transport ssh needs an "
                              "ssh {host, port?, user?} object" % name)
            unknown = sorted(set(ssh) - SSH_FIELDS)
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
                return None, ("device %s: ssh.port must be an int in "
                              "1..65535" % name)
            user = ssh.get("user")
            if user is not None and (not isinstance(user, str)
                                     or not USER_RE.match(user)):
                return None, "device %s: ssh.user must match %s" % (
                    name, USER_RE_STR)
        elif ssh is not None:
            return None, "device %s: ssh is only valid with transport ssh" % name
        out.append(d)
    return out, None


def load_devices(path):
    """Read + validate devices/1. Returns (devices, manifest_sha16, err)."""
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
    if err:
        return None, None, err
    return devices, hashlib.sha256(blob).hexdigest()[:16], None


# --------------------------------------------------------------------------- #
# registry I/O (the only writer is the master — pull mode keeps it that way)
# --------------------------------------------------------------------------- #

def load_registry(path):
    """Read the registry, tolerating absence and corruption. Returns
    (registry dict, problems list). A missing or unusable file yields a
    fresh empty registry — the next successful check rebuilds it."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return ({"schema": REGISTRY_SCHEMA, "updated_ts": None,
                 "manifest_sha256_16": None, "devices": {}}), []
    reg, problems = parse_registry(text)
    if reg is None:
        problems = ["registry unreadable (%s) — starting fresh" % problems[0]]
        reg = ({"schema": REGISTRY_SCHEMA, "updated_ts": None,
                "manifest_sha256_16": None, "devices": {}})
    return reg, problems


def save_registry(path, registry):
    """Atomic write (tmp + os.replace) so a killed check never leaves a
    half-written evidence chain. Returns None or an error string."""
    parent = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(parent, exist_ok=True)
        tmp = os.path.join(parent, ".%s.tmp-%d" % (
            os.path.basename(path), os.getpid()))
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(registry, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
        return None
    except OSError as e:
        return "cannot write registry %s: %s" % (path, e.strerror or e)


# --------------------------------------------------------------------------- #
# daemon pure core — state diff + A2 chain + anchor assembly (selftest-pinned)
# --------------------------------------------------------------------------- #

def diff_states(prev_states, states):
    """One daemon round's registry diff (pure). prev_states/states are
    {device: state}; prev None = first sighting ("new" device), current
    None = the device left the manifest (GONE). Returns [(name, prev, cur)]
    for NEW and CHANGED devices only, sorted by name — an unchanged round
    diffs to []. State values are never interpreted here (any labels work),
    so the selftest pins the diff shape, not the vocabulary."""
    prev_states = prev_states or {}
    out = []
    for name in sorted(set(prev_states) | set(states)):
        prev = prev_states.get(name)
        cur = states.get(name)
        if prev != cur:
            out.append((name, prev, cur))
    return out


def audit_line_sha(raw_line):
    """sha256_16 of one audit line's exact bytes (trailing newline excluded).
    Mirror of router.py audit_line_sha — no import, by design (same policy
    as the devices/1 validator above)."""
    return hashlib.sha256(raw_line.rstrip("\n").encode("utf-8")).hexdigest()[:16]


def chain_link(prev_raw, seq):
    """Chain fields linking a new record onto prev_raw (mirror of
    router.py chain_link; None = fresh chain)."""
    return {"seq": seq,
            "prev_sha256_16": audit_line_sha(prev_raw) if prev_raw else None}


def audit_tail_raw(text):
    """Pure tail scan over audit file text (router.py _audit_tail
    semantics): (last non-empty raw line, highest chained seq seen).
    Legacy unchained rows still set prev_raw but not seq. (None, 0) when
    the audit has no rows yet."""
    prev_raw, last_seq = None, 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        prev_raw = raw
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("seq"), int):
            last_seq = obj["seq"]
    return prev_raw, last_seq


def round_event(round_no, states, manifest_sha, ts):
    """Pure: one FLEET_ROUND record body — what a daemon round observed
    (seq/prev_sha256_16 are added by append_audit_event, never here)."""
    return {"event": ROUND_EVENT,
            "round": round_no,
            "ts": round(ts, 3),
            "utc": iso_utc(ts),
            "states": dict(sorted(states.items())),
            "manifest_sha256_16": manifest_sha}


def anchor_text(tail_sha, seq, audit_path, ts):
    """Pure: the EXACT bytes written to the anchor file — one sorted-key
    JSON line + newline, so an external copy (cron-copied off-host) can be
    compared byte-for-byte against the audit's actual tail at any time."""
    return json.dumps({"schema": ANCHOR_SCHEMA,
                       "audit_path": audit_path,
                       "tail_sha256_16": tail_sha,
                       "seq": seq,
                       "updated_ts": round(ts, 3),
                       "updated_utc": iso_utc(ts)},
                      ensure_ascii=False, sort_keys=True) + "\n"


def append_audit_event(path, rec):
    """Append one chained JSONL event (router.py append_audit semantics:
    open-append-flush-fsync-close, crash-safe). The record honestly chains
    onto the exact tail bytes observed on disk — after tampering the break
    stays visible at every future verify — and the daemon's SEPARATE anchor
    file makes even last-row deletion externally comparable. Returns
    (new_tail_sha16, seq, None) or (None, None, err)."""
    d = os.path.dirname(path)
    try:
        if d:
            os.makedirs(d, exist_ok=True)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                prev_raw, prev_seq = audit_tail_raw(f.read())
        except OSError:
            prev_raw, prev_seq = None, 0
        rec = dict(rec)
        rec.update(chain_link(prev_raw, prev_seq + 1))
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        return audit_line_sha(line), rec["seq"], None
    except OSError as e:
        return None, None, "cannot append audit %s: %s" % (
            path, e.strerror or e)


def save_anchor(path, text):
    """Atomic anchor write (tmp + os.replace — same discipline as the
    registry, an externally compared file must never be seen half-written).
    Returns None or an error string."""
    parent = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(parent, exist_ok=True)
        tmp = os.path.join(parent, ".%s.tmp-%d" % (
            os.path.basename(path), os.getpid()))
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
        return None
    except OSError as e:
        return "cannot write anchor %s: %s" % (path, e.strerror or e)


# --------------------------------------------------------------------------- #
# the one door to the outside world — runner injection
# --------------------------------------------------------------------------- #

class RunResult:
    """Value object a runner returns: rc + captured stdout/stderr bytes."""
    __slots__ = ("rc", "stdout", "stderr")

    def __init__(self, rc, stdout, stderr):
        self.rc, self.stdout, self.stderr = rc, stdout, stderr


def default_runner(argv, timeout_s):
    """The ONLY place a real subprocess is spawned. cmd_check injects this;
    selftest injects a stub, so tests never touch devices or networks."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout_s)
        return RunResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return RunResult(124, b"",
                         ("timed out after %ss" % timeout_s).encode("utf-8"))
    except OSError as e:
        return RunResult(127, b"", ("failed to start: %s" % e).encode("utf-8"))


def probe_device(dev, probe_path, reports_dir, runner, timeout_s):
    """Pull one probe/1 report through the device's transport.

    Returns (report_path | None, sha256_16 | None, detail). The report is
    fetched to a temp file, validated as probe/1, THEN atomically moved to
    reports/<name>.json — last_report_path in the registry only ever
    points at a fully valid report (STALE evidence stays trustworthy).
    """
    name = dev["name"]
    os.makedirs(reports_dir, exist_ok=True)
    final = os.path.join(reports_dir, "%s.json" % name)
    tmp = os.path.join(reports_dir, ".%s.tmp-%d" % (name, os.getpid()))
    try:
        if dev["transport"] == "local":
            steps = [("probe", probe_run_argv(probe_path, tmp))]
        else:
            steps = plan_ssh_probe(dev["ssh"], probe_path, REMOTE_SANDBOX, tmp)
        failed, detail = run_steps(steps, runner, timeout_s)
        if failed:
            return None, None, detail
        with open(tmp, "rb") as f:
            blob = f.read()
        _, err = validate_report_blob(blob)
        if err:
            return None, None, err
        os.replace(tmp, final)
        return final, hashlib.sha256(blob).hexdigest()[:16], "ok"
    except OSError as e:
        return None, None, "%s" % (e.strerror or e)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# human table (stdout is data)
# --------------------------------------------------------------------------- #

def print_table(rows):
    headers = ("device", "transport", "state", "last_seen_utc",
               "age_s", "report_sha256_16", "detail")
    table = [headers] + [tuple(r[h] for h in headers) for r in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(headers))]
    for row in table:
        print("  ".join(cell.ljust(widths[i])
                        for i, cell in enumerate(row)).rstrip())


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def probe_round_rows(devices, registry, probe_path, reports_dir,
                     runner, timeout_s, stale_s, now):
    """One check round over every device: probe, classify, update the
    registry in place on ONLINE, return the table rows. This is exactly
    the loop cmd_check has always run — the daemon reuses it verbatim
    each round, so resident and one-shot checks can never drift apart."""
    rows = []
    for dev in devices:
        name = dev["name"]
        path, sha, detail = probe_device(
            dev, probe_path, reports_dir, runner, timeout_s)
        age = entry_age(registry, name, now)
        state = classify(age, path is not None, stale_s)
        if state == ONLINE:
            entry = registry["devices"].get(name) or {}
            registry["devices"][name] = {
                "last_seen_ts": round(time.time(), 3),
                "last_report_path": path,
                "report_sha256_16": sha}
        else:
            entry = registry["devices"].get(name) or {}
        rows.append({"device": name, "transport": dev["transport"],
                     "state": state,
                     "last_seen_utc": iso_utc(entry["last_seen_ts"])
                     if entry else "-",
                     "age_s": fmt_age(age),
                     "report_sha256_16": entry.get("report_sha256_16", "-")
                     if entry else "-",
                     "detail": "-" if state == ONLINE else detail})
    return rows


def cmd_check(args):
    devices, manifest_sha, err = load_devices(args.devices)
    if err:
        print("fleet: devices: %s" % err, file=sys.stderr)
        return 2
    registry, problems = load_registry(args.registry)
    for p in problems:
        print("fleet: registry: %s" % p, file=sys.stderr)
    reports_dir = os.path.join(
        os.path.dirname(os.path.abspath(args.registry)), "reports")
    now = time.time()
    rows = probe_round_rows(devices, registry, args.probe, reports_dir,
                            default_runner, args.timeout_s, args.stale_s,
                            now)
    registry["updated_ts"] = round(time.time(), 3)
    registry["manifest_sha256_16"] = manifest_sha
    print_table(rows)
    save_err = save_registry(args.registry, registry)
    if save_err:
        print("fleet: %s" % save_err, file=sys.stderr)
        return 2
    counts = {s: sum(1 for r in rows if r["state"] == s)
              for s in (ONLINE, STALE, OFFLINE)}
    print("fleet: %d device(s): %d ONLINE, %d STALE, %d OFFLINE "
          "(registry=%s stale_s=%g)"
          % (len(rows), counts[ONLINE], counts[STALE], counts[OFFLINE],
             args.registry, args.stale_s), file=sys.stderr)
    return 1 if counts[OFFLINE] else 0


def cmd_status(args):
    try:
        with open(args.registry, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        print("fleet: no registry at %s (%s) — run fleet.py check first"
              % (args.registry, e.strerror), file=sys.stderr)
        return 1
    registry, problems = parse_registry(text)
    for p in problems:
        print("fleet: registry: %s" % p, file=sys.stderr)
    if registry is None:
        print("fleet: registry %s is corrupt — run fleet.py check to rebuild"
              % args.registry, file=sys.stderr)
        return 1
    if not registry["devices"]:
        print("fleet: registry %s has no devices yet — run fleet.py check"
              % args.registry, file=sys.stderr)
        return 1
    now = time.time()
    rows = []
    for name in sorted(registry["devices"]):
        age = entry_age(registry, name, now)
        entry = registry["devices"][name]
        rows.append({"device": name, "transport": "-",
                     "state": classify(age, False, args.stale_s),
                     "last_seen_utc": iso_utc(entry["last_seen_ts"]),
                     "age_s": fmt_age(age),
                     "report_sha256_16": entry["report_sha256_16"],
                     "detail": "(no probe: status reads the registry only)"})
    print_table(rows)
    offline = sum(1 for r in rows if r["state"] == OFFLINE)
    print("fleet: %d device(s) in registry, %d OFFLINE (stale_s=%g)"
          % (len(rows), offline, args.stale_s), file=sys.stderr)
    return 1 if offline else 0


def cmd_daemon(args):
    """Resident loop: the exact check round every --interval, STATE-change
    events on transitions, every round chained onto the fleet audit with
    its tail sha256_16 anchored into a separate file (A2 residual closed:
    last-row deletion becomes externally visible). SIGTERM/SIGINT finish
    the current round — evidence and anchor are always consistent — and
    exit 0."""
    if not (isinstance(args.interval, (int, float)) and args.interval > 0):
        print("fleet: --interval must be a positive number of seconds, "
              "got %r" % (args.interval,), file=sys.stderr)
        return 2
    devices, manifest_sha, err = load_devices(args.devices)
    if err:
        print("fleet: devices: %s" % err, file=sys.stderr)
        return 2
    registry, problems = load_registry(args.registry)
    for p in problems:
        print("fleet: registry: %s" % p, file=sys.stderr)
    reg_dir = os.path.dirname(os.path.abspath(args.registry))
    reports_dir = os.path.join(reg_dir, "reports")
    audit_path = os.path.join(reg_dir, FLEET_AUDIT_NAME)
    anchor_path = args.anchor or os.path.join(reg_dir, FLEET_ANCHOR_NAME)
    # Previous states start as what `status` would print right now (the
    # probe-less registry classify) — a daemon restart therefore does not
    # invent spurious transitions; devices absent from the registry start
    # "new". The fleet audit is the daemon's own chain, co-located with the
    # registry; the anchor deliberately lives in a separate file.
    now = time.time()
    prev_states = {name: classify(entry_age(registry, name, now), False,
                                  args.stale_s)
                   for name in registry["devices"]}
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_nf: stop.set())
    print("fleet: daemon start pid=%d devices=%s registry=%s audit=%s "
          "anchor=%s interval=%gs stale_s=%gs"
          % (os.getpid(), args.devices, args.registry, audit_path,
             anchor_path, args.interval, args.stale_s), file=sys.stderr)
    rounds = 0
    while not stop.is_set():
        rounds += 1
        devices_r, manifest_r, err = load_devices(args.devices)
        if err:      # manifest broke mid-run: stay resident, retry later
            print("fleet: round %d: devices: %s (retrying next interval)"
                  % (rounds, err), file=sys.stderr)
            stop.wait(args.interval)
            continue
        now = time.time()
        rows = probe_round_rows(devices_r, registry, args.probe, reports_dir,
                                default_runner, args.timeout_s,
                                args.stale_s, now)
        states = {r["device"]: r["state"] for r in rows}
        for name, prev, cur in diff_states(prev_states, states):
            print("fleet: *** STATE %s: %s -> %s ***"
                  % (name, prev or "new", cur or "GONE"), file=sys.stderr)
        print_table(rows)
        registry["updated_ts"] = round(time.time(), 3)
        registry["manifest_sha256_16"] = manifest_r
        save_err = save_registry(args.registry, registry)
        if save_err:
            print("fleet: %s" % save_err, file=sys.stderr)
        counts = {s: sum(1 for r in rows if r["state"] == s)
                  for s in (ONLINE, STALE, OFFLINE)}
        print("fleet: round %d: %d device(s): %d ONLINE, %d STALE, "
              "%d OFFLINE (interval=%gs)"
              % (rounds, len(rows), counts[ONLINE], counts[STALE],
                 counts[OFFLINE], args.interval), file=sys.stderr)
        # A2 residual, automated: chain the round onto the fleet audit and
        # anchor the new tail into a separate, externally comparable file.
        ev = round_event(rounds, states, manifest_r, time.time())
        tail, seq, aerr = append_audit_event(audit_path, ev)
        if aerr:
            print("fleet: *** AUDIT APPEND FAILED — %s (round %d NOT "
                  "anchored) ***" % (aerr, rounds), file=sys.stderr)
        else:
            anchor_ts = time.time()
            aerr = save_anchor(anchor_path,
                               anchor_text(tail, seq, audit_path, anchor_ts))
            if aerr:
                print("fleet: *** ANCHOR WRITE FAILED — %s (tail "
                      "sha256_16=%s seq=%d NOT anchored) ***"
                      % (aerr, tail, seq), file=sys.stderr)
            else:
                print("fleet: anchored audit tail sha256_16=%s seq=%d -> %s"
                      % (tail, seq, anchor_path), file=sys.stderr)
        prev_states = states
        stop.wait(args.interval)   # returns at once when a signal fired
    print("fleet: daemon exit after %d round(s) (graceful)" % rounds,
          file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# selftest — pure functions + stub runner (no network, no ssh, no files)
# --------------------------------------------------------------------------- #

def cmd_selftest(_args) -> int:
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    # --- classify: the tri-state contract --- #
    check("classify.online_probe_wins",
          classify(99999.0, True, 300.0) == ONLINE
          and classify(None, True, 300.0) == ONLINE
          and classify(0.0, True, 300.0) == ONLINE)
    check("classify.stale_within_window",
          classify(10.0, False, 300.0) == STALE
          and classify(299.9, False, 300.0) == STALE)
    check("classify.stale_boundary_inclusive",
          classify(300.0, False, 300.0) == STALE)
    check("classify.offline_beyond_window",
          classify(300.1, False, 300.0) == OFFLINE
          and classify(86400.0, False, 300.0) == OFFLINE)
    check("classify.first_probe_never_seen",
          classify(None, False, 300.0) == OFFLINE)
    check("classify.clock_skew_clamped",
          classify(-5.0, False, 300.0) == STALE)
    for bad in (0, -1, "300", True, None):
        try:
            classify(1.0, False, bad)
            check("classify.rejects_stale_s_%r" % (bad,), False, "accepted")
        except ValueError:
            check("classify.rejects_stale_s_%r" % (bad,), True)
    try:
        classify(1.0, "yes", 300.0)
        check("classify.rejects_probe_ok_str", False, "accepted")
    except TypeError:
        check("classify.rejects_probe_ok_str", True)
    try:
        classify("x", False, 300.0)
        check("classify.rejects_age_str", False, "accepted")
    except TypeError:
        check("classify.rejects_age_str", True)

    # --- registry corruption tolerance --- #
    good_reg = json.dumps({
        "schema": REGISTRY_SCHEMA, "updated_ts": 1760000000.0,
        "manifest_sha256_16": "0123456789abcdef",
        "devices": {"jetson": {"last_seen_ts": 1760000000.0,
                               "last_report_path": "results/fleet/reports/"
                                                  "jetson.json",
                               "report_sha256_16": "9a4c1f2e3d5b6a70"}}})
    reg, problems = parse_registry(good_reg)
    check("registry.parses_good", reg is not None and not problems
          and "jetson" in reg["devices"]
          and reg["manifest_sha256_16"] == "0123456789abcdef")
    for label, text in [("corrupt_json", "{not json"),
                        ("wrong_schema", json.dumps({"schema": "fleet/2",
                                                     "devices": {}})),
                        ("devices_not_dict",
                         json.dumps({"schema": REGISTRY_SCHEMA,
                                     "devices": []})),
                        ("empty_string", "")]:
        reg, problems = parse_registry(text)
        check("registry.%s_yields_none" % label,
              reg is None and bool(problems), str(problems))
    rotten = json.loads(good_reg)
    rotten["devices"]["bi150"] = {"last_seen_ts": "yesterday"}       # bad ts
    rotten["devices"]["ghost"] = {"last_seen_ts": 1.0}               # missing
    rotten["devices"]["old"] = {"last_seen_ts": 1.0,
                                "last_report_path": "/x.json",
                                "report_sha256_16": "ZZ"}            # bad sha
    reg, problems = parse_registry(json.dumps(rotten))
    check("registry.drops_only_bad_entries",
          reg is not None and sorted(reg["devices"]) == ["jetson"]
          and len(problems) == 3, str(problems))
    reg, problems = parse_registry(json.dumps(
        {**json.loads(good_reg), "future_field": 1}))
    check("registry.unknown_top_ignored",
          reg is not None and "jetson" in reg["devices"])
    check("registry.entry_age_none_when_absent",
          entry_age({"devices": {}}, "x", 0.0) is None
          and entry_age({"devices": {"x": {"last_seen_ts": 100.0,
                                           "last_report_path": "/p",
                                           "report_sha256_16": "a" * 16}}},
                        "x", 160.0) == 60.0)

    # --- transport planning: structured fields only, no injection surface --- #
    steps = plan_ssh_probe({"user": "root", "host": "10.70.251.39",
                            "port": 31451},
                           "bicameral/probe.py", "/tmp/bicameral-fleet",
                           "/tmp/r/bi150.json")
    labels = [l for l, _ in steps]
    check("ssh.plan_four_steps_in_order",
          labels == ["ssh-mkdir", "scp-up", "ssh-run", "scp-down"], str(labels))
    ssh_mkdir = steps[0][1]
    check("ssh.mkdir_shape",
          ssh_mkdir[0] == "ssh" and ssh_mkdir[-1] == "mkdir -p /tmp/bicameral-fleet",
          " ".join(ssh_mkdir))
    scp_up = steps[1][1]
    check("ssh.scp_up_shape",
          scp_up[:2] == ["scp", "-o"] and "-P" in scp_up
          and scp_up[scp_up.index("-P") + 1] == "31451"
          and scp_up[-1] == "root@10.70.251.39:/tmp/bicameral-fleet/probe.py"
          and scp_up[-2] == "bicameral/probe.py", " ".join(scp_up))
    ssh_run = steps[2][1]
    check("ssh.run_shape",
          ssh_run[0] == "ssh" and "-p" in ssh_run
          and ssh_run[ssh_run.index("-p") + 1] == "31451"
          and ssh_run[-2] == "root@10.70.251.39"
          and ssh_run[-1] == ("python3 /tmp/bicameral-fleet/probe.py -o "
                              "/tmp/bicameral-fleet/report.json"),
          " ".join(ssh_run))
    check("ssh.batchmode_no_interactive_hang",
          "BatchMode=yes" in ssh_run and "ConnectTimeout=10" in ssh_run)
    check("ssh.hostile_manifest_values_cannot_add_options",
          all(not v.startswith("-") and "-o" not in v
              for v in (ssh_run[-2], scp_up[-1].split(":")[0])),
          "manifest strings must land as values, never flags")
    steps2 = plan_ssh_probe({"host": "h"}, "probe.py", "/tmp/s", "/tmp/r.json")
    check("ssh.defaults_no_port_no_user",
          "-P" not in steps2[1][1] and "-p" not in steps2[2][1]
          and steps2[1][1][-1] == "h:/tmp/s/probe.py"
          and steps2[2][1][-2] == "h"
          and steps2[0][1][-1] == "mkdir -p /tmp/s", " ".join(steps2[2][1]))
    check("local.probe_argv_shape",
          probe_run_argv("bicameral/probe.py", "/tmp/o.json")
          == ["python3", "bicameral/probe.py", "-o", "/tmp/o.json"])

    # --- runner injection: the ssh path runs through the stub, no device --- #
    ran = []

    def stub_runner(argv, timeout_s):
        ran.append((argv[0], timeout_s))
        return RunResult(0, b"", b"")

    failed, detail = run_steps(steps, stub_runner, 42.0)
    check("runner.stub_success_runs_all_steps",
          failed is None and detail == "ok"
          and [r[0] for r in ran] == ["ssh", "scp", "ssh", "scp"]
          and all(r[1] == 42.0 for r in ran), str(ran))
    ran.clear()

    def stub_failer(argv, timeout_s):
        ran.append(argv[0])
        if argv[0] == "ssh":
            return RunResult(255, b"", b"Connection refused\n")
        return RunResult(0, b"", b"")

    failed, detail = run_steps(steps, stub_failer, 42.0)
    check("runner.stub_failure_stops_at_step",
          failed == "ssh-mkdir" and "exit 255" in detail
          and "Connection refused" in detail and ran == ["ssh"],
          "%s | %s" % (ran, detail))
    check("runner.first_probe_failure_classifies_offline",
          classify(None, False, 300.0) == OFFLINE)
    check("runner.failure_with_fresh_report_classifies_stale",
          classify(45.0, False, 300.0) == STALE)

    # --- report validation: fail-closed evidence --- #
    good_blob = json.dumps(
        {"schema": "probe/1", "generated_at": "2026-10-16T00:00:00Z",
         "fingerprint": {"machine_id": "m", "probe_sha256_16": "a" * 16,
                         "fingerprint_id": "m-" + "a" * 16}}).encode("utf-8")
    rep, err = validate_report_blob(good_blob)
    check("report.accepts_probe1", rep is not None and err is None,
          err or "")
    for label, blob in [("rejects_garbage", b"\xff not json"),
                        ("rejects_wrong_schema",
                         b'{"schema": "probe/2"}'),
                        ("rejects_non_object", b"[1,2,3]")]:
        rep, err = validate_report_blob(blob)
        check("report.%s" % label, rep is None and bool(err), err or "accepted")

    # --- devices/1 validation mirrors the router's strictness --- #
    good_dev = {"schema": "devices/1", "devices": [
        {"name": "jetson", "transport": "local"},
        {"name": "bi150", "transport": "ssh",
         "ssh": {"user": "root", "host": "10.70.251.39", "port": 31451}}]}
    devs, err = validate_devices(good_dev)
    check("devices.accepts_heartbeat_subset", devs is not None and err is None,
          err or "")
    check("devices.local_rejects_ssh_field",
          validate_devices({"schema": "devices/1", "devices": [
              {"name": "x", "transport": "local", "ssh": {"host": "h"}}]})
          == (None, "device x: ssh is only valid with transport ssh"))
    check("devices.ssh_requires_structured_object",
          validate_devices({"schema": "devices/1", "devices": [
              {"name": "x", "transport": "ssh"}]})[1] is not None)
    check("devices.rejects_unknown_field",
          validate_devices({"schema": "devices/1", "devices": [
              {"name": "x", "transport": "local", "run": "rm -rf /"}]})
          [1] is not None)
    check("devices.rejects_option_injection_via_user",
          validate_devices({"schema": "devices/1", "devices": [
              {"name": "x", "transport": "ssh",
               "ssh": {"host": "h", "user": "-oProxyCommand"}}]})
          [1] is not None)
    check("devices.rejects_bad_port",
          validate_devices({"schema": "devices/1", "devices": [
              {"name": "x", "transport": "ssh",
               "ssh": {"host": "h", "port": "22"}}]})[1] is not None)

    # --- daemon pure core: round diff, A2 chain, anchor assembly --- #
    diff = diff_states({"jetson": ONLINE, "bi150": STALE},
                       {"bi150": STALE, "jetson": STALE, "bi100": ONLINE})
    check("daemon.diff_transition_and_new",
          diff == [("bi100", None, ONLINE), ("jetson", ONLINE, STALE)],
          str(diff))
    check("daemon.diff_no_change_is_empty",
          diff_states({"a": ONLINE, "b": OFFLINE},
                      {"b": OFFLINE, "a": ONLINE}) == [])
    check("daemon.diff_first_round_all_new",
          diff_states({}, {"a": OFFLINE, "b": ONLINE})
          == [("a", None, OFFLINE), ("b", None, ONLINE)],
          str(diff_states({}, {"a": OFFLINE, "b": ONLINE})))
    check("daemon.diff_reports_gone_device",
          diff_states({"x": STALE, "y": ONLINE}, {"y": ONLINE})
          == [("x", STALE, None)])

    check("daemon.audit_line_sha_excludes_newline",
          audit_line_sha('{"a":1}\n') == audit_line_sha('{"a":1}')
          and len(audit_line_sha("x")) == 16)
    prev_line = '{"event":"FLEET_ROUND","seq":1}'
    check("daemon.chain_link_hashes_prev_raw_bytes",
          chain_link(prev_line, 2) == {"seq": 2,
                                       "prev_sha256_16":
                                       audit_line_sha(prev_line)})
    check("daemon.chain_link_fresh_chain_null_prev",
          chain_link(None, 1) == {"seq": 1, "prev_sha256_16": None})
    check("daemon.audit_tail_raw_last_line_and_seq",
          audit_tail_raw("row-a\n\nrow-b\n") == ("row-b", 0)
          and audit_tail_raw('row-a\n{"seq":7}\n') == ('{"seq":7}', 7)
          and audit_tail_raw("") == (None, 0)
          and audit_tail_raw("legacy\n") == ("legacy", 0))
    ev = round_event(3, {"b": STALE, "a": ONLINE}, "0123456789abcdef",
                     1760000000.0)
    check("daemon.round_event_shape",
          ev == {"event": "FLEET_ROUND", "round": 3, "ts": 1760000000.0,
                 "utc": "2025-10-09T08:53:20Z", "states": {"a": ONLINE,
                                                           "b": STALE},
                 "manifest_sha256_16": "0123456789abcdef"}, str(ev))
    anchor = anchor_text("9a4c1f2e3d5b6a70", 4, "results/fleet/audit.jsonl",
                         1760000000.0)
    check("daemon.anchor_assembly_exact",
          anchor == json.dumps(
              {"schema": "fleet-anchor/1",
               "audit_path": "results/fleet/audit.jsonl",
               "tail_sha256_16": "9a4c1f2e3d5b6a70", "seq": 4,
               "updated_ts": 1760000000.0,
               "updated_utc": "2025-10-09T08:53:20Z"},
              ensure_ascii=False, sort_keys=True) + "\n",
          repr(anchor))
    check("daemon.anchor_is_one_line_and_separate_file",
          anchor.count("\n") == 1
          and FLEET_ANCHOR_NAME != FLEET_AUDIT_NAME
          and FLEET_ANCHOR_NAME.endswith(".anchor")
          and SHA16_RE.match(json.loads(anchor)["tail_sha256_16"]) is not None)

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    probe_default = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "probe.py")
    ap = argparse.ArgumentParser(
        prog="fleet.py",
        description="Bicameral fleet heartbeat (PULL mode): the master runs "
                    "probe/1 on each device through its transport and keeps "
                    "the last-known-good evidence in a registry. Stdlib-only, "
                    "diagnostics on stderr / data on stdout.")
    ap.add_argument("--selftest", action="store_true",
                    help="run the pure-function self-test and exit")
    sub = ap.add_subparsers(dest="cmd")

    ap_c = sub.add_parser(
        "check", help="probe every device now, update the registry, "
                      "print the state table (exit 1 if any device OFFLINE)")
    ap_c.add_argument("--devices", required=True, help="devices/1 manifest")
    ap_c.add_argument("--registry", default=DEFAULT_REGISTRY,
                      help="fleet-registry/1 path (default: %(default)s)")
    ap_c.add_argument("--stale-s", type=float, default=DEFAULT_STALE_S,
                      help="a failed probe stays STALE while the last "
                           "known-good report is younger than this many "
                           "seconds (default: %(default)s)")
    ap_c.add_argument("--probe", default=probe_default,
                      help="probe.py to ship/run (default: beside fleet.py)")
    ap_c.add_argument("--timeout-s", type=float, default=DEFAULT_TIMEOUT_S,
                      help="per subprocess step, per device "
                           "(default: %(default)s)")

    ap_s = sub.add_parser(
        "status", help="print per-device state/last-seen age from the "
                       "registry; never probes")
    ap_s.add_argument("--registry", default=DEFAULT_REGISTRY,
                      help="fleet-registry/1 path (default: %(default)s)")
    ap_s.add_argument("--stale-s", type=float, default=DEFAULT_STALE_S,
                      help="same freshness window as check "
                           "(default: %(default)s)")

    ap_d = sub.add_parser(
        "daemon", help="resident loop: the check round every --interval, "
                       "loud STATE-change events, each round chained onto "
                       "the fleet audit with its tail sha256_16 written to "
                       "a separate anchor file (SIGTERM/SIGINT exit "
                       "gracefully)")
    ap_d.add_argument("--devices", required=True, help="devices/1 manifest")
    ap_d.add_argument("--registry", default=DEFAULT_REGISTRY,
                      help="fleet-registry/1 path (default: %(default)s); "
                           "the daemon audit lives beside it as "
                           + FLEET_AUDIT_NAME)
    ap_d.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_S,
                      help="seconds between check rounds "
                           "(default: %(default)s)")
    ap_d.add_argument("--anchor", default=None,
                      help="file receiving the audit tail sha256_16 each "
                           "round — keep a copy OFF-HOST (default: "
                           + FLEET_ANCHOR_NAME + " beside the registry)")
    ap_d.add_argument("--stale-s", type=float, default=DEFAULT_STALE_S,
                      help="same freshness window as check "
                           "(default: %(default)s)")
    ap_d.add_argument("--probe", default=probe_default,
                      help="probe.py to ship/run (default: beside fleet.py)")
    ap_d.add_argument("--timeout-s", type=float, default=DEFAULT_TIMEOUT_S,
                      help="per subprocess step, per device "
                           "(default: %(default)s)")

    sub.add_parser("selftest", help="pure-function self-test "
                                    "(stub runner, no devices touched)")

    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "daemon":
        return cmd_daemon(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
