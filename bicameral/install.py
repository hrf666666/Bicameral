#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral install.py — appspec/1 controlled installation tool (mutating).

Implements docs/paradigm.md §3.4 (deployment & installation, the change
layer): one command takes one device from absent → ready, fully audited,
rollback on any failure. This is Bicameral's mutating controlled tool beyond
fs.write: sandboxed directories, size caps, bounded timeouts and retries,
audit events — 与 server.py 同一工程哲学 (stdlib single file).

Subcommands:
    apply <appspec.json>    absent → ready (idempotent: dedup by name +
                            model sha256 + deployment facts — port, health,
                            rendered args, engine — any drift restarts; a
                            re-apply on a ready app skips the download and
                            re-achieves READY)
    rollback <name>         remove one app, kill the process it started,
                            install_state → absent
    status [name]           report install_state from sandbox markers plus
                            live pid/health checks
    selftest                pure-function self-test (schema validation,
                            engine.install schema, URL building, dedup
                            decisions, redaction, pid-state/argv parsing,
                            tar-member traversal rejection, audit fail-closed)

Flow of apply (each step audited; ANY failure → rollback; the whole flow
runs under an exclusive <sandbox>/apps/<name>.lock — a second concurrent
apply of the same app exits 6 instead of racing the first):
    read appspec → validate schema (fail-closed engine whitelist, A5:
    engine.name must be listed in APPSPEC_ENGINE_BINARIES and engine.binary
    must have a whitelisted basename — interpreters never pass) → probe
    current install_state (sandbox
    marker + filesystem/service facts) → resolve engine (dual sha256, §5;
    with an engine.install node and no engine.binary, a not-on-disk engine
    is downloaded, verified and extracted first — see below) →
    download model (mirror_urls tried in order, bounded retries/timeouts; a
    hash mismatch on one mirror only fails that attempt) → verify sha256
    (mismatch ⇒ VERIFY_FAIL, the file is never installed) → place into
    <sandbox>/apps/<name>/ → start service → health check (the health
    endpoint must answer HTTP 200; an exited child is detected at once) →
    re-verify the placed sha256 (TOCTOU guard) → re-run probe/1 to refresh
    install_state → READY.

Engine-level install (optional engine.install node; the engine no longer
has to be pre-provisioned on the device):
    {"install": {"mirror_urls": ["http://…/llama-cpu.tgz"],   # concrete
                 "sha256": "<tarball sha256>", "format": "tgz",
                 "strip_components": 0, "binary_inside": "bin/llama-server"}}
    When engine.binary is absent and the whitelisted engine is not found on
    the device, the pinned tarball is downloaded with the same bounded
    machinery as models (mirror fallback, streaming sha256, stall guard,
    adaptive deadline) → extracted into <sandbox>/engines/<engine.name>/
    with per-member traversal checks (absolute names and any '..' part are
    rejected; links must stay inside; only dirs/regular files land) →
    binary_inside (or a unique whitelisted executable) is chmod 0755 →
    that path becomes engine.binary for the rest of the flow. Idempotent:
    an already-extracted resolvable engine skips the download. Audit:
    ENGINE_DOWNLOAD / ENGINE_VERIFY / ENGINE_PLACE (ENGINE_VERIFY_FAIL on
    a tarball-pin mismatch; a half-extracted tree is removed on failure).

Sandbox layout (default /root/bicameral-sandbox per paradigm; override with
--sandbox-root or BICAMERAL_SANDBOX_ROOT — the default assumes root; on a
non-root box redirect it):
    <sandbox>/apps/<name>/models/<file>                    installed model
    <sandbox>/apps/<name>/.bicameral-install-state.json    marker (state/pid/sha)
    <sandbox>/apps/<name>/service.log                      service stdout+stderr
    <sandbox>/apps/<name>.lock                             apply/rollback mutex
    <sandbox>/engines/<engine.name>/                       engine-level install
                                                           (engine.install node;
                                                           shared across apps)
    <sandbox>/downloads/<name>-<sha12>-<pid>.part          in-flight download
    <sandbox>/downloads/engine-<name>-<sha12>-<pid>.part   in-flight engine
                                                           archive download
    <sandbox>/audit.jsonl                                  audit trail (mandatory
                                                           for apply/rollback:
                                                           fail-closed when
                                                           unavailable)

Audit events (style-aligned with bicameral/server.py: ts + event + key
summary, never secrets — mirror URLs are redacted to scheme://host/path so a
token-bearing query never lands in the log):
    INSTALL_START, STATE, DEDUP, ENGINE_FOUND, ENGINE_DOWNLOAD,
    ENGINE_VERIFY, ENGINE_VERIFY_FAIL, ENGINE_PLACE, DOWNLOAD, VERIFY_OK,
    VERIFY_FAIL, PLACE, START, HEALTH, PROBE_REFRESH, READY, INSTALL_FAIL,
    ROLLBACK, AUDIT_DEGRADED (close-time: audit writes lost mid-flow).

Dual sha256 semantics (paradigm §5 supply-chain row: "appspec 双 sha256 +
下载后校验 + 安装目录指纹入审计"):
    - model.sha256 is MANDATORY. The file is hashed while streaming and must
      equal the pin exactly, else VERIFY_FAIL + rollback.
    - engine.sha256 is OPTIONAL (the binary may already be on the device).
      When the pin is given, the binary found at engine.binary (or via
      PATH/install roots, or freshly extracted from engine.install) must
      match exactly, else VERIFY_FAIL + rollback.
      When no pin is given, the found binary's sha256-16 is still
      fingerprinted into the audit trail — a fingerprint is a fact even
      without a pin.
    - engine.install.sha256 pins the ARCHIVE (the tarball as served by the
      mirror); engine.sha256, when also given, pins the extracted binary.
      Both are exact-match verified; neither byte is extracted or run
      before its pin passes.

Exit codes: 0 ok · 1 audit degraded (apply succeeded but events were lost) ·
2 usage/schema/audit-unavailable · 3 engine/download/verify failure ·
4 start/health failure · 5 rollback itself also failed · 6 another install
in progress (app lock held or unusable).

Python 3.10+, standard library only, no root required (only the default
sandbox path assumes it).
"""

from __future__ import annotations

import argparse
import fcntl
import glob
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

SCHEMA = "appspec/1"
MARKER_SCHEMA = "bicameral-install-state/1"
MARKER_NAME = ".bicameral-install-state.json"
ENGINE_MARKER_SCHEMA = "bicameral-engine-install/1"
ENGINE_MARKER_NAME = ".bicameral-engine-install.json"
DEFAULT_SANDBOX = "/root/bicameral-sandbox"
AUDIT_NAME = "audit.jsonl"

# engine.name → the engine binary the capability layer is allowed to run.
# Shape mirror of probe.APPSPEC_ENGINE_BINARIES (probe.py is NOT imported:
# both files stay independently deployable single files); this copy is the
# schema-level AUTHORITY since the 2026-10-15 red-team round (A5): every
# appspec's engine.name must hit this whitelist and a given engine.binary
# is accepted only when its basename matches the engine's executables (the
# path is free, the basename decides). An interpreter or any other binary
# (sh/bash/dash/zsh/python*/perl/ruby, look-alikes) can never match the
# executables tuple, so it is a schema error (exit 2, INSTALL_FAIL
# step=schema) before anything is downloaded or spawned — the argv this
# tool later starts is pinned to real engine executables no matter what an
# appspec claims. Extend only by adding a deliberately reviewed entry;
# anything unseen fails closed.
APPSPEC_ENGINE_BINARIES = {
    "llama.cpp": {"binary": "llama-server",
                  "executables": ("llama-server", "llama-server.exe")},
}

LIMITS = {
    "model_max_bytes": 32 * 1024 ** 3,     # hard cap on one model download
    "engine_max_bytes": 2 * 1024 ** 3,     # hard cap on one engine tarball
    "engine_extract_max_bytes": 4 * 1024 ** 3,   # uncompressed extract cap
    "download_read_timeout_s": 60,         # per-socket-read timeout
    "download_attempt_deadline_s": 900,    # wall clock per attempt (floor;
                                           # extended for known Content-Length)
    "download_min_bytes_per_s": 8 * 1024 ** 2,   # rate the deadline assumes
    "download_stall_timeout_s": 120,       # no-new-bytes budget per attempt
    "download_retries_per_mirror": 2,      # attempts per mirror (bounded)
    "download_retry_backoff_s": 2.0,       # sleep between attempts
    "download_mirror_max": 8,              # max mirror_urls accepted
    "health_timeout_s": 180,               # total health-check budget
    "health_interval_s": 1.0,              # poll interval
    "health_poll_timeout_s": 2.0,          # per-request timeout
    "engine_version_timeout_s": 15,        # `<binary> --version` budget
    "kill_grace_s": 5.0,                   # SIGTERM → SIGKILL grace
    "probe_timeout_s": 180,                # probe/1 refresh budget
    "status_http_timeout_s": 2.0,          # status subcommand health peek
    "args_max": 64,                        # max service.args items
    "arg_clip": 200,                       # audit clip per rendered arg
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MODEL_FORMATS = ("gguf", "safetensors")
ENGINE_INSTALL_FORMATS = ("tgz",)
FORBIDDEN_KEYS = ("actions", "tool_calls")   # same D8 philosophy as server.py

# resolve_engine prefixes its only "not installed anywhere" failure with
# this marker: it is the single condition an engine.install node is allowed
# to fix (a found-but-broken binary or a pin mismatch is a fact, never
# papered over by a fresh download).
ENGINE_NOT_FOUND = "ENGINE_BINARY_NOT_FOUND"


class InstallError(Exception):
    """A flow step failed; carries the step name and the exit code class."""

    def __init__(self, step: str, reason: str, code: int):
        super().__init__("%s: %s" % (step, reason))
        self.step = step
        self.reason = reason
        self.code = code


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def sha256_file(path: str, limit_bytes: int | None = None) -> str:
    """Full sha256 of a file, 1 MiB chunks. Raises OSError on read failure;
    ValueError if the file exceeds limit_bytes."""
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            read += len(chunk)
            if limit_bytes is not None and read > limit_bytes:
                raise ValueError("file exceeds %d bytes" % limit_bytes)
    return h.hexdigest()


def sha256_16(path: str) -> str:
    return sha256_file(path)[:16]


def redact_url(url: str) -> str:
    """scheme://host/path only — query/fragment (token carriers) dropped."""
    try:
        u = urllib.parse.urlsplit(url.strip())
        out = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", ""))
        return out[:300]
    except ValueError:
        return "<unparseable-url>"


def path_inside(root: str, path: str) -> bool:
    """realpath containment — the only gate under which we rm -rf."""
    rp = os.path.realpath(path)
    rr = os.path.realpath(root)
    return rp == rr or rp.startswith(rr + os.sep)


def now_note(msg: str) -> None:
    sys.stderr.write("install: %s\n" % msg)
    sys.stderr.flush()


def http_status(url: str, timeout: float) -> int | None:
    """GET url, return HTTP status; None on any failure. Reads ≤ 4 KiB."""
    req = urllib.request.Request(url, headers={"User-Agent": "bicameral-install/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(4096)
            return r.status
    except Exception:  # noqa: BLE001 — every failure mode is just "no"
        return None


class NoDowngradeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib redirect policy: never follow https → plain http. Returning
    None makes the opener raise the redirect as an HTTPError, which the
    download loop records as a failed attempt (selftest-covered)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if old.scheme == "https" and new.scheme != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# --------------------------------------------------------------------------- #
# audit (style-aligned with server.py: ts + event + non-None fields, JSONL)
# --------------------------------------------------------------------------- #

class Audit:
    """JSONL audit trail — mandatory for mutating flows: when the file cannot
    be opened, apply/rollback must fail closed (callers gate on `usable`).
    Write errors mid-flow are counted; close() surfaces them as an
    AUDIT_DEGRADED event on stderr and returns the lost count, which the
    caller turns into a non-zero exit."""

    def __init__(self, path: str):
        self.path = path
        self._f = None
        self._closed = False
        self.lost = 0
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._f = open(path, "a", encoding="utf-8")
        except OSError as e:
            self.lost += 1
            now_note("audit unavailable at %s (%s); flow must fail closed"
                     % (path, e))

    @property
    def usable(self) -> bool:
        return self._f is not None

    def emit(self, event: str, **fields) -> None:
        rec = {"ts": round(time.time(), 3), "event": event}
        rec.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        now_note(line)
        if self._f is not None:
            try:
                self._f.write(line + "\n")
                self._f.flush()
            except OSError:
                self.lost += 1          # degraded; surfaced at close()

    def close(self) -> int:
        """Close the trail (idempotent); returns the number of lost events
        (>0 ⇒ degraded). A non-zero count is also reported on stderr as an
        AUDIT_DEGRADED event."""
        if not self._closed:
            self._closed = True
            if self._f is not None:
                try:
                    self._f.close()
                except OSError:
                    self.lost += 1
                self._f = None
            if self.lost:
                rec = {"ts": round(time.time(), 3), "event": "AUDIT_DEGRADED",
                       "path": self.path, "lost": self.lost}
                now_note(json.dumps(rec, ensure_ascii=False,
                                    separators=(",", ":")))
        return self.lost


# --------------------------------------------------------------------------- #
# appspec/1 schema validation (pure; fail-closed like server.py bad_schema)
# --------------------------------------------------------------------------- #

def _has_forbidden_key(obj) -> bool:
    if isinstance(obj, dict):
        return any(k in FORBIDDEN_KEYS or _has_forbidden_key(v)
                   for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_forbidden_key(v) for v in obj)
    return False


def _bad_str(v, what: str) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return "%s must be a non-empty string" % what
    if "\x00" in v:
        return "%s must not contain NUL" % what
    return None


def _check_mirror_list(mirrors, label: str) -> str | None:
    """Shared mirror_urls shape check (model.mirror_urls and
    engine.install.mirror_urls): list, bounded count, http(s)/file only."""
    if not isinstance(mirrors, list):
        return "%s must be a list of base URLs" % label
    if len(mirrors) > LIMITS["download_mirror_max"]:
        return "%s exceeds %d entries" % (label, LIMITS["download_mirror_max"])
    for i, m in enumerate(mirrors):
        err = _bad_str(m, "%s[%d]" % (label, i))
        if err:
            return err
        u = urllib.parse.urlsplit(m)
        if u.scheme == "file":
            ok = bool(u.path)
        else:
            ok = u.scheme in ("http", "https") and bool(u.netloc)
        if not ok:
            return "%s[%d] must be an http(s) or file base URL" % (label, i)
    return None


def _validate_engine_install(inst, white: dict) -> tuple[dict | None, str | None]:
    """engine.install node (engine-level install): returns (normalized, None)
    or (None, reason). Fail-closed: mirror_urls/sha256/format mandatory,
    unknown fields rejected, binary_inside must be archive-relative with a
    whitelisted engine-executable basename (A5: the basename decides)."""
    if not isinstance(inst, dict):
        return None, "engine.install must be an object"
    i_need, i_opt = {"mirror_urls", "sha256", "format"}, \
                    {"strip_components", "binary_inside"}
    missing = sorted(i_need - set(inst))
    if missing:
        return None, "engine.install missing field(s): %s" % ", ".join(missing)
    unknown = sorted(set(inst) - i_need - i_opt)
    if unknown:
        return None, "engine.install unknown field(s): %s" % ", ".join(unknown)
    err = _check_mirror_list(inst["mirror_urls"], "engine.install.mirror_urls")
    if err:
        return None, err
    if not isinstance(inst["sha256"], str) or not HEX64_RE.match(inst["sha256"]):
        return None, "engine.install.sha256 is mandatory and must be 64 hex chars"
    if inst["format"] not in ENGINE_INSTALL_FORMATS:
        return None, ("engine.install.format must be one of %s"
                      % ", ".join(ENGINE_INSTALL_FORMATS))
    norm = {"mirror_urls": list(inst["mirror_urls"]),
            "sha256": inst["sha256"].lower(),
            "format": inst["format"],
            "strip_components": 0}
    if "strip_components" in inst:
        sc = inst["strip_components"]
        if isinstance(sc, bool) or not isinstance(sc, int) or not (0 <= sc <= 32):
            return None, "engine.install.strip_components must be an int in 0..32"
        norm["strip_components"] = sc
    if "binary_inside" in inst:
        err = _bad_str(inst["binary_inside"], "engine.install.binary_inside")
        if err:
            return None, err
        bi = inst["binary_inside"]
        if os.path.isabs(bi):
            return None, ("engine.install.binary_inside must be archive-relative"
                          " (no leading /)")
        if any(p in ("", ".", "..") for p in bi.split("/")):
            return None, ("engine.install.binary_inside must not contain "
                          "empty/./.. path parts")
        if white and os.path.basename(bi) not in white["executables"]:
            return None, ("engine.install.binary_inside basename %r is not a "
                          "whitelisted executable (one of: %s) — interpreters "
                          "and other binaries are rejected (A5)"
                          % (os.path.basename(bi), ", ".join(white["executables"])))
        norm["binary_inside"] = bi
    return norm, None


def validate_appspec(obj):
    """Strict appspec/1 validation. Returns (spec, None) or (None, reason).

    Fail-closed contract (server.py /issue style): unknown fields rejected,
    wrong types rejected, defaults filled in (service.health="/health",
    service.args=[], model.mirror_urls=[]).
    """
    if not isinstance(obj, dict):
        return None, "appspec must be a JSON object"
    need = {"schema", "name", "engine", "model", "service"}
    missing = sorted(need - set(obj))
    if missing:
        return None, "missing field(s): %s" % ", ".join(missing)
    unknown = sorted(set(obj) - need)
    if unknown:
        return None, "unknown field(s): %s" % ", ".join(unknown)
    if obj["schema"] != SCHEMA:
        return None, "schema must be %r" % SCHEMA
    err = _bad_str(obj["name"], "name")
    if err:
        return None, err
    if not NAME_RE.match(obj["name"]):
        return None, ("name must match %s (it becomes a directory name)"
                      % NAME_RE.pattern)

    eng = obj["engine"]
    if not isinstance(eng, dict):
        return None, "engine must be an object"
    eng_need, eng_opt = {"name"}, {"ref", "binary", "sha256", "install"}
    if not eng_need <= set(eng):
        return None, "engine missing field(s): name"
    if not set(eng) <= (eng_need | eng_opt):
        return None, "engine unknown field(s): %s" % ", ".join(
            sorted(set(eng) - eng_need - eng_opt))
    err = _bad_str(eng["name"], "engine.name")
    if err:
        return None, err
    for k in ("ref", "binary", "sha256"):
        if k in eng:
            err = _bad_str(eng[k], "engine." + k)
            if err:
                return None, err
    if "binary" in eng and not os.path.isabs(eng["binary"]):
        return None, "engine.binary must be an absolute device path when given"
    white = APPSPEC_ENGINE_BINARIES.get(eng["name"])
    if white is None:
        return None, ("engine.name must be one of %s (engine whitelist, A5: "
                      "unlisted engines are never installed or started)"
                      % ", ".join(sorted(APPSPEC_ENGINE_BINARIES)))
    if "binary" in eng:
        exe = os.path.basename(eng["binary"])
        if exe not in white["executables"]:
            return None, ("engine.binary basename %r is not a whitelisted "
                          "executable for engine.name %r (one of: %s) — "
                          "interpreters and other binaries are rejected "
                          "(A5)" % (exe, eng["name"],
                                    ", ".join(white["executables"])))
    if "sha256" in eng and not HEX64_RE.match(eng["sha256"]):
        return None, "engine.sha256 must be 64 hex chars"
    install_norm = None
    if "install" in eng:
        install_norm, err = _validate_engine_install(eng["install"], white)
        if err:
            return None, err

    mdl = obj["model"]
    if not isinstance(mdl, dict):
        return None, "model must be an object"
    mdl_need, mdl_opt = {"repo", "file", "format", "sha256"}, {"mirror_urls"}
    if not mdl_need <= set(mdl):
        return None, "model missing field(s): %s" % ", ".join(sorted(mdl_need - set(mdl)))
    if not set(mdl) <= (mdl_need | mdl_opt):
        return None, "model unknown field(s): %s" % ", ".join(
            sorted(set(mdl) - mdl_need - mdl_opt))
    for k in ("repo", "file"):
        err = _bad_str(mdl[k], "model." + k)
        if err:
            return None, err
    repo_parts = mdl["repo"].strip("/").split("/")
    if any(p in ("", ".", "..") for p in repo_parts):
        return None, "model.repo must be a plain <org>/<repo> path"
    if os.path.isabs(mdl["file"]):
        return None, "model.file must be repo-relative (no leading /)"
    if any(p in ("", ".", "..") for p in mdl["file"].split("/")):
        return None, "model.file must not contain empty/./.. path parts"
    if mdl["format"] not in MODEL_FORMATS:
        return None, "model.format must be one of %s" % ", ".join(MODEL_FORMATS)
    if not isinstance(mdl["sha256"], str) or not HEX64_RE.match(mdl["sha256"]):
        return None, "model.sha256 is mandatory and must be 64 hex chars"
    mirrors = mdl.get("mirror_urls", [])
    err = _check_mirror_list(mirrors, "model.mirror_urls")
    if err:
        return None, err

    svc = obj["service"]
    if not isinstance(svc, dict):
        return None, "service must be an object"
    svc_need, svc_opt = {"port"}, {"health", "args"}
    if not svc_need <= set(svc):
        return None, "service missing field(s): port"
    if not set(svc) <= (svc_need | svc_opt):
        return None, "service unknown field(s): %s" % ", ".join(
            sorted(set(svc) - svc_need - svc_opt))
    port = svc["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        return None, "service.port must be an int in 1..65535"
    if "health" in svc:
        err = _bad_str(svc["health"], "service.health")
        if err:
            return None, err
        if not svc["health"].startswith("/"):
            return None, "service.health must start with /"
    if "args" in svc:
        args = svc["args"]
        if not isinstance(args, list) or len(args) > LIMITS["args_max"]:
            return None, "service.args must be a list of at most %d strings" % LIMITS["args_max"]
        for i, a in enumerate(args):
            if not isinstance(a, str) or not a or "\x00" in a:
                return None, "service.args[%d] must be a non-empty string" % i

    if _has_forbidden_key(obj):
        return None, "forbidden key (actions/tool_calls) at some depth"

    eng_out = {k: eng[k] for k in ("name", "ref", "binary", "sha256") if k in eng}
    if install_norm is not None:
        eng_out["install"] = install_norm
    spec = {
        "schema": SCHEMA,
        "name": obj["name"],
        "engine": eng_out,
        "model": {"repo": mdl["repo"], "file": mdl["file"], "format": mdl["format"],
                  "sha256": mdl["sha256"].lower(), "mirror_urls": list(mirrors)},
        "service": {"port": port, "health": svc.get("health", "/health"),
                    "args": list(svc.get("args", []))},
    }
    return spec, None


def dedup_urls(urls: list[str]) -> list[str]:
    """First-occurrence-wins URL dedup, order preserved (engine.install
    mirror_urls are concrete artifact URLs — no repo/file join)."""
    out, seen = [], set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def build_mirror_urls(bases: list[str], repo: str, file: str) -> list[str]:
    """mirror base → concrete artifact URL: {base}/{repo}/resolve/main/{file}.

    The HF/hf-mirror convention; base order is preserved (first = preferred).
    """
    out, seen = [], set()
    for b in bases:
        url = "%s/%s/resolve/main/%s" % (b.rstrip("/"), repo.strip("/"),
                                         urllib.parse.quote(file))
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def dedup_key(spec: dict) -> str:
    """Idempotency key: app name + pinned model sha256."""
    return "%s:%s" % (spec["name"], spec["model"]["sha256"])


# --------------------------------------------------------------------------- #
# install_state (sandbox marker + filesystem/service facts)
# --------------------------------------------------------------------------- #

def sandbox_paths(sandbox: str, name: str) -> dict:
    apps = os.path.join(sandbox, "apps")
    return {"sandbox": sandbox, "apps": apps, "app": os.path.join(apps, name),
            "models": os.path.join(apps, name, "models"),
            "marker": os.path.join(apps, name, MARKER_NAME),
            "downloads": os.path.join(sandbox, "downloads"),
            "lock": os.path.join(apps, "%s.lock" % name)}


def acquire_app_lock(p: dict) -> int | None:
    """Try to take LOCK_EX|LOCK_NB on <sandbox>/apps/<name>.lock. The whole
    apply/rollback runs under it, so two concurrent installs of one app can
    never interleave (the loser gets None → exit 6). Returns the fd to hold,
    or None when another process holds the lock. Raises OSError when the
    lock file itself is unusable."""
    os.makedirs(p["apps"], exist_ok=True)
    fd = os.open(p["lock"], os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def release_app_lock(fd: int | None) -> None:
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def model_target(p: dict, spec: dict) -> str:
    return os.path.join(p["models"], spec["model"]["file"])


def read_marker(p: dict) -> dict | None:
    try:
        with open(p["marker"], "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) and d.get("schema") == MARKER_SCHEMA else None
    except (OSError, ValueError):
        return None


def write_marker(p: dict, data: dict) -> None:
    data = {"schema": MARKER_SCHEMA, "ts": round(time.time(), 3), **data}
    os.makedirs(os.path.dirname(p["marker"]), exist_ok=True)
    tmp = p["marker"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, p["marker"])               # atomic, fs.write idem pattern


def remove_marker(p: dict) -> None:
    try:
        os.remove(p["marker"])
    except OSError:
        pass


def _stat_state(data: str) -> str | None:
    """State letter from a /proc/<pid>/stat payload. Kernel format is
    `pid (comm) state …` and comm may contain spaces and parens, so parse
    after the LAST ')'. Pure; selftest-covered."""
    try:
        rest = data[data.rindex(")") + 1:].strip()
        return rest.split()[0] if rest else None
    except (ValueError, IndexError):
        return None


def proc_state(pid) -> str | None:
    """'R','S','Z',… from /proc/<pid>/stat; None when there is no such proc."""
    try:
        with open("/proc/%d/stat" % int(pid), "r", encoding="ascii",
                  errors="replace") as f:
            return _stat_state(f.read())
    except (OSError, TypeError, ValueError):
        return None


def pid_alive(pid) -> bool:
    """True only for a live process: a zombie (state Z) counts as dead, so
    `os.kill(pid, 0)`-style false positives never report a dead child as
    running (survived_sigkill would otherwise lie)."""
    st = proc_state(pid)
    return st is not None and st != "Z"


def parse_cmdline(data: bytes) -> list[str]:
    """argv from raw /proc/<pid>/cmdline: NUL-separated, trailing empty
    entry dropped. Pure; selftest-covered."""
    parts = data.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", "replace") for p in parts]


def argv_of(pid) -> list[str] | None:
    """Exact argv of a pid, or None when unreadable (process gone / race)."""
    try:
        with open("/proc/%d/cmdline" % int(pid), "rb") as f:
            data = f.read()
    except (OSError, TypeError, ValueError):
        return None
    return parse_cmdline(data) or None


def install_state_of(spec: dict, p: dict, engine_info: dict | None,
                     service_ok: bool | None) -> tuple[str, list[str]]:
    """absent/partial/ready per probe.eval_appspec semantics (§3.1 #4),
    computed from sandbox + filesystem facts. service_ok=None means the
    service is not checked (used on the READY path, where the health check
    just passed). The model file is ALWAYS hash-verified: cmd_apply calls
    this again right before READY as a TOCTOU guard, so a model corrupted
    (or swapped) after placement can never be reported ready."""
    missing: list[str] = []
    engine_present = bool(engine_info and engine_info.get("found"))
    if not engine_present:
        missing.append("engine %r binary not found" % spec["engine"]["name"])
    target = model_target(p, spec)
    model_present = False
    if os.path.isfile(target):
        try:
            if sha256_file(target) == spec["model"]["sha256"]:
                model_present = True
            else:
                missing.append("model sha256 mismatch at %s" % target)
        except (OSError, ValueError) as e:
            missing.append("model unreadable at %s (%s)" % (target, e))
    else:
        missing.append("model file not found: %s" % target)
    if service_ok is False:
        missing.append("service on port %d not healthy" % spec["service"]["port"])

    if missing:
        return ("partial" if (engine_present or model_present) else "absent",
                missing)
    return "ready", []


def deployment_facts(spec: dict, engine_binary: str, engine_sha256_16: str,
                     model_path: str, app_dir: str) -> dict:
    """The service-defining facts this appspec+engine would deploy right now
    (selftest-covered). name+model sha256 alone is too coarse a dedup key:
    a changed port/health/args/engine must restart, never be silently
    reused under a marker that mixes old and new facts."""
    return {"port": spec["service"]["port"],
            "health": spec["service"]["health"],
            "argv": [engine_binary] + render_args(spec["service"]["args"],
                                                  spec, model_path, app_dir),
            "engine_binary": engine_binary,
            "engine_sha256_16": engine_sha256_16}


def facts_drift(marker: dict | None, facts: dict) -> list[str]:
    """Fields where the recorded deployment differs from the wanted one.
    Pure; selftest-covered."""
    if marker is None:
        return []
    return [k for k in ("port", "health", "argv", "engine_binary",
                        "engine_sha256_16") if marker.get(k) != facts[k]]


def decide_resume(marker: dict | None, spec: dict, model_sha_ok: bool,
                  service_ok: bool,
                  facts: dict | None = None) -> tuple[str, str]:
    """Pure idempotency decision (selftest-covered).

    dedup_ready : marker on record, same name+model sha256, model file
                  verified, deployment facts identical, service healthy →
                  no download, straight to READY.
    restart     : same key, but the service is down OR any deployment fact
                  (port/health/argv/engine) drifted → kill the old process
                  and start a new one (no download).
    resume      : same key but model file missing/corrupt → re-download only.
    superseded  : same name, DIFFERENT model sha256 → roll the old one back,
                  then install fresh.
    fresh       : nothing on record.
    """
    if marker is None:
        return "fresh", "no marker"
    if marker.get("model_sha256") != spec["model"]["sha256"]:
        return "superseded", "marker model_sha256 differs from appspec pin"
    if not model_sha_ok:
        return "resume", "same key but model file missing/failed hash"
    drift = facts_drift(marker, facts) if facts is not None else []
    if drift:
        return "restart", "deployment facts changed: %s" % ", ".join(drift)
    if service_ok:
        return "dedup_ready", "same name+model sha256, service healthy"
    return "restart", "same name+model sha256, service down"


# --------------------------------------------------------------------------- #
# engine resolution (device-side, dual sha256 semantics)
# --------------------------------------------------------------------------- #

def search_binary(binname: str) -> str | None:
    """PATH + common install roots (probe.py extra_bin_dirs subset)."""
    dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    dirs += ["/usr/local/bin", "/usr/local/sbin",
             os.path.join(os.path.expanduser("~"), ".local/bin"),
             "/snap/bin"] + glob.glob("/opt/*/bin")
    seen = set()
    for d in dirs:
        if d in seen:
            continue
        seen.add(d)
        cand = os.path.join(d, binname)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def resolve_engine(spec: dict) -> tuple[dict | None, str | None]:
    """Locate the engine binary and apply the dual-sha256 rule.

    Returns (info, None) or (None, failure_reason). info carries the found
    binary, its full sha256 (fact), and whether a given ref/sha256 pin matched.
    A pinned-sha mismatch surfaces as a reason starting with VERIFY_FAIL.
    """
    eng = spec["engine"]
    white = APPSPEC_ENGINE_BINARIES.get(eng["name"])
    search_name = white["binary"] if white else eng["name"]
    binary = eng.get("binary") or search_binary(search_name)
    if not binary:
        return None, ("%s: engine %r: binary %r not found (no engine.binary "
                      "given, and not on PATH/install roots)"
                      % (ENGINE_NOT_FOUND, eng["name"], search_name))
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        return None, "engine binary not executable: %s" % binary
    try:
        digest = sha256_file(binary)
    except OSError as e:
        return None, "engine binary unreadable: %s (%s)" % (binary, e)
    info = {"found": True, "binary": binary, "sha256": digest,
            "sha256_16": digest[:16], "ref": eng.get("ref"),
            "ref_matched": None, "pin_matched": None}
    if eng.get("sha256"):
        info["pin_matched"] = (digest == eng["sha256"].lower())
        if not info["pin_matched"]:
            return None, ("VERIFY_FAIL: engine sha256 mismatch at %s "
                          "(want %s…, have %s…)" % (binary, eng["sha256"][:16],
                                                    digest[:16]))
    if eng.get("ref"):
        try:
            r = subprocess.run([binary, "--version"], capture_output=True,
                               text=True,
                               timeout=LIMITS["engine_version_timeout_s"])
            ver = (r.stdout or "") + (r.stderr or "")
        except (OSError, subprocess.SubprocessError) as e:
            ver = ""
            info["version_error"] = "%s: %s" % (type(e).__name__, e)
        info["ref_matched"] = str(eng["ref"]) in ver
        if not info["ref_matched"]:
            return None, ("engine ref %r not matched by %s --version output"
                          % (eng["ref"], binary))
    return info, None


# --------------------------------------------------------------------------- #
# engine-level install (engine.install node: download → verify → extract)
# --------------------------------------------------------------------------- #

def _tar_member_error(name: str) -> str | None:
    """Structural traversal check for one tar member name: absolute paths and
    any '..' path part are rejected (pure; selftest-covered)."""
    if not name or name.startswith("/") or os.path.isabs(name):
        return "absolute member path"
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return "'..' path part"
    return None


def extract_engine_tgz(tar_path: str, dest_root: str,
                       strip_components: int) -> tuple[int, int]:
    """Extract a gz tarball into dest_root, member by member (never
    extractall): every member name must pass _tar_member_error, links must
    resolve inside dest_root, and only directories/regular files/links are
    allowed (devices/fifos fail closed). realpath containment is re-checked
    per member so an earlier symlink member cannot redirect later writes.
    Total uncompressed size is capped (tar-bomb guard).
    Returns (extracted_bytes, member_count). Raises InstallError
    (step='engine')."""
    total = 0
    members_out = 0
    try:
        tf = tarfile.open(tar_path, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise InstallError("engine", "unreadable tarball: %s: %s"
                           % (type(e).__name__, str(e)[:200]), 3) from e
    with tf:
        try:
            members = tf.getmembers()
        except tarfile.TarError as e:
            raise InstallError("engine", "unreadable tarball index: %s"
                               % str(e)[:200], 3) from e
        for m in members:
            err = _tar_member_error(m.name)
            if err:
                raise InstallError("engine", "tar member rejected (%s): %r"
                                   % (err, m.name[:200]), 3)
            parts = [p for p in m.name.split("/") if p not in ("", ".")]
            if strip_components:
                parts = parts[strip_components:]
            if not parts:                      # stripped away entirely
                continue
            target = os.path.join(dest_root, *parts)
            if not path_inside(dest_root, target):
                raise InstallError("engine", "tar member escapes destination: "
                                   "%r" % m.name[:200], 3)
            if m.issym() or m.islnk():
                link = m.linkname
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(target), link))
                if os.path.isabs(link) or not path_inside(dest_root, resolved):
                    raise InstallError("engine",
                                       "tar link member escapes destination: "
                                       "%r -> %r" % (m.name[:200],
                                                     link[:200]), 3)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if os.path.lexists(target):
                    os.remove(target)
                if m.issym():
                    os.symlink(link, target)
                else:
                    os.link(resolved, target)
            elif m.isdir():
                os.makedirs(target, exist_ok=True)
            elif m.isfile():
                total += m.size
                if total > LIMITS["engine_extract_max_bytes"]:
                    raise InstallError("engine",
                                       "uncompressed size exceeds "
                                       "engine_extract_max_bytes (%d)"
                                       % LIMITS["engine_extract_max_bytes"], 3)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tf.extractfile(m)
                if src is None:
                    raise InstallError("engine", "tar member unreadable: %r"
                                       % m.name[:200], 3)
                with src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out, 1 << 20)
                os.chmod(target, m.mode & 0o777)
            else:
                raise InstallError("engine", "unsupported tar member type "
                                   "%r: %r" % (m.type, m.name[:200]), 3)
            members_out += 1
    return total, members_out


def _locate_engine_binary(dest_root: str, binary_inside: str | None,
                          exes: tuple[str, ...]) -> str:
    """The engine executable inside the extracted tree: binary_inside when
    given (schema already enforced a relative, traversal-free, whitelisted
    basename), else the unique whitelisted executable found by search —
    zero or several matches fail closed. Raises InstallError(step='engine')."""
    if binary_inside:
        cand = os.path.join(dest_root,
                            *[p for p in binary_inside.split("/")
                              if p not in ("", ".")])
        if not os.path.isfile(cand):
            raise InstallError("engine", "binary_inside %r not found in the "
                               "extracted archive (looked at %s)"
                               % (binary_inside, cand), 3)
        return cand
    hits: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(dest_root):
        for fn in filenames:
            if fn in exes:
                hits.append(os.path.join(dirpath, fn))
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise InstallError("engine", "no whitelisted executable (%s) found in "
                           "the extracted archive" % ", ".join(exes), 3)
    raise InstallError("engine", "ambiguous engine binary in the extracted "
                       "archive (%d hits: %s)" % (len(hits),
                                                  ", ".join(hits[:4])), 3)


def read_engine_marker(eng_root: str) -> dict | None:
    """Provenance of an engine-level install: which archive sha256 produced
    the tree at eng_root. None when absent/foreign/corrupt."""
    try:
        with open(os.path.join(eng_root, ENGINE_MARKER_NAME), "r",
                  encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) \
            and d.get("schema") == ENGINE_MARKER_SCHEMA else None
    except (OSError, ValueError):
        return None


def write_engine_marker(eng_root: str, data: dict) -> None:
    data = {"schema": ENGINE_MARKER_SCHEMA, "ts": round(time.time(), 3), **data}
    tmp = os.path.join(eng_root, ENGINE_MARKER_NAME + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, os.path.join(eng_root, ENGINE_MARKER_NAME))


def engine_provenance_matches(marker: dict | None, archive_sha: str) -> bool:
    """Pure skip gate (selftest-covered): an already-extracted engine may
    satisfy an engine.install node only when the recorded provenance names
    exactly the archive pin this appspec wants. A different pin means
    'reinstall with this pin' — the download then re-verifies every byte,
    so a wrong pin fails loudly (ENGINE_VERIFY_FAIL) instead of silently
    reusing a tree it cannot vouch for."""
    return bool(marker) and marker.get("archive_sha256") == archive_sha


def install_engine(audit: Audit, app: str, sandbox: str,
                   spec: dict) -> tuple[dict, None]:
    """Engine-level install: turn a not-on-disk whitelisted engine into a
    resolved one, reusing the model download machinery verbatim.

    Idempotent, provenance-gated: the extracted tree records the archive
    sha256 it was built from (.bicameral-engine-install.json); when the
    expected binary sits in <sandbox>/engines/<engine.name>/, passes
    resolve_engine (including any engine.sha256 pin) AND that provenance
    equals this appspec's install.sha256, the download is skipped
    (ENGINE_DOWNLOAD status=skip). A different pin means reinstall with the
    new pin. Otherwise: pinned tarball download (mirror fallback, streaming
    sha256, stall guard, adaptive deadline) → ENGINE_VERIFY →
    traversal-checked extraction → binary_inside chmod 0755 → ENGINE_PLACE
    → resolve_engine on that path (dual sha256 + ref semantics) → its info
    feeds the ordinary apply flow as engine.binary. Any failure removes the
    half-extracted tree and raises InstallError(step='engine', exit 3);
    a tarball pin mismatch additionally emits ENGINE_VERIFY_FAIL."""
    eng = spec["engine"]
    inst = eng["install"]
    white = APPSPEC_ENGINE_BINARIES.get(eng["name"])
    exes = white["executables"] if white else ()
    eng_root = os.path.join(sandbox, "engines", eng["name"])
    created = False                     # did this run create eng_root?
    ok = False                          # did the install finish cleanly?
    try:
        # --- idempotency: already installed, resolvable, right provenance? - #
        try:
            cand = _locate_engine_binary(eng_root, inst.get("binary_inside"),
                                         exes)
        except InstallError:
            cand = None
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            spec2 = dict(spec, engine=dict(eng, binary=cand))
            info, _err = resolve_engine(spec2)
            if info is not None and engine_provenance_matches(
                    read_engine_marker(eng_root), inst["sha256"]):
                audit.emit("ENGINE_DOWNLOAD", app=app, status="skip",
                           binary=cand, sha256_16=info["sha256_16"],
                           archive_sha256=inst["sha256"],
                           note="engine already installed from the pinned "
                                "archive; download/extract skipped "
                                "(idempotent)")
                ok = True
                return info, None

        # --- download the pinned archive (model machinery, engine events) -- #
        os.makedirs(eng_root, exist_ok=True)
        created = True
        os.makedirs(os.path.join(sandbox, "downloads"), exist_ok=True)
        urls = dedup_urls(inst["mirror_urls"])
        part = os.path.join(sandbox, "downloads", "engine-%s-%s-%d.part"
                            % (eng["name"], inst["sha256"][:12], os.getpid()))
        try:
            got, size = download_model(
                audit, app, urls, part, inst["sha256"], what="engine",
                ev_download="ENGINE_DOWNLOAD", ev_verify_fail="ENGINE_VERIFY",
                max_bytes=LIMITS["engine_max_bytes"])
        except InstallError as e:
            if e.reason.startswith("VERIFY_FAIL"):
                audit.emit("ENGINE_VERIFY_FAIL", app=app, final=True,
                           expected_sha256=inst["sha256"], error=e.reason)
            raise InstallError("engine", "engine install: %s" % e.reason,
                               3) from e
        audit.emit("ENGINE_VERIFY", app=app, status="ok", what="engine-archive",
                   sha256=got, bytes=size)

        # --- extract (traversal-checked) + place the executable ------------ #
        total, members = extract_engine_tgz(part, eng_root,
                                            inst.get("strip_components", 0))
        os.remove(part)
        binary = _locate_engine_binary(eng_root, inst.get("binary_inside"),
                                       exes)
        os.chmod(binary, 0o755)
        audit.emit("ENGINE_PLACE", app=app, path=eng_root, binary=binary,
                   archive_bytes=size, members=members, extracted_bytes=total,
                   binary_mode="0755",
                   note="engine.binary := %s for the rest of this flow" % binary)
        spec2 = dict(spec, engine=dict(eng, binary=binary))
        info, err = resolve_engine(spec2)   # fingerprint (+ optional pin/ref)
        if info is None:
            raise InstallError("engine", err or "installed engine unresolved", 3)
        write_engine_marker(eng_root, {"engine": eng["name"],
                                       "archive_sha256": got,
                                       "binary": binary,
                                       "binary_sha256_16": info["sha256_16"]})
        ok = True
        return info, None
    except OSError as e:
        raise InstallError("engine", "%s: %s"
                           % (type(e).__name__, str(e)[:200]), 3) from e
    finally:
        # a failed engine install never leaves a half-extracted tree behind;
        # a successful one keeps <sandbox>/engines/<name>/ (it IS the install)
        if created and not ok:
            shutil.rmtree(eng_root, ignore_errors=True)


# --------------------------------------------------------------------------- #
# download + verify (bounded)
# --------------------------------------------------------------------------- #

def _discard_part(part_path: str) -> None:
    try:
        os.remove(part_path)
    except OSError:
        pass


def attempt_budget(content_length: int | None) -> float:
    """Wall-clock budget for one download attempt: the fixed floor, extended
    when Content-Length is known so a legitimately large model still fits at
    the assumed minimum sustained rate (the fixed 900s and the 32 GiB cap
    are otherwise contradictory). Pure; selftest-covered."""
    budget = float(LIMITS["download_attempt_deadline_s"])
    if content_length is not None:
        budget = max(budget,
                     content_length / LIMITS["download_min_bytes_per_s"])
    return budget


def download_model(audit: Audit, app: str, urls: list[str], part_path: str,
                   want_sha: str, *, what: str = "model",
                   ev_download: str = "DOWNLOAD",
                   ev_verify_fail: str = "VERIFY_FAIL",
                   max_bytes: int | None = None) -> tuple[str, int]:
    """Stream the artifact to part_path, hashing as we go. mirror_urls tried
    in order; bounded retries per mirror; per-attempt wall clock is the fixed
    floor extended for a known Content-Length, with a no-new-bytes stall
    guard; hard size cap enforced before (Content-Length) and during the
    transfer. Redirects never downgrade https → http.

    `what`/`ev_download`/`ev_verify_fail` label the audit trail (the engine
    installer reuses this exact machinery with ENGINE_DOWNLOAD/ENGINE_VERIFY
    names); `max_bytes` overrides the size cap.

    A sha256 mismatch on ONE mirror/attempt is just that attempt failing
    (final=false, part discarded, next attempt/mirror); only when every
    mirror and retry is exhausted on mismatches is it fatal (final=true,
    exit 3). Other InstallErrors (size cap) fail immediately.
    The file is never installed unless it hashes to the pin.
    Returns (sha256_hex, bytes). Raises InstallError(step='download')."""
    if not urls:
        raise InstallError("download", "no mirror URLs given", 3)
    max_bytes = LIMITS["model_max_bytes"] if max_bytes is None else max_bytes
    last_err = "no mirror attempted"
    all_hash = True                     # every failure so far a hash mismatch
    opener = urllib.request.build_opener(NoDowngradeRedirectHandler())
    for mi, url in enumerate(urls):
        red = redact_url(url)
        for attempt in range(1, LIMITS["download_retries_per_mirror"] + 1):
            t_start = time.monotonic()
            deadline = t_start + attempt_budget(None)
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "bicameral-install/1"})
                h = hashlib.sha256()
                size = 0
                with opener.open(
                        req, timeout=LIMITS["download_read_timeout_s"]) as r, \
                        open(part_path, "wb") as out:
                    cl = r.headers.get("Content-Length")
                    total = int(cl) if cl and cl.isdigit() else None
                    if total is not None and total > max_bytes:
                        raise InstallError(
                            "download",
                            "content-length %d exceeds max_bytes (%d)"
                            % (total, max_bytes), 3)
                    deadline = t_start + attempt_budget(total)
                    last_progress = time.monotonic()
                    while True:
                        now = time.monotonic()
                        if now > deadline:
                            raise TimeoutError(
                                "attempt deadline %.0fs exceeded (budget "
                                "%.0fs)" % (now - t_start, deadline - t_start))
                        if now - last_progress > \
                                LIMITS["download_stall_timeout_s"]:
                            raise TimeoutError(
                                "stalled: no bytes for %ds"
                                % LIMITS["download_stall_timeout_s"])
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        last_progress = time.monotonic()
                        size += len(chunk)
                        if size > max_bytes:
                            raise InstallError(
                                "download",
                                "size exceeds max_bytes (%d)" % max_bytes, 3)
                        h.update(chunk)
                        out.write(chunk)
                got = h.hexdigest()
                if got != want_sha:
                    last_err = ("VERIFY_FAIL: sha256 mismatch (got %s…)"
                                % got[:16])
                    audit.emit(ev_verify_fail, app=app, what=what,
                               final=False, file=os.path.basename(part_path),
                               expected_sha256=want_sha,
                               got_sha256_16=got[:16], mirror=mi + 1,
                               attempt=attempt, url=red, bytes=size)
                    _discard_part(part_path)
                    # not fatal: this attempt failed, try again / next mirror
                else:
                    audit.emit(ev_download, app=app, status="ok",
                               mirror=mi + 1, attempt=attempt,
                               url=redact_url(r.geturl()), bytes=size,
                               sha256_16=got[:16])
                    return got, size
            except InstallError:
                raise                    # size cap & co fail immediately
            except Exception as e:  # noqa: BLE001 — a failed mirror is a fact
                last_err = "%s: %s" % (type(e).__name__, str(e)[:200])
                all_hash = False
                _discard_part(part_path)
                audit.emit(ev_download, app=app, status="fail", mirror=mi + 1,
                           attempt=attempt, url=red, error=last_err)
            if attempt < LIMITS["download_retries_per_mirror"]:
                time.sleep(LIMITS["download_retry_backoff_s"])
    if all_hash:
        audit.emit(ev_verify_fail, app=app, what=what, final=True,
                   expected_sha256=want_sha, error=last_err)
        raise InstallError("download",
                           "VERIFY_FAIL: sha256 mismatch on every mirror/"
                           "attempt (last: %s)" % last_err, 3)
    raise InstallError("download", "all mirrors exhausted (last: %s)" % last_err, 3)


# --------------------------------------------------------------------------- #
# service start + health
# --------------------------------------------------------------------------- #

def render_args(args: list[str], spec: dict, model_path: str,
                app_dir: str) -> list[str]:
    subs = {"{model}": model_path, "{port}": str(spec["service"]["port"]),
            "{app_dir}": app_dir}
    if args:
        return [subs.get(a, a) for a in args]
    return ["-m", model_path, "--host", "127.0.0.1",
            "--port", str(spec["service"]["port"])]   # llama.cpp default


def start_service(audit: Audit, app: str, engine_binary: str, spec: dict,
                  model_path: str, app_dir: str) -> tuple[subprocess.Popen, list[str]]:
    args = render_args(spec["service"]["args"], spec, model_path, app_dir)
    log_path = os.path.join(app_dir, "service.log")
    log = open(log_path, "ab")
    try:
        proc = subprocess.Popen([engine_binary] + args, stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    finally:
        log.close()
    audit.emit("START", app=app, pid=proc.pid, binary=engine_binary,
               port=spec["service"]["port"],
               args=[a[:LIMITS["arg_clip"]] for a in args], log="service.log")
    return proc, [engine_binary] + args


def argv_matches(live: list[str], recorded: list[str]) -> bool:
    """Exact identity of the argv recorded at START against a live
    /proc/<pid>/cmdline (pure; selftest-covered). Normally the two are
    equal; a script started via a shebang shows the interpreter as
    argv[0], so the recorded argv then appears verbatim at live[1:] —
    accepted. Anything else (recycled pid, unrelated process whose cmdline
    merely contains the app dir) is a no."""
    if not live or not recorded:
        return False
    return live == recorded or (len(live) > 1 and live[1:] == recorded)


def stop_process(pid, verify_argv: list[str] | None, grace: float) -> str:
    """SIGTERM → wait grace → SIGKILL. When verify_argv is given, the kill
    only proceeds if /proc/<pid>/cmdline equals that argv exactly (NUL-split,
    trailing empty entry dropped; see argv_matches for the shebang shape) —
    a stale or recycled pid, or an unrelated process whose cmdline merely
    contains the app dir (e.g. tail -f of the log), is never signalled.
    Returns an audit-ready outcome."""
    if not pid_alive(pid):
        return "already_dead"
    if verify_argv is not None:
        live = argv_of(pid)
        if live is None or not argv_matches(live,
                                            [str(a) for a in verify_argv]):
            return "skipped_unverified"
    try:
        os.kill(int(pid), signal.SIGTERM)
    except OSError:
        return "signal_failed"
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return "terminated"
        time.sleep(0.2)
    try:
        os.kill(int(pid), signal.SIGKILL)
    except OSError:
        pass
    time.sleep(0.2)
    return "killed" if not pid_alive(pid) else "survived_sigkill"


def wait_health(audit: Audit, app: str, port: int, health: str,
                timeout_s: float,
                proc: subprocess.Popen | None = None) -> bool:
    """Poll GET http://127.0.0.1:<port><health> until 200 or budget out.
    When `proc` is the child we started, a child exit is detected on every
    poll — a dead process must never be awaited into a fake READY."""
    url = "http://127.0.0.1:%d%s" % (port, health)
    t0 = time.monotonic()
    attempts, last = 0, None
    while time.monotonic() - t0 < timeout_s:
        attempts += 1
        if proc is not None and proc.poll() is not None:
            audit.emit("HEALTH", app=app, port=port, path=health,
                       proc_exited=True, returncode=proc.returncode,
                       attempts=attempts,
                       elapsed_ms=int((time.monotonic() - t0) * 1000))
            return False
        last = http_status(url, LIMITS["health_poll_timeout_s"])
        if last == 200:
            audit.emit("HEALTH", app=app, port=port, path=health,
                       http_status=200, attempts=attempts,
                       elapsed_ms=int((time.monotonic() - t0) * 1000))
            return True
        time.sleep(LIMITS["health_interval_s"])
    audit.emit("HEALTH", app=app, port=port, path=health, http_status=last,
               attempts=attempts, timed_out=True,
               elapsed_ms=int((time.monotonic() - t0) * 1000))
    return False


def service_healthy_now(spec: dict) -> bool:
    return http_status("http://127.0.0.1:%d%s"
                       % (spec["service"]["port"], spec["service"]["health"]),
                       LIMITS["status_http_timeout_s"]) == 200


# --------------------------------------------------------------------------- #
# probe/1 refresh (mandatory last step per paradigm §3.4)
# --------------------------------------------------------------------------- #

def probe_refresh(audit: Audit, app: str, appspec_path: str, p: dict) -> dict | None:
    """Re-run probe/1 (probe.py, same directory) against this appspec and
    record its install_state. A probe failure is recorded, never fatal: the
    install facts stand on their own evidence (marker + sha256 + health 200).
    """
    probe_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe.py")
    if not os.path.isfile(probe_py):
        audit.emit("PROBE_REFRESH", app=app,
                   skipped="probe.py not found next to install.py")
        return None
    fd, report = tempfile.mkstemp(prefix="bicameral-probe-", suffix=".json")
    os.close(fd)
    try:
        argv = [sys.executable, probe_py, "--appspec", appspec_path,
                "--model-dirs", p["models"], "--no-egress",
                "--compact", "-o", report]
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               timeout=LIMITS["probe_timeout_s"])
            if r.returncode != 0:
                audit.emit("PROBE_REFRESH", app=app,
                           error="probe exit %d" % r.returncode,
                           stderr_excerpt=(r.stderr or "")[-200:])
                return None
            with open(report, "r", encoding="utf-8") as f:
                rep = json.load(f)
            entries = rep.get("install_state") or []
            ent = entries[0] if entries else None
            audit.emit("PROBE_REFRESH", app=app,
                       probe_state=ent.get("state") if ent else None,
                       probe_missing=(ent.get("missing") or [])[:4] if ent else None,
                       probe_sha256_16=(rep.get("probe") or {}).get("sha256_16"),
                       note="probe engine scan covers PATH+install roots; an "
                            "engine.binary pinned at a custom path is reconciled "
                            "by the install marker")
            return ent
        except (subprocess.TimeoutExpired, OSError, ValueError) as e:
            audit.emit("PROBE_REFRESH", app=app,
                       error="%s: %s" % (type(e).__name__, str(e)[:200]))
            return None
    finally:
        try:
            os.remove(report)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# rollback (any-failure path; manual rollback subcommand reuses it)
# --------------------------------------------------------------------------- #

def rollback(audit: Audit, p: dict, name: str, reason: str,
             popen: subprocess.Popen | None = None) -> bool:
    """Remove the app dir, kill the process we started, state → absent.
    The kill is verified against the argv recorded at START (exact match of
    /proc/<pid>/cmdline) — a stale or recycled pid is never signalled. When
    the marker carries no argv the pid is still our own marker fact, so it
    is signalled unverified rather than leak a live service. Returns True
    when nothing was left behind (best effort)."""
    killed = None
    if popen is not None:
        try:
            popen.terminate()
            popen.wait(timeout=LIMITS["kill_grace_s"])
            killed = "terminated"
        except subprocess.TimeoutExpired:
            popen.kill()
            killed = "killed"
        except OSError:
            killed = "already_dead"
    else:
        marker = read_marker(p) or {}
        pid = marker.get("pid")
        if pid:
            argv = marker.get("argv")
            killed = stop_process(
                pid,
                verify_argv=argv
                if isinstance(argv, list) and argv else None,
                grace=LIMITS["kill_grace_s"])
    removed = False
    if os.path.isdir(p["app"]) and path_inside(os.path.join(p["sandbox"], "apps"),
                                               p["app"]):
        shutil.rmtree(p["app"], ignore_errors=True)
        removed = not os.path.isdir(p["app"])
    for stale in glob.glob(os.path.join(p["downloads"], "%s-*.part" % name)):
        _discard_part(stale)
    remove_marker(p)
    audit.emit("ROLLBACK", app=name, reason=reason, killed_pid_outcome=killed,
               removed_dir=removed, state="absent")
    return removed or not os.path.isdir(p["app"])


# --------------------------------------------------------------------------- #
# apply flow
# --------------------------------------------------------------------------- #

def cmd_apply(args) -> int:
    sandbox = os.path.abspath(args.sandbox_root)
    audit = Audit(args.audit_path or os.path.join(sandbox, AUDIT_NAME))
    if not audit.usable:               # fail-closed: no audit trail, no change
        now_note("refusing to apply: audit file unavailable (fail-closed)")
        audit.close()
        return 2
    p = None
    spec = None
    name = None
    popen = None                    # child we started; killed on any failure
    lock_fd = None                  # <sandbox>/apps/<name>.lock, held throughout

    def finish(code: int) -> int:
        """Single exit path: close the audit trail; a run that succeeded
        while losing audit events must not report success (exit 1)."""
        lost = audit.close()
        return code if (code != 0 or lost == 0) else 1

    try:
        try:
            with open(args.appspec, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError) as e:
            audit.emit("INSTALL_FAIL", step="read", appspec=args.appspec,
                       error="%s: %s" % (type(e).__name__, str(e)[:200]))
            now_note("appspec unreadable/invalid: %s" % e)
            return finish(2)
        spec, err = validate_appspec(raw)
        name = spec["name"] if spec else \
            (raw.get("name") if isinstance(raw, dict) else None)
        if err:
            audit.emit("INSTALL_FAIL", step="schema", app=name,
                       appspec_sha256_16=sha256_16(args.appspec)
                       if os.path.isfile(args.appspec) else None,
                       error=err)
            now_note("schema violation: %s" % err)
            return finish(2)

        p = sandbox_paths(sandbox, name)
        try:
            lock_fd = acquire_app_lock(p)
        except OSError as e:
            raise InstallError("lock", "app lock unusable at %s: %s"
                               % (p["lock"], e), 6) from e
        if lock_fd is None:
            raise InstallError("lock", "another install is in progress for "
                               "%r" % name, 6)
        audit.emit("INSTALL_START", app=name,
                   appspec_sha256_16=sha256_16(args.appspec),
                   dedup_key=dedup_key(spec), sandbox=p["sandbox"])
        os.makedirs(p["models"], exist_ok=True)
        os.makedirs(p["downloads"], exist_ok=True)

        # --- probe current install_state (marker + filesystem facts) ------ #
        marker = read_marker(p)
        engine_info, eng_err = resolve_engine(spec)
        if engine_info is None and eng_err is not None \
                and eng_err.startswith(ENGINE_NOT_FOUND) \
                and spec["engine"].get("install"):
            # engine-level install (engine.install node): no engine.binary
            # given and the whitelisted engine not on disk → download the
            # pinned archive, verify, extract into <sandbox>/engines/<name>/
            # and re-resolve on the placed path. Any OTHER engine failure
            # (found-but-unusable, pin mismatch) is a fact, never papered
            # over by a fresh download.
            engine_info, eng_err = install_engine(audit, name, sandbox, spec)
        if engine_info is None:
            if eng_err and eng_err.startswith("VERIFY_FAIL"):
                audit.emit("VERIFY_FAIL", app=name, what="engine", error=eng_err)
            raise InstallError("engine", eng_err or "engine unresolved", 3)
        audit.emit("ENGINE_FOUND", app=name, name=spec["engine"]["name"],
                   binary=engine_info["binary"],
                   sha256_16=engine_info["sha256_16"],
                   ref=spec["engine"].get("ref"),
                   ref_matched=engine_info.get("ref_matched"),
                   pin_matched=engine_info.get("pin_matched"),
                   note="pin_matched omitted means no engine.sha256 pin; the "
                        "fingerprint is recorded anyway (§5 安装目录指纹入审计)")
        service_ok = service_healthy_now(spec)
        pre_state, pre_missing = install_state_of(spec, p, engine_info, service_ok)
        audit.emit("STATE", app=name, phase="pre", state=pre_state,
                   missing=pre_missing, marker_state=(marker or {}).get("state"))

        # --- idempotency decision ----------------------------------------- #
        model_ok_now = not pre_missing or all("model" not in m for m in pre_missing)
        target = model_target(p, spec)
        facts = deployment_facts(spec, engine_info["binary"],
                                 engine_info["sha256_16"], target, p["app"])
        argv = facts["argv"]            # this run's facts; replaced by the
                                        # real spawn on fresh/restart paths
        action, why = decide_resume(marker, spec, model_ok_now, service_ok,
                                    facts=facts)
        audit.emit("STATE", app=name, phase="decision", action=action, why=why)

        if action == "superseded":
            rollback(audit, p, name, "superseded_by_new_model_sha256",
                     popen=popen)
            action, why = "fresh", "old version rolled back"

        if action in ("dedup_ready", "restart"):
            # idempotent path: no download
            audit.emit("DEDUP", app=name, key=dedup_key(spec), why=why)
            if action == "restart":
                old_pid = (marker or {}).get("pid")
                if old_pid:
                    old_argv = (marker or {}).get("argv")
                    outcome = stop_process(
                        old_pid,
                        verify_argv=old_argv
                        if isinstance(old_argv, list) and old_argv else None,
                        grace=LIMITS["kill_grace_s"])
                    audit.emit("STATE", app=name, phase="restart",
                               killed_pid_outcome=outcome)
                popen, argv = start_service(audit, name, engine_info["binary"],
                                            spec, target, p["app"])
                write_marker(p, {"app": name, "state": "partial",
                                 "dedup_key": dedup_key(spec),
                                 "model_sha256": spec["model"]["sha256"],
                                 "engine_binary": engine_info["binary"],
                                 "engine_sha256_16": engine_info["sha256_16"],
                                 "port": spec["service"]["port"],
                                 "health": spec["service"]["health"],
                                 "pid": popen.pid, "argv": argv})
                if not wait_health(audit, name, spec["service"]["port"],
                                   spec["service"]["health"],
                                   args.health_timeout, proc=popen):
                    raise InstallError("health", "no HTTP 200 on %s within %ss"
                                       % (spec["service"]["health"],
                                          args.health_timeout), 4)
            else:
                # dedup_ready: a healthy service is already running — keep it
                # exactly as it is (no second process on the same port). The
                # ready marker below keeps the recorded pid but writes THIS
                # run's self-consistent facts (no drift ⇔ they coincide).
                if not wait_health(audit, name, spec["service"]["port"],
                                   spec["service"]["health"],
                                   min(args.health_timeout, 30.0)):
                    raise InstallError("health",
                                       "service lost between probe and READY",
                                       4)
        else:  # fresh | resume
            if action == "resume":
                audit.emit("DEDUP", app=name, key=dedup_key(spec), why=why)
            if action == "resume" and os.path.isfile(target):
                os.remove(target)
            write_marker(p, {"app": name, "state": "installing",
                             "dedup_key": dedup_key(spec),
                             "model_sha256": spec["model"]["sha256"],
                             "engine_binary": engine_info["binary"],
                             "engine_sha256_16": engine_info["sha256_16"],
                             "port": spec["service"]["port"],
                             "health": spec["service"]["health"]})
            urls = build_mirror_urls(spec["model"]["mirror_urls"],
                                     spec["model"]["repo"], spec["model"]["file"])
            if not urls:
                raise InstallError("download", "appspec has no mirror_urls and "
                                   "no verified local copy", 3)
            part = os.path.join(p["downloads"], "%s-%s-%d.part"
                                % (name, spec["model"]["sha256"][:12],
                                   os.getpid()))
            got, size = download_model(audit, name, urls, part,
                                       spec["model"]["sha256"])
            audit.emit("VERIFY_OK", app=name, what="model", sha256=got,
                       bytes=size)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.replace(part, target)           # atomic within the sandbox fs
            audit.emit("PLACE", app=name, path=target, bytes=size)
            popen, argv = start_service(audit, name, engine_info["binary"],
                                        spec, target, p["app"])
            write_marker(p, {"app": name, "state": "partial",
                             "dedup_key": dedup_key(spec),
                             "model_sha256": got,
                             "engine_binary": engine_info["binary"],
                             "engine_sha256_16": engine_info["sha256_16"],
                             "port": spec["service"]["port"],
                             "health": spec["service"]["health"],
                             "pid": popen.pid, "argv": argv})
            if not wait_health(audit, name, spec["service"]["port"],
                               spec["service"]["health"], args.health_timeout,
                               proc=popen):
                raise InstallError("health", "no HTTP 200 on %s within %ss"
                                   % (spec["service"]["health"],
                                      args.health_timeout), 4)

        # --- ready: re-verify the placed bytes (a concurrent writer or a
        # lost race must never reach READY), then marker, probe, READY ----- #
        final_state, final_missing = install_state_of(spec, p, engine_info, None)
        if final_state != "ready":
            raise InstallError("verify",
                               "VERIFY_FAIL: post-placement re-verify failed "
                               "(%s)" % "; ".join(final_missing), 3)
        write_marker(p, {"app": name, "state": "ready",
                         "dedup_key": dedup_key(spec),
                         "model_sha256": spec["model"]["sha256"],
                         "engine_binary": engine_info["binary"],
                         "engine_sha256_16": engine_info["sha256_16"],
                         "port": spec["service"]["port"],
                         "health": spec["service"]["health"],
                         "pid": popen.pid if popen else (marker or {}).get("pid"),
                         "argv": argv,
                         "install_dir": p["app"]})
        probe_refresh(audit, name, args.appspec, p)
        audit.emit("READY", app=name, port=spec["service"]["port"],
                   install_dir=p["app"],
                   dedup=(action in ("dedup_ready", "restart")),
                   install_state=final_state,
                   missing=final_missing or None,
                   model_sha256_16=spec["model"]["sha256"][:16],
                   engine_binary=engine_info["binary"])
        now_note("READY: %s on port %d (%s)" % (name, spec["service"]["port"], action))
        popen = None                       # the running service is the product
        return finish(0)

    except InstallError as e:
        audit.emit("INSTALL_FAIL", app=name, step=e.step, error=e.reason,
                   exit_code=e.code)
        now_note("FAIL at %s: %s" % (e.step, e.reason))
        code = e.code
        # "lock" holds no lock and mutated nothing — never roll back another
        # install's live state just because we lost the race for it.
        if e.step not in ("read", "schema", "lock") \
                and spec is not None and p is not None:
            if not rollback(audit, p, name, "failed:%s" % e.step, popen=popen):
                code = 5                   # rollback itself left something behind
        return finish(code)
    except OSError as e:
        # Bare OSError (ENOSPC, EACCES, ENOENT on a model.file sub-directory…)
        # must reach the same fail-closed path as InstallError: whatever was
        # placed or started is rolled back (a service started before the
        # failing write dies with it), exit 3 — 5 if the rollback leaks.
        ie = InstallError("io", "%s: %s" % (type(e).__name__, str(e)[:200]), 3)
        audit.emit("INSTALL_FAIL", app=name, step=ie.step, error=ie.reason,
                   exit_code=ie.code)
        now_note("FAIL at %s: %s" % (ie.step, ie.reason))
        code = ie.code
        if spec is not None and p is not None:
            if not rollback(audit, p, name, "failed:%s" % ie.step, popen=popen):
                code = 5
        return finish(code)
    except KeyboardInterrupt:
        if spec is not None and p is not None:
            rollback(audit, p, name, "interrupted", popen=popen)
        return finish(4)
    finally:
        release_app_lock(lock_fd)


# --------------------------------------------------------------------------- #
# rollback / status subcommands
# --------------------------------------------------------------------------- #

def cmd_rollback(args) -> int:
    sandbox = os.path.abspath(args.sandbox_root)
    name = args.name
    if not NAME_RE.match(name or ""):
        now_note("invalid app name %r" % name)
        return 2
    p = sandbox_paths(sandbox, name)
    audit = Audit(args.audit_path or os.path.join(sandbox, AUDIT_NAME))
    if not audit.usable:               # fail-closed: no audit trail, no change
        now_note("refusing to roll back: audit file unavailable (fail-closed)")
        audit.close()
        return 2
    try:
        lock_fd = acquire_app_lock(p)
    except OSError as e:
        audit.emit("ROLLBACK", app=name, reason=args.reason,
                   error="app lock unusable: %s" % e, exit_code=6)
        now_note("FAIL: app lock unusable: %s" % e)
        audit.close()
        return 6
    if lock_fd is None:
        audit.emit("ROLLBACK", app=name, reason=args.reason,
                   error="another install in progress", exit_code=6)
        now_note("another install is in progress for %r" % name)
        audit.close()
        return 6
    try:
        if read_marker(p) is None and not os.path.isdir(p["app"]):
            audit.emit("ROLLBACK", app=name, reason=args.reason,
                       note="nothing to roll back", state="absent")
            now_note("nothing to roll back: %s" % name)
            return 0
        return 0 if rollback(audit, p, name, args.reason) else 5
    finally:
        release_app_lock(lock_fd)
        audit.close()


def cmd_status(args) -> int:
    sandbox = os.path.abspath(args.sandbox_root)
    apps_root = os.path.join(sandbox, "apps")
    if args.name:
        names = [args.name]
    else:
        # <name>.lock files are mutexes, not apps — never report them
        names = sorted(f for f in os.listdir(apps_root)
                       if not f.endswith(".lock")) \
            if os.path.isdir(apps_root) else []
    out = {"sandbox": sandbox, "apps": []}
    for name in names:
        p = sandbox_paths(sandbox, name)
        marker = read_marker(p)
        if marker is None:
            out["apps"].append({"app": name, "state": "absent"})
            continue
        entry = {"app": name, "state": marker.get("state"),
                 "model_sha256_16": (marker.get("model_sha256") or "")[:16] or None,
                 "port": marker.get("port"), "pid": marker.get("pid"),
                 "pid_alive": pid_alive(marker["pid"])
                 if marker.get("pid") else None,
                 "install_dir": marker.get("install_dir", p["app"])}
        if marker.get("port") and entry["pid_alive"]:
            spec = {"service": {"port": marker["port"],
                                "health": marker.get("health", "/health")}}
            entry["health_now"] = service_healthy_now(spec)
            entry["live_state"] = "ready" if entry["health_now"] else "degraded"
        elif marker.get("state") == "ready":
            entry["live_state"] = "degraded"
        out["apps"].append(entry)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# selftest — pure functions (no network, no sandbox writes; one throwaway
# tempdir exercises the audit fail-closed path)
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
        "schema": "appspec/1", "name": "qwen3-1.7b-q8_0",
        "engine": {"name": "llama.cpp", "ref": "b11062",
                   "binary": "/opt/llama/bin/llama-server",
                   "sha256": "a" * 64},
        "model": {"repo": "Qwen/Qwen3-1.7B-GGUF", "file": "Qwen3-1.7B-Q8_0.gguf",
                  "format": "gguf", "sha256": "b" * 64,
                  "mirror_urls": ["https://hf-mirror.com"]},
        "service": {"port": 18010, "health": "/health",
                    "args": ["-m", "{model}", "--port", "{port}"]},
    }
    spec, err = validate_appspec(good)
    check("schema.accepts_good", spec is not None and err is None, err or "")
    if spec:
        check("schema.defaults_args",
              spec["service"]["args"] == ["-m", "{model}", "--port", "{port}"])
    noargs = json.loads(json.dumps(good))
    del noargs["service"]["args"]
    del noargs["service"]["health"]
    del noargs["model"]["mirror_urls"]
    s2, e2 = validate_appspec(noargs)
    check("schema.defaults_fillin",
          s2 is not None and s2["service"]["health"] == "/health"
          and s2["service"]["args"] == []          # engine default applied at render
          and s2["model"]["mirror_urls"] == [], e2 or "")
    check("render.default_args",
          render_args([], s2, "/sb/m.gguf", "/sb/app")
          == ["-m", "/sb/m.gguf", "--host", "127.0.0.1", "--port", "18010"])
    check("render.placeholders",
          render_args(["-m", "{model}", "--port", "{port}", "--dir", "{app_dir}"],
                      s2, "/sb/m.gguf", "/sb/app")
          == ["-m", "/sb/m.gguf", "--port", "18010", "--dir", "/sb/app"])

    def bad(mutate, label):
        obj = json.loads(json.dumps(good))
        mutate(obj)
        s, e = validate_appspec(obj)
        check("schema.rejects_" + label, s is None and bool(e), e or "accepted")

    bad(lambda o: o.update(extra=1), "unknown_top_field")
    bad(lambda o: o.pop("engine"), "missing_engine")
    bad(lambda o: o.update(schema="appspec/2"), "wrong_schema")
    bad(lambda o: o.update(name=""), "empty_name")
    bad(lambda o: o.update(name="../evil"), "traversal_name")
    bad(lambda o: o.update(name="a/b"), "slash_name")
    bad(lambda o: o["engine"].update(sha256="xyz"), "bad_engine_sha")
    bad(lambda o: o["engine"].update(binary="relative/path"), "relative_binary")
    bad(lambda o: o["engine"].update(hack=1), "unknown_engine_field")
    bad(lambda o: o["engine"].pop("name"), "missing_engine_name")

    # --- A5: engine whitelist — basename decides, interpreters die here --- #
    good_bin = json.loads(json.dumps(good))
    good_bin["engine"]["binary"] = "/opt/llama.cpp/bin/llama-server"
    s5, e5 = validate_appspec(good_bin)
    check("engine.accepts_whitelisted_path", s5 is not None and e5 is None,
          e5 or "")
    good_exe = json.loads(json.dumps(good))
    good_exe["engine"]["binary"] = "/opt/w/llama-server.exe"   # windows form
    check("engine.accepts_whitelisted_exe",
          validate_appspec(good_exe)[0] is not None)
    bad(lambda o: o["engine"].update(binary="/bin/sh"), "engine_interpreter_sh")
    bad(lambda o: o["engine"].update(binary="/bin/bash"),
        "engine_interpreter_bash")
    bad(lambda o: o["engine"].update(binary="/usr/bin/python3.11"),
        "engine_interpreter_python")
    bad(lambda o: o["engine"].update(binary="/usr/bin/perl"),
        "engine_interpreter_perl")
    bad(lambda o: o["engine"].update(binary="/opt/evil/llama-server-evil"),
        "engine_basename_mismatch")
    bad(lambda o: o["engine"].update(name="vllm"),
        "engine_name_not_whitelisted")
    no_bin = json.loads(json.dumps(good))
    del no_bin["engine"]["binary"]        # search path: whitelist still gates
    del no_bin["engine"]["sha256"]
    del no_bin["engine"]["ref"]
    check("engine.no_binary_whitelisted_name_ok",
          validate_appspec(no_bin)[0] is not None)

    # --- engine.install node: schema for the engine-level install ---------- #
    inst_good = json.loads(json.dumps(good))
    del inst_good["engine"]["binary"]
    del inst_good["engine"]["sha256"]
    del inst_good["engine"]["ref"]
    inst_good["engine"]["install"] = {
        "mirror_urls": ["http://127.0.0.1:18099/llama-cpu.tgz"],
        "sha256": "c" * 64, "format": "tgz",
        "strip_components": 1, "binary_inside": "bin/llama-server"}
    si, ei = validate_appspec(inst_good)
    check("install.accepts_full_node", si is not None and ei is None, ei or "")
    if si:
        check("install.normalized",
              si["engine"]["install"] == {
                  "mirror_urls": ["http://127.0.0.1:18099/llama-cpu.tgz"],
                  "sha256": "c" * 64, "format": "tgz",
                  "strip_components": 1, "binary_inside": "bin/llama-server"},
              str(si["engine"].get("install")))
    minimal = json.loads(json.dumps(inst_good))
    minimal["engine"]["install"] = {"mirror_urls": ["file:///m/e.tgz"],
                                    "sha256": "d" * 64, "format": "tgz"}
    sm, em = validate_appspec(minimal)
    check("install.minimal_defaults_strip0",
          sm is not None and sm["engine"]["install"]["strip_components"] == 0
          and "binary_inside" not in sm["engine"]["install"], em or "")

    def bad_inst(mutate, label):
        obj = json.loads(json.dumps(inst_good))
        mutate(obj)
        s, e = validate_appspec(obj)
        check("install.rejects_" + label, s is None and bool(e), e or "accepted")

    bad_inst(lambda o: o["engine"]["install"].pop("mirror_urls"),
             "missing_mirror_urls")
    bad_inst(lambda o: o["engine"]["install"].pop("sha256"), "missing_sha256")
    bad_inst(lambda o: o["engine"]["install"].pop("format"), "missing_format")
    bad_inst(lambda o: o["engine"]["install"].update(zip="tgz"),
             "unknown_field")
    bad_inst(lambda o: o["engine"]["install"].update(format="zip"),
             "bad_format")
    bad_inst(lambda o: o["engine"]["install"].update(sha256="c" * 63),
             "short_sha256")
    bad_inst(lambda o: o["engine"]["install"].update(sha256="C" * 64),
             "uppercase_sha256")
    bad_inst(lambda o: o["engine"]["install"].update(strip_components=-1),
             "negative_strip")
    bad_inst(lambda o: o["engine"]["install"].update(strip_components=True),
             "bool_strip")
    bad_inst(lambda o: o["engine"]["install"].update(strip_components="1"),
             "str_strip")
    bad_inst(lambda o: o["engine"]["install"].update(strip_components=33),
             "huge_strip")
    bad_inst(lambda o: o["engine"]["install"].update(binary_inside="/etc/sh"),
             "abs_binary_inside")
    bad_inst(lambda o: o["engine"]["install"].update(binary_inside="../sh"),
             "traversal_binary_inside")
    bad_inst(lambda o: o["engine"]["install"].update(binary_inside="bin//sh"),
             "empty_part_binary_inside")
    bad_inst(lambda o: o["engine"]["install"].update(binary_inside="bin/sh"),
             "interpreter_basename_inside")
    bad_inst(lambda o: o["engine"]["install"].update(
        binary_inside="bin/llama-server-evil"), "basename_mismatch_inside")
    bad_inst(lambda o: o["engine"]["install"].update(mirror_urls=["ftp://x/e"]),
             "bad_mirror_scheme_inside")
    bad_inst(lambda o: o["engine"]["install"].update(mirror_urls="http://x/e"),
             "mirrors_not_list_inside")
    bad_inst(lambda o: o["engine"].update(install="tgz"), "install_not_object")
    # engine.binary + install both present: schema-legal (runtime prefers the
    # binary; install is the fallback), basename rules unchanged
    both = json.loads(json.dumps(good))
    both["engine"]["install"] = {"mirror_urls": ["http://x/e.tgz"],
                                 "sha256": "c" * 64, "format": "tgz"}
    check("install.binary_plus_install_ok", validate_appspec(both)[0] is not None)
    check("install.dedup_urls",
          dedup_urls(["http://a/x.tgz", "http://a/x.tgz", "http://b/x.tgz"])
          == ["http://a/x.tgz", "http://b/x.tgz"])

    # provenance gate: skip only when the tree was built from the pinned
    # archive; a foreign/corrupt/absent marker forces a (re)install
    check("install.provenance_gate",
          engine_provenance_matches({"schema": ENGINE_MARKER_SCHEMA,
                                     "archive_sha256": "c" * 64}, "c" * 64)
          and not engine_provenance_matches(
              {"schema": ENGINE_MARKER_SCHEMA, "archive_sha256": "c" * 64},
              "d" * 64)
          and not engine_provenance_matches(None, "c" * 64)
          and not engine_provenance_matches({"schema": "other"}, "c" * 64)
          and not engine_provenance_matches({}, "c" * 64))

    # resolve_engine's only installable failure is the marked not-found case
    # (search_binary patched through the module dict: resolve_engine looks it
    # up as a global at call time, so the patch is deterministic offline)
    _mod = sys.modules[__name__]
    orig_search = _mod.search_binary
    try:
        _mod.search_binary = lambda binname: None
        nf_info, nf_err = resolve_engine(
            {"engine": {"name": "llama.cpp",
                        "install": {"mirror_urls": ["http://x/e.tgz"],
                                    "sha256": "c" * 64, "format": "tgz"}}})
    finally:
        _mod.search_binary = orig_search
    check("install.not_found_marker",
          nf_info is None and nf_err is not None
          and nf_err.startswith(ENGINE_NOT_FOUND), str(nf_err))
    bad(lambda o: o["model"].update(sha256="0" * 63), "short_model_sha")
    bad(lambda o: o["model"].pop("sha256"), "missing_model_sha")
    bad(lambda o: o["model"].update(format="onnx"), "bad_format")
    bad(lambda o: o["model"].update(file="/abs/path.gguf"), "abs_model_file")
    bad(lambda o: o["model"].update(file="a/../../b.gguf"), "traversal_model_file")
    bad(lambda o: o["model"].update(repo="../org/repo"), "traversal_repo")
    bad(lambda o: o["model"].update(mirror_urls="https://x"), "mirrors_not_list")
    bad(lambda o: o["model"].update(mirror_urls=["ftp://x"]), "bad_mirror_scheme")
    bad(lambda o: o["model"].update(mirror_urls=["https://x"] * 9), "too_many_mirrors")
    bad(lambda o: o["service"].update(port=0), "port_zero")
    bad(lambda o: o["service"].update(port=70000), "port_too_big")
    bad(lambda o: o["service"].update(port=True), "port_bool")
    bad(lambda o: o["service"].update(port="18010"), "port_str")
    bad(lambda o: o["service"].update(health="health"), "health_no_slash")
    bad(lambda o: o["service"].update(args=["-m", None]), "args_not_str")
    bad(lambda o: o["service"].update(probe_period_s=30), "unknown_service_field")
    bad(lambda o: o["engine"].update({"actions": []}), "forbidden_key")

    urls = build_mirror_urls(["https://hf-mirror.com/", "https://hf-mirror.com"],
                             "Qwen/Qwen3-1.7B-GGUF", "Qwen3-1.7B-Q8_0.gguf")
    check("urls.built_and_deduped", urls == [
        "https://hf-mirror.com/Qwen/Qwen3-1.7B-GGUF/resolve/main/Qwen3-1.7B-Q8_0.gguf"],
        str(urls))
    check("urls.quoted", build_mirror_urls(["https://x.com"], "o/r", "a b.gguf")
          == ["https://x.com/o/r/resolve/main/a%20b.gguf"])
    check("urls.file_scheme",
          build_mirror_urls(["file:///tmp/mirror"], "o/r", "m.gguf")
          == ["file:///tmp/mirror/o/r/resolve/main/m.gguf"])

    check("redact.query_dropped",
          redact_url("https://hf-mirror.com/a/b?token=SECRET#frag")
          == "https://hf-mirror.com/a/b")

    mk = lambda state, sha: {"schema": MARKER_SCHEMA, "app": "x", "state": state,
                             "model_sha256": sha, "pid": None}
    S, T = "b" * 64, "c" * 64
    cases = [
        (None, False, False, "fresh"),
        (mk("ready", S), False, True, "resume"),
        (mk("ready", S), True, True, "dedup_ready"),
        (mk("ready", S), True, False, "restart"),
        (mk("partial", S), False, True, "resume"),
        (mk("ready", T), True, True, "superseded"),
        (mk("ready", T), True, False, "superseded"),
    ]
    for marker, model_ok, svc_ok, want in cases:
        action, _ = decide_resume(marker, good, model_ok, svc_ok)
        check("decide.%s" % want, action == want, "got %s" % action)

    check("dedup.key", dedup_key(good) == "qwen3-1.7b-q8_0:" + "b" * 64)
    check("containment.rejects_escape",
          not path_inside("/sb/apps", "/sb/apps-x")
          and not path_inside("/sb/apps", "/etc")
          and path_inside("/sb/apps", "/sb/apps/n/../n/m.gguf"))

    # --- pid facts: zombie ≠ alive (fix 5); exact-argv kill gate (fix 6) --- #
    check("proc.stat_state.comm_with_parens",
          _stat_state("1234 (my (weird) proc) S 1 2") == "S")
    check("proc.stat_state.zombie", _stat_state("42 (x) Z 1 2") == "Z")
    check("proc.stat_state.garbage", _stat_state("no parens") is None
          and _stat_state("") is None)
    check("proc.pid_alive.self", pid_alive(os.getpid()) is True)
    check("proc.pid_alive.no_such_pid", pid_alive(2 ** 31 - 1) is False)
    check("proc.parse_cmdline",
          parse_cmdline(b"tail\x00-f\x00app.log\x00")
          == ["tail", "-f", "app.log"]
          and parse_cmdline(b"a\x00b") == ["a", "b"]          # tolerant
          and parse_cmdline(b"") == [])
    check("proc.stop_process.skips_unverified_argv",
          stop_process(os.getpid(), verify_argv=["definitely", "not", "us"],
                       grace=0) == "skipped_unverified")
    check("proc.stop_process.already_dead",
          stop_process(2 ** 31 - 1, verify_argv=None, grace=0)
          == "already_dead")
    check("proc.argv_matches.exact",
          argv_matches(["/opt/e/server", "-m", "x"], ["/opt/e/server", "-m", "x"]))
    check("proc.argv_matches.shebang_interp_prefix",
          argv_matches(["python3", "/opt/e/server", "-m", "x"],
                       ["/opt/e/server", "-m", "x"]))
    check("proc.argv_matches.rejects_substring_shapes",
          not argv_matches(["tail", "-f", "/sb/apps/a/service.log"],
                           ["/sb/apps/a"])
          and not argv_matches(["/opt/e/server", "-m", "OTHER"],
                               ["/opt/e/server", "-m", "x"])
          and not argv_matches([], ["/x"])
          and not argv_matches(["python3"], ["/x"]))

    # --- deployment facts: dedup decision is facts-complete (fix 7) -------- #
    eng_bin = "/opt/llama/bin/llama-server"
    facts = deployment_facts(good, eng_bin, "a" * 16, "/sb/m.gguf", "/sb/app")
    check("facts.complete",
          facts["port"] == 18010 and facts["health"] == "/health"
          and facts["engine_binary"] == eng_bin
          and facts["engine_sha256_16"] == "a" * 16
          and facts["argv"] == [eng_bin, "-m", "/sb/m.gguf", "--port", "18010"],
          str(facts))
    mfull = {"schema": MARKER_SCHEMA, "app": "x", "state": "ready",
             "model_sha256": S, "pid": 4242, **facts}
    check("facts.no_drift_dedup_ready",
          decide_resume(mfull, good, True, True, facts=facts)[0]
          == "dedup_ready")
    check("facts.no_drift_restart_when_down",
          decide_resume(mfull, good, True, False, facts=facts)[0] == "restart")
    for k, v in (("port", 19999), ("health", "/live"), ("argv", ["other"]),
                 ("engine_binary", "/other/engine"),
                 ("engine_sha256_16", "f" * 16)):
        drifted = dict(mfull)
        drifted[k] = v
        action, why = decide_resume(drifted, good, True, True, facts=facts)
        check("facts.drift_%s_restarts" % k, action == "restart" and k in why,
              "%s/%s" % (action, why))

    # --- download budget: known size extends the fixed floor (fix 10) ------ #
    check("download.budget_floor",
          attempt_budget(None) == float(LIMITS["download_attempt_deadline_s"]))
    cap = LIMITS["model_max_bytes"]
    check("download.budget_extends",
          attempt_budget(cap) == max(float(LIMITS["download_attempt_deadline_s"]),
                                     cap / LIMITS["download_min_bytes_per_s"]))
    check("download.stall_budget_present",
          LIMITS["download_stall_timeout_s"] == 120)

    # --- redirect policy: never downgrade https → http (fix 9) ------------- #
    rh = NoDowngradeRedirectHandler()
    check("redirect.refuses_downgrade",
          rh.redirect_request(urllib.request.Request("https://a.example/b"),
                              None, 302, "found", {},
                              "http://a.example/b") is None)
    r2 = rh.redirect_request(urllib.request.Request("http://a.example/b"),
                             None, 302, "found", {}, "http://a.example/c")
    check("redirect.allows_plain_http",
          isinstance(r2, urllib.request.Request)
          and r2.full_url == "http://a.example/c")
    r3 = rh.redirect_request(urllib.request.Request("https://a.example/b"),
                             None, 302, "found", {}, "https://a.example/c")
    check("redirect.allows_https_to_https",
          isinstance(r3, urllib.request.Request))

    # --- audit: fail-closed when unavailable, lost-count at close (fix 8) -- #
    with tempfile.TemporaryDirectory(prefix="bicameral-selftest-") as td:
        a = Audit(os.path.join(td, "audit.jsonl"))
        ok = a.usable
        a.emit("T", x=1)
        check("audit.roundtrip", ok and a.close() == 0)
        blocker = os.path.join(td, "blocker")
        open(blocker, "w").close()
        b = Audit(os.path.join(blocker, "nested", "audit.jsonl"))
        check("audit.unavailable_fails_closed",
              not b.usable and b.lost > 0 and b.close() > 0)

    # --- engine archive extraction: traversal rejection + binary_inside ---- #
    check("tar.member_name_checks",
          _tar_member_error("bin/llama-server") is None
          and _tar_member_error("bin/./llama-server") is None
          and _tar_member_error("/etc/shadow") == "absolute member path"
          and _tar_member_error("../evil") == "'..' path part"
          and _tar_member_error("a/../../evil") == "'..' path part"
          and _tar_member_error("") == "absolute member path")
    with tempfile.TemporaryDirectory(prefix="bicameral-selftest-tar-") as td:
        def _member(tf_arc, name, data=b"x", type=tarfile.REGTYPE,
                    linkname="", mode=0o644):
            ti = tarfile.TarInfo(name)
            ti.size = len(data) if type == tarfile.REGTYPE else 0
            ti.type = type
            ti.linkname = linkname
            ti.mode = mode
            tf_arc.addfile(ti, io.BytesIO(data) if type == tarfile.REGTYPE
                           else None)

        def _mk_tar(path, member_fn):
            with tarfile.open(path, "w:gz") as arc:
                member_fn(arc)

        def _good_members(arc):
            _member(arc, "pkg/", type=tarfile.DIRTYPE, mode=0o755)
            _member(arc, "pkg/bin/", type=tarfile.DIRTYPE, mode=0o755)
            _member(arc, "pkg/bin/llama-server", b"#!/bin/sh\nexit 0\n",
                    mode=0o644)
            _member(arc, "pkg/README", b"hi\n")

        good_tgz = os.path.join(td, "good.tgz")
        _mk_tar(good_tgz, _good_members)
        dest = os.path.join(td, "dest-good")
        total, members = extract_engine_tgz(good_tgz, dest, 1)
        placed = os.path.join(dest, "bin", "llama-server")
        check("tar.extract_strip_and_bytes",
              total == 20 and members == 3                # "pkg/" stripped away
              and open(placed, "rb").read() == b"#!/bin/sh\nexit 0\n",
              "total=%s members=%s" % (total, members))

        def _reject_case(label, member_fn, outside="evil.txt"):
            tgz = os.path.join(td, "bad-%s.tgz" % label)
            _mk_tar(tgz, member_fn)
            d = os.path.join(td, "dest-%s" % label)
            escaped_out = os.path.join(td, outside)
            if os.path.lexists(escaped_out):
                os.remove(escaped_out)
            raised = None
            try:
                extract_engine_tgz(tgz, d, 0)
            except InstallError as e:
                raised = e
            check("tar.rejects_%s" % label,
                  raised is not None and raised.step == "engine"
                  and not os.path.lexists(escaped_out),
                  str(raised))

        _reject_case("dotdot_member",
                     lambda arc: _member(arc, "../evil.txt", b"nope"))
        _reject_case("deep_dotdot_member",
                     lambda arc: _member(arc, "a/../../evil.txt", b"nope"))
        _reject_case("abs_member",
                     lambda arc: _member(arc, "/abs/evil.txt", b"nope"),
                     outside="abs")
        _reject_case("symlink_escape",
                     lambda arc: _member(arc, "link", type=tarfile.SYMTYPE,
                                         linkname="../../outside"),
                     outside="outside")
        _reject_case("symlink_then_write",
                     lambda arc: (_member(arc, "out", type=tarfile.DIRTYPE),
                                  _member(arc, "out_link", type=tarfile.SYMTYPE,
                                          linkname="../.."),
                                  _member(arc, "out_link/evil.txt", b"nope")))
        _reject_case("abs_link",
                     lambda arc: _member(arc, "link", type=tarfile.SYMTYPE,
                                         linkname="/etc"))
        _reject_case("fifo_member",
                     lambda arc: _member(arc, "f", type=tarfile.FIFOTYPE))

        # binary_inside resolution: explicit, unique-search, ambiguous, missing
        loc = _locate_engine_binary(dest, "bin/llama-server",
                                    ("llama-server",))
        check("tar.locate_explicit", loc == placed, loc)
        check("tar.locate_search_unique",
              _locate_engine_binary(dest, None, ("llama-server",)) == placed)
        os.rename(placed, os.path.join(dest, "bin", "llama-server2"))
        try:
            _locate_engine_binary(dest, None, ("llama-server",))
            check("tar.locate_missing_fails", False, "accepted")
        except InstallError as e:
            check("tar.locate_missing_fails", e.step == "engine")
        os.rename(os.path.join(dest, "bin", "llama-server2"), placed)
        os.makedirs(os.path.join(dest, "sbin"), exist_ok=True)
        open(os.path.join(dest, "sbin", "llama-server"), "wb").close()
        try:
            _locate_engine_binary(dest, None, ("llama-server",))
            check("tar.locate_ambiguous_fails", False, "accepted")
        except InstallError as e:
            check("tar.locate_ambiguous_fails", e.step == "engine")

    # shipped examples must validate (the bad sha is a runtime VERIFY_FAIL,
    # not a schema error — schema sees 64 hex and accepts)
    here = os.path.dirname(os.path.abspath(__file__))
    ex = os.path.join(here, "..", "examples", "appspec-qwen3-1.7b-q8_0.json")
    if os.path.isfile(ex):
        with open(ex, "r", encoding="utf-8") as f:
            s, e = validate_appspec(json.load(f))
        check("examples.good_appspec_valid", s is not None and e is None, e or "")
    bad_ex = os.path.join(here, "..", "examples", "appspec-badsha.json")
    if os.path.isfile(bad_ex):
        with open(bad_ex, "r", encoding="utf-8") as f:
            s, e = validate_appspec(json.load(f))
        check("examples.badsha_schema_valid", s is not None and e is None, e or "")
        if s:
            check("examples.badsha_differs_only_in_sha",
                  s["model"]["sha256"] != (json.load(open(ex))["model"]["sha256"]))
    inst_ex = os.path.join(here, "..", "examples", "appspec-engine-install.json")
    if os.path.isfile(inst_ex):
        with open(inst_ex, "r", encoding="utf-8") as f:
            s, e = validate_appspec(json.load(f))
        check("examples.engine_install_valid", s is not None and e is None,
              e or "")
        if s:
            check("examples.engine_install_shape",
                  s["engine"].get("install", {}).get("format") == "tgz"
                  and s["engine"]["install"].get("binary_inside")
                  and s["model"]["sha256"].startswith("9465e63a"),
                  str(s["engine"].get("install")))

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="install.py",
        description="Bicameral appspec/1 controlled install (paradigm §3.4). "
                    "Stdlib-only, mutating, fully audited, rollback on failure.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sb = os.environ.get("BICAMERAL_SANDBOX_ROOT", DEFAULT_SANDBOX)

    ap_apply = sub.add_parser("apply", help="absent → ready (idempotent)")
    ap_apply.add_argument("appspec", help="appspec/1 JSON file")
    ap_apply.add_argument("--sandbox-root", default=sb)
    ap_apply.add_argument("--audit-path", default=None,
                          help="default <sandbox>/audit.jsonl")
    ap_apply.add_argument("--health-timeout", type=float,
                          default=LIMITS["health_timeout_s"])

    ap_rb = sub.add_parser("rollback", help="remove one app, state → absent")
    ap_rb.add_argument("name")
    ap_rb.add_argument("--sandbox-root", default=sb)
    ap_rb.add_argument("--audit-path", default=None)
    ap_rb.add_argument("--reason", default="manual")

    ap_st = sub.add_parser("status", help="report install_state per app")
    ap_st.add_argument("name", nargs="?", default=None)
    ap_st.add_argument("--sandbox-root", default=sb)

    sub.add_parser("selftest", help="pure-function self-test")

    args = ap.parse_args(argv)
    if args.cmd == "apply":
        return cmd_apply(args)
    if args.cmd == "rollback":
        return cmd_rollback(args)
    if args.cmd == "status":
        return cmd_status(args)
    return cmd_selftest(args)


if __name__ == "__main__":
    sys.exit(main())
