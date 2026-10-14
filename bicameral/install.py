#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral install.py — appspec/1 controlled installation tool (mutating).

Implements docs/paradigm.md §3.4 (deployment & installation, the change
layer): one command takes one device from absent → ready, fully audited,
rollback on any failure. This is Bicameral's mutating controlled tool beyond
fs.write: sandboxed directories, size caps, bounded timeouts and retries,
audit events — 与 server.py 同一工程哲学 (stdlib single file).

Subcommands:
    apply <appspec.json>    absent → ready (idempotent: dedup by
                            name + model sha256; a re-apply on a ready app
                            skips the download and re-achieves READY)
    rollback <name>         remove one app, kill the process it started,
                            install_state → absent
    status [name]           report install_state from sandbox markers plus
                            live pid/health checks
    selftest                pure-function self-test (schema validation,
                            URL building, dedup decisions, redaction)

Flow of apply (each step audited; ANY failure → rollback):
    read appspec → validate schema → probe current install_state (sandbox
    marker + filesystem/service facts) → resolve engine (dual sha256, §5) →
    download model (mirror_urls tried in order, bounded retries/timeouts) →
    verify sha256 (mismatch ⇒ VERIFY_FAIL, the file is never installed) →
    place into <sandbox>/apps/<name>/ → start service → health check (the
    health endpoint must answer HTTP 200) → re-run probe/1 to refresh
    install_state → READY.

Sandbox layout (default /root/bicameral-sandbox per paradigm; override with
--sandbox-root or BICAMERAL_SANDBOX_ROOT — the default assumes root; on a
non-root box redirect it):
    <sandbox>/apps/<name>/models/<file>                    installed model
    <sandbox>/apps/<name>/.bicameral-install-state.json    marker (state/pid/sha)
    <sandbox>/apps/<name>/service.log                      service stdout+stderr
    <sandbox>/downloads/<name>-<sha12>.part                in-flight download
    <sandbox>/audit.jsonl                                  audit trail

Audit events (style-aligned with bicameral/server.py: ts + event + key
summary, never secrets — mirror URLs are redacted to scheme://host/path so a
token-bearing query never lands in the log):
    INSTALL_START, STATE, DEDUP, ENGINE_FOUND, DOWNLOAD, VERIFY_OK,
    VERIFY_FAIL, PLACE, START, HEALTH, PROBE_REFRESH, READY, INSTALL_FAIL,
    ROLLBACK.

Dual sha256 semantics (paradigm §5 supply-chain row: "appspec 双 sha256 +
下载后校验 + 安装目录指纹入审计"):
    - model.sha256 is MANDATORY. The file is hashed while streaming and must
      equal the pin exactly, else VERIFY_FAIL + rollback.
    - engine.sha256 is OPTIONAL (the binary may already be on the device).
      When the pin is given, the binary found at engine.binary (or via
      PATH/install roots) must match exactly, else VERIFY_FAIL + rollback.
      When no pin is given, the found binary's sha256-16 is still
      fingerprinted into the audit trail — a fingerprint is a fact even
      without a pin.

Exit codes: 0 ok · 2 usage/schema · 3 engine/download/verify failure ·
4 start/health failure · 5 rollback itself also failed.

Python 3.10+, standard library only, no root required (only the default
sandbox path assumes it).
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

SCHEMA = "appspec/1"
MARKER_SCHEMA = "bicameral-install-state/1"
MARKER_NAME = ".bicameral-install-state.json"
DEFAULT_SANDBOX = "/root/bicameral-sandbox"
AUDIT_NAME = "audit.jsonl"

# engine.name → binary name the capability layer actually looks for.
# Mirror of probe.APPSPEC_ENGINE_BINARIES (probe.py is NOT imported: both
# files stay independently deployable single files).
APPSPEC_ENGINE_BINARIES = {
    "llama.cpp": "llama-server",
    "llama-server": "llama-server",
    "vllm": "vllm",
    "strata": "strata",
}

LIMITS = {
    "model_max_bytes": 32 * 1024 ** 3,     # hard cap on one model download
    "download_read_timeout_s": 60,         # per-socket-read timeout
    "download_attempt_deadline_s": 900,    # wall clock per attempt (bounded)
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
FORBIDDEN_KEYS = ("actions", "tool_calls")   # same D8 philosophy as server.py


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


# --------------------------------------------------------------------------- #
# audit (style-aligned with server.py: ts + event + non-None fields, JSONL)
# --------------------------------------------------------------------------- #

class Audit:
    def __init__(self, path: str):
        self.path = path
        self._f = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._f = open(path, "a", encoding="utf-8")
        except OSError as e:
            now_note("audit unavailable at %s (%s); events go to stderr only"
                     % (path, e))

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
                pass

    def close(self) -> None:
        if self._f is not None:
            try:
                self._f.close()
            except OSError:
                pass


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
    eng_need, eng_opt = {"name"}, {"ref", "binary", "sha256"}
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
    if "sha256" in eng and not HEX64_RE.match(eng["sha256"]):
        return None, "engine.sha256 must be 64 hex chars"

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
    if not isinstance(mirrors, list):
        return None, "model.mirror_urls must be a list of base URLs"
    if len(mirrors) > LIMITS["download_mirror_max"]:
        return None, "model.mirror_urls exceeds %d entries" % LIMITS["download_mirror_max"]
    for i, m in enumerate(mirrors):
        err = _bad_str(m, "model.mirror_urls[%d]" % i)
        if err:
            return None, err
        u = urllib.parse.urlsplit(m)
        if u.scheme == "file":
            ok = bool(u.path)
        else:
            ok = u.scheme in ("http", "https") and bool(u.netloc)
        if not ok:
            return None, ("model.mirror_urls[%d] must be an http(s) or file "
                          "base URL" % i)

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

    spec = {
        "schema": SCHEMA,
        "name": obj["name"],
        "engine": {k: eng[k] for k in ("name", "ref", "binary", "sha256") if k in eng},
        "model": {"repo": mdl["repo"], "file": mdl["file"], "format": mdl["format"],
                  "sha256": mdl["sha256"].lower(), "mirror_urls": list(mirrors)},
        "service": {"port": port, "health": svc.get("health", "/health"),
                    "args": list(svc.get("args", []))},
    }
    return spec, None


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
            "downloads": os.path.join(sandbox, "downloads")}


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


def pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, TypeError, ValueError):
        return False


def cmdline_of(pid) -> str | None:
    try:
        with open("/proc/%d/cmdline" % int(pid), "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except (OSError, TypeError, ValueError):
        return None


def install_state_of(spec: dict, p: dict, engine_info: dict | None,
                     service_ok: bool | None,
                     skip_model_hash: bool = False) -> tuple[str, list[str]]:
    """absent/partial/ready per probe.eval_appspec semantics (§3.1 #4),
    computed from sandbox + filesystem facts. service_ok=None means the
    service is not checked (used on the READY path, where the health check
    just passed); skip_model_hash trusts the just-verified download."""
    missing: list[str] = []
    engine_present = bool(engine_info and engine_info.get("found"))
    if not engine_present:
        missing.append("engine %r binary not found" % spec["engine"]["name"])
    target = model_target(p, spec)
    model_present = False
    if skip_model_hash:
        model_present = os.path.isfile(target)
        if not model_present:
            missing.append("model file not found: %s" % target)
    elif os.path.isfile(target):
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


def decide_resume(marker: dict | None, spec: dict, model_sha_ok: bool,
                  service_ok: bool) -> tuple[str, str]:
    """Pure idempotency decision (selftest-covered).

    dedup_ready : marker on record, same name+model sha256, model file
                  verified, service healthy → no download, straight to READY.
    restart     : same, but service down → start it again (no download).
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
    binary = eng.get("binary") or search_binary(
        APPSPEC_ENGINE_BINARIES.get(eng["name"], eng["name"]))
    if not binary:
        return None, ("engine %r: binary %r not found (no engine.binary given, "
                      "and not on PATH/install roots)"
                      % (eng["name"], APPSPEC_ENGINE_BINARIES.get(eng["name"], eng["name"])))
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
# download + verify (bounded)
# --------------------------------------------------------------------------- #

def _discard_part(part_path: str) -> None:
    try:
        os.remove(part_path)
    except OSError:
        pass


def download_model(audit: Audit, app: str, urls: list[str], part_path: str,
                   want_sha: str) -> tuple[str, int]:
    """Stream the model to part_path, hashing as we go. mirror_urls tried in
    order; bounded retries per mirror, bounded per-attempt wall clock, hard
    size cap. A sha256 mismatch is VERIFY_FAIL and never installed.
    Returns (sha256_hex, bytes). Raises InstallError(step='download')."""
    last_err = "no mirror attempted"
    for mi, url in enumerate(urls):
        red = redact_url(url)
        for attempt in range(1, LIMITS["download_retries_per_mirror"] + 1):
            deadline = time.monotonic() + LIMITS["download_attempt_deadline_s"]
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "bicameral-install/1"})
                h = hashlib.sha256()
                size = 0
                with urllib.request.urlopen(
                        req, timeout=LIMITS["download_read_timeout_s"]) as r, \
                        open(part_path, "wb") as out:
                    while True:
                        if time.monotonic() > deadline:
                            raise TimeoutError(
                                "attempt deadline %ds exceeded"
                                % LIMITS["download_attempt_deadline_s"])
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > LIMITS["model_max_bytes"]:
                            raise ValueError(
                                "size exceeds model_max_bytes (%d)"
                                % LIMITS["model_max_bytes"])
                        h.update(chunk)
                        out.write(chunk)
                got = h.hexdigest()
                if got != want_sha:
                    audit.emit("VERIFY_FAIL", app=app, what="model",
                               file=os.path.basename(part_path),
                               expected_sha256=want_sha, got_sha256_16=got[:16],
                               mirror=mi + 1, url=red, bytes=size)
                    _discard_part(part_path)
                    raise InstallError(
                        "download", "VERIFY_FAIL: sha256 mismatch (got %s…)"
                        % got[:16], 3)
                audit.emit("DOWNLOAD", app=app, status="ok", mirror=mi + 1,
                           attempt=attempt, url=red, bytes=size,
                           sha256_16=got[:16])
                return got, size
            except InstallError:
                raise
            except Exception as e:  # noqa: BLE001 — a failed mirror is a fact
                last_err = "%s: %s" % (type(e).__name__, str(e)[:200])
                _discard_part(part_path)
                audit.emit("DOWNLOAD", app=app, status="fail", mirror=mi + 1,
                           attempt=attempt, url=red, error=last_err)
                if attempt < LIMITS["download_retries_per_mirror"]:
                    time.sleep(LIMITS["download_retry_backoff_s"])
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


def stop_process(pid, verify_substrings: list[str] | None,
                 grace: float) -> str:
    """SIGTERM → wait grace → SIGKILL. When verify_substrings is given, the
    kill only proceeds if /proc/<pid>/cmdline matches one of them — a stale
    or recycled pid is never signalled. Returns an audit-ready outcome."""
    if not pid_alive(pid):
        return "already_dead"
    if verify_substrings is not None:
        cl = cmdline_of(pid)
        if cl is None or not any(s and s in cl for s in verify_substrings):
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
                timeout_s: float) -> bool:
    """Poll GET http://127.0.0.1:<port><health> until 200 or budget out."""
    url = "http://127.0.0.1:%d%s" % (port, health)
    t0 = time.monotonic()
    attempts, last = 0, None
    while time.monotonic() - t0 < timeout_s:
        attempts += 1
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
    The kill is verified against the argv recorded at START (exact cmdline
    match; the app dir as fallback) — a stale or recycled pid is never
    signalled. Returns True when nothing was left behind (best effort)."""
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
            verify = [" ".join(argv)] if isinstance(argv, list) and argv else []
            verify.append(p["app"])
            killed = stop_process(pid, verify_substrings=verify,
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
    p = None
    spec = None
    name = None
    popen = None                    # child we started; killed on any failure
    try:
        try:
            with open(args.appspec, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError) as e:
            audit.emit("INSTALL_FAIL", step="read", appspec=args.appspec,
                       error="%s: %s" % (type(e).__name__, str(e)[:200]))
            now_note("appspec unreadable/invalid: %s" % e)
            return 2
        spec, err = validate_appspec(raw)
        name = spec["name"] if spec else \
            (raw.get("name") if isinstance(raw, dict) else None)
        if err:
            audit.emit("INSTALL_FAIL", step="schema", app=name,
                       appspec_sha256_16=sha256_16(args.appspec)
                       if os.path.isfile(args.appspec) else None,
                       error=err)
            now_note("schema violation: %s" % err)
            return 2

        p = sandbox_paths(sandbox, name)
        audit.emit("INSTALL_START", app=name,
                   appspec_sha256_16=sha256_16(args.appspec),
                   dedup_key=dedup_key(spec), sandbox=p["sandbox"])
        os.makedirs(p["models"], exist_ok=True)
        os.makedirs(p["downloads"], exist_ok=True)

        # --- probe current install_state (marker + filesystem facts) ------ #
        marker = read_marker(p)
        engine_info, eng_err = resolve_engine(spec)
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
        action, why = decide_resume(marker, spec, model_ok_now, service_ok)
        audit.emit("STATE", app=name, phase="decision", action=action, why=why)
        argv = (marker or {}).get("argv")   # kept on the dedup path, replaced on start

        if action == "superseded":
            rollback(audit, p, name, "superseded_by_new_model_sha256",
                     popen=popen)
            action, why = "fresh", "old version rolled back"

        if action in ("dedup_ready", "restart"):
            # idempotent path: no download
            audit.emit("DEDUP", app=name, key=dedup_key(spec), why=why)
            target = model_target(p, spec)
            if action == "restart":
                old_pid = (marker or {}).get("pid")
                if old_pid:
                    old_argv = (marker or {}).get("argv")
                    verify = ([" ".join(old_argv)]
                              if isinstance(old_argv, list) and old_argv else [])
                    verify.append(p["app"])
                    outcome = stop_process(old_pid, verify_substrings=verify,
                                           grace=LIMITS["kill_grace_s"])
                    audit.emit("STATE", app=name, phase="restart",
                               killed_pid_outcome=outcome)
                popen, argv = start_service(audit, name, engine_info["binary"],
                                            spec, target, p["app"])
                write_marker(p, {"app": name, "state": "partial",
                                 "dedup_key": dedup_key(spec),
                                 "model_sha256": spec["model"]["sha256"],
                                 "engine_binary": engine_info["binary"],
                                 "port": spec["service"]["port"],
                                 "health": spec["service"]["health"],
                                 "pid": popen.pid, "argv": argv})
                if not wait_health(audit, name, spec["service"]["port"],
                                   spec["service"]["health"],
                                   args.health_timeout):
                    raise InstallError("health", "no HTTP 200 on %s within %ss"
                                       % (spec["service"]["health"],
                                          args.health_timeout), 4)
            else:
                # dedup_ready: a healthy service is already running — keep it
                # exactly as it is (no second process on the same port); the
                # ready marker below retains the existing pid.
                if not wait_health(audit, name, spec["service"]["port"],
                                   spec["service"]["health"],
                                   min(args.health_timeout, 30.0)):
                    raise InstallError("health",
                                       "service lost between probe and READY",
                                       4)
        else:  # fresh | resume
            if action == "resume":
                audit.emit("DEDUP", app=name, key=dedup_key(spec), why=why)
            target = model_target(p, spec)
            if action == "resume" and os.path.isfile(target):
                os.remove(target)
            write_marker(p, {"app": name, "state": "installing",
                             "dedup_key": dedup_key(spec),
                             "model_sha256": spec["model"]["sha256"],
                             "engine_binary": engine_info["binary"],
                             "port": spec["service"]["port"],
                             "health": spec["service"]["health"]})
            urls = build_mirror_urls(spec["model"]["mirror_urls"],
                                     spec["model"]["repo"], spec["model"]["file"])
            if not urls:
                raise InstallError("download", "appspec has no mirror_urls and "
                                   "no verified local copy", 3)
            part = os.path.join(p["downloads"],
                                "%s-%s.part" % (name, spec["model"]["sha256"][:12]))
            got, size = download_model(audit, name, urls, part,
                                       spec["model"]["sha256"])
            audit.emit("VERIFY_OK", app=name, what="model", sha256=got,
                       bytes=size)
            os.makedirs(p["models"], exist_ok=True)
            os.replace(part, target)           # atomic within the sandbox fs
            audit.emit("PLACE", app=name, path=target, bytes=size)
            popen, argv = start_service(audit, name, engine_info["binary"],
                                        spec, target, p["app"])
            write_marker(p, {"app": name, "state": "partial",
                             "dedup_key": dedup_key(spec),
                             "model_sha256": got,
                             "engine_binary": engine_info["binary"],
                             "port": spec["service"]["port"],
                             "health": spec["service"]["health"],
                             "pid": popen.pid, "argv": argv})
            if not wait_health(audit, name, spec["service"]["port"],
                               spec["service"]["health"], args.health_timeout):
                raise InstallError("health", "no HTTP 200 on %s within %ss"
                                   % (spec["service"]["health"],
                                      args.health_timeout), 4)

        # --- ready: marker, mandatory probe/1 refresh, READY --------------- #
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
        final_state, final_missing = install_state_of(
            spec, p, engine_info, None, skip_model_hash=True)
        audit.emit("READY", app=name, port=spec["service"]["port"],
                   install_dir=p["app"],
                   dedup=(action in ("dedup_ready", "restart")),
                   install_state=final_state,
                   missing=final_missing or None,
                   model_sha256_16=spec["model"]["sha256"][:16],
                   engine_binary=engine_info["binary"])
        now_note("READY: %s on port %d (%s)" % (name, spec["service"]["port"], action))
        popen = None                       # the running service is the product
        return 0

    except InstallError as e:
        audit.emit("INSTALL_FAIL", app=name, step=e.step, error=e.reason,
                   exit_code=e.code)
        now_note("FAIL at %s: %s" % (e.step, e.reason))
        code = e.code
        if e.step not in ("read", "schema") and spec is not None and p is not None:
            if not rollback(audit, p, name, "failed:%s" % e.step, popen=popen):
                code = 5                   # rollback itself left something behind
        return code
    except KeyboardInterrupt:
        if spec is not None and p is not None:
            rollback(audit, p, name, "interrupted", popen=popen)
        return 4
    finally:
        audit.close()


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
    try:
        if read_marker(p) is None and not os.path.isdir(p["app"]):
            audit.emit("ROLLBACK", app=name, reason=args.reason,
                       note="nothing to roll back", state="absent")
            now_note("nothing to roll back: %s" % name)
            return 0
        return 0 if rollback(audit, p, name, args.reason) else 5
    finally:
        audit.close()


def cmd_status(args) -> int:
    sandbox = os.path.abspath(args.sandbox_root)
    apps_root = os.path.join(sandbox, "apps")
    if args.name:
        names = [args.name]
    else:
        names = sorted(os.listdir(apps_root)) if os.path.isdir(apps_root) else []
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
# selftest — pure functions only (no network, no sandbox writes)
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
