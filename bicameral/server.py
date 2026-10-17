#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral — master-edge permission layer for LLM agent orchestration (cap/3).

两院：异构 agent 各自审议，调和为一案；未经全链校验不放行。
Reference: docs/architecture-v3.md. Paper lineage: docs/architecture-v2.md.

Single process, two ThreadingHTTPServer planes:
    control plane : 0.0.0.0:18000   POST /issue   GET /audit /capabilities /healthz
    agent plane   : 0.0.0.0:18001   POST /agent/invoke

Optional TLS data plane (deploy/tls/README.md): --tls-cert + --tls-key wrap
BOTH planes in TLS (get_request wraps each accepted socket); --tls-client-ca
additionally requires and verifies client certificates (mTLS). Off by
default — without a certificate the plain-HTTP behaviour is unchanged; when
on, /healthz stays token-free but rides the same TLS.

Python 3.11+/3.12, standard library only (no packages, no venv).

PoC simplifications (production replacements live in docs/architecture-v2.md
hardening section):
    - HMAC-SHA256 symmetric master key via env POC_MASTER_KEY (64 hex), with a
      built-in dev fallback key. Production: Ed25519 capability tokens (v2 X1).
    - /issue is unauthenticated. Production: control-plane authn + mTLS.
    - Wall-clock TTL, strict expiry (no skew tolerance). Production: monotonic
      clock / lease server.

v0.2 fixes (after the 14-case red team, all independently re-verified):
    - D2 strict: expired is expired (was exp+30s usable window).
    - /issue budget: aliases (max_calls/max_llm_calls/max_bytes_out) accepted;
      unknown or non-int budget keys are rejected 400 (was silently ignored).
    - D10 429 body carries dim=<calls|llm_calls|bytes>.
    - Response-side smuggle strip on EVERY tool result (was llm.complete only;
      fs.read summary was an unguarded exfil channel).
    - D16 TOKEN_BURNED: 3 policy denials (D5/D6/D7/D12) on one token burn it.
    - D7 SCOPE_VIOLATION 403 (scope escapes no longer fall into D14/500).
    - Nonce store partitioned per jti (a token can no longer evict other
      tokens' replay nonces by flooding its own).
    - D1 DENY carries best-effort unverified jti_claim for forensics.
    - /issue rejects unknown envelope fields with 400 (fail-closed contract).
    - /healthz + START audit expose build_sha (source fingerprint of the
      running file) to kill deploy/version drift.

Audit redaction (stand-in for hardening §4, whose text was not available to
this implementation): audit records never contain prompt text, file contents,
capability token strings, or the master key — only key NAMES, byte sizes,
short digests, reason codes, and (for SMUGGLE_STRIP) an 80-char sample of the
stripped attack payload.

Enforce chain order is normative: D1 D2 D16 D3 D4 D11 D9 D5 D6 D15 D8 D12 D10,
then handler (Scope->D7, TooLarge->D9, Degraded->D13, any Exception->D14).
"""

import argparse
import base64
import collections
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #

POL_VER = 1
DEV_MASTER_KEY_HEX = "d3adc0d3" * 8            # PoC-only fallback; override with POC_MASTER_KEY (64 hex)

DATA_DIR = "/tmp/bicameral"                    # re-targeted by --data-dir in main()
DATA_SCOPE = DATA_DIR + "/data"
AUDIT_PATH = DATA_DIR + "/audit.jsonl"
IDEM_DIR = DATA_DIR + "/idem"
STATE_PATH = DATA_DIR + "/state.json"          # ledger snapshot; re-targeted in main()

AUDIT_RING_MAX = 512                           # in-memory audit ring
NONCE_PER_JTI = 256                            # bounded replay-nonce set per token
NONCE_JTI_MAX = 1024                           # bounded number of tokens tracked
BURN_THRESHOLD = 3                             # policy denials before token burn
BUDGET_MAX_TOKENS = 4096                       # bounded budget ledger (expired evicted first)
DENY_MAX = 8192                                # bounded burn-counter table
SAVE_PERIOD_S = 5.0                            # ledger snapshot interval (persistence)
TTL_MAX = 3600                                 # /issue ttl_s clamp
LLM_TIMEOUT = 60                               # strata chat/completions timeout (s);
                                               # measured round-trip on bi150 was 26.8s for a
                                               # 16-token request (reasoning model + queueing),
                                               # so the paper spec's 10s read as a timeout.
PROBE_PERIOD = 30                              # strata probe thread period (s)
PROBE_TIMEOUT = 2                              # strata probe timeout (s)

LIMITS = {
    "body": 64 * 1024,          # agent-plane /agent/invoke body cap
    "issue_body": 16 * 1024,    # control-plane /issue body cap
    "file_read": 4096,          # fs.read returns a truncated 4 KiB summary
    "fs_write": 256 * 1024,     # fs.write content byte cap
    "llm_prompt": 8 * 1024,     # llm.complete prompt byte cap
    "llm_max_tokens": 64,
    "llm_reply": 512,           # content_summary truncation
}
BUDGET_CAPS = {"calls": 1000, "llm_calls": 100, "bytes": 1024 * 1024}

REGISTRY = {
    "fs.read":      {"class": "derived",  "side_effect": "read-only"},
    "fs.write":     {"class": "authored", "side_effect": "mutating"},
    "llm.complete": {"class": "authored", "side_effect": "read-only", "remote": True},
}
SUBJECTS = {
    "agent-ro": ["fs.read", "llm.complete"],   # read-only agent (real LLM path)
    "agent-rw": ["fs.read", "fs.write"],       # writable agent (no llm)
    "judge":    ["llm.complete"],              # cloud-side judge, same Strata
}
SCHEMAS = {
    "fs.read":      {"path": str},
    "fs.write":     {"path": str, "content": str, "idem_key": str},
    "llm.complete": {"prompt": str, "max_tokens": int},   # max_tokens optional
}
OPTIONAL_FIELDS = {"max_tokens"}
FORBIDDEN_KEYS = ("actions", "tool_calls")     # D8 at any depth; D12/D-strip in LLM replies

# Running-source fingerprint (set at import): /healthz and START audit expose
# it so the deployed copy provably matches the reviewed local copy.
try:
    BUILD_SHA = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()[:16]
except OSError:
    BUILD_SHA = "unknown"

# --------------------------------------------------------------------------- #
# globals / state
# --------------------------------------------------------------------------- #

KEY = None                                     # 32-byte master key, set in main()
STRATA_URL = "http://127.0.0.1:8960/v1"        # re-set in main() from --strata-url

STATE_LOCK = threading.Lock()
STATE = {"pol_ver": POL_VER, "strata": "unknown", "model_id": None}

AUDIT_LOCK = threading.Lock()
AUDIT_FILE = None                              # opened in main()
RING = collections.deque(maxlen=AUDIT_RING_MAX)

NONCE_LOCK = threading.Lock()
NONCES = collections.OrderedDict()             # jti -> OrderedDict(nonce -> True), both bounded

BUDGET_LOCK = threading.Lock()
BUDGETS = {}                                   # jti -> {"calls","llm_calls","bytes"} ledger

BURNS = set()                                  # jtis burned after repeated policy denials
DENY_COUNTS = {}                               # jti -> policy-denial count (burn counter)
JTI_EXP = {}                                   # jti -> exp (drives expired-first eviction/sweep)

SAVE_DIRTY = False                             # set by ledger mutators; snapshot thread consumes
ADMIN_TOKEN = None                             # control-plane token; set in main()
NO_THINK = False                               # suppress reasoning-template thinking on llm.complete


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fp(name):
    """Tool fingerprint: sha256 of the canonical tool-definition JSON, 16 hex."""
    canon = json.dumps({"name": name, **REGISTRY[name]},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]


BUDGET_ALIASES = {"max_calls": "calls", "max_llm_calls": "llm_calls",
                  "max_bytes_out": "bytes"}


def norm_budget(raw):
    """Canonicalise a /issue budget: aliases accepted, violations rejected.

    Fail-closed contract: unknown keys, non-int values and alias+canonical
    duplicates are errors (HTTP 400), never silently ignored.
    Returns (budget dict, None) or (None, error string).
    """
    if raw is None:
        return dict(BUDGET_CAPS), None
    if not isinstance(raw, dict):
        return None, "budget must be an object"
    merged = {}
    for k, v in raw.items():
        name = BUDGET_ALIASES.get(k, k)
        if name not in BUDGET_CAPS:
            return None, "unknown budget key: %s" % k
        if name in merged:
            return None, "duplicate budget key (alias+canonical): %s" % name
        if isinstance(v, bool) or not isinstance(v, int):
            return None, "budget.%s must be an int" % k
        merged[name] = max(0, min(v, BUDGET_CAPS[name]))
    return {name: merged.get(name, cap) for name, cap in BUDGET_CAPS.items()}, None


def audit(event, **fields):
    """Append one redacted event to the file log + in-memory ring."""
    rec = {"ts": round(time.time(), 3), "event": event}
    rec.update({k: v for k, v in fields.items() if v is not None})
    line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
    with AUDIT_LOCK:
        RING.append(rec)
        if AUDIT_FILE is not None:
            try:
                AUDIT_FILE.write(line + "\n")
                AUDIT_FILE.flush()
            except OSError:
                pass


def mark_dirty():
    global SAVE_DIRTY
    SAVE_DIRTY = True


def _snapshot():
    """Collect all ledger state (short lock takes, no I/O under locks)."""
    with BUDGET_LOCK:
        budgets = {j: dict(b) for j, b in BUDGETS.items()}
        jti_exp = dict(JTI_EXP)
        deny_counts = dict(DENY_COUNTS)
        burns = sorted(BURNS)
    with NONCE_LOCK:
        nonces = {j: list(per.keys())[-NONCE_PER_JTI:] for j, per in NONCES.items()}
    return {"schema": "state/1", "saved_at": round(time.time(), 3),
            "jti_exp": jti_exp, "budgets": budgets, "deny_counts": deny_counts,
            "burns": burns, "nonces": nonces}


def save_state(force=False):
    """Throttled atomic ledger snapshot.

    Persistence closes the restart fail-open window: nonces (replay guard)
    and budgets survive a restart instead of silently clearing.
    """
    global SAVE_DIRTY
    if not (force or SAVE_DIRTY):
        return
    SAVE_DIRTY = False        # cleared BEFORE snapshot: changes racing this save
    snap = _snapshot()        # re-dirty themselves and land in the next tick
    tmp = "%s.tmp.%d" % (STATE_PATH, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(snap, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_PATH)
        os.chmod(STATE_PATH, 0o600)
    except OSError as e:
        sys.stderr.write("state snapshot failed: %s\n" % e)


def load_state():
    """Restore ledgers from the last snapshot (once, at startup)."""
    if not os.path.isfile(STATE_PATH):
        return None
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            snap = json.load(f)
        if snap.get("schema") != "state/1":
            raise ValueError("unknown state schema")
        now = time.time()
        with BUDGET_LOCK:
            for j, e in snap.get("jti_exp", {}).items():
                if isinstance(e, (int, float)) and e >= now:
                    JTI_EXP[j] = e
            for j, b in snap.get("budgets", {}).items():
                if j in JTI_EXP and isinstance(b, dict):
                    BUDGETS[j] = {k: int(v) for k, v in b.items() if k in BUDGET_CAPS}
            for j, n in snap.get("deny_counts", {}).items():
                if j in JTI_EXP and isinstance(n, int):
                    DENY_COUNTS[j] = n
            for j in snap.get("burns", []):
                if j in JTI_EXP:
                    BURNS.add(j)
        with NONCE_LOCK:
            for j, keys in snap.get("nonces", {}).items():
                if j in JTI_EXP:
                    NONCES[j] = collections.OrderedDict(
                        (str(k), True) for k in keys[-NONCE_PER_JTI:])
            while len(NONCES) > NONCE_JTI_MAX:
                NONCES.popitem(last=False)
        global SAVE_DIRTY
        SAVE_DIRTY = False
        return {"budgets": len(BUDGETS), "nonce_jtis": len(NONCES), "burns": len(BURNS)}
    except Exception as e:                                 # noqa: BLE001 — a bad snapshot
        sys.stderr.write("state restore skipped: %s\n" % e)  # must never block startup
        try:
            audit("RESTORE_FAILED", err=type(e).__name__)
        except Exception:
            pass
        return None


def state_saver_loop():
    while True:
        time.sleep(SAVE_PERIOD_S)
        save_state()


def nonce_seen(jti, nonce):
    """Per-jti bounded check-and-insert; atomic under lock (deny-side replay guard).

    Partitioned by jti, and eviction is expired-first: flooding nonces with one
    token evicts only that token's own slots, and flooding /issue with fresh
    tokens evicts only EXPIRED tokens' slot sets — a live victim's replay
    protection can no longer be washed out from either dimension.
    """
    key = str(nonce)
    with NONCE_LOCK:
        if jti not in NONCES and len(NONCES) >= NONCE_JTI_MAX:
            now = time.time()
            dead = sorted((j for j, e in JTI_EXP.items() if e < now),
                          key=lambda j: JTI_EXP[j])
            for j in dead:
                NONCES.pop(j, None)
                JTI_EXP.pop(j, None)
            while len(NONCES) >= NONCE_JTI_MAX:
                NONCES.popitem(last=False)     # oldest-inserted as the last resort
        per = NONCES.get(jti)
        if per is None:
            per = collections.OrderedDict()
            NONCES[jti] = per
        if key in per:
            return True
        per[key] = True
        while len(per) > NONCE_PER_JTI:
            per.popitem(last=False)
        mark_dirty()
        return False


def budget_take(jti, tool, n_bytes):
    """Atomic 3-dimension (calls / llm_calls / bytes) debit.

    Returns (ok, exhausted_dim). ok=False -> D10, with the dimension that was
    exhausted (None when ok). Ledger gone (restart) -> deny, fail-closed.
    """
    is_llm = (tool == "llm.complete")
    with BUDGET_LOCK:
        b = BUDGETS.get(jti)
        if b is None:
            return False, "calls"
        if b["calls"] <= 0:
            return False, "calls"
        if is_llm and b["llm_calls"] <= 0:
            return False, "llm_calls"
        if n_bytes > b["bytes"]:
            return False, "bytes"
        b["calls"] -= 1
        if is_llm:
            b["llm_calls"] -= 1
        b["bytes"] -= n_bytes
        mark_dirty()
        return True, None


def est_bytes(tool, params):
    if tool == "fs.read":
        return LIMITS["file_read"]
    if tool == "fs.write":
        return len(params.get("content", "").encode("utf-8"))
    if tool == "llm.complete":
        return len(params.get("prompt", "").encode("utf-8"))
    return 0


# --------------------------------------------------------------------------- #
# capability token (cap/3): payload_b64u.hmac_b64u
# --------------------------------------------------------------------------- #

def issue_token(agent, task_id, tools, ttl_s, budget):
    now = int(time.time())
    uniq = sorted(set(tools))
    payload = {
        "v": "cap/3",
        "jti": secrets.token_hex(8),
        "sub": agent,
        "aud": "agent",
        "task_id": task_id,
        "tools": uniq,
        "tools_fp": [fp(n) for n in uniq],     # list of fingerprints (D15 set compare)
        "data_scope": DATA_SCOPE,
        "pol_ver": POL_VER,
        "iat": now,
        "exp": now + int(ttl_s),
        "budget": budget,
    }
    p = b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    s = b64u(hmac.new(KEY, p.encode("utf-8"), hashlib.sha256).digest())
    return p + "." + s, payload


def verify(tok_str):
    """D1: two-part token, constant-time HMAC compare. Returns dict or None."""
    if not isinstance(tok_str, str) or "." not in tok_str:
        return None
    try:
        p, s = tok_str.rsplit(".", 1)
        expect = b64u(hmac.new(KEY, p.encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(expect.encode("ascii"), s.encode("utf-8", "replace")):
            return None
        d = json.loads(b64u_dec(p))
    except Exception:
        return None
    return d if isinstance(d, dict) and d.get("v") == "cap/3" else None


# --------------------------------------------------------------------------- #
# schema (D8), injection scan (D12), smuggle strip
# --------------------------------------------------------------------------- #

def _has_forbidden_key(obj):
    """True if key 'actions'/'tool_calls' appears at ANY depth."""
    if isinstance(obj, dict):
        return any(k in FORBIDDEN_KEYS or _has_forbidden_key(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_forbidden_key(v) for v in obj)
    return False


def _looks_like_envelope(obj):
    """True if obj is shaped like an EXECUTABLE tool-call envelope.

    An actions/tool_calls key that is a non-empty list of call-shaped dicts.
    A config file that merely contains an "actions" MAPPING is legitimate
    data — stripping it corrupted real content (false-positive fix).
    """
    if not isinstance(obj, dict):
        return _has_forbidden_key(obj)
    acts = obj.get("actions")
    if isinstance(acts, list) and acts and all(
            isinstance(a, dict) and ("tool" in a or "name" in a) for a in acts):
        return True
    tcs = obj.get("tool_calls")
    if isinstance(tcs, list) and tcs and all(isinstance(x, dict) for x in tcs):
        return True
    return False


def bad_schema(tool, params):
    """Strict schema. Returns None if ok, else a short reason string (-> D8)."""
    if not isinstance(params, dict):
        return "params must be an object"
    spec = SCHEMAS[tool]
    for name, want in spec.items():
        if name in OPTIONAL_FIELDS and name not in params:
            continue
        if name not in params:
            return "missing field: " + name
        v = params[name]
        if want is int:
            if isinstance(v, bool) or not isinstance(v, int):
                return "field must be int: " + name
        elif not isinstance(v, str):
            return "field must be str: " + name
    for name in params:
        if name not in spec:
            return "unknown field: " + name
    for v in params.values():                  # NUL evades regex-based injection scan
        if isinstance(v, str) and "\x00" in v:
            return "control character NUL not allowed"
    if _has_forbidden_key(params):
        return "forbidden key (actions/tool_calls) at some depth"
    if tool == "llm.complete":
        mt = params.get("max_tokens", LIMITS["llm_max_tokens"])
        if not (1 <= mt <= LIMITS["llm_max_tokens"]):
            return "max_tokens out of range 1..%d" % LIMITS["llm_max_tokens"]
    if tool in ("fs.read", "fs.write") and not params["path"].strip():
        return "path is empty"
    if tool == "fs.write":
        if not params["idem_key"].strip():
            return "idem_key is empty"
        if len(params["content"].encode("utf-8")) > LIMITS["fs_write"]:
            return "content exceeds fs_write limit"
    return None


INJECT_PATTERNS = [
    ("ignore_previous", re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|preceding|above)", re.I)),
    ("disregard_instructions", re.compile(
        r"disregard\s+(all\s+|any\s+)?((previous|prior|above|your)\s+)?(instructions|rules|prompts?)", re.I)),
    ("prompt_steal", re.compile(
        r"(reveal|print|show|repeat|expose|output)\s+(me\s+)?(your\s+)?(system\s+|hidden\s+|initial\s+)?(prompt|instructions)", re.I)),
    ("role_override", re.compile(
        r"(you\s+are\s+now|pretend\s+to\s+be|act\s+as\s+(an?\s+)?(unrestricted|uncensored|dan\b))", re.I)),
    ("fake_system_tag", re.compile(r"<\s*/?\s*(system|assistant|im_start|im_end)\b", re.I)),
    # envelope shape only: an "actions" MAPPING in legitimate data (config
    # files) must pass; the executable form is key -> [ {tool/name ...}
    ("tool_call_inject", re.compile(r"[\"']?(actions|tool_calls)[\"']?\s*:\s*\[\s*\{", re.I)),
]


def inject_hit(obj):
    """Scan string values recursively for prompt-injection markers -> hits list."""
    hits = []

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, path + "." + str(k))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, path + "[" + str(i) + "]")
        elif isinstance(o, str):
            for name, pat in INJECT_PATTERNS:
                m = pat.search(o)
                if m:
                    lo = max(0, m.start() - 20)
                    hits.append({"path": path, "pattern": name,
                                 "sample": o[lo:m.end() + 20][:80]})

    walk(obj, "$")
    return hits[:8]


def _json_objects(text):
    """Yield (start, end) spans of balanced {...} blocks in text."""
    i, n = 0, len(text)
    while i < n:
        if text[i] == "{":
            depth = 0
            found = None
            for j in range(i, n):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        found = (i, j + 1)
                        break
            if found is None:      # unbalanced rest -> stop scanning
                return
            yield found
            i = found[1]
        else:
            i += 1


def strip_smuggle(text):
    """Strip JSON objects containing actions/tool_calls keys from an LLM reply.

    Returns (clean_text, hits). Called on llm.complete replies; hits are
    audited as SMUGGLE_STRIP. Non-JSON text passes through unchanged.
    """
    hits, out, pos = [], [], 0
    for start, end in _json_objects(text[:100000]):
        blob = text[start:end]
        try:
            flagged = _looks_like_envelope(json.loads(blob))
        except Exception:
            flagged = re.search(r"[\"']?(actions|tool_calls)[\"']?\s*:", blob) is not None
        if flagged:
            hits.append({"path": "$.reply", "sample": blob[:80]})
            out.append(text[pos:start])
            out.append("[BICAMERAL:SMUGGLE_STRIPPED]")
            pos = end
    out.append(text[pos:])
    return "".join(out), hits


def peek_jti(tok_str):
    """Best-effort UNVERIFIED jti extraction from a failed token (D1 forensics).

    The claim is attacker-controlled and never used for any decision — audit
    trail only, audited under the name jti_claim.
    """
    try:
        d = json.loads(b64u_dec(tok_str.rsplit(".", 1)[0]))
        j = d.get("jti")
        return j if isinstance(j, str) else None
    except Exception:
        return None


def strip_result(result):
    """Response-side smuggle strip applied to EVERY tool result.

    Channel-independent: any string leaf (fs.read summary, write receipts,
    llm content) carrying JSON blobs with actions/tool_calls gets the blob
    replaced by a marker. Returns (clean_result, hits) — hits are audited as
    SMUGGLE_STRIP with the result path they were found at.
    """
    hits = []

    def walk(o, path):
        if isinstance(o, dict):
            return {k: walk(v, path + "." + str(k)) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v, "%s[%d]" % (path, i)) for i, v in enumerate(o)]
        if isinstance(o, str):
            clean, hs = strip_smuggle(o)
            for h in hs:
                hits.append({"path": path, "sample": h["sample"]})
            return clean
        return o

    return walk(result, "$"), hits


# --------------------------------------------------------------------------- #
# Strata (real capability proxy) state: probe / degrade / recover
# --------------------------------------------------------------------------- #

def _http_get_json(url, timeout):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as rsp:
        return json.loads(rsp.read().decode("utf-8", "replace"))


def probe_strata():
    """GET {STRATA_URL}/health (2s); on any exception fall back to /v1/models.

    Returns (ok, model_id_or_None).
    """
    try:
        _http_get_json(STRATA_URL + "/health", PROBE_TIMEOUT)
        return True, None
    except Exception:
        try:
            models = _http_get_json(STRATA_URL + "/models", PROBE_TIMEOUT)
            ids = [m.get("id") for m in (models.get("data") or [])
                   if isinstance(m, dict) and m.get("id")]
            return True, (ids[0] if ids else None)
        except Exception:
            return False, None


def fetch_model_id():
    """MODEL_ID: first id from GET /v1/models; None -> omit model field."""
    try:
        models = _http_get_json(STRATA_URL + "/models", 3)
        ids = [m.get("id") for m in (models.get("data") or [])
               if isinstance(m, dict) and m.get("id")]
        return ids[0] if ids else None
    except Exception:
        return None


def mark_degraded(why):
    with STATE_LOCK:
        prev = STATE["strata"]
        STATE["strata"] = "degraded"
    if prev != "degraded":
        audit("DEGRADE", why=why)


def mark_ok(model_id):
    with STATE_LOCK:
        prev = STATE["strata"]
        STATE["strata"] = "ok"
        if model_id:
            STATE["model_id"] = model_id
    if prev != "ok":
        audit("RECOVER")


def strata_probe_loop():
    while True:
        time.sleep(PROBE_PERIOD)
        try:
            ok, mid = probe_strata()
        except Exception:
            ok, mid = False, None
        if ok:
            mark_ok(mid)
        else:
            mark_degraded("probe_failed")


# --------------------------------------------------------------------------- #
# tool handlers
# --------------------------------------------------------------------------- #

class Degraded(Exception):
    """Strata unavailable -> D13."""


class TooLarge(Exception):
    """Payload over handler-level limit -> D9."""


class ScopeError(Exception):
    """Path outside data_scope -> D7 (dedicated code, not D14 fallback)."""


def in_scope(path, scope):
    """realpath-normalised exact prefix match against data_scope."""
    rp = os.path.realpath(path)
    sc = os.path.realpath(scope)
    return (rp == sc or rp.startswith(sc + os.sep)), rp


def h_fs_read(p, scope):
    ok, rp = in_scope(p["path"], scope)
    if not ok:
        raise ScopeError("path outside data_scope")
    if not os.path.isfile(rp):
        raise FileNotFoundError(rp)
    size = os.path.getsize(rp)
    with open(rp, "rb") as f:
        raw = f.read(LIMITS["file_read"] + 1)
    truncated = len(raw) > LIMITS["file_read"]
    raw = raw[:LIMITS["file_read"]]
    try:
        summary, encoding = raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        summary, encoding = base64.b64encode(raw).decode("ascii"), "base64"
    return {"path": rp, "size": size, "truncated": truncated,
            "encoding": encoding, "summary": summary}


def h_fs_write(p, scope):
    ok, rp = in_scope(p["path"], scope)
    if not ok:
        raise ScopeError("path outside data_scope")
    if os.path.isdir(rp):
        raise IsADirectoryError(rp)
    data = p["content"].encode("utf-8")
    if len(data) > LIMITS["fs_write"]:
        raise TooLarge()
    # idem_key (v2 :176 idempotency): same key + same content + same path -> dedup.
    # Same key with different content/path is a client bug -> ValueError -> D14.
    key_hash = hashlib.sha256(p["idem_key"].encode("utf-8")).hexdigest()
    content_hash = hashlib.sha256(data).hexdigest()
    marker = os.path.join(IDEM_DIR, key_hash[:32] + ".json")
    if os.path.isfile(marker):
        with open(marker, "r", encoding="utf-8") as f:
            prev = json.load(f)
        if prev.get("content_sha256") == content_hash and prev.get("path") == rp:
            return {"path": rp, "bytes": len(data), "deduplicated": True}
        raise ValueError("idem_key reuse with different content/path")
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    tmp = rp + ".tmp-" + secrets.token_hex(4)
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, rp)                        # atomic within data_scope
    with open(marker, "w", encoding="utf-8") as f:
        json.dump({"idem_key_sha256": key_hash, "content_sha256": content_hash,
                   "path": rp, "ts": round(time.time(), 3)}, f)
    return {"path": rp, "bytes": len(data), "deduplicated": False}


def h_llm_complete(p, scope):
    """Real capability proxy: forward to local Strata (llama-server 8960)."""
    with STATE_LOCK:
        strata_ok = STATE["strata"] == "ok"
        model_id = STATE["model_id"]
    if not strata_ok:
        raise Degraded()
    prompt = p["prompt"]
    if len(prompt.encode("utf-8")) > LIMITS["llm_prompt"]:
        raise TooLarge()
    max_tokens = min(int(p.get("max_tokens", LIMITS["llm_max_tokens"])),
                     LIMITS["llm_max_tokens"])
    out_prompt = ("/no_think\n" + prompt) if NO_THINK else prompt
    body = {"messages": [{"role": "user", "content": out_prompt}],
            "max_tokens": max_tokens, "temperature": 0}
    if NO_THINK:
        # dual mechanism: /no_think prefix + chat-template switch, because
        # deployments differ in which one the reasoning template honours
        body["chat_template_kwargs"] = {"enable_thinking": False}
    if model_id:
        body["model"] = model_id               # else omitted; llama.cpp tolerates
    req = urllib.request.Request(
        STRATA_URL.rstrip("/") + "/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as rsp:
            out = json.loads(rsp.read().decode("utf-8", "replace"))
    except Exception:
        # A call failure IS the degradation criterion; the 30s probe recovers.
        mark_degraded("chat_completions_call_failed")
        raise Degraded()
    try:
        content = out["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise ValueError("unexpected strata response shape")
    content, hits = strip_smuggle(content)
    for h in hits:
        audit("SMUGGLE_STRIP", tool="llm.complete", path=h["path"], sample=h["sample"])
    return {"content_summary": content[:LIMITS["llm_reply"]],
            "usage": out.get("usage", {})}     # whitelist-only response fields


HANDLERS = {
    "fs.read": h_fs_read,
    "fs.write": h_fs_write,
    "llm.complete": h_llm_complete,
}


# --------------------------------------------------------------------------- #
# enforce chain: D1 D2 D16 D3 D4 D11 D9 D5 D6 D15 D8 D12 D10 -> handler
#   (Scope->D7, TooLarge->D9, Degraded->D13, any Exception->D14; response-side
#    smuggle strip runs on every result before ALLOW)
# --------------------------------------------------------------------------- #

BURN_ON = {"D5", "D6", "D7", "D12"}            # attacker-probe denials that burn


def enforce(tok_str, plane, req):
    t = None

    def deny(code, reason, status, audit_extra=None, **extra):
        body = {"ok": False, "reason_code": code + "/" + reason}
        if extra:
            body.update(extra)
        # audit_extra decouples what the CALLER sees from what the LOG keeps:
        # D12/D14 keep raw detail out of the audit (redaction promise) or out
        # of the response (internal-state leak), respectively.
        detail = extra if audit_extra is None else audit_extra
        audit("DENY", reason_code=body["reason_code"],
              jti=(t or {}).get("jti"), task_id=(t or {}).get("task_id"),
              agent=(t or {}).get("sub"), tool=req.get("tool"),
              detail=detail)
        if t is not None and code in BURN_ON:  # D16: repeated probing burns the token
            with BUDGET_LOCK:                  # atomic check-and-increment (race fix)
                n = DENY_COUNTS.get(t["jti"], 0) + 1
                DENY_COUNTS[t["jti"]] = n
                mark_dirty()
                burn = n >= BURN_THRESHOLD and t["jti"] not in BURNS
                if burn:
                    BURNS.add(t["jti"])
                    BUDGETS.pop(t["jti"], None)
            if burn:
                audit("BURN", jti=t["jti"], denials=n, last=code)
                mark_dirty()
        return status, body

    t = verify(tok_str or "")                                               # D1
    if t is None:
        return deny("D1", "TOKEN_INVALID", 401, jti_claim=peek_jti(tok_str or ""))
    if (not isinstance(t.get("jti"), str) or not t["jti"]                   # D1b: signature
            or not isinstance(t.get("sub"), str)                            #  valid but
            or not isinstance(t.get("data_scope"), str)                     #  payload
            or not isinstance(t.get("tools"), list)                         #  malformed ->
            or isinstance(t.get("exp"), bool)                               #  reject here,
            or not isinstance(t.get("exp"), (int, float))):                 #  never 500
        return deny("D1", "TOKEN_MALFORMED", 401,
                    jti_claim=t.get("jti") if isinstance(t.get("jti"), str) else None,
                    audit_extra={"malformed_fields":
                                 sorted(k for k in ("jti", "sub", "data_scope", "tools", "exp")
                                        if not t.get(k))})
    if time.time() > float(t["exp"]):                                       # D2, strict
        return deny("D2", "TOKEN_EXPIRED", 401)
    if t["jti"] in BURNS:                                                   # D16
        return deny("D16", "TOKEN_BURNED", 401)
    if nonce_seen(t["jti"], req["nonce"]):                                  # D3
        return deny("D3", "REPLAY_DETECTED", 401)
    if t.get("aud") != plane:                                               # D4
        return deny("D4", "AUD_MISMATCH", 403)
    if t.get("pol_ver") != STATE["pol_ver"]:                                # D11
        return deny("D11", "POLICY_STALE", 409)
    if req["_body_len"] > LIMITS["body"]:                                   # D9
        return deny("D9", "PAYLOAD_TOO_LARGE", 413)
    if req["tool"] not in REGISTRY:                                         # D5
        return deny("D5", "TOOL_UNKNOWN", 403)
    if req["tool"] not in t.get("tools", []):                               # D6
        return deny("D6", "TOOL_NOT_ALLOWED", 403)
    if set(t.get("tools_fp", [])) != {fp(n) for n in t.get("tools", [])}:   # D15
        return deny("D15", "TOOL_FINGERPRINT_MISMATCH", 409)
    err = bad_schema(req["tool"], req["params"])                            # D8
    if err:
        return deny("D8", "SCHEMA_VIOLATION", 400, what=err)
    hit = inject_hit(req["params"])                                         # D12
    if hit:
        # redaction promise: the audit keeps pattern/path/digest only — never
        # the prompt-text sample (that goes to the caller's 422 body alone)
        return deny("D12", "INJECTION_SUSPECTED", 422, hits=hit,
                    audit_extra={"hits": [{"path": h["path"], "pattern": h["pattern"],
                                           "frag_sha256_16": hashlib.sha256(
                                               h["sample"].encode("utf-8")).hexdigest()[:16]}
                                          for h in hit]})
    ok, dim = budget_take(t["jti"], req["tool"],
                          est_bytes(req["tool"], req["params"]))            # D10
    if not ok:
        return deny("D10", "BUDGET_EXHAUSTED", 429, dim=dim)
    try:
        result = HANDLERS[req["tool"]](req["params"], t["data_scope"])
    except ScopeError:
        return deny("D7", "SCOPE_VIOLATION", 403)
    except TooLarge:
        return deny("D9", "PAYLOAD_TOO_LARGE", 413)
    except Degraded:
        return deny("D13", "CAPABILITY_DEGRADED", 503)
    except Exception as e:
        # internal detail stays in the audit, out of the response body
        return deny("D14", "INTERNAL_DENY", 500,
                    audit_extra={"err": type(e).__name__})
    result, strip_hits = strip_result(result)     # response-side, every channel
    for h in strip_hits:
        audit("SMUGGLE_STRIP", tool=req["tool"], path=h["path"], sample=h["sample"])
    audit("ALLOW", jti=t["jti"], task_id=t.get("task_id"), agent=t.get("sub"),
          tool=req["tool"], result_keys=sorted(result.keys()),
          est_bytes=est_bytes(req["tool"], req["params"]))
    return 200, {"ok": True, "result": result}     # response = handler whitelist only


# --------------------------------------------------------------------------- #
# TLS data plane (optional, off by default — backward compatible)
#   --tls-cert + --tls-key (both or neither)  : both planes serve TLS
#   --tls-client-ca                            : additionally require and
#                                                verify client certificates
#                                                (mTLS) on BOTH planes
# /healthz stays token-free but rides the same TLS. The default plain-HTTP
# behaviour is byte-for-byte unchanged when no certificate is given.
# --------------------------------------------------------------------------- #

TLS_HANDSHAKE_TIMEOUT = 10                    # bound a stalled TLS handshake


def tls_mode(cert, key, client_ca):
    """Validate the --tls-* argument combination (pure; selftest-covered).

    Returns (mode, error): mode is "off" / "tls" / "mtls", error a
    user-facing message or None. Only the combination is decided here —
    file existence is checked in main() so the selftest stays I/O-free.
    Half a certificate pair (e.g. --tls-cert without --tls-key) is a
    startup error, never a silent fallback to plain HTTP.
    """
    c, k, ca = bool(cert), bool(key), bool(client_ca)
    if c != k:
        return None, ("--tls-cert and --tls-key must be given together "
                      "(missing --tls-%s)" % ("key" if c else "cert"))
    if ca and not (c and k):
        return None, "--tls-client-ca requires --tls-cert and --tls-key"
    if not c:
        return "off", None
    return ("mtls" if ca else "tls"), None


def build_ssl_context(cert, key, client_ca):
    """Server-side SSLContext: the server certificate, plus mandatory
    client-certificate verification when a client CA is configured (mTLS).
    Only called when tls_mode() returned a non-"off" mode."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    if client_ca:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=client_ca)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# --------------------------------------------------------------------------- #
# HTTP planes
# --------------------------------------------------------------------------- #

class BodyError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status
        self.msg = msg


class Handler(BaseHTTPRequestHandler):
    server_version = "bicameral/0.1.0"
    protocol_version = "HTTP/1.1"
    timeout = 30            # slow-connection guard: a stalled read/keep-alive
                            # connection is closed instead of pinning a thread

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s %s\n" % (getattr(self.server, "plane", "?"),
                                         self.log_date_time_string(), fmt % args))

    def _send(self, status, obj):
        try:
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_body(self, limit):
        """Content-Length pre-check; over-limit -> 413 WITHOUT reading the stream."""
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise BodyError(411, "Content-Length required")
        try:
            n = int(raw)
        except ValueError:
            raise BodyError(400, "malformed Content-Length")
        if n < 0:
            raise BodyError(400, "malformed Content-Length")
        if n > limit:
            raise BodyError(413, "payload too large")
        data = self.rfile.read(n)
        if len(data) != n:
            raise BodyError(400, "truncated body")
        return data

    def _control_auth(self):
        """Control plane (except /healthz) requires the admin token when one
        is configured. Startup is fail-closed without a token unless the dev
        opt-out is given, so an open control plane is always a stated choice."""
        if ADMIN_TOKEN is None:
            return True
        tok = self.headers.get("X-Admin-Token") or ""
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            tok = tok or auth[7:].strip()
        if not tok:
            return False
        return hmac.compare_digest(tok.encode("utf-8"), ADMIN_TOKEN.encode("utf-8"))

    def _reject_control(self):
        audit("DENY", reason_code="CTL/AUTH_REQUIRED",
              plane=getattr(self.server, "plane", "?"), path=self.path[:128])
        self._send(401, {"ok": False, "reason_code": "CTL/AUTH_REQUIRED"})

    # ---------------- POST ---------------- #

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if self.server.plane == "control" and path == "/issue":
                if not self._control_auth():
                    return self._reject_control()
                self.h_issue()
            elif self.server.plane == "agent" and path == "/agent/invoke":
                self.h_invoke()
            else:
                self._send(404, {"ok": False, "error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            audit("ERROR", plane=getattr(self.server, "plane", "?"),
                  path=self.path, err=type(e).__name__)   # type stays out of the body
            self._send(500, {"ok": False, "error": "handler error"})

    def h_issue(self):
        try:
            data = self._read_body(LIMITS["issue_body"])
        except BodyError as e:
            return self._send(e.status, {"ok": False, "error": e.msg})
        try:
            req = json.loads(data.decode("utf-8"))
        except Exception:
            return self._send(400, {"ok": False, "error": "body is not valid JSON"})
        if not isinstance(req, dict):
            return self._send(400, {"ok": False, "error": "body must be a JSON object"})
        unknown = sorted(set(req.keys())
                         - {"agent", "task_id", "tools", "ttl_s", "budget"})
        if unknown:
            return self._send(400, {"ok": False,
                                    "error": "unknown field(s) in /issue body",
                                    "unknown": unknown})
        agent = req.get("agent")
        task_id = req.get("task_id")
        tools = req.get("tools")
        ttl_s = req.get("ttl_s", 600)
        if agent not in SUBJECTS:
            return self._send(400, {"ok": False, "error": "unknown agent",
                                    "known": sorted(SUBJECTS)})
        if not isinstance(task_id, str) or not task_id:
            return self._send(400, {"ok": False, "error": "task_id must be a non-empty string"})
        if not isinstance(tools, list) or not tools or not all(isinstance(x, str) for x in tools):
            return self._send(400, {"ok": False, "error": "tools must be a non-empty list of strings"})
        # issue-side cross-validation: tools ⊆ SUBJECTS[agent] ∩ REGISTRY
        allowed = set(SUBJECTS[agent]) & set(REGISTRY)
        disallowed = sorted(set(tools) - allowed)
        if disallowed:
            return self._send(403, {"ok": False, "error": "tools exceed subject grant",
                                    "disallowed": disallowed})
        if not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or ttl_s <= 0:
            return self._send(400, {"ok": False, "error": "ttl_s must be a positive int"})
        ttl_s = min(ttl_s, TTL_MAX)            # clamp to 3600
        budget, berr = norm_budget(req.get("budget"))
        if berr:
            return self._send(400, {"ok": False, "error": berr})
        tok, payload = issue_token(agent, task_id, tools, ttl_s, budget)
        with BUDGET_LOCK:
            BUDGETS[payload["jti"]] = dict(budget)
            JTI_EXP[payload["jti"]] = payload["exp"]
            now = time.time()                  # sweep: expired ledgers leave first
            for j in [j for j, e in JTI_EXP.items() if e < now]:
                BUDGETS.pop(j, None)
                DENY_COUNTS.pop(j, None)
                JTI_EXP.pop(j, None)
            while len(BUDGETS) > BUDGET_MAX_TOKENS:
                BUDGETS.popitem(last=False)    # oldest ledger goes (fail-closed: loss = deny)
            while len(DENY_COUNTS) > DENY_MAX:
                DENY_COUNTS.popitem(last=False)
        mark_dirty()
        audit("ISSUE", jti=payload["jti"], agent=agent, task_id=task_id,
              tools=payload["tools"], ttl_s=ttl_s, budget=budget)
        self._send(200, {"ok": True, "token": tok, "jti": payload["jti"],
                         "agent": agent, "task_id": task_id,
                         "tools": payload["tools"], "ttl_s": ttl_s,
                         "exp": payload["exp"], "budget": budget, "pol_ver": POL_VER})

    def h_invoke(self):
        tok = self.headers.get("X-Capability-Token") or ""
        try:
            data = self._read_body(LIMITS["body"])
        except BodyError as e:
            if e.status == 413:
                audit("DENY", reason_code="D9/PAYLOAD_TOO_LARGE", tool=None,
                      detail={"body_bytes_declared": "over limit"})
                return self._send(413, {"ok": False, "reason_code": "D9/PAYLOAD_TOO_LARGE"})
            return self._send(e.status, {"ok": False, "reason_code": "CTL/BAD_REQUEST",
                                         "error": e.msg})
        try:
            req = json.loads(data.decode("utf-8"))
        except Exception:
            return self._send(400, {"ok": False, "reason_code": "D8/SCHEMA_VIOLATION",
                                    "what": "body is not valid JSON"})
        # strict envelope: exactly {nonce, tool, params}; extra field -> D8
        if (not isinstance(req, dict)
                or not set(req.keys()) <= {"nonce", "tool", "params"}
                or not isinstance(req.get("nonce"), str) or not req.get("nonce")
                or not isinstance(req.get("tool"), str)):
            return self._send(400, {"ok": False, "reason_code": "D8/SCHEMA_VIOLATION",
                                    "what": "envelope must be {nonce, tool, params}"})
        status, body = enforce(tok, "agent",
                               {"nonce": req["nonce"], "tool": req["tool"],
                                "params": req.get("params", {}),
                                "_body_len": len(data),
                                "_client": self.client_address[0]})
        self._send(status, body)

    # ---------------- GET (control plane only) ---------------- #

    def do_GET(self):
        try:
            if self.server.plane != "control":
                return self._send(404, {"ok": False, "error": "not found"})
            u = urllib.parse.urlparse(self.path)
            if u.path == "/healthz":
                return self._send(200, {"status": "ok",
                                        "build_sha": BUILD_SHA,
                                        "strata_state": STATE["strata"],
                                        "pol_ver": STATE["pol_ver"]})
            if not self._control_auth():
                return self._reject_control()
            if u.path == "/capabilities":
                return self._send(200, {
                    "pol_ver": STATE["pol_ver"],
                    "strata_state": STATE["strata"],
                    "model_id": STATE["model_id"],
                    "registry": REGISTRY,
                    "fingerprints": {n: fp(n) for n in REGISTRY},
                    "limits": LIMITS,
                    "llm": {"thinking": "off" if NO_THINK else "default",
                            "max_tokens_cap": LIMITS["llm_max_tokens"]},
                })
            if u.path == "/audit":
                q = urllib.parse.parse_qs(u.query)
                task_id = (q.get("task_id") or [None])[0]
                try:
                    limit = int((q.get("limit") or ["50"])[0])
                except ValueError:
                    limit = 50
                limit = max(1, min(limit, AUDIT_RING_MAX))
                with AUDIT_LOCK:
                    events = list(RING)
                if task_id:
                    events = [e for e in events if e.get("task_id") == task_id]
                return self._send(200, events[-limit:])
            return self._send(404, {"ok": False, "error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            audit("ERROR", plane=getattr(self.server, "plane", "?"),
                  path=self.path, err=type(e).__name__)   # type stays out of the body
            self._send(500, {"ok": False, "error": "handler error"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tls_context = None              # set per-instance in main() when TLS is on

    def __init__(self, *args, tls_context=None, **kwargs):
        super().__init__(*args, **kwargs)
        if tls_context is not None:
            self.tls_context = tls_context

    def get_request(self):
        """accept(), then TLS-wrap the connection server-side when enabled.

        The handshake runs here (bounded by TLS_HANDSHAKE_TIMEOUT so a
        client that connects and stalls cannot pin the accept loop); a
        failed handshake — e.g. a missing client certificate under mTLS —
        raises ssl.SSLError (an OSError), which _handle_request_noblock
        swallows: the connection is dropped, the planes keep serving.
        """
        sock, addr = self.socket.accept()
        if self.tls_context is None:
            return sock, addr
        sock.settimeout(TLS_HANDSHAKE_TIMEOUT)
        try:
            conn = self.tls_context.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError):
            try:
                sock.close()
            except OSError:
                pass
            raise
        # The timeout above bounds only the HANDSHAKE; once wrapped, clear
        # it so a long-lived keep-alive connection is not killed by it
        # (Handler.timeout is the slow-connection guard for the session).
        conn.settimeout(None)
        return conn, addr


class ControlServer(Server):
    plane = "control"


class AgentServer(Server):
    plane = "agent"


# --------------------------------------------------------------------------- #
# selftest — pure functions only (no network, no TLS handshake, no files)
# --------------------------------------------------------------------------- #

def cmd_selftest(_args) -> int:
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    # --- TLS argument combination matrix (tls_mode is the whole contract:
    #     half a pair must refuse to start, never fall back to plain HTTP) --- #
    check("tls.off_by_default",
          tls_mode(None, None, None) == ("off", None))
    check("tls.tls_with_cert_and_key",
          tls_mode("s.crt", "s.key", None) == ("tls", None))
    check("tls.mtls_with_client_ca",
          tls_mode("s.crt", "s.key", "ca.crt") == ("mtls", None))
    m, e = tls_mode("s.crt", None, None)       # cert without key
    check("tls.cert_without_key_rejected",
          m is None and bool(e) and "--tls-key" in e, e or "accepted")
    m, e = tls_mode(None, "s.key", None)       # key without cert
    check("tls.key_without_cert_rejected",
          m is None and bool(e) and "--tls-cert" in e, e or "accepted")
    m, e = tls_mode(None, None, "ca.crt")      # client CA without a server pair
    check("tls.ca_without_server_pair_rejected",
          m is None and bool(e) and "--tls-client-ca" in e, e or "accepted")
    m, e = tls_mode(None, "s.key", "ca.crt")
    check("tls.ca_with_half_pair_rejected",
          m is None and bool(e), e or "accepted")

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# TLS integration self-test (--tls-integration): the pure selftest above
# stays I/O-free; this mode live-fires the TLS data plane once. It mints a
# throwaway self-signed certificate (openssl subprocess — the stdlib cannot
# generate certificates), serves the control plane over it on an ephemeral
# loopback port, and asserts the auth matrix end-to-end:
#   no token   POST /issue   -> 401
#   token      POST /issue   -> 200 (a real capability token is issued)
#   no token   GET  /healthz -> 200 (health stays token-free, same TLS)
# --------------------------------------------------------------------------- #

def _mint_selfsigned_cert(cert_pem, key_pem):
    """openssl -> throwaway self-signed cert/key in the given paths.
    Returns None on success or the combined stdout/stderr on failure.
    -addext needs openssl >= 1.1.1; retry without it (SAN is irrelevant —
    the client context does not verify the hostname)."""
    for extra in (["-addext", "subjectAltName=IP:127.0.0.1"], []):
        proc = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key_pem, "-out", cert_pem, "-days", "2",
             "-nodes", "-subj", "/CN=127.0.0.1"] + extra,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode == 0:
            return None
    return (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()


def cmd_tls_integration(_args) -> int:
    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        print(("%s %s %s" % ("PASS" if cond else "FAIL", name, detail)).rstrip())

    global KEY, ADMIN_TOKEN
    KEY = bytes.fromhex(DEV_MASTER_KEY_HEX)
    ADMIN_TOKEN = "tls-integration-token-0123456789"   # >= 16 chars, throwaway
    import tempfile
    with tempfile.TemporaryDirectory(prefix="bicameral-tls-itest-") as td:
        cert_pem = os.path.join(td, "cert.pem")
        key_pem = os.path.join(td, "key.pem")
        err = _mint_selfsigned_cert(cert_pem, key_pem)
        if err is not None:
            check("tls_integration.mint_selfsigned_cert", False, err[:200])
            print("tls-integration: %d/%d passed (no openssl?)"
                  % (sum(results), len(results)))
            return 1
        check("tls_integration.mint_selfsigned_cert", True)

        ctx = build_ssl_context(cert_pem, key_pem, None)   # mode "tls"
        port = 0                                           # ephemeral loopback
        try:
            httpd = ControlServer(("127.0.0.1", port), Handler, tls_context=ctx)
        except OSError as e:
            check("tls_integration.server_bind", False, str(e))
            print("tls-integration: %d/%d passed"
                  % (sum(results), len(results)))
            return 1
        port = httpd.server_address[1]
        th = threading.Thread(target=httpd.serve_forever, daemon=True)
        th.start()
        check("tls_integration.server_up", port > 0, "127.0.0.1:%d" % port)

        client_ctx = ssl._create_unverified_context()  # noqa: SLF001 - self-signed test cert
        base = "https://127.0.0.1:%d" % port

        def req(method, path, body=None, headers=None):
            r = urllib.request.Request(base + path, data=body,
                                       headers=headers or {}, method=method)
            try:
                with urllib.request.urlopen(r, timeout=10,
                                            context=client_ctx) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()
            except Exception as e:                        # noqa: BLE001
                return None, repr(e).encode("utf-8")

        issue_body = json.dumps({"agent": "agent-ro",
                                 "task_id": "tls-integration",
                                 "tools": ["llm.complete"]}).encode("utf-8")
        # 1: no token -> 401 (CTL/AUTH_REQUIRED), and it came over TLS at all
        code, raw = req("POST", "/issue", body=issue_body,
                        headers={"Content-Type": "application/json"})
        check("tls_integration.issue_without_token_401",
              code == 401 and b"CTL/AUTH_REQUIRED" in raw,
              "code=%r body=%s" % (code, raw[:120]))
        # 2: with the admin token -> 200 + a real capability token
        code, raw = req("POST", "/issue", body=issue_body,
                        headers={"Content-Type": "application/json",
                                 "X-Admin-Token": ADMIN_TOKEN})
        ok_issue = False
        try:
            ok_issue = (code == 200 and json.loads(raw).get("ok") is True
                        and isinstance(json.loads(raw).get("token"), str))
        except Exception:                                 # noqa: BLE001
            pass
        check("tls_integration.issue_with_token_200",
              ok_issue, "code=%r body=%s" % (code, raw[:120]))
        # 3: /healthz stays token-free (over the same TLS)
        code, raw = req("GET", "/healthz")
        ok_hz = False
        try:
            ok_hz = (code == 200 and json.loads(raw).get("status") == "ok")
        except Exception:                                 # noqa: BLE001
            pass
        check("tls_integration.healthz_token_free_200",
              ok_hz, "code=%r body=%s" % (code, raw[:120]))

        httpd.shutdown()
        httpd.server_close()
    print("tls-integration: %d/%d passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main():
    global KEY, STRATA_URL, AUDIT_FILE, DATA_DIR, DATA_SCOPE, AUDIT_PATH, IDEM_DIR
    global STATE_PATH, ADMIN_TOKEN
    ap = argparse.ArgumentParser(description="bicameral (master-edge permission layer, cap/3)")
    ap.add_argument("--control-port", type=int, default=18000)
    ap.add_argument("--agent-port", type=int, default=18001)
    ap.add_argument("--strata-url", default="http://127.0.0.1:8960/v1")
    ap.add_argument("--data-dir", default="/tmp/bicameral")
    ap.add_argument("--admin-token", default=os.environ.get("BICAMERAL_ADMIN_TOKEN") or "",
                    help="control-plane token (X-Admin-Token / Bearer); env BICAMERAL_ADMIN_TOKEN")
    ap.add_argument("--allow-open-control", action="store_true",
                    help="dev only: run the control plane without an admin token")
    ap.add_argument("--no-think", action="store_true",
                    help="suppress reasoning-template thinking on llm.complete "
                         "(/no_think prefix + chat_template_kwargs)")
    ap.add_argument("--llm-max-tokens", type=int, default=64,
                    help="cap for llm.complete max_tokens (raise for reasoning models)")
    ap.add_argument("--tls-cert", default=None, metavar="PEM",
                    help="server certificate; requires --tls-key (both planes serve TLS)")
    ap.add_argument("--tls-key", default=None, metavar="PEM",
                    help="server private key; requires --tls-cert")
    ap.add_argument("--tls-client-ca", default=None, metavar="PEM",
                    help="CA for client certificates: require + verify them "
                         "(mTLS); needs --tls-cert/--tls-key")
    ap.add_argument("--selftest", action="store_true",
                    help="run the pure-function self-test and exit")
    ap.add_argument("--tls-integration", action="store_true",
                    help="run the TLS integration self-test and exit: mint a "
                         "throwaway self-signed cert (openssl subprocess), "
                         "serve the control plane over TLS on an ephemeral "
                         "loopback port, assert 401/200/token-free matrix")
    args = ap.parse_args()

    if args.selftest:
        return cmd_selftest(args)
    if args.tls_integration:
        return cmd_tls_integration(args)

    DATA_DIR = args.data_dir.rstrip("/")
    DATA_SCOPE = DATA_DIR + "/data"
    AUDIT_PATH = DATA_DIR + "/audit.jsonl"
    IDEM_DIR = DATA_DIR + "/idem"
    STATE_PATH = DATA_DIR + "/state.json"
    STRATA_URL = args.strata_url.rstrip("/")

    # TLS argument combination first: half a pair must fail the startup
    # before anything else is validated (selftest-pinned contract).
    tls, tls_err = tls_mode(args.tls_cert, args.tls_key, args.tls_client_ca)
    if tls_err:
        sys.exit("tls: %s" % tls_err)
    for p in (args.tls_cert, args.tls_key, args.tls_client_ca):
        if p and not os.path.isfile(p):
            sys.exit("tls: file not found: %s" % p)
    tls_ctx = None
    if tls != "off":
        tls_ctx = build_ssl_context(args.tls_cert, args.tls_key,
                                    args.tls_client_ca)

    global NO_THINK
    NO_THINK = bool(args.no_think)
    LIMITS["llm_max_tokens"] = max(1, min(int(args.llm_max_tokens), 4096))
    ADMIN_TOKEN = args.admin_token.strip() or None   # "" (open mode) normalises to None
    if ADMIN_TOKEN and len(ADMIN_TOKEN) < 16:
        sys.exit("admin token must be at least 16 characters")
    if not ADMIN_TOKEN and not args.allow_open_control:
        sys.exit("control plane auth required: set BICAMERAL_ADMIN_TOKEN "
                 "(or --allow-open-control for local experiments)")

    key_hex = os.environ.get("POC_MASTER_KEY") or DEV_MASTER_KEY_HEX
    try:
        KEY = bytes.fromhex(key_hex)
    except ValueError:
        sys.exit("POC_MASTER_KEY must be 64 hex chars")
    if len(KEY) != 32:
        sys.exit("POC_MASTER_KEY must decode to 32 bytes")

    os.makedirs(DATA_SCOPE, exist_ok=True)
    os.makedirs(IDEM_DIR, exist_ok=True)
    AUDIT_FILE = open(AUDIT_PATH, "a", encoding="utf-8")
    restored = load_state()
    if restored:
        audit("RESTORE", **restored)
    audit("START", pol_ver=POL_VER, build_sha=BUILD_SHA, control_port=args.control_port,
          agent_port=args.agent_port, strata=STRATA_URL,
          control_auth="token" if ADMIN_TOKEN else "open",
          tls=tls, master_key_source="env" if os.environ.get("POC_MASTER_KEY") else "dev-default")
    threading.Thread(target=state_saver_loop, daemon=True).start()

    # startup probe: Strata unreachable -> llm.complete marked degraded, service still starts
    ok, mid = probe_strata()
    if ok:
        with STATE_LOCK:
            STATE["strata"] = "ok"
            STATE["model_id"] = mid or fetch_model_id()
        audit("RECOVER", why="startup_probe_ok")
    else:
        with STATE_LOCK:
            STATE["strata"] = "degraded"
        audit("DEGRADE", why="startup_probe_failed",
              note="llm.complete degraded; probe thread will recover within 30s")
    threading.Thread(target=strata_probe_loop, daemon=True).start()

    httpd_c = ControlServer(("0.0.0.0", args.control_port), Handler,
                            tls_context=tls_ctx)
    httpd_a = AgentServer(("0.0.0.0", args.agent_port), Handler,
                          tls_context=tls_ctx)
    for d in (httpd_c, httpd_a):
        threading.Thread(target=d.serve_forever, daemon=True).start()
    sys.stderr.write("bicameral up: control=0.0.0.0:%d agent=0.0.0.0:%d "
                     "strata=%s strata_state=%s model_id=%s tls=%s\n"
                     % (args.control_port, args.agent_port, STRATA_URL,
                        STATE["strata"], STATE["model_id"], tls))
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        save_state(force=True)
        httpd_c.shutdown()
        httpd_a.shutdown()


if __name__ == "__main__":
    sys.exit(main())
