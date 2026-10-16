#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral nodeagent/1 — node self-autonomy agent (四自: 自感知/自适应/自检/自排查).

One agent takes one fresh node from bare metal to a serving appspec with ZERO
human intervention, and when it truly cannot, it escalates a structured
DIAGNOSIS_REPORT instead of failing silently. The response to the "architecture
cannot do 四自" review: every stage is a first-class command.

Subcommands:
    sense       probe the device and distill DECISION FACTS (os/arch/glibc/
                cores/mem/toolchain/pkg_mgr/egress/engines/port_free) — the
                自感知 half; output is one JSON object.
    bootstrap   appspec → install_state=ready, zero-touch (自适应): a bounded
                sense → plan → act → verify loop; every round appends one
                {observed, diagnosis, action, outcome} NA_DIAGNOSE event.
                One instance per sandbox: <sandbox>/nodeagent/bootstrap.lock
                is taken LOCK_EX|LOCK_NB; a second concurrent run escalates
                with step="lock" (exit 3) instead of racing sandbox removals.
                Strategy 1: appspec carries a prebuilt engine artifact → try
                it, run `--version` selfcheck; failure to RUN (e.g. missing
                GLIBC symbol) or a layout miss (binary_inside/whitelist)
                diagnoses cross-distro non-portability → strategy 2.
                Strategy 2: local source build — install toolchain via the
                package manager → acquire source (--engine-source-tgz with a
                MANDATORY sha256 pin, or a git clone channel ordered by sensed
                egress, resolved commit audited) → cmake build
                (GGML_NATIVE, RPATH $ORIGIN, -j cores) → selfcheck (--version
                + ldd zero unresolved) → package as an engine artifact →
                install.py apply → selfcheck gates READY: all PASS → ready
                (exit 0); any FAIL or a crashed selfcheck → ready_degraded
                (exit 4), audit honest.
                429/rate-limit → bounded exponential backoff and retry.
                Deterministic dead ends (rules exhausted, or the same rule
                failing identically twice in a row) → NA_ESCALATE
                DIAGNOSIS_REPORT, exit non-zero — escalate, never paper over.
    selfcheck   the 自检 half: /health, /v1/models, one REAL /completion
                inference; optionally the control plane: /healthz, audit
                appendable, budget/nonce ledgers alive (replay the same nonce
                and the second call must DENY D3; exhaust the budget and the
                next call must DENY D10). Per-item PASS/FAIL/SKIP, every FAIL
                carries a diagnosis suggestion.
    status      read the node state file (nodeagent-state.json: last sense
                snapshot, DIAGNOSE history, bootstrap result).
    --selftest  self-test (classify/rules/backoff/envelope/mirror ordering/
                ldd+glibc parsing/apply-spec assembly); no ssh, no network,
                no filesystem writes except ONE sandboxed tempfile that
                exercises the bootstrap instance lock.

Engineering contract (docs/paradigm.md §2, same as probe/install/server):
single file, Python 3.10+, standard library only. probe.py / install.py are
IMPORTED (never forked): their functions are the sensing and the mutating
controlled tool; this file adds only the autonomy loop. Destructive actions
(apt/dnf install, directory removal) stay inside the package manager's
declared domain and the sandbox — each one is logged as NA_ACTION BEFORE it
runs, and directory deletion is gated on install.path_inside. Diagnosis rules
are an explicit, extensible table over pure predicates: error text → class →
rule → action, so failure injection is unit-testable (--selftest covers it).

Audit events (install.Audit JSONL, <sandbox>/nodeagent/audit.jsonl):
    NA_SENSE      one per sensing pass (the distilled facts)
    NA_DIAGNOSE   one per loop round: {observed, diagnosis, action, outcome}
    NA_ACTION     before+after each mutating step (pkg install, build,
                  package, apply, backoff, guarded removal)
    NA_VERIFY     the verify half of each round (incl. the final selfcheck)
    NA_ESCALATE   terminal DIAGNOSIS_REPORT when rules are exhausted
    NA_BOOTSTRAP  lifecycle markers (start / done)

Exit codes: 0 ok · 2 usage/schema · 3 bootstrap escalated (rules exhausted /
no progress / another instance holds the lock) · 4 selfcheck FAIL (the
selfcheck subcommand, or bootstrap READY gated down to ready_degraded).
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import inspect
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import install                                       # noqa: E402 (sibling)
import probe                                         # noqa: E402 (sibling)

SCHEMA = "nodeagent/1"
STATE_SCHEMA = "nodeagent-state/1"
STATE_NAME = "nodeagent-state.json"
AUDIT_NAME = "nodeagent-audit.jsonl"
NA_DIRNAME = "nodeagent"
DEFAULT_SANDBOX = install.DEFAULT_SANDBOX
DEFAULT_PORT = 18010

ENGINE_BINARY = "llama-server"      # whitelisted capability-layer binary
CMAKE_FLAGS = ["-DGGML_NATIVE=ON",              # build for THIS core (自适应)
               "-DLLAMA_CURL=OFF",
               "-DCMAKE_BUILD_RPATH_USE_ORIGIN=ON",   # RUNPATH $ORIGIN: the
               # artifact is self-contained once extracted (bi100 gate lesson)
               "-DCMAKE_BUILD_TYPE=Release"]

LIMITS = {
    "max_rounds": 12,                 # sense→plan→act→verify rounds, bounded
    "backoff_base_s": 20.0,           # 429 backoff: base * 2^(n-1), capped
    "backoff_cap_s": 240.0,
    "backoff_max": 4,                 # bounded retries after rate limiting
    "pkg_timeout_s": 1800,            # apt-get update+install budget
    "cmake_timeout_s": 3600,          # configure + build budget (128 cores ≈ 2min)
    "version_timeout_s": 20,          # engine --version selfcheck budget
    "clone_timeout_s": 600,           # git clone --depth 1 budget
    "http_timeout_s": 10.0,           # selfcheck per-request budget
    "completion_timeout_s": 120.0,    # real inference budget (slow boxes)
    "toolchain_packages": ["build-essential", "cmake"],
    "runtime_packages": ["libgomp1"],  # the classic unresolved .so on bare nodes
    "toolchain_need": ["gcc", "cmake", "make"],
}

# mirror URL host → sense.egress key (order_mirrors is driven by this map)
EGRESS_HOST_MAP = {
    "hf-mirror.com": "hf_mirror",
    "huggingface.co": "hf",
    "pypi.org": "pypi",
    "github.com": "github_https",
}

SOURCE_CLONE_URL = "https://github.com/ggml-org/llama.cpp"

# the mandatory supply-chain pin: a local source tgz WITHOUT its sha256 is a
# structured escalation, never an assumption — the text must classify to
# fs_missing so the rule table treats it as a deterministic dead end.
SOURCE_PIN_MISSING = ("source archive sha256 pin missing — the supply-chain "
                      "pin is mandatory for a local engine-source tgz "
                      "(fs_missing)")

# --------------------------------------------------------------------------- #
# error classification + diagnosis rule table (pure; failure-injection friendly)
# --------------------------------------------------------------------------- #

ERROR_CLASSES = ("missing_toolchain", "artifact_run_failed", "artifact_layout",
                 "lib_missing", "rate_limited", "network_unreachable",
                 "hash_mismatch", "engine_not_found", "download_exhausted",
                 "fs_missing", "ref_mismatch", "unknown")

_CLASSIFY_PATTERNS = [
    # (error_class, regex) — FIRST match wins, so the specific beats the generic
    ("rate_limited", re.compile(r"\b429\b|too many requests|rate.?limit", re.I)),
    ("missing_toolchain", re.compile(
        r"\b(gcc|g\+\+|cc|cmake|make|build-essential)\b[^\n]{0,60}"
        r"(not found|command not found|no such file)", re.I)),
    ("missing_toolchain", re.compile(
        r"no cmake_c(_cx)?_compiler could be found", re.I)),
    ("artifact_run_failed", re.compile(
        r"version `glibc_[0-9.]+' not found|cannot execute binary file|"
        r"glc[iI]c[_ ]|version `gl", re.I)),
    # the prebuilt artifact could not even be LOCATED inside its archive
    # (binary_inside miss, no/ambiguous whitelisted executable) — same remedy
    # as a run failure: stop trusting the artifact, build from source
    ("artifact_layout", re.compile(
        r"binary_inside[^\n]{0,80}not found|no whitelisted executable|"
        r"ambiguous engine binary", re.I)),
    ("lib_missing", re.compile(
        r"error while loading shared libraries|cannot open shared object file|"
        r"ldd unresolved|\.so[^\s:]*:\s*not found", re.I)),
    ("hash_mismatch", re.compile(r"verify_fail|sha256 mismatch", re.I)),
    ("engine_not_found", re.compile(r"ENGINE_BINARY_NOT_FOUND|engine .* not found",
                                    re.I)),
    ("download_exhausted", re.compile(r"all mirrors exhausted", re.I)),
    ("network_unreachable", re.compile(
        r"errno\s*-?9[9]\b|ehostunreach|enetunreach|econnrefused|econnreset|"
        r"timed? ?out|temporary failure in name resolution|"
        r"name or service not known|connection reset|errno 101|unreachable",
        re.I)),
    ("ref_mismatch", re.compile(r"engine ref .* not matched", re.I)),
    ("fs_missing", re.compile(
        r"(source (archive|tarball)|engine-source)[^\n]{0,40}missing|"
        r"no source channel", re.I)),
]


def classify_error(error_text: str) -> str:
    """error text → one ERROR_CLASSES member (pure; selftest-covered).

    The single funnel every observed failure goes through: subprocess stderr,
    install.py audit INSTALL_FAIL reasons, artifact --version selfcheck
    output — one vocabulary for the rule table below."""
    text = error_text or ""
    for cls, pat in _CLASSIFY_PATTERNS:
        if pat.search(text):
            return cls
    return "unknown"


def next_backoff(attempt: int, base: float = LIMITS["backoff_base_s"],
                 cap: float = LIMITS["backoff_cap_s"]) -> float:
    """Bounded exponential backoff for attempt (1-based): base*2^(n-1) capped
    (pure; selftest-covered)."""
    if attempt < 1:
        attempt = 1
    return min(cap, base * (2 ** (attempt - 1)))


def host_of(url: str) -> str:
    """https://user@host:port/path → host (lowercase, no port). Pure."""
    try:
        netloc = urllib.parse.urlsplit(url).netloc
    except ValueError:
        return ""
    netloc = netloc.rpartition("@")[2]
    host = netloc.rpartition(":")[0] if ":" in netloc else netloc
    return host.strip("[]").lower()


def redact_url(url: str) -> str:
    """The audit/state form of any URL (pure; selftest-covered): goes through
    install.redact_url (query/fragment — the usual token carriers — dropped)
    AND strips userinfo, so a credentialed control-plane URL can never leak
    its password into NA_VERIFY or the state file. Every URL that is about to
    be audited or persisted goes through THIS, without exception."""
    out = install.redact_url(url)
    try:
        u = urllib.parse.urlsplit(out)
        netloc = u.netloc
        if "@" in netloc:
            out = urllib.parse.urlunsplit(
                (u.scheme, netloc.rpartition("@")[2], u.path, "", ""))
    except ValueError:
        return "<unparseable-url>"
    return out


def order_mirrors(urls: list[str], egress: dict) -> list[str]:
    """Reorder mirror_urls by sensed egress (pure; selftest-covered): hosts
    whose egress key is DOWN sink to the end (stable relative order); up or
    unknown stays. E.g. hf-mirror up + huggingface.co down flips the default
    order automatically — the 自适应 mirror policy."""
    def down(url: str) -> bool:
        key = EGRESS_HOST_MAP.get(host_of(url))
        return bool(key) and (egress or {}).get(key) == "down"
    return [u for u in urls if not down(u)] + [u for u in urls if down(u)]


def parse_glibc(text: str) -> str | None:
    """`ldd (Ubuntu GLIBC 2.35-0ubuntu3.8) 2.35` → "2.35" (pure)."""
    m = re.search(r"\)\s+(\d+\.\d+)\s*$", (text or "").strip().splitlines()[0]
                  if (text or "").strip() else "")
    return m.group(1) if m else None


def parse_ldd_unresolved(text: str) -> list[str]:
    """`libgomp.so.1: not found` lines → ['libgomp.so.1', …] (pure). The build
    selfcheck demands ZERO entries here before the artifact is packaged."""
    out = []
    for line in (text or "").splitlines():
        if "not found" in line:
            m = re.search(r"(\S+\.so[^\s:]*):", line)
            if m:
                out.append(m.group(1))
    return out


def toolchain_missing(facts: dict) -> list[str]:
    """Which of the needed build tools the sense snapshot lacks (pure)."""
    tc = facts.get("toolchain") or {}
    return [t for t in LIMITS["toolchain_need"]
            if not (tc.get(t) or {}).get("present")]


def pkg_mgr_name(facts: dict) -> str:
    return (facts.get("pkg_mgr") or {}).get("name") or "none"


def fresh_flags(strategy: str) -> dict:
    """Initial plan-state flags for one bootstrap run (pure)."""
    return {"strategy": strategy, "artifact_probed": False, "artifact_ok": False,
            "source_extracted": False, "build_ok": False, "binary_ok": False,
            "runtime_lib_ok": False, "artifact_packaged": False,
            "apply_spec_written": False, "apply_done": False, "ready": False,
            "backoffs_used": 0, "apply_attempts": 0, "probe_attempts": 0}


# --- the rule table: explicit data, ordered, first match wins; extend by
# --- appending a reviewed entry, never by editing flow code.
RULES = [
    {"id": "probe_artifact",
     "diagnosis": "appspec 带预构建引擎工件：先试工件，--version 自检验证可移植性",
     "action": "probe_artifact"},
    {"id": "switch_to_source",
     "diagnosis": "预构建工件在本 (arch, os_version/glibc) 无法运行——跨发行版不可移植，切换本机源码构建",
     "action": "switch_strategy"},
    {"id": "escalate_no_pkg_mgr",
     "diagnosis": "缺编译工具链且节点无可用包管理器（apt/dnf 均不存在），无法自装",
     "action": "escalate"},
    {"id": "install_toolchain",
     "diagnosis": "sense 发现缺编译工具链 → 用节点包管理器自装 build-essential + cmake",
     "action": "install_toolchain"},
    {"id": "acquire_source",
     "diagnosis": "引擎源码未就位：本地 tgz 优先，否则按设备出网选通道（github https 通则 clone）",
     "action": "acquire_source"},
    {"id": "install_runtime_lib",
     "diagnosis": "构建产物缺运行时共享库（如 libgomp）→ 包管理器补装运行库",
     "action": "install_runtime_lib"},
    {"id": "build_engine",
     "diagnosis": "源码就位但引擎未过自检 → cmake 本机构建（GGML_NATIVE，RPATH $ORIGIN，-j cores）+ --version/ldd 自检",
     "action": "build"},
    {"id": "package_artifact",
     "diagnosis": "引擎二进制自检通过 → 打包为引擎工件（bin/ 布局）并组装 apply 用 appspec（模型镜像按出网排序）",
     "action": "package"},
    {"id": "backoff_retry",
     "diagnosis": "模型镜像限流（429/Too Many Requests）→ 有界指数退避后重试 apply（apply 幂等，引擎段已 skip）",
     "action": "backoff"},
    {"id": "apply_install",
     "diagnosis": "引擎工件与 appspec 就绪 → 调 install.py apply 完成 absent→ready",
     "action": "apply"},
    {"id": "escalate", "diagnosis": "规则穷尽仍失败", "action": "escalate"},
]


def plan_round(strategy: str, facts: dict, flags: dict,
               last_error_text: str | None) -> dict:
    """One sense→plan decision (pure; selftest-covered). Returns a RULES row
    (plus `error_class`). The same function drives the loop and the selftest —
    failure injection just means feeding it a crafted error_text/facts."""
    cls = classify_error(last_error_text or "")
    row = {"error_class": cls}

    def pick(rule_id: str) -> dict:
        rule = next(r for r in RULES if r["id"] == rule_id)
        return dict(row, **copy.deepcopy(rule))

    if strategy == "artifact" and not flags.get("artifact_probed"):
        return pick("probe_artifact")
    # artifact failed to RUN (glibc/exec) or was never found whole inside its
    # archive (layout): either way the prebuilt channel is dead — flip to the
    # local source build
    if cls in ("artifact_run_failed", "artifact_layout") \
            and strategy == "artifact":
        return pick("switch_to_source")
    if strategy == "source":
        missing = toolchain_missing(facts)
        if missing:
            if pkg_mgr_name(facts) == "none":
                return pick("escalate_no_pkg_mgr")
            return pick("install_toolchain")
        if not flags.get("source_extracted"):
            return pick("acquire_source")
        if cls == "lib_missing" and not flags.get("runtime_lib_ok"):
            return pick("install_runtime_lib")
        if not flags.get("binary_ok"):
            return pick("build_engine")
        if not flags.get("artifact_packaged"):
            return pick("package_artifact")
    # deterministic failures: retrying cannot fix a wrong pin, a missing
    # injected file, a closed firewall or a dead package manager — escalate
    # NOW with the structured report instead of burning bounded rounds.
    if cls in ("hash_mismatch", "ref_mismatch", "engine_not_found",
               "fs_missing", "missing_toolchain"):
        return pick("escalate")
    # transient egress trouble (429 rate limiting, a flapping mirror) gets the
    # bounded exponential backoff; when the backoff budget is gone the loop
    # still ends in the round-budget escalation
    if cls in ("rate_limited", "network_unreachable", "download_exhausted") \
            and flags.get("backoffs_used", 0) < LIMITS["backoff_max"]:
        return pick("backoff_retry")
    if not flags.get("apply_done"):
        return pick("apply_install")
    return pick("escalate")


def no_progress(history: list[dict]) -> bool:
    """The SAME rule failed with the SAME error in the two most recent rounds
    (pure; selftest-covered): the rule table has routed one deterministic
    failure twice, so escalating now beats burning the remaining round budget
    on it. Backoff rounds never count — the backoff action itself succeeds by
    design, and its surrounding apply/probe rounds alternate rule ids."""
    if len(history) < 2:
        return False
    a, b = history[-2], history[-1]
    return (a.get("rule") == b.get("rule")
            and (a.get("outcome") or {}).get("status") != "ok"
            and (b.get("outcome") or {}).get("status") != "ok"
            and (a.get("outcome") or {}).get("error")
            == (b.get("outcome") or {}).get("error"))


# root-cause hypotheses + what a human should do, per error class — the
# terminal DIAGNOSIS_REPORT is assembled from this table (never from thin air).
HYPOTHESES = {
    "missing_toolchain": (
        "节点镜像缺编译工具链且包管理器自装失败",
        "换用含 build-essential/cmake 的基础镜像，或由主控注入工具链工件后重跑 bootstrap（幂等）"),
    "artifact_run_failed": (
        "预构建引擎工件与目标 (arch, os_version/glibc) 不兼容",
        "提供本机构建通道：--engine-source-tgz 注入源码包；或发布 GGML_NATIVE=OFF 的可移植工件"),
    "artifact_layout": (
        "预构建工件布局不符（binary_inside 未命中，或白名单可执行缺失/歧义）",
        "核对 appspec engine.install.binary_inside 与工件 bin/ 布局；或改走本机源码构建"
        "（--engine-source-tgz + sha256 钉死）"),
    "lib_missing": (
        "构建产物缺运行时共享库（典型 libgomp）",
        "人工确认 pkg_mgr 可安装运行库；或把该 .so 一并打入引擎工件"),
    "rate_limited": (
        "模型镜像按 IP 限流（hf-mirror 429），退避重试已达上限",
        "等待限流窗口后重跑 bootstrap（引擎段幂等 skip，只续模型下载）；或主控注入模型文件并把 mirror_urls 换成 file://"),
    "network_unreachable": (
        "设备出口不可达（防火墙/断网），全部通道失败",
        "开通到镜像域的出网，或主控注入源码与模型工件"),
    "hash_mismatch": (
        "下载字节与 appspec 钉死 sha256 不符——供应链事实，agent 无权改 pin",
        "人工核对发布渠道 sha256；确认后更新 appspec 重跑"),
    "engine_not_found": (
        "引擎二进制不存在且无构建/工件通道",
        "提供 --engine-source-tgz 或 appspec engine.install 工件"),
    "download_exhausted": (
        "全部镜像/重试耗尽",
        "检查镜像可用性后重跑；或主控注入工件改 file://"),
    "fs_missing": (
        "声明的本地源码包/工件文件不存在",
        "核对 --engine-source-tgz 路径，重新注入后重跑"),
    "ref_mismatch": (
        "引擎 --version 输出与 appspec engine.ref 不符",
        "appspec ref 与本机构建版本不匹配：改 ref 或提供钉死版本的工件"),
    "unknown": (
        "未归类失败",
        "取 nodeagent-state.json 与 <sandbox>/audit.jsonl（install 侧）人工排查"),
}


def escalation_report(name: str, last_error_text: str, history: list[dict],
                      rounds: int) -> dict:
    """The structured DIAGNOSIS_REPORT (pure; selftest-covered): phenomenon /
    actions tried / root-cause hypotheses / what a human should do."""
    cls = classify_error(last_error_text or "")
    hyp, human = HYPOTHESES.get(cls, HYPOTHESES["unknown"])
    return {"report": "DIAGNOSIS_REPORT", "schema": SCHEMA, "app": name,
            "rounds": rounds,
            "phenomenon": (last_error_text or "rules exhausted without a "
                           "recorded error")[:probe.EXCERPT],
            "error_class": cls,
            "actions_tried": [{"round": h.get("round"), "rule": h.get("rule"),
                               "action": h.get("action"),
                               "outcome": h.get("outcome")}
                              for h in history[-LIMITS["max_rounds"]:]],
            "root_cause_hypothesis": hyp,
            "human_actions": human}


# --------------------------------------------------------------------------- #
# apply-spec assembly (pure; selftest-covered)
# --------------------------------------------------------------------------- #

def artifact_filename(facts: dict) -> str:
    """llama-jammy-x86_64.tgz style name from a sense snapshot (pure)."""
    os_id = (facts.get("os_id") or "linux").replace("/", "-")
    os_version = (facts.get("os_version") or "0").replace("/", "-")
    arch = facts.get("arch") or platform.machine()
    return "llama-%s%s-%s.tgz" % (os_id, os_version, arch)


def build_apply_spec(spec: dict, artifact_path: str, artifact_sha256: str,
                     facts: dict) -> dict:
    """spec → the appspec install.py will consume (pure; selftest-covered):
    engine.install pinned to the freshly built local artifact (file:// mirror,
    exact sha256, bin/ member layout), model mirror_urls reordered by sensed
    egress. Input spec must already be validated + hint-stripped."""
    out = copy.deepcopy(spec)
    if out["engine"].get("binary"):
        raise ValueError("engine.binary pinned; local build not needed")
    if "install" in out["engine"]:
        raise ValueError("engine.install already present; artifact strategy")
    out["engine"]["install"] = {
        "mirror_urls": ["file://" + os.path.abspath(artifact_path)],
        "sha256": artifact_sha256, "format": "tgz", "strip_components": 0,
        "binary_inside": "bin/" + ENGINE_BINARY}
    out["model"]["mirror_urls"] = order_mirrors(
        out["model"].get("mirror_urls", []), facts.get("egress") or {})
    return out


def strip_hints(raw: dict) -> tuple[dict, dict]:
    """Split an input appspec into (core appspec, nodeagent hints). The
    optional top-level "nodeagent" object is THIS tool's strategy hints and
    must never reach install.validate_appspec (unknown field → reject)."""
    raw = copy.deepcopy(raw)
    hints = raw.pop("nodeagent", None) or {}
    return raw, hints if isinstance(hints, dict) else {}


def source_request(args_tgz: str | None, args_sha: str | None,
                   hints: dict) -> tuple[str | None, str | None, str | None]:
    """Resolve the local source-tgz channel inputs — CLI args first, then
    nodeagent hints (pure; selftest-covered). Returns (tgz, sha256, pin_error):
    a tgz WITHOUT its sha256 pin is a supply-chain fact to escalate, never an
    assumption, so pin_error = SOURCE_PIN_MISSING (classifies to fs_missing →
    the rule table escalates deterministically)."""
    src = (hints.get("engine_source") or {}) if isinstance(hints, dict) else {}
    tgz = args_tgz or src.get("tgz")
    sha = args_sha or src.get("sha256")
    if tgz and not sha:
        return tgz, None, SOURCE_PIN_MISSING
    return tgz, sha, None


def build_agent_envelope(token: str, nonce: str, tool: str,
                         params: dict) -> tuple[dict, bytes]:
    """Strict /agent/invoke request for server.py: headers + body bytes with
    EXACTLY {nonce, tool, params} (pure; selftest-covered — D8 rejects any
    extra field, so the envelope shape is contract)."""
    body = json.dumps({"nonce": nonce, "tool": tool, "params": params},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "X-Capability-Token": token,
               "Content-Length": str(len(body))}
    return headers, body


def check_failed_suggestion(check: str, detail: dict) -> str:
    """Per-check diagnosis suggestion for selfcheck FAILs (pure)."""
    return {
        "base_health": "llama-server 未监听/未就绪：查 install.py status 与 <app>/service.log；"
                       "端口被占则换 appspec service.port 重跑 bootstrap",
        "base_models": "服务活着但 /v1/models 空：模型未加载完或 gguf 损坏；查 service.log 加载行，"
                       "必要时删 <sandbox>/apps/<name>/models/<file> 重跑 bootstrap（幂等续下）",
        "base_completion": "/health+/v1/models 通过但推理失败：查 service.log 是否 OOM/参数错；"
                           "重试一次（首请求含 warmup），仍失败看 timings/错误体",
        "agent_healthz": "控制面未起：nodeagent 不管主控进程——人工确认 server.py 在 --agent 地址监听",
        "agent_audit": "审计不可追加：/audit 401 检查 --admin-token；计数不涨查 RING/AUDIT_PATH 写权限",
        "agent_nonce_replay": "重放同一 nonce 未被判 D3：nonce 表失效属安全缺陷——立即停用该实例并回报主控",
        "agent_budget": "预算耗尽未被判 D10：预算台账失效属安全缺陷——立即停用该实例并回报主控",
    }.get(check, "看 detail 字段定位，结合 <sandbox>/audit.jsonl 排查")


def selfcheck_failures(selfcheck: dict) -> list[dict]:
    """The FAIL rows of a selfcheck result (pure; selftest-covered). A result
    WITHOUT a checks list — the internal-crash shape — counts as ONE synthetic
    failure, so a crashed battery can never be mistaken for a green one and
    READY is never granted on a selfcheck that never ran."""
    checks = (selfcheck or {}).get("checks")
    if not isinstance(checks, list):
        return [{"check": "selfcheck", "status": "FAIL",
                 "detail": {"reason": (selfcheck or {}).get("error")
                            or (selfcheck or {}).get("reason")
                            or "selfcheck produced no checks"}}]
    return [c for c in checks
            if isinstance(c, dict) and c.get("status") == "FAIL"]


# --------------------------------------------------------------------------- #
# small impure helpers (thin, never in the selftest)
# --------------------------------------------------------------------------- #

def note(msg: str) -> None:
    sys.stderr.write("nodeagent: %s\n" % msg)
    sys.stderr.flush()


def check_port_free(port: int, host: str = "127.0.0.1") -> bool | None:
    """Bind-test a loopback port; None = cannot decide (e.g. no permission)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def http_json(url: str, method: str = "GET", body: bytes | None = None,
              headers: dict | None = None,
              timeout: float = LIMITS["http_timeout_s"]) -> dict:
    """One HTTP exchange; never raises. {status, json|body, error}."""
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(1 << 20)
            text = raw.decode("utf-8", "replace")
            try:
                return {"status": r.status, "json": json.loads(text)}
            except ValueError:
                return {"status": r.status, "body": text[:probe.EXCERPT]}
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read(1 << 20).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 — body best-effort
            pass
        try:
            return {"status": e.code, "json": json.loads(raw)}
        except ValueError:
            return {"status": e.code, "body": raw[:probe.EXCERPT]}
    except Exception as e:  # noqa: BLE001 — every failure mode is a fact
        return {"status": None, "error": "%s: %s" % (type(e).__name__,
                                                     str(e)[:200])}


def read_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) and d.get("schema") == STATE_SCHEMA \
            else {}
    except (OSError, ValueError):
        return {}


def write_state(path: str, data: dict) -> None:
    data = {"schema": STATE_SCHEMA, "updated_at": probe.now_utc(), **data}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def parse_jsonl_tail(text: str, k: int = 200) -> list[dict]:
    """Last k parseable JSONL records (pure; selftest-covered)."""
    out = []
    for line in (text or "").splitlines()[-k:]:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def install_audit_error(sandbox: str, since_ts: float) -> str:
    """Latest failure reason install.py appended to <sandbox>/audit.jsonl —
    the 'observed' input for the next round's classify (never raises)."""
    path = os.path.join(sandbox, install.AUDIT_NAME)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            recs = parse_jsonl_tail(f.read(), k=400)
    except OSError:
        return ""
    hits = [r for r in recs
            if r.get("ts", 0) >= since_ts
            and (r.get("event") in ("INSTALL_FAIL", "ENGINE_VERIFY_FAIL",
                                    "VERIFY_FAIL")
                 or (r.get("event") in ("DOWNLOAD", "ENGINE_DOWNLOAD")
                     and r.get("status") == "fail"))]
    parts = []
    for r in hits[-6:]:
        parts.append(str(r.get("error") or r.get("url") or r.get("event")))
    return " | ".join(parts)


def guarded_rmtree(root: str, path: str) -> bool:
    """rm -rf confined to the sandbox (install.path_inside is the only gate
    under which this tool ever deletes a tree); root itself is NEVER deleted
    (realpath equality is refused before the gate, which would otherwise pass
    it — path_inside admits rp == rr). NA_ACTION is logged by the caller
    BEFORE calling this."""
    if os.path.realpath(path) == os.path.realpath(root):
        return False
    if path_inside_quiet(root, path) and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
        return not os.path.isdir(path)
    return False


def path_inside_quiet(root: str, path: str) -> bool:
    try:
        return install.path_inside(root, path)
    except (OSError, ValueError):
        return False


def na_paths(sandbox: str) -> dict:
    na = os.path.join(sandbox, NA_DIRNAME)
    return {"na": na, "state": os.path.join(na, STATE_NAME),
            "audit": os.path.join(na, AUDIT_NAME),
            "lock": os.path.join(na, "bootstrap.lock"),
            "src": os.path.join(na, "src"),
            "build": os.path.join(na, "build"),
            "artifacts": os.path.join(na, "artifacts"),
            "scratch": os.path.join(na, "scratch")}


def acquire_bootstrap_lock(na_dir: str) -> int | None:
    """LOCK_EX|LOCK_NB on <na>/bootstrap.lock — ONE bootstrap per sandbox
    (install.acquire_app_lock style): concurrent instances would race each
    other's guarded sandbox removals (source tree, build dirs). Returns the
    fd to hold for the run's lifetime, or None when another instance holds
    it — the caller then escalates with step="lock" (exit 3) and never
    touches the sandbox. Raises OSError when the lock file is unusable."""
    os.makedirs(na_dir, exist_ok=True)
    fd = os.open(os.path.join(na_dir, "bootstrap.lock"),
                 os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def release_bootstrap_lock(fd: int | None) -> None:
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


# --------------------------------------------------------------------------- #
# sense (自感知) — decision facts, distilled from probe/1 functions
# --------------------------------------------------------------------------- #

def collect_facts(port: int | None = None, no_egress: bool = False) -> dict:
    """The decision facts one planning round needs — distilled from probe/1
    functions (never re-implemented here). Every entry is either a fact or an
    honest None; sensing never raises."""
    osr = probe.parse_os_release()
    cores = os.cpu_count() or 0
    mem_gb = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_gb = round(int(line.split()[1]) / (1024 * 1024), 1)
                    break
    except (OSError, ValueError, IndexError):
        pass

    glibc = parse_glibc((probe.run_cmd(["ldd", "--version"]).get("output") or ""))

    toolchain: dict = {}
    for tool in ("gcc", "g++", "cmake", "make", "git"):
        path = install.search_binary(tool)
        ent: dict = {"present": False, "path": None, "version": None}
        if path:
            r = probe.run_cmd([path, "--version"],
                              timeout=probe.SUBPROC_TIMEOUT)
            if r["status"] == "ok":
                ent = {"present": True, "path": path,
                       "version": probe.first_meaningful_line(r.get("output") or "")}
            else:
                ent["path"] = path
        toolchain[tool] = ent

    pkg_mgr = {"name": "none", "path": None}
    for name, mgr in (("apt-get", "apt"), ("dnf", "dnf")):
        path = install.search_binary(name)
        if path:
            pkg_mgr = {"name": mgr, "path": path}
            break

    if no_egress:
        egress = {"skipped": "--no-egress"}
    else:
        targets = probe.probe_egress(False).get("targets", {})
        # probe/1 names the github-https target "github"; the decision facts
        # keep the paradigm name github_https
        egress = {k: (targets.get(pk) or {}).get("status", "unknown")
                  for k, pk in (("pypi", "pypi"), ("hf", "hf"),
                                ("hf_mirror", "hf_mirror"),
                                ("github_https", "github"))}

    engines = [{"name": e["name"], "status": e.get("status"),
                "version": e.get("version"), "sha256_16": e.get("sha256_16")}
               for e in probe.probe_engines()]

    facts = {"schema": SCHEMA, "generated_at": probe.now_utc(),
             "os_id": osr.get("id"), "os_version": osr.get("version_id"),
             "os_pretty": osr.get("pretty_name"),
             "arch": platform.machine(), "glibc": glibc, "cores": cores,
             "mem_gb": mem_gb, "toolchain": toolchain, "pkg_mgr": pkg_mgr,
             "egress": egress, "engines": engines,
             "port_free": check_port_free(port) if port else None,
             "port": port}
    return facts


def cmd_sense(args) -> int:
    facts = collect_facts(port=args.port, no_egress=args.no_egress)
    text = json.dumps(facts, ensure_ascii=False, indent=2)
    if args.sandbox:
        paths = na_paths(os.path.abspath(args.sandbox))
        audit = install.Audit(paths["audit"])
        audit.emit("NA_SENSE", port=facts["port"],
                   os_id=facts["os_id"], os_version=facts["os_version"],
                   arch=facts["arch"], glibc=facts["glibc"],
                   cores=facts["cores"], pkg_mgr=facts["pkg_mgr"]["name"],
                   egress=facts["egress"],
                   toolchain={k: v["present"]
                              for k, v in facts["toolchain"].items()},
                   engines=[e["name"] + ":" + str(e["status"])
                            for e in facts["engines"]])
        audit.close()
        state = read_state(paths["state"])
        state["last_sense"] = facts
        write_state(paths["state"], state)
        note("NA_SENSE recorded to %s" % paths["audit"])
    print(text)
    return 0


# --------------------------------------------------------------------------- #
# actions (自适应) — each logs NA_ACTION before it mutates
# --------------------------------------------------------------------------- #

def act_pkg_install(audit: install.Audit, facts: dict,
                    packages: list[str]) -> dict:
    """Destructive, declared-domain: the package manager installs the named
    packages. NA_ACTION is logged BEFORE apt/dnf runs; elapsed time recorded
    (the task's 「记录耗时」). Never runs outside mgr apt/dnf."""
    mgr = pkg_mgr_name(facts)
    if mgr == "none":
        return {"status": "fail", "error": "no package manager (apt/dnf absent)"}
    if mgr == "apt":
        argvs = [["apt-get", "update"],
                 ["apt-get", "install", "-y"] + list(packages)]
    else:                                    # dnf
        argvs = [["dnf", "install", "-y"] + list(packages)]
    t0 = time.monotonic()
    audit.emit("NA_ACTION", action="pkg_install", mgr=mgr, packages=packages,
               argvs=argvs, phase="start",
               note="destructive action confined to the package manager's "
                    "declared domain")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    outs = []
    for i, argv in enumerate(argvs):
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=LIMITS["pkg_timeout_s"], env=env)
            merged = ((p.stdout or "") + (p.stderr or ""))[-probe.EXCERPT:]
            outs.append("rc=%d %s" % (p.returncode, merged.strip()
                                      .splitlines()[-1] if merged.strip() else ""))
            # `apt-get update` failing (blocked mirror, stale lists) is only a
            # note: cached lists may still satisfy the install. The INSTALL
            # step (last argv) is the one that must succeed.
            if p.returncode != 0 and i == len(argvs) - 1:
                audit.emit("NA_ACTION", action="pkg_install", mgr=mgr,
                           packages=packages, phase="done", status="fail",
                           argv=argv, rc=p.returncode, output=merged,
                           elapsed_s=round(time.monotonic() - t0, 1))
                return {"status": "fail",
                        "error": "pkg_install rc=%d: %s"
                                 % (p.returncode, merged[-probe.EXCERPT:])}
        except (OSError, subprocess.SubprocessError) as e:
            err = "%s: %s" % (type(e).__name__, str(e)[:200])
            audit.emit("NA_ACTION", action="pkg_install", mgr=mgr,
                       packages=packages, phase="done", status="error",
                       error=err)
            return {"status": "fail", "error": err}
    elapsed = round(time.monotonic() - t0, 1)
    audit.emit("NA_ACTION", action="pkg_install", mgr=mgr, packages=packages,
               phase="done", status="ok", elapsed_s=elapsed, steps=outs)
    return {"status": "ok", "elapsed_s": elapsed}


def act_acquire_source(audit: install.Audit, ctx) -> dict:
    """Source acquisition, channel-ordered: --engine-source-tgz (its sha256
    pin is MANDATORY — hints or CLI, no unverified source is ever extracted)
    → git clone over an up https egress (resolved commit audited) → fail with
    a channel report. Extraction reuses install.extract_engine_tgz
    (traversal-checked); failed trees are removed from inside the sandbox."""
    src = ctx.paths["src"]
    tgz, want_sha, pin_error = source_request(
        getattr(ctx.args, "engine_source_tgz", None),
        getattr(ctx.args, "engine_source_sha256", None), ctx.hints)
    channels = []
    if tgz:
        if pin_error:
            # structured escalation via the rule table: fs_missing is a
            # deterministic dead end, retried once only to be detected as
            # no-progress, then NA_ESCALATE — never an unverified extraction
            return {"status": "fail", "error": pin_error}
        channels.append("local_tgz:" + tgz)
    if (ctx.facts.get("egress") or {}).get("github_https") == "up" \
            and (ctx.facts.get("toolchain") or {}).get("git", {}) \
            .get("present"):
        channels.append("git_clone:" + SOURCE_CLONE_URL)
    audit.emit("NA_ACTION", action="acquire_source", channels=channels,
               phase="start")

    if tgz:
        if not os.path.isfile(tgz):
            return {"status": "fail",
                    "error": "source archive missing at %s (fs_missing)" % tgz}
        try:
            got = install.sha256_file(tgz)
        except OSError as e:
            return {"status": "fail", "error": "%s: %s"
                    % (type(e).__name__, str(e)[:160])}
        if got != want_sha.lower():
            return {"status": "fail",
                    "error": "VERIFY_FAIL: source tgz sha256 mismatch "
                             "(want %s…, have %s…)"
                             % (want_sha[:16], got[:16])}
        guarded_rmtree(ctx.sandbox, src)
        os.makedirs(src, exist_ok=True)
        audit.emit("NA_ACTION", action="extract_source", src=src, tgz=tgz,
                   sha256=want_sha, phase="start",
                   note="sandbox-confined extraction (install.path_inside)")
        try:
            total, members = install.extract_engine_tgz(tgz, src, 1)
        except install.InstallError as e:
            guarded_rmtree(ctx.sandbox, src)
            return {"status": "fail", "error": "extract: %s" % e.reason}
        if not os.path.isfile(os.path.join(src, "CMakeLists.txt")):
            guarded_rmtree(ctx.sandbox, src)
            return {"status": "fail",
                    "error": "source archive missing CMakeLists.txt at top "
                             "level (strip_components=1) (fs_missing)"}
        audit.emit("NA_ACTION", action="extract_source", phase="done",
                   status="ok", members=members, extracted_bytes=total)
        return {"status": "ok", "channel": "local_tgz", "members": members}

    # no local tgz: the egress-ordered clone channel
    if channels and channels[0].startswith("git_clone:"):
        t0 = time.monotonic()
        try:
            p = subprocess.run(["git", "clone", "--depth", "1",
                                SOURCE_CLONE_URL, src],
                               capture_output=True, text=True,
                               timeout=LIMITS["clone_timeout_s"])
        except (OSError, subprocess.SubprocessError) as e:
            return {"status": "fail", "error": "clone: %s: %s"
                    % (type(e).__name__, str(e)[:160])}
        if p.returncode != 0:
            guarded_rmtree(ctx.sandbox, src)
            return {"status": "fail", "error": "clone rc=%d: %s"
                    % (p.returncode, (p.stderr or "")[-probe.EXCERPT:])}
        # pin the built provenance: which commit the shallow clone resolved to
        head = probe.run_cmd(["git", "-C", src, "rev-parse", "HEAD"],
                             timeout=probe.SUBPROC_TIMEOUT)
        resolved = probe.first_meaningful_line(head.get("output") or "") \
            if head.get("status") == "ok" else None
        audit.emit("NA_ACTION", action="git_clone", url=SOURCE_CLONE_URL,
                   phase="done", status="ok",
                   resolved_commit=resolved,
                   elapsed_s=round(time.monotonic() - t0, 1))
        return {"status": "ok", "channel": "git_clone",
                "resolved_commit": resolved}

    return {"status": "fail",
            "error": "no source channel: no --engine-source-tgz and github "
                     "https down/unclonable (fs_missing)"}


def engine_selfcheck(audit: install.Audit, binary: str, label: str) -> dict:
    """--version + ldd zero-unresolved (the task's 自检). Returns
    {status, error, version, unresolved} — error text is classify_error bait
    (GLIBC symbol failures classify as artifact_run_failed, missing .so as
    lib_missing)."""
    r = probe.run_cmd([binary, "--version"],
                      timeout=LIMITS["version_timeout_s"])
    version = probe.first_meaningful_line(r.get("output") or "")
    if r["status"] != "ok":
        err = "%s --version selfcheck failed rc=%s: %s" \
              % (label, r.get("code"), (r.get("output") or
                                        r.get("error") or "")[-probe.EXCERPT:])
        audit.emit("NA_VERIFY", what=label + "_version", status="fail",
                   binary=binary, rc=r.get("code"), output=(r.get("output")
                                                            or "")[-probe.EXCERPT:])
        return {"status": "fail", "error": err, "unresolved": None}
    ld = probe.run_cmd(["ldd", binary], timeout=LIMITS["version_timeout_s"])
    unresolved = parse_ldd_unresolved(ld.get("output") or "")
    if unresolved:
        audit.emit("NA_VERIFY", what=label + "_ldd", status="fail",
                   binary=binary, unresolved=unresolved)
        return {"status": "fail",
                "error": "%s ldd unresolved: %s (lib_missing)"
                         % (label, ", ".join(unresolved)),
                "version": version, "unresolved": unresolved}
    audit.emit("NA_VERIFY", what=label + "_selfcheck", status="ok",
               binary=binary, version=version)
    return {"status": "ok", "version": version, "unresolved": []}


def act_build(audit: install.Audit, ctx) -> dict:
    """cmake configure + build llama-server (-j cores), then engine_selfcheck.
    Build dir lives under the sandbox; timeouts bounded."""
    src, build = ctx.paths["src"], ctx.paths["build"]
    if not os.path.isfile(os.path.join(src, "CMakeLists.txt")):
        return {"status": "fail", "error": "source tree missing CMakeLists.txt"
                                           " (fs_missing)"}
    jobs = max(1, min(int(ctx.facts.get("cores") or 1), 128))
    steps = [
        ["cmake", "-S", src, "-B", build] + CMAKE_FLAGS,
        ["cmake", "--build", build, "--target", ENGINE_BINARY, "-j", str(jobs)],
    ]
    t0 = time.monotonic()
    for argv in steps:
        audit.emit("NA_ACTION", action="build", argv=argv, phase="start",
                   note="sandbox-confined build; jobs=%d" % jobs)
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=LIMITS["cmake_timeout_s"])
        except (OSError, subprocess.SubprocessError) as e:
            return {"status": "fail", "error": "build: %s: %s"
                    % (type(e).__name__, str(e)[:200])}
        if p.returncode != 0:
            tail = ((p.stderr or "") + (p.stdout or ""))[-probe.EXCERPT:]
            audit.emit("NA_ACTION", action="build", argv=argv, phase="done",
                       status="fail", rc=p.returncode, output=tail,
                       elapsed_s=round(time.monotonic() - t0, 1))
            return {"status": "fail", "error": "build rc=%d: %s"
                    % (p.returncode, tail)}
        audit.emit("NA_ACTION", action="build", argv=argv, phase="done",
                   status="ok")
    binary = os.path.join(build, "bin", ENGINE_BINARY)
    if not os.path.isfile(binary):
        return {"status": "fail", "error": "engine binary not found at %s "
                                           "after build (fs_missing)" % binary}
    sc = engine_selfcheck(audit, binary, "built-engine")
    sc["elapsed_s"] = round(time.monotonic() - t0, 1)
    return sc


def act_package(audit: install.Audit, ctx) -> dict:
    """Self-checked binary → engine artifact tgz (bin/ member layout, the
    layout install.py's binary_inside expects) → roundtrip-verify the artifact
    (--version from the extracted tree proves RUNPATH $ORIGIN self-containment)
    → write <name>.apply.json for install.py."""
    build, artifacts = ctx.paths["build"], ctx.paths["artifacts"]
    binary = os.path.join(build, "bin", ENGINE_BINARY)
    os.makedirs(artifacts, exist_ok=True)
    fname = artifact_filename(ctx.facts)
    artifact = os.path.join(artifacts, fname)
    audit.emit("NA_ACTION", action="package", artifact=artifact, phase="start",
               note="tar czf bin/ layout (llama-server + bundled .so)")
    if os.path.exists(artifact):
        remove_stale(audit, ctx, artifact)
    with tarfile.open(artifact, "w:gz") as tf:
        for fn in sorted(os.listdir(os.path.join(build, "bin"))):
            full = os.path.join(build, "bin", fn)
            if os.path.isfile(full):
                info = tf.gettarinfo(full, arcname="bin/" + fn)
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                with open(full, "rb") as f:
                    tf.addfile(info, f)
    artifact_sha = install.sha256_file(artifact)
    size = os.path.getsize(artifact)

    # artifact roundtrip: extract into scratch (sandbox) and run --version —
    # proves the packaged artifact is portable to a bare directory.
    scratch = os.path.join(ctx.paths["scratch"], "roundtrip")
    guarded_rmtree(ctx.sandbox, scratch)
    os.makedirs(scratch, exist_ok=True)
    try:
        install.extract_engine_tgz(artifact, scratch, 0)
    except install.InstallError as e:
        guarded_rmtree(ctx.sandbox, scratch)
        return {"status": "fail", "error": "artifact roundtrip extract: %s"
                % e.reason}
    sc = engine_selfcheck(audit, os.path.join(scratch, "bin", ENGINE_BINARY),
                          "artifact")
    guarded_rmtree(ctx.sandbox, scratch)
    if sc["status"] != "ok":
        return sc

    try:
        apply_spec = build_apply_spec(ctx.spec, artifact, artifact_sha,
                                      ctx.facts)
    except ValueError as e:
        return {"status": "fail", "error": "apply-spec: %s" % e}
    apply_path = os.path.join(ctx.paths["na"], "%s.apply.json" % ctx.spec["name"])
    with open(apply_path, "w", encoding="utf-8") as f:
        json.dump(apply_spec, f, ensure_ascii=False, indent=2)
    audit.emit("NA_ACTION", action="package", phase="done", status="ok",
               artifact=artifact, sha256=artifact_sha, bytes=size,
               apply_spec=apply_path,
               model_mirrors=apply_spec["model"]["mirror_urls"])
    ctx.apply_appspec = apply_path
    return {"status": "ok", "artifact": artifact, "sha256": artifact_sha,
            "bytes": size, "apply_spec": apply_path,
            "version": sc.get("version")}


def remove_stale(audit: install.Audit, ctx, path: str) -> bool:
    """Audit-then-remove ONE stale path inside the sandbox — a file with
    os.remove, a tree with guarded_rmtree — so the audit note and the fact
    agree (the old file-path call was a silent no-op that still claimed a
    removal). Returns whether the path is actually gone."""
    audit.emit("NA_ACTION", action="remove_stale", path=path, phase="start",
               note="sandbox-confined removal (install.path_inside gate; "
                    "file → os.remove, tree → guarded_rmtree)")
    if path_inside_quiet(ctx.sandbox, path) and os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
    else:
        guarded_rmtree(ctx.sandbox, path)
    return not os.path.lexists(path)


def act_probe_artifact(audit: install.Audit, ctx) -> dict:
    """Strategy 1: the appspec carries a prebuilt engine artifact — download
    it (pinned sha256 via install.download_model), extract into sandbox
    scratch, and run the --version selfcheck. Failure to RUN (missing GLIBC
    symbol, cannot execute) diagnoses cross-distro non-portability and flips
    the strategy to a local source build. A clean pass leaves the apply to
    install.py's own audited engine.install path."""
    inst = ctx.spec["engine"].get("install") or {}
    scratch = os.path.join(ctx.paths["scratch"], "artifact-probe")
    os.makedirs(ctx.paths["scratch"], exist_ok=True)
    part = os.path.join(ctx.paths["scratch"], "artifact-probe.tgz.part")
    urls = install.dedup_urls(inst.get("mirror_urls") or [])
    audit.emit("NA_ACTION", action="probe_artifact",
               urls=[redact_url(u) for u in urls], phase="start")
    try:
        install.download_model(audit, ctx.spec["name"], urls, part,
                               inst["sha256"], what="engine-artifact-probe",
                               ev_download="NA_ACTION",
                               ev_verify_fail="NA_VERIFY",
                               max_bytes=install.LIMITS["engine_max_bytes"])
    except install.InstallError as e:
        return {"status": "fail", "error": "artifact download: %s" % e.reason}
    guarded_rmtree(ctx.sandbox, scratch)
    os.makedirs(scratch, exist_ok=True)
    try:
        install.extract_engine_tgz(part, scratch,
                                   int(inst.get("strip_components") or 0))
    except install.InstallError as e:
        guarded_rmtree(ctx.sandbox, scratch)
        try:
            os.remove(part)
        except OSError:
            pass
        return {"status": "fail", "error": "artifact extract: %s" % e.reason}
    try:
        os.remove(part)
    except OSError:
        pass
    try:
        binary = install._locate_engine_binary(
            scratch, inst.get("binary_inside"),
            install.APPSPEC_ENGINE_BINARIES.get(ctx.spec["engine"]["name"],
                                                {}).get("executables", ()))
    except install.InstallError as e:
        # layout miss (binary_inside not in the archive / no or ambiguous
        # whitelisted executable): a per-round recorded FAIL like any other —
        # never a crash that skips the round's bookkeeping; classifies as
        # artifact_layout → the rule table flips to the source build
        audit.emit("NA_VERIFY", what="prebuilt-artifact_locate", status="fail",
                   error=e.reason)
        guarded_rmtree(ctx.sandbox, scratch)
        return {"status": "fail", "error": e.reason}
    sc = engine_selfcheck(audit, binary, "prebuilt-artifact")
    guarded_rmtree(ctx.sandbox, scratch)
    return sc


def act_backoff(audit: install.Audit, ctx, seconds: float) -> dict:
    audit.emit("NA_ACTION", action="backoff", seconds=seconds, phase="start",
               note="bounded exponential backoff before retrying apply")
    time.sleep(seconds)
    audit.emit("NA_ACTION", action="backoff", seconds=seconds, phase="done",
               status="ok")
    return {"status": "ok", "slept_s": seconds}


def act_apply(audit: install.Audit, ctx) -> dict:
    """The controlled mutating tool, verbatim: install.cmd_apply (its own
    audit trail lives at <sandbox>/audit.jsonl). Idempotent — a rerun after
    backoff skips the engine (provenance) and resumes the model."""
    apply_path = ctx.apply_appspec
    if not os.path.isfile(apply_path):
        return {"status": "fail", "error": "apply spec missing (fs_missing): "
                                           + apply_path}
    ns = argparse.Namespace(appspec=apply_path, sandbox_root=ctx.sandbox,
                            audit_path=None,
                            health_timeout=float(ctx.args.health_timeout))
    audit.emit("NA_ACTION", action="apply", appspec=apply_path, phase="start",
               note="install.py apply: absent → ready (its own audited flow)")
    since = time.time()
    rc = install.cmd_apply(ns)
    error = install_audit_error(ctx.sandbox, since) if rc != 0 else ""
    audit.emit("NA_ACTION", action="apply", phase="done", rc=rc,
               status="ok" if rc == 0 else "fail", error=error or None)
    if rc != 0:
        return {"status": "fail", "error": error or "apply exit %d" % rc,
                "rc": rc}
    marker = install.read_marker(
        install.sandbox_paths(ctx.sandbox, ctx.spec["name"]))
    if (marker or {}).get("state") != "ready":
        return {"status": "fail", "error": "apply rc=0 but marker state=%r"
                % (marker or {}).get("state")}
    return {"status": "ok", "marker": marker}


# --------------------------------------------------------------------------- #
# bootstrap (自适应) — the bounded sense→plan→act→verify loop
# --------------------------------------------------------------------------- #

class Ctx:
    """One bootstrap run's carried state (facts refreshed every round)."""

    def __init__(self, args, sandbox: str, paths: dict, spec: dict, hints: dict):
        self.args = args
        self.sandbox = sandbox
        self.paths = paths
        self.spec = spec
        self.hints = hints
        self.facts: dict = {}
        self.history: list[dict] = []
        # the appspec install.py consumes: the caller's file until a local
        # build produces the artifact-backed one (act_package swaps it in)
        self.apply_appspec: str = args.appspec


def cmd_bootstrap(args) -> int:
    sandbox = os.path.abspath(args.sandbox)
    paths = na_paths(sandbox)
    os.makedirs(paths["na"], exist_ok=True)
    audit = install.Audit(paths["audit"])
    if not audit.usable:
        note("refusing to bootstrap: nodeagent audit unavailable (fail-closed)")
        audit.close()
        return 2

    try:
        with open(args.appspec, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        note("appspec unreadable: %s" % e)
        audit.emit("NA_ESCALATE", step="read", error=str(e)[:200])
        audit.close()
        return 2
    core, hints = strip_hints(raw)
    spec, err = install.validate_appspec(core)
    if err:
        note("appspec schema violation: %s" % err)
        audit.emit("NA_ESCALATE", step="schema", error=err)
        audit.close()
        return 2

    strategy = args.strategy
    if strategy == "auto":
        strategy = "artifact" if spec["engine"].get("install") else "source"
    # fast path: the engine is already on disk and satisfies every pin —
    # resolve_engine enforces engine.binary/sha256/ref exactly like apply will.
    if strategy == "source":
        info, _err = install.resolve_engine(spec)
        if info is not None:
            strategy = "present"

    # instance lock (install.cmd_apply style): two concurrent bootstraps would
    # race the same sandbox tree (guarded removals vs a running build) — the
    # loser escalates with step="lock" and never touches the sandbox.
    try:
        lock_fd = acquire_bootstrap_lock(paths["na"])
    except OSError as e:
        audit.emit("NA_ESCALATE", step="lock",
                   error="bootstrap lock unusable at %s: %s"
                         % (paths["lock"], str(e)[:160]))
        audit.close()
        return 3
    if lock_fd is None:
        audit.emit("NA_ESCALATE", step="lock", app=spec["name"],
                   error="another bootstrap instance holds %s — refusing to "
                         "race sandbox mutations" % paths["lock"])
        audit.close()
        note("refusing to bootstrap: another instance holds %s (exit 3)"
             % paths["lock"])
        return 3

    t0 = time.monotonic()
    ctx = Ctx(args, sandbox, paths, spec, hints)
    flags = fresh_flags(strategy)
    state = read_state(paths["state"])
    state["bootstrap"] = {"app": spec["name"], "status": "running",
                          "strategy": strategy,
                          "started_at": probe.now_utc()}
    state.setdefault("diagnose_history", [])
    write_state(paths["state"], state)
    audit.emit("NA_BOOTSTRAP", phase="start", app=spec["name"],
               strategy=strategy, sandbox=sandbox,
               appspec_sha256_16=install.sha256_16(args.appspec)
               if os.path.isfile(args.appspec) else None)

    last_error = None
    escalated = None
    rounds = 0
    try:
        for round_no in range(1, LIMITS["max_rounds"] + 1):
            rounds = round_no
            # ---- sense ---- #
            ctx.facts = collect_facts(port=spec["service"]["port"])
            audit.emit("NA_SENSE", round=round_no,
                       toolchain={k: v["present"]
                                  for k, v in ctx.facts["toolchain"].items()},
                       pkg_mgr=ctx.facts["pkg_mgr"]["name"],
                       egress=ctx.facts["egress"],
                       port_free=ctx.facts["port_free"],
                       glibc=ctx.facts["glibc"], cores=ctx.facts["cores"])
            state["last_sense"] = ctx.facts

            # ---- plan ---- #
            if strategy == "present":          # engine already resolvable
                flags["binary_ok"] = True
                flags["artifact_packaged"] = True   # nothing to build/package
            plan = plan_round(flags["strategy"], ctx.facts, flags, last_error)
            observed = {"error_class": plan["error_class"],
                        "error": (last_error or "")[:probe.EXCERPT] or None,
                        "facts_digest": {
                            "toolchain_missing": toolchain_missing(ctx.facts),
                            "pkg_mgr": pkg_mgr_name(ctx.facts),
                            "egress": ctx.facts["egress"],
                            "port_free": ctx.facts["port_free"]}}

            # ---- act ---- #
            action, outcome = plan["action"], {"status": "skip"}
            if action == "probe_artifact":
                flags["probe_attempts"] += 1
                outcome = act_probe_artifact(audit, ctx)
                flags["artifact_probed"] = True
                flags["artifact_ok"] = outcome["status"] == "ok"
            elif action == "switch_strategy":
                flags["strategy"] = strategy = "source"
                outcome = {"status": "ok", "strategy": "source"}
            elif action == "install_toolchain":
                outcome = act_pkg_install(audit, ctx.facts,
                                          LIMITS["toolchain_packages"])
            elif action == "install_runtime_lib":
                outcome = act_pkg_install(audit, ctx.facts,
                                          LIMITS["runtime_packages"])
                flags["runtime_lib_ok"] = outcome["status"] == "ok"
            elif action == "acquire_source":
                outcome = act_acquire_source(audit, ctx)
                flags["source_extracted"] = outcome["status"] == "ok"
            elif action == "build":
                outcome = act_build(audit, ctx)
                flags["build_ok"] = outcome["status"] == "ok"
                flags["binary_ok"] = outcome["status"] == "ok"
            elif action == "package":
                outcome = act_package(audit, ctx)
                flags["artifact_packaged"] = outcome["status"] == "ok"
                flags["apply_spec_written"] = outcome["status"] == "ok"
            elif action == "backoff":
                flags["backoffs_used"] += 1
                outcome = act_backoff(audit, ctx,
                                      next_backoff(flags["backoffs_used"]))
            elif action == "apply":
                flags["apply_attempts"] += 1
                outcome = act_apply(audit, ctx)
                flags["apply_done"] = outcome["status"] == "ok"
                flags["ready"] = outcome["status"] == "ok"
            elif action == "escalate":
                outcome = {"status": "fail", "error": last_error or "rules "
                                                                  "exhausted"}
            else:                            # defensive: unknown action row
                outcome = {"status": "fail", "error": "unknown action %s"
                           % action}

            # ---- verify / record ---- #
            audit.emit("NA_DIAGNOSE", round=round_no, observed=observed,
                       diagnosis=plan["diagnosis"], rule=plan["id"],
                       action=action, outcome=outcome)
            audit.emit("NA_VERIFY", round=round_no, rule=plan["id"],
                       status=outcome["status"], error=outcome.get("error"),
                       elapsed_s=outcome.get("elapsed_s"))
            entry = {"round": round_no, "ts": probe.now_utc(),
                     "observed": observed, "rule": plan["id"],
                     "diagnosis": plan["diagnosis"], "action": action,
                     "outcome": outcome}
            ctx.history.append(entry)
            state["diagnose_history"] = \
                (state.get("diagnose_history") or [])[-64:] + [entry]
            state["bootstrap"].update({"rounds": rounds,
                                       "last_rule": plan["id"]})
            write_state(paths["state"], state)
            note("round %d: rule=%s action=%s → %s%s"
                 % (round_no, plan["id"], action, outcome["status"],
                    (" (%s)" % outcome["error"][:120])
                    if outcome.get("error") else ""))

            if action == "escalate":
                escalated = escalation_report(
                    spec["name"], last_error or outcome.get("error", ""),
                    ctx.history, rounds)
                break
            last_error = outcome.get("error")
            # the same rule failing with the same error twice in a row is a
            # deterministic dead end — escalate NOW instead of burning the
            # remaining round budget on it
            if no_progress(ctx.history):
                escalated = escalation_report(
                    spec["name"], last_error or "no progress across rounds",
                    ctx.history, rounds)
                escalated["escalation_reason"] = \
                    "no_progress: rule %s produced the identical failure " \
                    "twice in a row" % plan["id"]
                note("round %d: no progress (rule %s, identical failure twice) "
                     "— escalating early" % (round_no, plan["id"]))
                break
            if flags["ready"]:
                break
        else:
            escalated = escalation_report(spec["name"],
                                          last_error or "round budget exhausted",
                                          ctx.history, rounds)
    except Exception as e:  # noqa: BLE001 — the agent escalates, never dies quiet
        escalated = escalation_report(
            spec["name"], "internal: %s: %s" % (type(e).__name__, str(e)[:200]),
            ctx.history, rounds)
    finally:
        release_bootstrap_lock(lock_fd)
        elapsed = round(time.monotonic() - t0, 1)
        if escalated is not None:
            audit.emit("NA_ESCALATE", app=spec["name"], rounds=rounds,
                       report=escalated)
            state["bootstrap"] = {"app": spec["name"], "status": "escalated",
                                  "strategy": flags["strategy"],
                                  "rounds": rounds, "elapsed_s": elapsed,
                                  "escalation": escalated,
                                  "finished_at": probe.now_utc()}
            write_state(paths["state"], state)
            audit.close()
            print(json.dumps(escalated, ensure_ascii=False, indent=2))
            note("ESCALATED after %d rounds (%.1fs) — see DIAGNOSIS_REPORT"
                 % (rounds, elapsed))
            return 3

        # ---- READY: the 自检 half, in-process. A crashed or failing
        # selfcheck is a fact, never a green light: a result without a checks
        # list IS a failure (selfcheck_failures), any FAIL row gates the run
        # down to ready_degraded + exit 4 with an honest audit. ---- #
        selfcheck: dict = {}
        sc_error = None
        try:
            selfcheck = run_selfcheck(
                base="http://127.0.0.1:%d" % spec["service"]["port"],
                agent=args.selfcheck_agent, admin_token=args.selfcheck_admin_token,
                data_scope=args.selfcheck_agent_data_scope,
                completion_timeout=LIMITS["completion_timeout_s"],
                agent_plane=args.selfcheck_agent_plane)
        except Exception as e:  # noqa: BLE001 — the crash itself is the FAIL
            sc_error = "%s: %s" % (type(e).__name__, str(e)[:200])
            selfcheck = {"checks": [], "summary": "selfcheck crashed: %s"
                         % sc_error}
        failed = selfcheck_failures(selfcheck)
        ready = not failed
        sc_suggestion = None
        if not ready:
            if sc_error:
                sc_suggestion = (
                    "selfcheck 内部异常，未得到完整结论（按 FAIL 处理）：%s；"
                    "单独重跑 selfcheck 子命令定位——base 不通查 install.py status "
                    "与 service.log；反复异常查 python 环境与 <sandbox>/nodeagent/%s"
                    % (sc_error, AUDIT_NAME))
            else:
                sc_suggestion = "; ".join(
                    c.get("suggestion") or check_failed_suggestion(
                        c.get("check") or "selfcheck", c.get("detail") or {})
                    for c in failed)[:probe.EXCERPT]
        audit.emit("NA_VERIFY", what="selfcheck", app=spec["name"],
                   status="ok" if ready else "fail",
                   failed=[c.get("check") or "selfcheck" for c in failed]
                   or None,
                   error=sc_error, suggestion=sc_suggestion,
                   summary=selfcheck.get("summary"))
        boot_status = "ready" if ready else "ready_degraded"
        state["bootstrap"] = {"app": spec["name"], "status": boot_status,
                              "strategy": flags["strategy"], "rounds": rounds,
                              "elapsed_s": elapsed, "apply_attempts":
                                  flags["apply_attempts"],
                              "backoffs": flags["backoffs_used"],
                              "selfcheck_summary": selfcheck.get("summary"),
                              "selfcheck_failed":
                                  [c.get("check") for c in failed] or None,
                              "finished_at": probe.now_utc()}
        write_state(paths["state"], state)
        audit.emit("NA_BOOTSTRAP", phase="done", app=spec["name"],
                   status=boot_status, rounds=rounds, elapsed_s=elapsed)
        audit.close()
        print(json.dumps({"bootstrap": {"app": spec["name"],
                                        "status": boot_status,
                                        "strategy": flags["strategy"],
                                        "rounds": rounds, "elapsed_s": elapsed},
                          "selfcheck": selfcheck},
                         ensure_ascii=False, indent=2))
        return 0 if ready else 4


# --------------------------------------------------------------------------- #
# selfcheck (自检) — base plane + optional control plane, per-item PASS/FAIL
# --------------------------------------------------------------------------- #

def derive_agent_plane(control_url: str) -> str:
    """server.py layout: control plane :18000, agent (invoke) plane :18001 —
    the invoke plane is control port + 1 on the same host (pure)."""
    u = urllib.parse.urlsplit(control_url if "//" in control_url
                              else "//" + control_url, scheme="http")
    port = u.port or 18000
    netloc = "%s:%d" % (u.hostname or "127.0.0.1", port + 1)
    if u.username:
        netloc = "%s:%s@%s" % (u.username, u.password or "", netloc)
    return urllib.parse.urlunsplit((u.scheme, netloc, "", "", ""))


def run_selfcheck(base: str, agent: str | None, admin_token: str | None,
                  data_scope: str | None,
                  completion_timeout: float,
                  agent_plane: str | None = None) -> dict:
    """The check battery. Returns {"checks": [...], "summary": "..."}; every
    FAIL carries a `suggestion` (check_failed_suggestion)."""
    checks: list[dict] = []
    base = (base or "").rstrip("/")

    def add(check, status, detail=None, suggestion=None):
        checks.append({"check": check, "status": status, "detail": detail,
                       "suggestion": suggestion if status == "FAIL" else None})

    def finish() -> dict:
        """Fill every FAIL's diagnosis suggestion, then build the summary —
        the ONE exit shape, so the documented contract (every FAIL carries a
        suggestion) holds on the agentless path too."""
        for c in checks:
            if c["status"] == "FAIL" and not c.get("suggestion"):
                c["suggestion"] = check_failed_suggestion(c["check"],
                                                          c["detail"] or {})
        return {"checks": checks,
                "summary": "%d checks: %d PASS, %d FAIL, %d SKIP"
                           % (len(checks),
                              sum(1 for c in checks if c["status"] == "PASS"),
                              sum(1 for c in checks if c["status"] == "FAIL"),
                              sum(1 for c in checks if c["status"] == "SKIP"))}

    # 1. base /health
    r = http_json(base + "/health")
    ok = r.get("status") == 200
    add("base_health", "PASS" if ok else "FAIL",
        {"url": redact_url(base + "/health"), "http_status": r.get("status"),
         "body": r.get("json") or r.get("body")})
    # 2. base /v1/models
    r = http_json(base + "/v1/models")
    model_ids = [m.get("id") for m in ((r.get("json") or {}).get("data") or [])
                 if isinstance(m, dict) and m.get("id")]
    ok = r.get("status") == 200 and bool(model_ids)
    add("base_models", "PASS" if ok else "FAIL",
        {"http_status": r.get("status"), "models": model_ids[:8]})
    # 3. base /completion — one REAL inference
    body = json.dumps({"prompt": "The capital of France is",
                       "n_predict": 16, "temperature": 0}).encode("utf-8")
    r = http_json(base + "/completion", method="POST", body=body,
                  headers={"Content-Type": "application/json",
                           "Content-Length": str(len(body))},
                  timeout=completion_timeout)
    j = r.get("json") or {}
    tps = ((j.get("timings") or {}).get("predicted_per_second"))
    ok = r.get("status") == 200 and bool((j.get("content") or "").strip())
    add("base_completion", "PASS" if ok else "FAIL",
        {"http_status": r.get("status"),
         "content_excerpt": (j.get("content") or "")[:120],
         "predicted_per_second": tps,
         "error": r.get("error") or j.get("error")})

    # ---- control plane (optional) ---- #
    if not agent:
        add("agent_healthz", "SKIP", {"reason": "no --agent given"})
        add("agent_audit", "SKIP", {"reason": "no --agent given"})
        add("agent_nonce_replay", "SKIP", {"reason": "no --agent given"})
        add("agent_budget", "SKIP", {"reason": "no --agent given"})
        return finish()

    agent = agent.rstrip("/")
    auth = {"X-Admin-Token": admin_token} if admin_token else {}
    # --agent is the CONTROL plane (/healthz /audit /issue); /agent/invoke
    # lives on the invoke plane (server.py: control port + 1)
    invoke = (agent_plane or derive_agent_plane(agent)).rstrip("/")

    # 4. /healthz (no auth by design)
    r = http_json(agent + "/healthz")
    j = r.get("json") or {}
    ok = r.get("status") == 200 and j.get("status") == "ok" and j.get("build_sha")
    add("agent_healthz", "PASS" if ok else "FAIL",
        {"http_status": r.get("status"), "build_sha": j.get("build_sha"),
         "pol_ver": j.get("pol_ver")})

    # 5. audit appendable: count → /issue → count again
    r1 = http_json(agent + "/audit?limit=512", headers=auth)
    n1 = len(r1.get("json") or []) if isinstance(r1.get("json"), list) else None
    scope = (data_scope or "/tmp/bicameral/data").rstrip("/")
    issue_body = json.dumps({"agent": "agent-rw",
                             "task_id": "selfcheck-%d" % int(time.time()),
                             "tools": ["fs.read", "fs.write"],
                             "ttl_s": 600,
                             "budget": {"calls": 2}}).encode("utf-8")
    r = http_json(agent + "/issue", method="POST", body=issue_body,
                  headers=dict(auth, **{"Content-Type": "application/json",
                                        "Content-Length": str(len(issue_body))}))
    tok = (r.get("json") or {}).get("token")
    r2 = http_json(agent + "/audit?limit=512", headers=auth)
    n2 = len(r2.get("json") or []) if isinstance(r2.get("json"), list) else None
    ok = r1.get("status") == 200 and r.get("status") == 200 \
        and r2.get("status") == 200 and None not in (n1, n2) and n2 > n1
    add("agent_audit", "PASS" if ok else "FAIL",
        {"audit_before": n1, "issue_status": r.get("status"),
         "audit_after": n2})

    # 6. nonce ledger alive: two DIFFERENT-strict calls then a REPLAY → D3
    if tok and n2:
        stamp = "%d" % int(time.time())
        probe_path = scope + "/selfcheck-%s.txt" % stamp
        h1, b1 = build_agent_envelope(
            tok, "sc-write-" + stamp, "fs.write",
            {"path": probe_path, "content": "bicameral selfcheck %s" % stamp,
             "idem_key": "selfcheck-" + stamp})
        h2, b2 = build_agent_envelope(tok, "sc-read-" + stamp, "fs.read",
                                      {"path": probe_path})
        w = http_json(invoke + "/agent/invoke", method="POST", body=b1,
                      headers=h1, timeout=LIMITS["http_timeout_s"])
        d = http_json(invoke + "/agent/invoke", method="POST", body=b2,
                      headers=dict(h2), timeout=LIMITS["http_timeout_s"])
        # replay: EXACTLY the same bytes (same nonce) — the second must be D3
        rp = http_json(invoke + "/agent/invoke", method="POST", body=b2,
                       headers=dict(h2), timeout=LIMITS["http_timeout_s"])
        rpj = rp.get("json") or {}
        replay_is_d3 = rp.get("status") == 401 \
            and "D3" in str(rpj.get("reason_code", ""))
        ok = (w.get("status") == 200 and d.get("status") == 200
              and replay_is_d3)
        add("agent_nonce_replay", "PASS" if ok else "FAIL",
            {"invoke_plane": redact_url(invoke),
             "write": w.get("status"), "read": d.get("status"),
             "replay_status": rp.get("status"),
             "replay_reason": rpj.get("reason_code"),
             "note": None if replay_is_d3 else
             "second call with the same nonce was not D3/REPLAY_DETECTED"})
        if not ok and all(s == 404 for s in (w.get("status"), d.get("status"),
                                             rp.get("status"))):
            checks[-1]["suggestion"] = (
                "/agent/invoke 404：invoke 面未命中——--agent 是控制面"
                "（/healthz /audit /issue），invoke 面默认 control+1；确认 "
                "server.py 在 %s 监听 agent 面，或用 --agent-plane 显式指定"
                % redact_url(invoke))

        # 7. budget ledger alive: calls=2 are spent above (write+read); the
        # next fresh-nonce call must be D10 BUDGET_EXHAUSTED.
        h3, b3 = build_agent_envelope(tok, "sc-over-" + stamp, "fs.read",
                                      {"path": probe_path})
        be = http_json(invoke + "/agent/invoke", method="POST", body=b3,
                       headers=dict(h3), timeout=LIMITS["http_timeout_s"])
        bej = be.get("json") or {}
        ok = be.get("status") == 429 \
            and "D10" in str(bej.get("reason_code", ""))
        add("agent_budget", "PASS" if ok else "FAIL",
            {"status": be.get("status"), "reason": bej.get("reason_code"),
             "budget_spent": "fs.write + fs.read = 2/2 calls"})
    else:
        add("agent_nonce_replay", "FAIL", {"reason": "no token from /issue"})
        add("agent_budget", "FAIL", {"reason": "no token from /issue"})

    return finish()


def cmd_selfcheck(args) -> int:
    base = args.base or "http://127.0.0.1:%d" % args.port
    result = run_selfcheck(base, args.agent, args.admin_token,
                           args.agent_data_scope, LIMITS["completion_timeout_s"],
                           agent_plane=args.agent_plane)
    if args.sandbox:
        paths = na_paths(os.path.abspath(args.sandbox))
        audit = install.Audit(paths["audit"])
        failed = [c["check"] for c in result["checks"] if c["status"] == "FAIL"]
        audit.emit("NA_VERIFY", what="selfcheck", base=redact_url(base),
                   agent=redact_url(args.agent) if args.agent else None,
                   status="ok" if not failed else "fail",
                   failed=failed or None, summary=result["summary"])
        audit.close()
        state = read_state(paths["state"])
        state["last_selfcheck"] = result
        write_state(paths["state"], state)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not any(c["status"] == "FAIL"
                        for c in result["checks"]) else 4


# --------------------------------------------------------------------------- #
# status — the node state file
# --------------------------------------------------------------------------- #

def cmd_status(args) -> int:
    path = args.state or os.path.join(na_paths(os.path.abspath(args.sandbox))["na"],
                                      STATE_NAME)
    state = read_state(path)
    if not state:
        out = {"state_file": path, "exists": False,
               "note": "no nodeagent state yet — run sense/bootstrap"}
    else:
        hist = state.get("diagnose_history") or []
        out = {"state_file": path, "exists": True,
               "updated_at": state.get("updated_at"),
               "last_sense": state.get("last_sense"),
               "bootstrap": state.get("bootstrap"),
               "last_selfcheck": (state.get("last_selfcheck") or {})
               .get("summary"),
               "diagnose_history_tail": hist[-10:],
               "diagnose_history_total": len(hist)}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# selftest — pure functions only: no ssh, no network, no filesystem mutation
# --------------------------------------------------------------------------- #

def cmd_selftest(_args) -> int:
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    # ---- classify_error: error text → class ---- #
    cases = [
        ("HTTP Error 429: Too Many Requests", "rate_limited"),
        ("DOWNLOAD fail url=https://hf-mirror.com/x error 429", "rate_limited"),
        ("/bin/sh: 1: gcc: not found", "missing_toolchain"),
        ("cmake: command not found", "missing_toolchain"),
        ("The C compiler \"cc\" is not found… no", "missing_toolchain"),
        ("No CMAKE_C_COMPILER could be found", "missing_toolchain"),
        ("version `GLIBC_2.38' not found (required by llama-server)",
         "artifact_run_failed"),
        ("bash: ./llama-server: cannot execute binary file: Exec format error",
         "artifact_run_failed"),
        ("binary_inside 'bin/llama-server' not found in the extracted archive "
         "(looked at /sb/x/bin/llama-server)", "artifact_layout"),
        ("no whitelisted executable (llama-server, llama-cli) found in the "
         "extracted archive", "artifact_layout"),
        ("ambiguous engine binary in the extracted archive (2 hits: …)",
         "artifact_layout"),
        ("error while loading shared libraries: libgomp.so.1: wrong ELF class",
         "lib_missing"),
        ("libggml.so: cannot open shared object file: No such file or directory",
         "lib_missing"),
        ("built-engine ldd unresolved: libgomp.so.1", "lib_missing"),
        ("libgomp.so.1: not found", "lib_missing"),
        ("VERIFY_FAIL: sha256 mismatch (got abc…)", "hash_mismatch"),
        ("ENGINE_BINARY_NOT_FOUND: engine 'llama.cpp': binary 'llama-server' "
         "not found", "engine_not_found"),
        ("all mirrors exhausted (last: HTTP Error 429)", "rate_limited"),
        ("urlopen error [Errno 99] Cannot assign requested address",
         "network_unreachable"),
        ("socket.timeout: timed out", "network_unreachable"),
        ("engine ref 'b11062' not matched by … --version output",
         "ref_mismatch"),
        ("source archive missing at /x/y.tgz", "fs_missing"),
        ("no source channel: github down", "fs_missing"),
        (SOURCE_PIN_MISSING, "fs_missing"),
        ("some totally novel failure", "unknown"),
    ]
    for text, want in cases:
        got = classify_error(text)
        # "all mirrors exhausted (last: 429)" must stay rate_limited-shaped so
        # the backoff rule picks it up after install.py stops retrying
        check("classify.%s" % want, got == want, "got %r for %r" % (got, text[:60]))

    # ---- backoff computation ---- #
    check("backoff.first", next_backoff(1) == 20.0)
    check("backoff.double", next_backoff(2) == 40.0)
    check("backoff.cap", next_backoff(9) == LIMITS["backoff_cap_s"])
    check("backoff.floor", next_backoff(0) == 20.0)

    # ---- mirror ordering by sensed egress ---- #
    urls = ["https://huggingface.co", "https://hf-mirror.com"]
    check("mirrors.hf_down_sinks",
          order_mirrors(urls, {"hf": "down", "hf_mirror": "up"})
          == ["https://hf-mirror.com", "https://huggingface.co"])
    check("mirrors.both_up_keeps_order",
          order_mirrors(urls, {"hf": "up", "hf_mirror": "up"}) == urls)
    check("mirrors.unknown_stays",
          order_mirrors(urls, {}) == urls)
    check("mirrors.file_scheme_untouched",
          order_mirrors(["file:///x/a.tgz", "https://hf-mirror.com"],
                        {"hf_mirror": "down"})
          == ["file:///x/a.tgz", "https://hf-mirror.com"])
    check("host_of.basic", host_of("https://hf-mirror.com/a/b") == "hf-mirror.com")
    check("host_of.port", host_of("http://127.0.0.1:18099/x.tgz") == "127.0.0.1")

    # ---- URL redaction for audit/state: query/fragment AND userinfo dropped
    # ---- (the selfcheck must never persist a credential-bearing URL)
    check("redact.query_and_userinfo_dropped",
          redact_url("http://ctrl:sekret@127.0.0.1:18010/health?token=x#f")
          == "http://127.0.0.1:18010/health")
    check("redact.plain_url_untouched",
          redact_url("http://127.0.0.1:18010/health")
          == "http://127.0.0.1:18010/health")
    check("redact.file_scheme_untouched",
          redact_url("file:///sb/artifacts/x.tgz") == "file:///sb/artifacts/x.tgz")

    # ---- glibc / ldd parsing ---- #
    check("glibc.ubuntu",
          parse_glibc("ldd (Ubuntu GLIBC 2.35-0ubuntu3.8) 2.35") == "2.35")
    check("glibc.plain", parse_glibc("ldd (GNU libc) 2.36") == "2.36")
    check("glibc.none", parse_glibc("not a version line") is None)
    check("ldd.unresolved",
          parse_ldd_unresolved("libgomp.so.1: not found\n"
                               "\tlibggml.so => /x\n"
                               "libstdc++.so.6: not found")
          == ["libgomp.so.1", "libstdc++.so.6"])
    check("ldd.clean", parse_ldd_unresolved("linux-vdso.so.1 => (0x…)\n"
                                            "libc.so.6 => /lib/x") == [])

    # ---- toolchain facts ---- #
    facts_bare = {"toolchain": {"gcc": {"present": False},
                                "cmake": {"present": False},
                                "make": {"present": False}},
                  "pkg_mgr": {"name": "apt"}}
    check("toolchain.missing_all",
          toolchain_missing(facts_bare) == ["gcc", "cmake", "make"])
    check("toolchain.pkg_mgr", pkg_mgr_name(facts_bare) == "apt")
    facts_none = {"toolchain": {"gcc": {"present": False}},
                  "pkg_mgr": {"name": "none"}}
    check("toolchain.no_pkg_mgr", pkg_mgr_name(facts_none) == "none")

    # ---- plan_round: the rule table under failure injection ---- #
    def plan(strategy, facts, flags, err=None):
        return plan_round(strategy, facts, flags, err)

    flags = fresh_flags("source")
    p = plan("source", facts_bare, flags, None)
    check("plan.missing_toolchain", p["id"] == "install_toolchain", p["id"])
    p = plan("source", facts_none, flags, None)
    check("plan.no_pkg_mgr_escalates", p["id"] == "escalate_no_pkg_mgr", p["id"])
    f2 = {"toolchain": {t: {"present": True}
                        for t in LIMITS["toolchain_need"]},
          "pkg_mgr": {"name": "apt"}}
    flags = fresh_flags("source")
    p = plan("source", f2, flags, None)
    check("plan.acquire_source", p["id"] == "acquire_source", p["id"])
    flags["source_extracted"] = True
    p = plan("source", f2, flags, None)
    check("plan.build", p["id"] == "build_engine", p["id"])
    flags["build_ok"] = True
    p = plan("source", f2, flags, "built-engine ldd unresolved: libgomp.so.1 "
                                  "(lib_missing)")
    check("plan.lib_missing", p["id"] == "install_runtime_lib", p["id"])
    flags["runtime_lib_ok"] = True
    p = plan("source", f2, flags, "libgomp.so.1: not found")
    check("plan.rebuild_after_lib", p["id"] == "build_engine", p["id"])
    flags["binary_ok"] = True
    p = plan("source", f2, flags, None)
    check("plan.package", p["id"] == "package_artifact", p["id"])
    flags["artifact_packaged"] = True
    p = plan("source", f2, flags, None)
    check("plan.apply", p["id"] == "apply_install", p["id"])
    p = plan("source", f2, flags, "INSTALL_FAIL step=download error HTTP Error "
                                  "429: Too Many Requests")
    check("plan.rate_limited_backoff", p["id"] == "backoff_retry", p["id"])
    flags["backoffs_used"] = LIMITS["backoff_max"]
    p = plan("source", f2, flags, "HTTP Error 429: Too Many Requests")
    check("plan.backoff_bounded_then_apply", p["id"] == "apply_install", p["id"])
    p = plan("source", f2, flags, "urlopen error [Errno 99] Cannot assign "
                                  "requested address")
    check("plan.backoff_bounded_egress", p["id"] == "apply_install", p["id"])
    flags["backoffs_used"] = 0
    p = plan("source", f2, flags, "urlopen error [Errno 99] Cannot assign "
                                  "requested address")
    check("plan.egress_backoff_first", p["id"] == "backoff_retry", p["id"])
    p = plan("source", f2, flags, "VERIFY_FAIL: sha256 mismatch on every "
                                  "mirror/attempt")
    check("plan.hash_mismatch_not_backoff", p["id"] == "escalate", p["id"])
    p = plan("source", f2, flags, "source archive missing at /x/src.tgz")
    check("plan.fs_missing_escalates", p["id"] == "escalate", p["id"])
    flags["backoffs_used"] = LIMITS["backoff_max"]
    flags["apply_done"] = True
    p = plan("source", f2, flags, "HTTP Error 429: Too Many Requests")
    check("plan.exhausted_escalates", p["id"] == "escalate", p["id"])
    p = plan("source", f2, flags, "VERIFY_FAIL: sha256 mismatch")
    check("plan.hash_mismatch_not_backoff", p["id"] == "escalate", p["id"])
    # strategy 1 → 2 flip on a GLIBC failure
    fa = fresh_flags("artifact")
    p = plan("artifact", f2, fa, None)
    check("plan.artifact_probe_first", p["id"] == "probe_artifact", p["id"])
    fa["artifact_probed"] = True
    p = plan("artifact", f2, fa,
             "prebuilt-artifact --version selfcheck failed rc=1: version "
             "`GLIBC_2.38' not found")
    check("plan.artifact_unportable_switch", p["id"] == "switch_to_source",
          p["id"])
    # a layout miss (binary_inside not in the archive) must ALSO flip to the
    # source build — and never crash the probe round past its bookkeeping
    p = plan("artifact", f2, fa,
             "binary_inside 'bin/llama-server' not found in the extracted "
             "archive")
    check("plan.artifact_layout_switch", p["id"] == "switch_to_source", p["id"])
    fa["strategy"] = "source"
    p = plan("source", f2, fa, "version `GLIBC_2.38' not found")
    check("plan.source_ignores_artifact_error", p["id"] == "acquire_source",
          p["id"])
    # rule table integrity: ids unique, every class has an escalation row
    ids = [r["id"] for r in RULES]
    check("rules.unique_ids", len(ids) == len(set(ids)))
    check("rules.actions_known",
          all(r["action"] in ("probe_artifact", "switch_strategy", "escalate",
                              "install_toolchain", "acquire_source",
                              "install_runtime_lib", "build", "package",
                              "backoff", "apply") for r in RULES))
    # rule-table ↔ dispatcher integrity: a bare substring pin is weak (any
    # comment or literal satisfies it), so assert per rule that cmd_bootstrap
    # contains an actual `action == "<action>"` comparison LINE
    dispatch_src = inspect.getsource(cmd_bootstrap)
    check("rules.dispatch_covered",
          all(any(('action == "%s"' % r["action"]) in line
                  for line in dispatch_src.splitlines()) for r in RULES))
    # reverse pins: every RULES id must be reachable from the planner (a rule
    # no plan_round path can pick is dead data), and the diagnosis table must
    # mirror the classify_error output enumeration exactly — no stale
    # hypothesis, no class without a hypothesis
    plan_src = inspect.getsource(plan_round)
    check("rules.ids_picked_by_planner",
          all(('pick("%s")' % r["id"]) in plan_src for r in RULES))
    check("rules.hypotheses_mirror_classes",
          set(HYPOTHESES) == set(ERROR_CLASSES))

    # ---- no-progress detection: one deterministic failure must not be able
    # ---- to burn the whole round budget through repeated identical routing
    def _ent(rule, err, status="fail"):
        return {"rule": rule, "outcome": {"status": status, "error": err}}
    check("no_progress.identical_double_fires",
          no_progress([_ent("acquire_source", "boom"),
                       _ent("acquire_source", "boom")]))
    check("no_progress.different_error_stays",
          not no_progress([_ent("acquire_source", "boom"),
                           _ent("acquire_source", "different")]))
    check("no_progress.different_rule_stays",
          not no_progress([_ent("acquire_source", "boom"),
                           _ent("build_engine", "boom")]))
    check("no_progress.success_between_stays",
          not no_progress([_ent("apply_install", "e1", "fail"),
                           _ent("backoff_retry", None, "ok"),
                           _ent("apply_install", "e1", "fail")]))
    check("no_progress.short_history_stays",
          not no_progress([_ent("acquire_source", "boom")]))
    check("no_progress.ok_outcome_stays",
          not no_progress([_ent("apply_install", None, "ok"),
                           _ent("apply_install", None, "ok")]))
    # end-to-end shape: hints tgz without the mandatory sha pin fails
    # acquire_source, the identical retry is detected, the loop escalates
    flags_np = fresh_flags("source")
    p = plan("source", f2, flags_np, SOURCE_PIN_MISSING)
    check("no_progress.pin_fail_first_acquire", p["id"] == "acquire_source",
          p["id"])
    check("no_progress.pin_fail_second_escalates",
          no_progress([_ent("acquire_source", SOURCE_PIN_MISSING),
                       _ent("acquire_source", SOURCE_PIN_MISSING)]))

    # ---- escalation report ---- #
    rep = escalation_report("qwen3-0.6b-q8_0", "HTTP Error 429: Too Many Requests",
                            [{"round": 1, "rule": "apply_install",
                              "action": "apply",
                              "outcome": {"status": "fail"}}], 3)
    check("escalate.shape",
          rep["report"] == "DIAGNOSIS_REPORT" and rep["error_class"] == "rate_limited"
          and rep["root_cause_hypothesis"] and rep["human_actions"]
          and rep["actions_tried"][0]["rule"] == "apply_install")
    check("escalate.every_class_has_hypothesis",
          all(cls in HYPOTHESES and HYPOTHESES[cls][0] and HYPOTHESES[cls][1]
              for cls in ERROR_CLASSES))

    # ---- apply-spec assembly + hint stripping ---- #
    spec = {"schema": "appspec/1", "name": "qwen3-0.6b-q8_0",
            "engine": {"name": "llama.cpp"},
            "model": {"repo": "Qwen/Qwen3-0.6B-GGUF",
                      "file": "Qwen3-0.6B-Q8_0.gguf", "format": "gguf",
                      "sha256": "b" * 64,
                      "mirror_urls": ["https://huggingface.co",
                                      "https://hf-mirror.com"]},
            "service": {"port": 18010, "health": "/health", "args": []}}
    facts = {"egress": {"hf": "down", "hf_mirror": "up"}, "os_id": "ubuntu",
             "os_version": "22.04", "arch": "x86_64"}
    ap_spec = build_apply_spec(spec, "/sb/nodeagent/artifacts/"
                                     "llama-ubuntu22.04-x86_64.tgz", "a" * 64,
                               facts)
    inst = ap_spec["engine"]["install"]
    check("applyspec.install_shape",
          inst["mirror_urls"] == ["file:///sb/nodeagent/artifacts/"
                                  "llama-ubuntu22.04-x86_64.tgz"]
          and inst["sha256"] == "a" * 64 and inst["format"] == "tgz"
          and inst["strip_components"] == 0
          and inst["binary_inside"] == "bin/llama-server")
    check("applyspec.mirrors_reordered",
          ap_spec["model"]["mirror_urls"] == ["https://hf-mirror.com",
                                              "https://huggingface.co"])
    check("applyspec.core_untouched",
          ap_spec["name"] == spec["name"] and ap_spec["schema"] == "appspec/1"
          and ap_spec["service"]["port"] == 18010)
    spec_pin = copy.deepcopy(spec)
    spec_pin["engine"]["binary"] = "/opt/llama/bin/llama-server"
    try:
        build_apply_spec(spec_pin, "/x.tgz", "a" * 64, facts)
        check("applyspec.refuses_binary_pin", False, "accepted binary pin")
    except ValueError:
        check("applyspec.refuses_binary_pin", True)
    try:
        build_apply_spec(ap_spec, "/x.tgz", "a" * 64, facts)
        check("applyspec.refuses_double_install", False, "accepted 2nd install")
    except ValueError:
        check("applyspec.refuses_double_install", True)

    raw = {"schema": "appspec/1", "name": "x", "nodeagent":
           {"strategy": "source", "engine_source": {"tgz": "/p.tgz"}}}
    core, hints = strip_hints(raw)
    check("hints.stripped", "nodeagent" not in core and core["name"] == "x")
    check("hints.kept", hints.get("engine_source", {}).get("tgz") == "/p.tgz")
    core2, hints2 = strip_hints({"schema": "appspec/1", "name": "y"})
    check("hints.absent_ok", hints2 == {} and "nodeagent" not in core2)

    # ---- source channel: the sha256 pin is MANDATORY (hints or CLI) — a tgz
    # ---- without it is a structured escalation, never an extracted unknown
    tgz, sha, perr = source_request(None, None,
                                    {"engine_source": {"tgz": "/p.tgz"}})
    check("source.hints_tgz_without_pin_refused",
          tgz == "/p.tgz" and sha is None and perr == SOURCE_PIN_MISSING)
    check("source.pin_error_classifies_fs_missing",
          classify_error(perr) == "fs_missing")
    tgz, sha, perr = source_request(
        None, None, {"engine_source": {"tgz": "/p.tgz", "sha256": "a" * 64}})
    check("source.hints_tgz_with_pin_ok",
          perr is None and sha == "a" * 64)
    tgz, sha, perr = source_request("/q.tgz", None, {})
    check("source.args_tgz_without_pin_refused",
          tgz == "/q.tgz" and perr == SOURCE_PIN_MISSING)
    tgz, sha, perr = source_request(None, None, {})
    check("source.no_tgz_no_channel", tgz is None and perr is None)

    check("artifact_filename.shape",
          artifact_filename(facts) == "llama-ubuntu22.04-x86_64.tgz")

    # validate_appspec (imported authority) accepts the assembled apply spec
    val, verr = install.validate_appspec(ap_spec)
    check("applyspec.passes_install_schema", val is not None and verr is None,
          verr or "")

    # ---- agent envelope: strict {nonce, tool, params} ---- #
    headers, body = build_agent_envelope("tok", "n-1", "fs.read",
                                         {"path": "/x"})
    j = json.loads(body.decode("utf-8"))
    check("envelope.keys", set(j.keys()) == {"nonce", "tool", "params"})
    check("envelope.values", j["nonce"] == "n-1" and j["tool"] == "fs.read"
          and j["params"] == {"path": "/x"})
    check("envelope.token_header",
          headers["X-Capability-Token"] == "tok"
          and headers["Content-Type"] == "application/json"
          and int(headers["Content-Length"]) == len(body))
    check("agent_plane.derived_default",
          derive_agent_plane("http://127.0.0.1:18000")
          == "http://127.0.0.1:18001")
    check("agent_plane.derived_remote",
          derive_agent_plane("http://10.0.0.9:19000")
          == "http://10.0.0.9:19001")

    # ---- selfcheck suggestions: every guarded check has a diagnosis ---- #
    for ck in ("base_health", "base_models", "base_completion", "agent_healthz",
               "agent_audit", "agent_nonce_replay", "agent_budget"):
        s = check_failed_suggestion(ck, {})
        check("suggestion.%s" % ck, bool(s) and s != "看 detail 字段定位，结合 "
                                                   "<sandbox>/audit.jsonl 排查")

    # ---- selfcheck gate: a result WITHOUT checks (the internal-crash shape)
    # ---- is ONE synthetic FAIL — READY can never be granted on a battery
    # ---- that crashed instead of running
    check("selfcheck_failures.crash_counts_as_fail",
          len(selfcheck_failures({"skipped": True, "reason": "internal "
                                                            "error"})) == 1)
    check("selfcheck_failures.missing_key_counts_as_fail",
          len(selfcheck_failures({})) == 1)
    check("selfcheck_failures.all_pass_is_clean",
          selfcheck_failures({"checks": [{"check": "base_health",
                                          "status": "PASS"},
                                         {"check": "base_models",
                                          "status": "SKIP"}]}) == [])
    failed_rows = selfcheck_failures(
        {"checks": [{"check": "base_health", "status": "PASS"},
                    {"check": "base_completion", "status": "FAIL"}]})
    check("selfcheck_failures.fail_row_caught",
          len(failed_rows) == 1 and failed_rows[0]["check"] == "base_completion")

    # ---- jsonl tail parse (install-audit observation) ---- #
    tail = parse_jsonl_tail(
        'garbage line\n{"ts":1,"event":"INSTALL_FAIL","error":"429"}\n'
        '{"ts":2,"event":"READY"}\n', k=10)
    check("jsonl_tail.skips_garbage", len(tail) == 2
          and tail[0]["event"] == "INSTALL_FAIL")

    # ---- bootstrap instance lock + guarded_rmtree root gate: the only
    # ---- selftest cases that touch the filesystem, in ONE sandboxed
    # ---- tempfile. The occupied-lock branch is what maps to the structured
    # ---- step="lock" escalation (exit 3).
    with tempfile.TemporaryDirectory(prefix="na-selftest-lock.") as lockdir:
        fd1 = acquire_bootstrap_lock(lockdir)
        check("lock.first_instance_acquires", fd1 is not None)
        check("lock.second_instance_blocked",
              acquire_bootstrap_lock(lockdir) is None)
        release_bootstrap_lock(fd1)
        fd3 = acquire_bootstrap_lock(lockdir)
        check("lock.reacquire_after_release", fd3 is not None)
        release_bootstrap_lock(fd3)
        # the sandbox root itself is never deletable — realpath equality is
        # refused even though install.path_inside would admit the exact path
        canary = os.path.join(lockdir, "canary.txt")
        with open(canary, "w", encoding="utf-8") as f:
            f.write("the root must survive")
        check("guarded_rmtree.root_refused",
              not guarded_rmtree(lockdir, lockdir)
              and os.path.isfile(canary))

    print("selftest: %d failure(s)" % len(failures))
    return 0 if not failures else 1


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="nodeagent.py",
        description="Bicameral nodeagent/1 — node self-autonomy (四自): sense, "
                    "zero-touch bootstrap, selfcheck, diagnose-and-escalate. "
                    "Stdlib-only; imports sibling probe.py/install.py.")
    ap.add_argument("--selftest", action="store_true",
                    help="pure-function self-test (no ssh, no network)")
    sub = ap.add_subparsers(dest="cmd")

    ap_s = sub.add_parser("sense", help="probe + distill decision facts (JSON)")
    ap_s.add_argument("--port", type=int, default=None,
                      help="also report whether this loopback port is free")
    ap_s.add_argument("--no-egress", action="store_true",
                      help="skip egress reachability checks")
    ap_s.add_argument("--sandbox", default=None,
                      help="record NA_SENSE + state under <sandbox>/nodeagent/")

    ap_b = sub.add_parser("bootstrap",
                          help="appspec → ready, zero-touch "
                               "(sense→plan→act→verify loop)")
    ap_b.add_argument("--appspec", required=True, help="appspec/1 JSON file "
                                                       "(optional nodeagent "
                                                       "hint node stripped)")
    ap_b.add_argument("--sandbox", default=DEFAULT_SANDBOX)
    ap_b.add_argument("--strategy", choices=("auto", "artifact", "source"),
                      default="auto",
                      help="auto: artifact when the appspec carries "
                           "engine.install, else source")
    ap_b.add_argument("--engine-source-tgz", default=None,
                      help="local engine source tarball (strategy 2 input)")
    ap_b.add_argument("--engine-source-sha256", default=None,
                      help="MANDATORY sha256 pin when --engine-source-tgz "
                           "(or nodeagent hints) supply the source tarball — "
                           "an unpinned source escalates, never extracts")
    ap_b.add_argument("--health-timeout", type=float,
                      default=install.LIMITS["health_timeout_s"])
    ap_b.add_argument("--selfcheck-agent", default=None,
                      help="control-plane base URL for the post-READY "
                           "selfcheck (e.g. http://127.0.0.1:18000)")
    ap_b.add_argument("--selfcheck-admin-token", default=None)
    ap_b.add_argument("--selfcheck-agent-plane", default=None,
                      help="invoke-plane base URL (default: --selfcheck-agent "
                           "host, control port + 1, per server.py layout)")
    ap_b.add_argument("--selfcheck-agent-data-scope", default=None,
                      help="server.py data scope for the fs.read/write probes")

    ap_c = sub.add_parser("selfcheck", help="per-item PASS/FAIL health battery")
    ap_c.add_argument("--base", default=None,
                      help="inference base URL (default "
                           "http://127.0.0.1:<--port>)")
    ap_c.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap_c.add_argument("--agent", default=None,
                      help="control-plane base URL carrying /healthz /audit "
                           "/issue (agent checks skipped when absent)")
    ap_c.add_argument("--agent-plane", default=None,
                      help="invoke-plane base URL for /agent/invoke "
                           "(default: --agent host, port + 1)")
    ap_c.add_argument("--admin-token", default=None)
    ap_c.add_argument("--agent-data-scope", default="/tmp/bicameral/data",
                      help="server.py data scope the fs.read/write probes "
                           "target (must be inside; D7 otherwise)")
    ap_c.add_argument("--sandbox", default=None,
                      help="record NA_VERIFY + state under "
                           "<sandbox>/nodeagent/")

    ap_st = sub.add_parser("status", help="read nodeagent-state.json")
    ap_st.add_argument("--sandbox", default=DEFAULT_SANDBOX)
    ap_st.add_argument("--state", default=None, help="explicit state file path")

    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if args.cmd == "sense":
        return cmd_sense(args)
    if args.cmd == "bootstrap":
        return cmd_bootstrap(args)
    if args.cmd == "selfcheck":
        return cmd_selfcheck(args)
    if args.cmd == "status":
        return cmd_status(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
