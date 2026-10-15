#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral probe/1 — device sensing & install-state inventory.

Implements docs/paradigm.md §3.1: one command produces one self-contained
DeviceReport (JSON, schema "probe/1") with four sections:

    hardware       CPU / memory / unified-memory flag; accelerator enumeration
                   in a FIXED order (paradigm §3.1 #1):
                     1. /dev node scan  (nvidia* | davinci* | iluvatar* | xpu*
                        | mthreads* | dri/*)
                     2. lspci vendor-ID table (10de NVIDIA, 1e3e Iluvatar 天数,
                        19e5 Ascend 昇腾, 1002 AMD/海光, 126f Moore Threads)
                     3. vendor management tools — PATH first, then install
                        roots /usr/local/{nvidia,corex,ascend,hygon,mthreads,
                        rocm}, each attempt injecting the vendor's
                        LD_LIBRARY_PATH (bi150 lesson: ixsmi does not run
                        without it).
    stack          OS / kernel / container markers; driver & runtime versions
                   (CUDA + cc value, ROCm, CANN, corex); Python/venv
                   availability; egress reachability (pypi / hf / hf-mirror /
                   github https + ssh-over-443) — each recorded up/down,
                   never fatal.
    installed      inference engines (llama-server / vllm / strata binary +
                   --version, with binary sha256-16 fingerprints); local model
                   file inventory (path/size/format/quantization by directory
                   convention); listening services: `ss -tln` cross-checked
                   with GET /health and GET /v1/models (how bi150's four
                   llama-server were found).
    install_state  one of absent/partial/ready/degraded per master-issued
                   appspec/1 (pass --appspec FILE); a standalone probe run
                   reports [] with a note — install_state is defined against
                   AppSpecs the master dispatched, not against thin air.

Engineering contract (docs/paradigm.md §2, same philosophy as server.py):
single file, Python 3.10+, standard library only, read-only with respect to
the machine (the only disk write is the -o report itself), no root required,
no egress requirement. A missing tool is recorded as status "absent" — an
absent tool is a fact, not an error; the probe exits 0 unless it cannot
produce a report at all.

Report header carries the device fingerprint: /etc/machine-id + the probe's
own sha256 (first 16 hex) — the server.py build_sha lesson against
deploy/version drift.

Usage:
    python3 probe.py                          # report to stdout
    python3 probe.py -o device.json           # report to file (+1-line stderr)
    python3 probe.py --appspec spec.json ...  # evaluate install_state
    python3 probe.py --no-egress              # skip egress reachability
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import glob
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import importlib.metadata
import importlib.util
import urllib.error
import urllib.request

SCHEMA = "probe/1"
EXCERPT = 600            # max chars of any captured tool output kept verbatim
LINE_CUT = 200           # max chars of any single captured line
CAPTURE_FULL_CAP = 256 * 1024  # raw-output cap in run_cmd capture_full mode
MAX_MODEL_ENTRIES = 400  # cap inventory entries kept in the report
MAX_WALK_DEPTH = 6
SUBPROC_TIMEOUT = 12     # seconds for --version / smi invocations
EGRESS_TIMEOUT = 5.0
LOCAL_HTTP_TIMEOUT = 2.0

# ---------------------------------------------------------------- constants

# lspci vendor IDs probed, in the fixed order of §3.1.
LSPCI_VENDORS = {
    "10de": ("NVIDIA", "NVIDIA"),
    "1e3e": ("Iluvatar", "Iluvatar / 天数智芯"),
    "19e5": ("Ascend", "Huawei Ascend / 昇腾"),
    "1002": ("AMD-Hygon", "AMD / Hygon 海光"),
    "126f": ("Moore-Threads", "Moore Threads / 摩尔线程"),
}

# /dev node classes, same fixed order. Canonical vendor keys as above.
DEV_NODE_CLASSES = [
    (["nvidia*"], "NVIDIA"),
    (["davinci*", "devmm_svm", "hisi_kernel"], "Ascend"),
    (["iluvatar*"], "Iluvatar"),
    (["xpu*"], "XPU"),
    (["mthreads*"], "Moore-Threads"),
]

# Vendor management tools: tried on PATH first, then under install roots.
# "roots" entries expand to /usr/local/<root> and /opt/<root>; when a tool is
# found there, <root>/{lib,lib64} are prepended to LD_LIBRARY_PATH.
VENDOR_TOOLS = [
    {"vendor": "NVIDIA", "tools": ["nvidia-smi"], "roots": ["nvidia"],
     "platform_tools": ["tegrastats", "jetson_clocks"]},  # Jetson quirks (§1)
    {"vendor": "Iluvatar", "tools": ["ixsmi"], "roots": ["corex"]},
    {"vendor": "Ascend", "tools": ["npu-smi"], "roots": ["ascend", "Ascend"]},
    {"vendor": "AMD-Hygon", "tools": ["rocm-smi", "hy-smi"], "roots": ["rocm", "hygon"]},
    {"vendor": "Moore-Threads", "tools": ["musa-smi", "mthreads-gmi"], "roots": ["mthreads"]},
]

# Engines probed in `installed` (paradigm §3.1 #3 names these three).
ENGINE_SPECS = [
    {"name": "llama-server"},
    {"name": "vllm", "pip_name": "vllm"},
    {"name": "strata"},
]

# appspec/1 engine.name → binary the capability layer actually looks for.
APPSPEC_ENGINE_BINARIES = {
    "llama.cpp": "llama-server",
    "llama-server": "llama-server",
    "vllm": "vllm",
    "strata": "strata",
}

QUANT_RE = re.compile(
    r"(IQ[0-9]{1,2}_[A-Z0-9]+|Q[0-9]{1,2}_[A-Z0-9_]+|Q[0-9]{1,2}"
    r"|FP[0-9]{2}|BF16|F16|F32|INT8|INT4|MXFP4)",
    re.IGNORECASE,
)

EGRESS_TARGETS = [
    ("pypi", "https://pypi.org/simple/", "http"),
    ("hf", "https://huggingface.co/api/models?limit=1", "http"),
    ("hf_mirror", "https://hf-mirror.com/api/models?limit=1", "http"),
    ("github", "https://github.com", "http"),
    ("github_ssh_443", "ssh.github.com:443", "tcp"),
]

# ------------------------------------------------------------ small helpers


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clip(text: str, limit: int = EXCERPT) -> str:
    text = (text or "").strip()
    return text[:limit]


def clip_lines(text: str, limit: int = EXCERPT) -> str:
    out = []
    used = 0
    for line in (text or "").splitlines():
        line = line[:LINE_CUT]
        if used + len(line) > limit:
            out.append("…")
            break
        out.append(line)
        used += len(line) + 1
    return "\n".join(out)


def read_text(path: str, limit: int = 4096) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def sha256_16(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def human_bytes(n: int | None) -> str | None:
    if n is None:
        return None
    x = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if x < 1024 or unit == "TiB":
            return f"{x:.1f}{unit}"
        x /= 1024
    return None  # unreachable


def run_cmd(argv: list[str], timeout: int = SUBPROC_TIMEOUT,
            ld_prepend: list[str] | None = None,
            capture_full: bool = False) -> dict:
    """Run a read-only command; never raise. status ∈ ok|nonzero|absent|timeout|error.

    Default mode keeps only the clipped excerpt ("output") — report evidence.
    capture_full=True additionally returns "full_output": raw stdout+stderr up
    to CAPTURE_FULL_CAP chars, for commands whose output must be *parsed*
    (ss -tln — the 600-char excerpt silently dropped listening ports).
    "truncated" flags a cap hit so the consuming section can say so.
    """
    env = dict(os.environ)
    if ld_prepend:
        base = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(ld_prepend + ([base] if base else []))
    try:
        # errors="replace": binary / non-UTF-8 tool output is a fact to record,
        # never a UnicodeDecodeError that kills the whole report.
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=env)
        merged = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        out: dict = {"status": "ok" if p.returncode == 0 else "nonzero",
                     "code": p.returncode, "output": clip_lines(merged)}
        if capture_full:
            out["full_output"] = merged[:CAPTURE_FULL_CAP]
            out["truncated"] = len(merged) > CAPTURE_FULL_CAP
        return out
    except FileNotFoundError:
        return {"status": "absent", "error": f"executable not found: {argv[0]}"}
    except PermissionError:
        return {"status": "error", "error": "permission denied"}
    except subprocess.TimeoutExpired as e:
        # keep partial output: streaming tools (tegrastats) are evidence, not errors
        partial = b"".join(x for x in (e.stdout, e.stderr) if x).decode("utf-8", "replace")
        res = {"status": "timeout", "error": f"timeout after {timeout}s (streaming tool?)",
               "output": clip_lines(partial)}
        if capture_full:
            res["full_output"] = partial[:CAPTURE_FULL_CAP]
            res["truncated"] = len(partial) > CAPTURE_FULL_CAP
        return res
    except OSError as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


def extra_bin_dirs() -> list[str]:
    """PATH first, then common install-root bin dirs (§3.1 tool-order rule)."""
    dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    home = os.path.expanduser("~")
    dirs += ["/usr/local/bin", "/usr/local/sbin", os.path.join(home, ".local/bin"),
             os.path.join(home, "bin"), "/snap/bin"]
    dirs += glob.glob("/opt/*/bin")
    seen, out = set(), []
    for d in dirs:
        if d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append(d)
    return out


def find_binary(name: str, dirs: list[str] | None = None) -> tuple[str | None, str | None]:
    for d in (dirs if dirs is not None else extra_bin_dirs()):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p, d
    return None, None


def first_meaningful_line(text: str) -> str | None:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:LINE_CUT]
    return None


# ----------------------------------------------------------------- hardware


def scan_dev_nodes() -> dict:
    """Stage 1 of §3.1: /dev node classes → canonical vendor keys."""
    groups: dict[str, list[str]] = {}
    for patterns, vendor in DEV_NODE_CLASSES:
        nodes: list[str] = []
        for pat in patterns:
            nodes.extend(sorted(glob.glob("/dev/" + pat)))
        if nodes:
            groups[vendor] = nodes
    dri = sorted(p for p in glob.glob("/dev/dri/*") if not os.path.isdir(p))
    if dri:
        groups.setdefault("DRM-generic", []).extend(dri)
    return {v: {"dev_nodes": nodes,
                "device_instances": sum(1 for n in nodes if n.rstrip("/").split("-")[-1][-1:].isdigit())}
            for v, nodes in groups.items()}


def scan_lspci() -> dict:
    """Stage 2 of §3.1: lspci filtered by the vendor-ID table."""
    r = run_cmd(["lspci", "-nn"])
    if r["status"] not in ("ok", "nonzero"):
        return {"tool": "lspci", "status": r["status"], "error": r.get("error")}
    hits = []
    for line in (r.get("output") or "").splitlines():
        m = re.search(r"\[([0-9a-f]{4}):([0-9a-f]{4})\]", line)
        if not m or m.group(1) not in LSPCI_VENDORS:
            continue
        key, display = LSPCI_VENDORS[m.group(1)]
        hits.append({"slot": (line.split()[0] if line.split() else None),
                     "vendor_key": key, "vendor": display,
                     "vendor_id": m.group(1), "device_id": m.group(2),
                     "line": clip(line, LINE_CUT)})
    return {"tool": "lspci", "status": "present", "vendor_table": {k: v[1] for k, v in LSPCI_VENDORS.items()},
            "matches": hits}


def probe_one_tool(tool: str, vendor: str, roots: list[str] | None,
                   inject_ld: bool = True, timeout: int = SUBPROC_TIMEOUT) -> dict:
    """Stage 3 of §3.1: PATH first, then /usr/local|opt/<root>/bin with
    LD_LIBRARY_PATH injection. Missing → status "absent" (a fact, not an error)."""
    path, source, libs, searched = None, None, [], ["PATH"]
    p, d = find_binary(tool)
    if p:
        path, source = p, "PATH"
    else:
        for root in roots or []:
            for tpl in ("/usr/local/{root}", "/opt/{root}"):
                for base in sorted(glob.glob(tpl.format(root=root))):
                    bindir = os.path.join(base, "bin")
                    searched.append(bindir)
                    cand = os.path.join(bindir, tool)
                    if os.path.isfile(cand) and os.access(cand, os.X_OK):
                        path, source = cand, bindir
                        for sub in ("lib", "lib64"):
                            lib = os.path.join(base, sub)
                            if os.path.isdir(lib):
                                libs.append(lib)
                        break
                if path:
                    break
            if path:
                break
    entry: dict = {"tool": tool, "vendor": vendor}
    if not path:
        entry.update({"status": "absent", "searched": searched})
        return entry
    entry.update({"status": "present", "path": path, "source": source})
    if libs and inject_ld:
        entry["ld_library_path_prepend"] = libs
    entry["run"] = run_cmd([path], timeout=timeout,
                           ld_prepend=libs if inject_ld else None)
    # Best-effort structured query (nvidia-smi / ixsmi dialect); harmless if
    # the tool doesn't speak this dialect — recorded, never fatal. Field set
    # carries a fallback chain (bi150 lesson: ixsmi rejects compute_cap, which
    # used to discard the whole row) and acceptance is structural — a CSV
    # header row — never a keyword blacklist (which let jetson_clocks' usage
    # text pass as data on the 2026-10-14 bench).
    for fields in ("name,driver_version,compute_cap,memory.total",
                   "name,driver_version,memory.total"):
        q = run_cmd([path, f"--query-gpu={fields}", "--format=csv"],
                    timeout=timeout, ld_prepend=libs if inject_ld else None)
        if q["status"] == "ok" and looks_like_gpu_csv(q.get("output")):
            entry["gpu_query_csv"] = q["output"]
            entry["gpu_query_fields"] = fields
            break
    return entry


def probe_vendor_tools() -> list[dict]:
    results: list[dict] = []
    for spec in VENDOR_TOOLS:
        for tool in spec["tools"]:
            results.append(probe_one_tool(tool, spec["vendor"], spec["roots"]))
        for tool in spec.get("platform_tools", []):
            # platform tools (tegrastats/jetson_clocks): no lib injection, short
            # budget (tegrastats streams forever; partial output is kept)
            results.append(probe_one_tool(tool, spec["vendor"] + " platform", None,
                                          inject_ld=False, timeout=5))
    return results


def merge_accelerators(dev_groups: dict, lspci: dict, tools: list[dict]) -> list[dict]:
    acc: dict[str, dict] = {}

    def slot(key: str) -> dict:
        return acc.setdefault(key, {"vendor_key": key,
                                    "display": LSPCI_VENDORS.get(key, (key, key))[1],
                                    "evidence": {}})

    for key, info in dev_groups.items():
        slot(key)["evidence"]["dev_nodes"] = info
    for h in (lspci or {}).get("matches") or []:
        slot(h["vendor_key"]).setdefault("evidence", {}).setdefault("lspci", []).append(h)
    for t in tools:
        if t.get("status") == "present" and t.get("vendor") in (
                list(dev_groups) + [k for k in LSPCI_VENDORS] + [k + " platform" for k in LSPCI_VENDORS]):
            key = t["vendor"].replace(" platform", "")
            slot(key)["evidence"].setdefault("tools", []).append(
                {"tool": t["tool"], "path": t["path"], "gpu_query_csv": t.get("gpu_query_csv")})
    return list(acc.values())


def probe_hardware() -> dict:
    cpu_model = None
    cpu_cores = 0
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                key, _, val = line.partition(":")
                key = key.strip()
                if key in ("model name", "Model", "Hardware", "processor model") and cpu_model is None:
                    cpu_model = clip(val, LINE_CUT) or None
                if key == "processor":
                    cpu_cores += 1
    except OSError:
        pass
    mem_total = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) * 1024
                    break
    except (OSError, ValueError):
        pass

    # unified-memory flag: only asserted on detectable evidence, else None.
    tegra = read_text("/etc/nv_tegra_release")
    platform_tag = "jetson" if tegra else None
    unified = {"value": None, "evidence": "no detectable signal"}
    if tegra:
        unified = {"value": True,
                   "evidence": "/etc/nv_tegra_release present (Tegra iGPU shares system DRAM)"}

    dev_groups = scan_dev_nodes()
    lspci = scan_lspci()
    tools = probe_vendor_tools()
    accel = merge_accelerators(dev_groups, lspci, tools)

    # If an NVIDIA iGPU reports memory N/A, that corroborates unified memory.
    for a in accel:
        for t in a.get("evidence", {}).get("tools", []):
            q = t.get("gpu_query_csv") or ""
            if "n/a" in q.lower() and a["vendor_key"] == "NVIDIA" and tegra:
                unified["evidence"] += f"; {t['tool']} memory.total=N/A ({clip(q, 120)})"
                break

    return {
        "host": {"hostname": socket.gethostname(), "arch": platform.machine(),
                 "cpu_model": cpu_model, "cpu_cores": cpu_cores or os.cpu_count(),
                 "mem_total_bytes": mem_total, "mem_total_human": human_bytes(mem_total)},
        "platform": platform_tag,
        "tegra_release": clip(tegra.splitlines()[0], LINE_CUT) if tegra else None,
        "unified_memory": unified,
        "accelerators": accel,
        "accel_enumeration_order": ["/dev node scan", "lspci vendor table", "vendor tools"],
        "dev_nodes_by_vendor": dev_groups,
        "lspci": lspci,
        "vendor_tools": tools,
    }


# -------------------------------------------------------------------- stack


def parse_os_release() -> dict:
    out = {}
    txt = read_text("/etc/os-release")
    if txt:
        for line in txt.splitlines():
            key, _, val = line.partition("=")
            val = val.strip().strip('"')
            if key in ("PRETTY_NAME", "ID", "VERSION_ID"):
                out[key.lower()] = val
    return out


def container_markers() -> dict:
    cg = ""
    for p in ("/proc/self/cgroup", "/proc/1/cgroup"):
        cg += read_text(p) or ""
    hits = sorted({m for m in ("docker", "lxc", "kubepods", "containerd", "podman")
                   if m in cg})
    markers = {"dot_dockerenv": os.path.exists("/.dockerenv"),
               "dot_containerenv": os.path.exists("/.containerenv"),
               "cgroup_hits": hits,
               "kubernetes_env": bool(os.environ.get("KUBERNETES_SERVICE_HOST"))}
    markers["is_container"] = any([markers["dot_dockerenv"], markers["dot_containerenv"],
                                   bool(hits), markers["kubernetes_env"]])
    return markers


def probe_cuda() -> dict:
    """nvcc on PATH, then /usr/local/cuda{,-*}; fall back to version files."""
    dirs = extra_bin_dirs()
    nvcc, source = find_binary("nvcc", dirs)
    if not nvcc and os.path.isfile("/usr/local/cuda/bin/nvcc"):
        nvcc, source = "/usr/local/cuda/bin/nvcc", "/usr/local/cuda/bin"
    if not nvcc:
        # numeric (major, minor) ordering: lexicographic sort would rank
        # /usr/local/cuda-9.0 above /usr/local/cuda-10.2
        def cuda_key(p: str) -> tuple[int, int]:
            m = re.search(r"cuda-(\d+)(?:\.(\d+))?", p)
            return (int(m.group(1)), int(m.group(2) or 0)) if m else (0, 0)
        cands = glob.glob("/usr/local/cuda-*/bin/nvcc")
        if cands:
            nvcc = max(cands, key=cuda_key)
            source = os.path.dirname(nvcc)
    if not nvcc:
        # version-file fallbacks (nvcc-less runtime installs)
        for pat in ("/usr/local/cuda/version.json", "/usr/local/cuda/version.txt",
                    "/usr/local/cuda*/version.*"):
            for f in sorted(glob.glob(pat)):
                txt = read_text(f, 2048)
                if txt:
                    m = (re.search(r'"version"\s*:\s*"([\d.]+)"', txt)
                         or re.search(r"CUDA Version\s+([\d.]+)", txt))
                    if m:
                        return {"status": "present", "version": m.group(1),
                                "source": f, "nvcc": None}
        return {"status": "absent", "searched": ["PATH", "/usr/local/cuda/bin",
                                                 "/usr/local/cuda-*/bin"]}
    r = run_cmd([nvcc, "--version"])
    m = re.search(r"release ([\d.]+), V(\S+)", r.get("output") or "")
    return {"status": "present" if m else r["status"], "nvcc": nvcc, "source": source,
            "version": m.group(1) if m else None,
            "nvcc_full": m.group(2) if m else None,
            "probe": None if m else r}


def read_version_file(patterns: list[str], regex: str | None = None) -> dict:
    for pat in patterns:
        for f in sorted(glob.glob(pat)):
            txt = read_text(f, 2048)
            if not txt:
                continue
            if regex:
                m = re.search(regex, txt, re.I)
                if m:
                    return {"status": "present", "version": m.group(1), "source": f}
            else:
                line = first_meaningful_line(txt)
                if line:
                    return {"status": "present", "version": line, "source": f}
    return {"status": "absent", "searched": patterns}


COREX_RUN_VERSION_RE = re.compile(r"(?:CoreX|IX-ML)\s*Version:\s*(\S+)", re.I)


def probe_corex(vendor_tools: list[dict] | None) -> dict:
    """CoreX version: plain version files, then release-corex.txt (which the
    plain reader's first-line heuristic mis-reads), then the banner printed by
    the vendor tool itself (ixsmi run output) as last resort."""
    r = read_version_file(["/usr/local/corex*/version", "/usr/local/corex*/version.*"])
    if r.get("status") == "present":
        return r
    r2 = read_version_file(["/usr/local/corex*/release-corex.txt"],
                           regex=r"(?:CoreX|IX-ML)\s*Version:\s*(\S+)")
    if r2.get("status") == "present":
        return r2
    for t in vendor_tools or []:
        m = COREX_RUN_VERSION_RE.search((t.get("run") or {}).get("output") or "")
        if m:
            return {"status": "present", "version": m.group(1),
                    "source": f"{t.get('tool')} run output"}
    return {**r, "searched": list(r.get("searched", [])) + list(r2.get("searched", []))}


def looks_like_gpu_csv(text: str | None) -> bool:
    """Structural acceptance for --query-gpu output: the header row must start
    with "name," and carry >= 3 columns. Usage/error banners (tegrastats,
    jetson_clocks) have no such header and are rejected without any keyword
    blacklist."""
    if not text or not text.strip():
        return False
    first = text.strip().splitlines()[0].strip()
    return first.lower().startswith("name,") and len(first.split(",")) >= 3


def parse_smi_csv(csv: str | None) -> dict | None:
    """Parse `--query-gpu=... --format=csv` output (header + first data row);
    also tolerates the historical noheader layout name,driver,compute_cap,…"""
    if not csv or not csv.splitlines():
        return None
    lines = [ln for ln in csv.splitlines() if ln.strip()]
    if not lines:
        return None
    header = [c.strip().lower() for c in lines[0].split(",")]
    if header[0] == "name" and len(header) >= 3:
        if len(lines) < 2:
            return None
        row = [c.strip() for c in lines[1].split(",")]

        def col(key: str) -> str | None:
            for i, h in enumerate(header):
                if h.split()[0] == key and i < len(row):
                    return row[i]
            return None

        return {"name": row[0] if row else None,
                "driver_version": col("driver_version"),
                "compute_cap": col("compute_cap"),
                "memory_total": col("memory.total")}
    row = [c.strip() for c in lines[0].split(",")]
    if len(row) < 3:
        return None
    return {"name": row[0], "driver_version": row[1], "compute_cap": row[2],
            "memory_total": row[3] if len(row) > 3 else None}


def probe_egress(skip: bool) -> dict:
    if skip:
        return {"skipped": "--no-egress", "summary": "skipped"}

    def http_check(url: str) -> dict:
        t0 = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": "bicameral-probe/1",
                                                   "Range": "bytes=0-255"})
        try:
            with urllib.request.urlopen(req, timeout=EGRESS_TIMEOUT) as r:
                r.read(256)
                return {"status": "up", "http_status": r.status,
                        "latency_ms": int((time.monotonic() - t0) * 1000)}
        except urllib.error.HTTPError as e:
            # a response (even 4xx/5xx) still proves DNS+TCP+TLS+HTTP egress
            return {"status": "up", "http_status": e.code,
                    "note": "endpoint answered with HTTP error", "latency_ms": int((time.monotonic() - t0) * 1000)}
        except Exception as e:  # noqa: BLE001 — every failure mode is a fact
            return {"status": "down", "error": f"{type(e).__name__}: {e}"[:200],
                    "latency_ms": int((time.monotonic() - t0) * 1000)}

    def tcp_check(target: str) -> dict:
        host, _, port = target.partition(":")
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=EGRESS_TIMEOUT):
                return {"status": "up", "latency_ms": int((time.monotonic() - t0) * 1000)}
        except Exception as e:  # noqa: BLE001
            return {"status": "down", "error": f"{type(e).__name__}: {e}"[:200],
                    "latency_ms": int((time.monotonic() - t0) * 1000)}

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(EGRESS_TARGETS)) as ex:
        futs = {ex.submit(http_check if kind == "http" else tcp_check, target): name
                for name, target, kind in EGRESS_TARGETS}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()
    summary = " ".join(f"{n}:{results[n]['status']}" for n, _, _ in EGRESS_TARGETS)
    return {"targets": results, "summary": summary}


def probe_stack(accel: list[dict], skip_egress: bool,
                vendor_tools: list[dict] | None = None) -> dict:
    st: dict = {"os": parse_os_release(), "kernel": platform.release(),
                "container": container_markers()}

    # driver/runtime versions
    smi_csv = None
    for a in accel:
        for t in a.get("evidence", {}).get("tools", []):
            if t.get("gpu_query_csv"):
                smi_csv = parse_smi_csv(t["gpu_query_csv"])
                break
        if smi_csv:
            break

    st["runtimes"] = {
        "cuda": probe_cuda(),
        "nvidia_smi_reported": smi_csv,
        "rocm": read_version_file(["/usr/local/rocm*/.info/version", "/opt/rocm*/.info/version"]),
        "cann": read_version_file(
            ["/usr/local/[Aa]scend/ascend-toolkit/latest/version.cfg",
             "/usr/local/[Aa]scend/nnal/atb/latest/version.cfg",
             "/usr/local/[Aa]scend/aascend-toolkit/latest/version.cfg"],
            regex=r"version\s*=\s*(\S+)"),
        "corex": probe_corex(vendor_tools),
    }

    st["python"] = {
        "version": platform.python_version(),
        "executable": sys.executable,
        "venv_importable": importlib.util.find_spec("venv") is not None,
        "ensurepip_importable": importlib.util.find_spec("ensurepip") is not None,
    }
    st["egress"] = probe_egress(skip_egress)
    return st


# ---------------------------------------------------------------- installed


def probe_engines() -> list[dict]:
    dirs = extra_bin_dirs()
    out = []
    for spec in ENGINE_SPECS:
        name = spec["name"]
        entry: dict = {"name": name, "status": "absent",
                       "searched_dir_count": len(dirs)}
        path, source = find_binary(name, dirs)
        if path:
            entry.update({"status": "present", "path": path, "source_dir": source})
            try:
                entry["sha256_16"] = sha256_16(path)
            except OSError as e:
                entry["sha256_error"] = f"{type(e).__name__}: {e}"
            r = run_cmd([path, "--version"], timeout=15)
            entry["version_probe"] = {"status": r["status"], "code": r.get("code")}
            line = None
            for cand_line in (r.get("output") or "").splitlines():
                if "version" in cand_line.lower():
                    line = clip(cand_line, LINE_CUT)
                    break
            entry["version"] = line or first_meaningful_line(r.get("output") or "")
            if r["status"] in ("timeout", "error", "absent"):
                entry["version_probe"]["detail"] = r
        if spec.get("pip_name"):
            try:
                entry["python_package_version"] = importlib.metadata.version(spec["pip_name"])
            except importlib.metadata.PackageNotFoundError:
                entry["python_package_version"] = None
        out.append(entry)
    return out


def quant_of(filename: str) -> str | None:
    m = QUANT_RE.search(filename)
    return m.group(0).upper() if m else None


def model_scan_roots(cli_dirs: list[str]) -> tuple[list[str], list[dict]]:
    home = os.path.expanduser("~")
    candidates = sorted(glob.glob(os.path.join(home, "models*")))
    candidates += ["/data/models", "/models", "/opt/models", "/mnt/models",
                   "/srv/models", "/workspace/models",
                   os.path.join(home, ".cache/huggingface/hub"),
                   os.path.join(home, ".cache/lm-studio/models")]
    env = os.environ.get("BI_PROBE_MODEL_DIRS")
    if env:
        candidates += [d for d in env.split(":") if d]
    candidates += cli_dirs or []
    seen: dict[str, dict] = {}
    for c in candidates:
        if c in seen:
            continue
        seen[c] = {"path": c, "exists": os.path.isdir(c), "origin":
                   "cli" if c in (cli_dirs or []) else
                   "env:BI_PROBE_MODEL_DIRS" if env and c in env.split(":") else "convention"}
    return ([c for c, meta in seen.items() if meta["exists"]], list(seen.values()))


def scan_models(cli_dirs: list[str]) -> dict:
    usable, root_meta = model_scan_roots(cli_dirs)
    entries: list[dict] = []
    truncated = False
    total_bytes = 0
    by_format = {"gguf": 0, "safetensors": 0}
    for root in usable:
        base_depth = os.path.normpath(root).rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if os.path.normpath(dirpath).rstrip("/").count("/") - base_depth >= MAX_WALK_DEPTH:
                dirnames[:] = []
            dirnames[:] = sorted(d for d in dirnames
                                 if not os.path.islink(os.path.join(dirpath, d)))
            for fn in sorted(filenames):
                low = fn.lower()
                fmt = ("gguf" if low.endswith(".gguf")
                       else "safetensors" if low.endswith(".safetensors") else None)
                if not fmt:
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    size = os.stat(p).st_size  # follows symlink (hf snapshots)
                except OSError:
                    continue
                ent: dict = {"path": p, "format": fmt, "size_bytes": size,
                             "size_human": human_bytes(size), "quantization": quant_of(fn)}
                if fmt == "gguf":
                    try:
                        with open(p, "rb") as f:
                            ent["gguf_magic_ok"] = f.read(4) == b"GGUF"
                    except OSError:
                        ent["gguf_magic_ok"] = None
                by_format[fmt] += 1
                total_bytes += size
                if len(entries) < MAX_MODEL_ENTRIES:
                    entries.append(ent)
                else:
                    truncated = True
    return {"roots_considered": root_meta, "roots_scanned": usable,
            "count": sum(by_format.values()),
            "count_note": f"first {MAX_MODEL_ENTRIES} listed" if truncated else "complete",
            "truncated": truncated, "total_bytes": total_bytes,
            "total_human": human_bytes(total_bytes), "by_format": by_format,
            "models": entries}


def http_get_local(port: int, path: str,
                   addrs: list[str] | None = None) -> dict:
    """GET http://<loopback>:<port><path>; never raises. Tries 127.0.0.1 and,
    when ss reported a wildcard IPv6 listener ("[::…"), ::1 as well — a v6-only
    listener is otherwise invisible to the v4-only probe. The full body read
    (up to 4096 bytes) travels in "body" for parsing; only "body_excerpt" is
    clipped for the report."""
    hosts = ["127.0.0.1"]
    if any((a or "").startswith("[::") for a in (addrs or [])):
        hosts.append("::1")
    last: dict = {"http_status": None, "host": hosts[0], "error": "no attempt made"}
    for host in hosts:
        bracket = f"[{host}]" if ":" in host else host
        url = f"http://{bracket}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "bicameral-probe/1"})
        try:
            with urllib.request.urlopen(req, timeout=LOCAL_HTTP_TIMEOUT) as r:
                body = r.read(4096).decode("utf-8", "replace")
                return {"http_status": r.status, "host": host,
                        "body": body, "body_excerpt": clip(body, 300)}
        except urllib.error.HTTPError as e:
            # an HTTP answer proves the endpoint speaks HTTP on this loopback;
            # no need to retry ::1
            return {"http_status": e.code, "host": host,
                    "error": "endpoint answered with HTTP error"}
        except Exception as e:  # noqa: BLE001 — non-HTTP listeners are a fact
            last = {"http_status": None, "host": host,
                    "error": f"{type(e).__name__}: {e}"[:160]}
    return last


def parse_ss_tln(out: str) -> dict[int, list[str]]:
    ports: dict[int, list[str]] = {}
    for line in out.splitlines()[1:]:  # skip header
        toks = line.split()
        if not toks or toks[0] != "LISTEN" or len(toks) < 4:
            continue
        local = toks[3]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        ports.setdefault(int(port), [])
        if addr not in ports[int(port)]:
            ports[int(port)].append(addr)
    return ports


def probe_services(extra_health_paths: list[str] | None = None) -> dict:
    r = run_cmd(["ss", "-tln"], capture_full=True)
    method = "ss -tln"
    truncated = bool(r.get("truncated"))
    listeners: dict[int, list[str]] = {}
    if r["status"] in ("ok", "nonzero") and r.get("full_output"):
        # parse the FULL capture: the 600-char excerpt silently dropped ports
        listeners = parse_ss_tln(r["full_output"])
    else:
        r2 = run_cmd(["netstat", "-tln"], capture_full=True)
        truncated = truncated or bool(r2.get("truncated"))
        if r2["status"] in ("ok", "nonzero") and r2.get("full_output"):
            method = "netstat -tln (ss unavailable)"
            for line in r2["full_output"].splitlines()[2:]:
                toks = line.split()
                if len(toks) >= 6 and toks[-1] == "LISTEN":
                    addr, _, port = toks[3].rpartition(":")
                    if port.isdigit():
                        ports = listeners.setdefault(int(port), [])
                        if addr not in ports:
                            ports.append(addr)
        else:
            return {"tool": "ss", "status": r["status"], "error": r.get("error"),
                    "truncated": truncated,
                    "note": "neither ss nor netstat available; listening services unknown"}
    # appspec-declared health paths (item: appspec.service.health honoured),
    # probed per listener alongside the generic /health + /v1/models pair
    extras = sorted({p if p.startswith("/") else "/" + p
                     for p in (extra_health_paths or []) if p} - {"/health"})

    def probe_port(port: int, addrs: list[str]) -> dict:
        health = http_get_local(port, "/health", addrs)
        models_raw = http_get_local(port, "/v1/models", addrs)
        model_ids: list[str] = []
        # parse the full body read (4096B), not its 300-char excerpt —
        # the excerpt cut mid-JSON and model_ids came out empty every time
        try:
            j = json.loads((models_raw.get("body") or "").split("\ufffd")[0] or "null")
            data = j.get("data") if isinstance(j, dict) else None
            if isinstance(data, list):
                model_ids = [str(m.get("id")) for m in data[:32]
                             if isinstance(m, dict) and m.get("id")]
        except (ValueError, AttributeError):
            pass
        health_probes: dict[str, dict] = {}
        for pth in extras:
            rp = http_get_local(port, pth, addrs)
            health_probes[pth] = {"http_status": rp.get("http_status"),
                                  "host": rp.get("host"), "error": rp.get("error")}
        healthy = health.get("http_status") == 200
        served = bool(model_ids)
        health_rec = {"http_status": health.get("http_status"),
                      "host": health.get("host"), "error": health.get("error")}
        if healthy:
            health_rec["body_excerpt"] = health.get("body_excerpt")
        return {"port": port, "listen_addrs": addrs,
                "health": health_rec,
                "health_probes": health_probes,
                "v1_models": {"http_status": models_raw.get("http_status"),
                              "host": models_raw.get("host"),
                              "model_ids": model_ids,
                              "error": models_raw.get("error")},
                "inference_server": bool(healthy or served)}

    probed = []
    if listeners:
        items = sorted(listeners.items())
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(items))) as ex:
            futs = {ex.submit(probe_port, port, addrs): port for port, addrs in items}
            for fut in concurrent.futures.as_completed(futs):
                probed.append(fut.result())
        probed.sort(key=lambda s: s["port"])
    inference = [s for s in probed if s["inference_server"]]
    return {"tool": method, "listener_count": len(listeners),
            "truncated": truncated,
            "listeners": [{"port": p, "addrs": a} for p, a in sorted(listeners.items())],
            "cross_check": probed,
            "inference_services": inference,
            "note": "each listening port cross-checked with GET /health and GET /v1/models (§3.1 #3)"}


def probe_installed(cli_model_dirs: list[str],
                    extra_health_paths: list[str] | None = None) -> dict:
    return {"engines": probe_engines(), "models": scan_models(cli_model_dirs),
            "services": probe_services(extra_health_paths)}


# ------------------------------------------------------------ install_state


def eval_appspec(spec: dict, engines: list[dict], services: dict,
                 models: dict, verify_hashes: bool, label: str) -> dict:
    """appspec/1 → absent/partial/ready/degraded (§3.1 #4, §3.4)."""
    missing: list[str] = []
    eng = spec.get("engine") or {}
    model = spec.get("model") or {}
    svc = spec.get("service") or {}

    binname = APPSPEC_ENGINE_BINARIES.get(eng.get("name"), eng.get("name"))
    eng_ent = next((e for e in engines if e["name"] == binname), None)
    engine_present = bool(eng_ent and eng_ent.get("status") == "present")
    if not engine_present:
        missing.append(f"engine '{eng.get('name')}' (binary '{binname}') not found")
    elif eng.get("ref"):
        hay = (eng_ent.get("version") or "") + " " + (eng_ent.get("sha256_16") or "")
        if str(eng["ref"]) not in hay:
            missing.append(f"engine ref '{eng['ref']}' not matched by detected version/sha")

    model_file = model.get("file")
    model_present = False
    if not model_file:
        missing.append("appspec has no model.file to check")
    elif not isinstance(model_file, str):
        missing.append(f"appspec model.file is not a path string: {model_file!r}")
    elif os.path.isabs(model_file) and os.path.isfile(model_file):
        model_present = True
        want_raw = model.get("size_bytes")
        want = None
        if want_raw is not None:
            try:
                want = int(want_raw)
            except (TypeError, ValueError):
                missing.append(f"appspec model.size_bytes invalid: {want_raw!r}")
        if want and os.path.getsize(model_file) != want:
            missing.append(f"model size mismatch at {model_file} "
                           f"(want {want}, have {os.path.getsize(model_file)})")
            model_present = False
        if model_present and verify_hashes and model.get("sha256"):
            try:
                have = sha256_16(model_file)
            except OSError as e:
                missing.append(f"model sha256 unreadable at {model_file}: "
                               f"{type(e).__name__}: {e}")
                model_present = False
            else:
                if not model.get("sha256", "").startswith(have[:16]):
                    missing.append(f"model sha256 mismatch at {model_file}")
                    model_present = False
        elif model_present and model.get("sha256"):
            missing.append("model sha256 provided but unverified (run probe with --verify-hashes)")
    else:
        base = os.path.basename(model_file)
        hit = next((m for m in models.get("models", [])
                    if os.path.basename(m["path"]) == base), None)
        if hit:
            model_present = True
            missing.append(f"model file found outside appspec path: {hit['path']}")
        else:
            missing.append(f"model file not found: {model_file}")

    # service health: honour a declared appspec.service.health path (default
    # /health). An unhealthy service is NOT counted into `missing` — engine +
    # model ready with the service down is exactly `degraded` (§3.1 #4); the
    # old code appended it to missing, making degraded unreachable.
    service_state = None
    health_path = svc.get("health")
    if health_path is not None and not isinstance(health_path, str):
        missing.append(f"appspec service.health is not a string: {health_path!r}")
        health_path = None
    health_path = (health_path if health_path else "/health")
    if not health_path.startswith("/"):
        health_path = "/" + health_path
    port_raw = svc.get("port")
    if port_raw is not None:
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            missing.append(f"appspec service.port invalid: {port_raw!r}")
        else:
            hit = next((s for s in services.get("cross_check", []) if s["port"] == port), None)
            if health_path == "/health":
                healthy = bool(hit and hit["inference_server"])
            else:
                rec = (hit.get("health_probes") or {}).get(health_path) if hit else None
                healthy = bool(rec and rec.get("http_status") == 200)
            service_state = "healthy" if healthy else "not_healthy"

    if missing:
        state = "partial" if (engine_present or model_present) else "absent"
    elif service_state == "not_healthy":
        state = "degraded"
    else:
        state = "ready"
    return {"appspec": label, "state": state, "missing": missing,
            "engine_present": engine_present, "model_present": model_present,
            "service_state": service_state, "service_health_path": health_path,
            "note": "states per §3.1 #4: absent/partial/ready/degraded; "
                    "partial must say what is missing"}


# --------------------------------------------------------------------- main


def build_report(args: argparse.Namespace) -> dict:
    probe_path = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else "probe.py"
    try:
        probe_sha = sha256_16(probe_path)
    except OSError:
        probe_sha = None
    machine_id = read_text("/etc/machine-id", 128)
    if not machine_id:
        machine_id = read_text("/var/lib/dbus/machine-id", 128)
    machine_id = machine_id.strip() if machine_id else None

    notes: list[str] = []
    if not machine_id:
        notes.append("/etc/machine-id unreadable; fingerprint lacks machine-id")

    # appspecs load first: a declared service.health steers the services probe
    appspecs: list[tuple[str, dict | None, str | None]] = []  # (label, spec, load_error)
    if args.appspec:
        for label, path in args.appspec:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    spec = json.load(f)
            except (OSError, ValueError) as e:
                appspecs.append((label, None, str(e)))
                continue
            appspecs.append((label, spec, None))
    else:
        notes.append("no --appspec supplied (standalone run): install_state is "
                     "defined against master-issued appspec/1, reported as []")

    extra_health_paths: set[str] = set()
    for _, spec, load_err in appspecs:
        if load_err is not None or not isinstance(spec, dict):
            continue
        hp = (spec.get("service") or {}).get("health")
        if isinstance(hp, str) and hp:
            extra_health_paths.add(hp if hp.startswith("/") else "/" + hp)

    hardware = probe_hardware()
    stack = probe_stack(hardware.get("accelerators", []), args.no_egress,
                        hardware.get("vendor_tools") or [])
    installed = probe_installed(args.model_dirs, sorted(extra_health_paths))
    engines = installed["engines"]
    services = installed["services"]
    models = installed["models"]

    install_state: list[dict] = []
    for label, spec, load_err in appspecs:
        if load_err is not None:
            install_state.append({"appspec": label, "state": "absent",
                                  "missing": [f"appspec unreadable/invalid: {load_err}"]})
            continue
        try:
            # per-appspec guard: one malformed spec must not kill the report
            install_state.append(eval_appspec(spec, engines, services, models,
                                              args.verify_hashes, label))
        except Exception as e:  # noqa: BLE001 — recorded as a per-item error state
            install_state.append({"appspec": label, "state": "absent",
                                  "missing": [f"appspec evaluation failed: "
                                              f"{type(e).__name__}: {e}"]})

    report = {
        "schema": SCHEMA,
        "generated_at": now_utc(),
        "probe": {"path": probe_path, "sha256_16": probe_sha,
                  "args": {"no_egress": args.no_egress,
                           "verify_hashes": args.verify_hashes,
                           "model_dirs": args.model_dirs}},
        "fingerprint": {
            "machine_id": machine_id,
            "probe_sha256_16": probe_sha,
            "fingerprint_id": f"{machine_id}-{probe_sha}" if machine_id and probe_sha else None,
        },
        "hardware": hardware,
        "stack": stack,
        "installed": installed,
        "install_state": install_state,
        "notes": notes,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="probe.py",
        description="Bicameral probe/1 — device sensing & install-state inventory "
                    "(docs/paradigm.md §3.1). Stdlib-only, read-only, no root, "
                    "no egress requirement.")
    ap.add_argument("-o", "--output", help="write JSON report here (default: stdout)")
    ap.add_argument("--appspec", metavar="FILE", action="append", default=[],
                    help="appspec/1 JSON to evaluate install_state (repeatable)")
    ap.add_argument("--model-dirs", metavar="DIR", action="append", default=[],
                    help="extra model-scan directory (repeatable)")
    ap.add_argument("--no-egress", action="store_true",
                    help="skip egress reachability checks")
    ap.add_argument("--verify-hashes", action="store_true",
                    help="hash model files when an appspec provides sha256")
    ap.add_argument("--compact", action="store_true", help="one-line JSON output")
    args = ap.parse_args(argv)

    # appspec entries arrive as (label, path)
    args.appspec = [(os.path.basename(a), a) for a in args.appspec]

    try:
        report = build_report(args)
    except Exception as e:  # noqa: BLE001 — last-resort guard
        print(f"probe: failed to build report: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    text = json.dumps(report, ensure_ascii=False,
                      indent=None if args.compact else 2, sort_keys=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)

    # one-line human summary on stderr (stdout stays pure JSON)
    hw = report["hardware"]
    acc = ",".join(a["vendor_key"] for a in hw.get("accelerators", [])) or "none"
    eng = ",".join(e["name"] for e in report["installed"]["engines"]
                   if e["status"] == "present") or "none"
    svc = report["installed"]["services"].get("inference_services") or []
    egr = report["stack"]["egress"].get("summary", "n/a")
    print(f"probe/1: accel=[{acc}] engines=[{eng}] "
          f"inference_services={[s['port'] for s in svc]} egress=[{egr}]",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
