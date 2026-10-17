#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral probe/1 — device sensing & install-state inventory.

Implements docs/paradigm.md §3.1: one command produces one self-contained
DeviceReport (JSON, schema "probe/1") with five sections (the fifth,
`segmentation` — can-the-card-be-split? vGPU/instance surface, read-only —
is a schema-compatible append, 2026-10-17):

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
    segmentation   can the accelerator be split? (vGPU / instance slicing)
                   READ-ONLY surface inventory: {tools[{name,path,status,
                   capabilities[]}], vgpu_capable bool|null, slicing_method
                   str|null, notes[]}. Tool existence + documented --help
                   subcommand/flag enumeration + `vgpu -s/-c/-q` listings
                   (queries only). NEVER creates a vGPU/instance: an
                   experiment runs only on a *documented reversible* CLI
                   path (create+destroy in the tool's own help), which as of
                   2026-10-17 neither machine exposes — reasons in notes[].

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
    python3 probe.py --selftest               # pure-function self-test (seg parsers)
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

# ------------------------------------------------- segmentation constants

# Vendor split-control device channels (kernel char devices of the Iluvatar
# driver stack). Majors observed 2026-10-17: bi150 itrlink 236 / itrctl 237,
# bi100 itrlink 234 / itrctl 235 — the nodes are container-visibility facts,
# the majors may differ per host, so they are parsed, never hard-coded.
SEG_DEV_NODES = ["/dev/itrctl", "/dev/itrlink"]

# --help keyword → capability tag tables. Structural, order-stable: a tag is
# emitted only when its own help text appears (same philosophy as
# looks_like_gpu_csv: no keyword blacklist in the acceptance direction).
SEG_IXSMI_HELP_TABLE = [
    (r"GRID vGPU", "vgpu.subcommand"),
]
SEG_ITRCTL_HELP_TABLE = [
    (r"(?i)\bcreate\b", "create"),
    (r"(?i)\bdestroy\b|\bdelete\b|\bremove\b", "destroy"),
    (r"(?i)\bvgpu\b", "vgpu"),
    (r"(?i)\binstance\b", "instance"),
    (r"(?i)\bslice\b|\bpartition\b", "slice"),
]
SEG_VGPU_FLAG_TABLE = [
    (r"-q,--query", "vgpu.query"),
    (r"-u,--utilization", "vgpu.utilization"),
    (r"-p,--pmon", "vgpu.process_monitor"),
    (r"-s,--supported", "vgpu.supported_list"),
    (r"-c,--creatable", "vgpu.creatable_list"),
    (r"-v,--verbose", "vgpu.verbose"),
]

# Symbol names that mark vGPU / MIG-style instance API surface inside the
# vendor management library (libixml.so). Presence is C-API *evidence* only —
# never by itself a documented reversible CLI path (bi150/bi100 2026-10-17:
# symbols exist, no CLI wrapper does).
SEG_LIB_SYMBOLS = [
    "nvmlDeviceGetSupportedVgpus",
    "nvmlDeviceGetCreatableVgpus",
    "nvmlDeviceGetActiveVgpus",
    "nvmlDeviceCreateGpuInstance",
    "nvmlGpuInstanceCreateComputeInstance",
    "nvmlComputeInstanceDestroy",
    "nvmlGpuInstanceDestroy",
    "nvmlSetVgpuVersion",
]
SEG_LIB_CAP_BYTES = 64 * 1024 * 1024  # read cap for the .so scan

VGPU_NO_TYPES_RE = re.compile(r"No vGPUs found on this device", re.I)
VGPU_UNSUPPORTED_RE = re.compile(r"Not supported devices in vGPU mode", re.I)
VGPU_CARD_RE = re.compile(r"^\s*GPU:\s+(\S+)", re.M)
VGPU_TYPE_ROW_RE = re.compile(r"^\s+\d+\s+\S")
VGPU_ACTIVE_RE = re.compile(r"^\s*Active vGPUs\s*:\s*(\d+)\s*$", re.I)

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


# ------------------------------------------------------------ segmentation
#
# 「卡可否分割」的只读探测（2026-10-17 增补，schema 兼容追加）：
#   - 工具存在性 + **其自身 --help 枚举**分割相关子命令/旗标（不加黑名单）；
#   - `ixsmi vgpu -s|-c|-q` 三个只读 listing 的结构化解析；
#   - /dev/itrctl·itrlink 通道与 /proc/devices 主设备号；
#   - libixml 的 vGPU/MIG 式 C-API 符号（仅作证据，非 CLI 路径）。
# 红线：绝不创建任何 vGPU/实例。受控实验仅在「文档化可逆路径」（工具自身
# help 同时给出 create+destroy）出现时才允许，判定函数 has_reversible_pair。


def parse_proc_devices(text: str | None) -> dict[str, int]:
    """/proc/devices lines "<major> <name>" → {name: major} (pure; selftest-
    covered). Header lines ("Character devices:") and noise are ignored."""
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        m = re.match(r"\s*(\d+)\s+(\S+)", line)
        if m:
            out.setdefault(m.group(2), int(m.group(1)))
    return out


def parse_help_capabilities(text: str | None,
                            table: list[tuple[str, str]]) -> list[str]:
    """Tool's own --help text → capability tags, in table order (pure;
    selftest-covered). A tag appears only if its help text does; None/empty
    text → [] (absent tolerance)."""
    if not text:
        return []
    return [tag for pat, tag in table if re.search(pat, text)]


def has_reversible_pair(capabilities: list[str]) -> bool:
    """True only when the tool's own help documents BOTH create and destroy
    (pure; selftest-covered) — the sole gate for the controlled-experiment
    decision. Capability-surface presence alone never unlocks an experiment."""
    return "create" in capabilities and "destroy" in capabilities


def parse_vgpu_listing(text: str | None) -> dict:
    """`ixsmi vgpu -s|-c|-q` output → structured summary (pure; selftest-
    covered). Conservatively structured: cards via "GPU:" headers, explicit
    denial markers, "Active vGPUs: N" per-card counts (summed into
    active_vgpus_total, None when absent), type rows (whitespace-indented
    "<id> <name>" lines, the nvidia-smi vGPU listing layout), everything
    else kept as clipped evidence lines — an uninterpretable answer stays
    evidence, never a guess. None/empty → zeroed record (absent tolerance)."""
    res = {"cards": 0, "card_ids": [], "unsupported_mode": False,
           "no_types_markers": 0, "type_rows": 0, "other_lines": [],
           "active_vgpus_total": None}
    if not text or not text.strip():
        return res
    res["card_ids"] = [m.group(1) for m in VGPU_CARD_RE.finditer(text)]
    res["cards"] = len(res["card_ids"])
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if VGPU_UNSUPPORTED_RE.search(line):
            res["unsupported_mode"] = True
            continue
        if VGPU_NO_TYPES_RE.search(line):
            res["no_types_markers"] += 1
            continue
        m = VGPU_ACTIVE_RE.match(line)
        if m:
            n = int(m.group(1))
            res["active_vgpus_total"] = (res["active_vgpus_total"] or 0) + n
            continue
        if s.startswith("GPU:"):
            continue
        if s.startswith(("Timestamp", "+--", "+==", "===")) or \
                set(s) <= set("=-+| "):
            continue  # table chrome
        if VGPU_TYPE_ROW_RE.match(line):
            res["type_rows"] += 1
            continue
        if len(res["other_lines"]) < 20:
            res["other_lines"].append(clip(line, LINE_CUT))
    return res


def decide_vgpu_capable(listings: list[dict]) -> bool | None:
    """Combine vgpu -s/-c/-q parsed listings into the observed verdict (pure;
    selftest-covered).
      True   — at least one listing shows actual vGPU type rows
      False  — listings answered but every one is an interpretable denial
               (unsupported-mode marker, per-card no-types marker, or an
               "Active vGPUs: 0" total)
      None   — nothing interpretable answered (tool absent, empty, or only
               unstructured output) — recorded as unknown, never guessed."""
    answered = [l for l in listings if l and any(
        (l.get("cards"), l.get("unsupported_mode"), l.get("no_types_markers"),
         l.get("type_rows"), l.get("other_lines"),
         l.get("active_vgpus_total") is not None))]
    if not answered:
        return None
    if any(l.get("type_rows") for l in answered):
        return True

    def interpretable_denial(l: dict) -> bool:
        return bool(l.get("unsupported_mode") or l.get("no_types_markers")
                    or l.get("active_vgpus_total") == 0)

    if all(interpretable_denial(l) for l in answered):
        return False
    return None


def symbol_scan(data: bytes | None, names: list[str]) -> list[str]:
    """Which known symbol names appear in a library image (pure; selftest-
    covered). Plain byte containment — enough for exported-name evidence."""
    if not data:
        return []
    return [n for n in names if n.encode() in data]


def find_seg_binary(name: str, roots: list[str]) -> tuple[str | None, list[str]]:
    """PATH first, then /usr/local|opt/<root>/bin with the root's lib dirs
    returned for LD injection (same order rule as §3.1). Returns (path|None,
    lib_dirs)."""
    p, _ = find_binary(name)
    if p:
        return p, []
    libs: list[str] = []
    for root in roots or []:
        for tpl in ("/usr/local/{root}", "/opt/{root}"):
            for base in sorted(glob.glob(tpl.format(root=root))):
                cand = os.path.join(base, "bin", name)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    for sub in ("lib", "lib64"):
                        lib = os.path.join(base, sub)
                        if os.path.isdir(lib):
                            libs.append(lib)
                    return cand, libs
    return None, []


def probe_segmentation(vendor_tools: list[dict] | None = None) -> dict:
    """READ-ONLY segmentation-surface inventory (see module docstring).
    Never creates a vGPU/instance: the only executed things are --help /
    documented query listings of already-present tools."""
    notes: list[str] = []
    tools: list[dict] = []

    # -- itrctl: the vendor split-control CLI suggested by /dev/itrctl.
    #    Existence only; if present, ONLY "--help" runs (never bare — an
    #    unknown CLI's no-arg behaviour is not assumed read-only).
    itr_path, itr_libs = find_seg_binary("itrctl", ["iluvatar", "corex"])
    itr_caps: list[str] = []
    if itr_path:
        # capture_full: "GRID vGPU"-style sections live at the tail of help
        # text — the 600-char default excerpt cuts them off (2026-10-17 lesson)
        r = run_cmd([itr_path, "--help"], ld_prepend=itr_libs, capture_full=True)
        help_text = r.get("full_output") or r.get("output") or ""
        itr_caps = parse_help_capabilities(help_text, SEG_ITRCTL_HELP_TABLE)
        tools.append({"name": "itrctl", "path": itr_path, "status": "present",
                      "capabilities": itr_caps,
                      "help_excerpt": clip_lines(help_text, 600)})
    else:
        tools.append({"name": "itrctl", "path": None, "status": "absent",
                      "capabilities": [],
                      "searched": ["PATH", "/usr/local|opt/{iluvatar,corex}/bin"]})

    # -- ixsmi `vgpu` subcommand surface (bi150: corex root, bi100: iluvatar
    #    root — both searched; LD injected per the 2026-10-14 lesson).
    ix_path, ix_libs = find_seg_binary("ixsmi", ["corex", "iluvatar"])
    listings: list[dict] = []
    vgpu_capable: bool | None = None
    if ix_path:
        r_help = run_cmd([ix_path, "--help"], ld_prepend=ix_libs, capture_full=True)
        caps = parse_help_capabilities(
            r_help.get("full_output") or r_help.get("output"),
            SEG_IXSMI_HELP_TABLE)
        tool_rec = {"name": "ixsmi", "path": ix_path,
                    "status": "present", "capabilities": caps}
        if "vgpu.subcommand" in caps:
            r_vh = run_cmd([ix_path, "vgpu", "-h"], ld_prepend=ix_libs,
                           capture_full=True)
            caps += parse_help_capabilities(
                r_vh.get("full_output") or r_vh.get("output"),
                SEG_VGPU_FLAG_TABLE)
            tool_rec["capabilities"] = caps
            for flag in ("-s", "-c", "-q"):
                r = run_cmd([ix_path, "vgpu", flag], ld_prepend=ix_libs,
                            capture_full=True)  # 8 cards can exceed the excerpt
                lst = parse_vgpu_listing(
                    r.get("full_output") or r.get("output")
                    if r["status"] in ("ok", "nonzero") else None)
                lst["flag"] = flag
                listings.append(lst)
            vgpu_capable = decide_vgpu_capable(listings)
            if not has_reversible_pair(caps):
                notes.append("ixsmi vgpu subcommand exposes only query flags "
                             "(q/u/p/s/c/v/l per its own -h); no create/destroy "
                             "option exists in any --help — no documented "
                             "reversible CLI segmentation path")
        else:
            notes.append("ixsmi present but its --help carries no GRID vGPU "
                         "section; vgpu surface not exercised")
        tool_rec["vgpu_listings"] = listings
        tools.append(tool_rec)
    else:
        tools.append({"name": "ixsmi", "path": None, "status": "absent",
                      "capabilities": [],
                      "searched": ["PATH", "/usr/local|opt/{corex,iluvatar}/bin"]})
        notes.append("ixsmi not found; vGPU surface unknown (vgpu_capable=null)")

    # -- kernel device channels (control planes of the vendor driver stack)
    majors = parse_proc_devices(read_text("/proc/devices", 8192))
    dev_channels = []
    for node in SEG_DEV_NODES:
        dev_channels.append({"node": node, "present": os.path.exists(node),
                             "major": majors.get(os.path.basename(node))})

    # -- vendor management library C-API evidence (libixml.so)
    lib_syms: list[str] = []
    lib_path = None
    for root in ("corex", "iluvatar"):
        for sub in ("lib64", "lib"):
            cand = f"/usr/local/{root}/{sub}/libixml.so"
            if os.path.isfile(cand):
                lib_path = cand
                break
        if lib_path:
            break
    if lib_path:
        try:
            with open(lib_path, "rb") as f:
                lib_syms = symbol_scan(f.read(SEG_LIB_CAP_BYTES), SEG_LIB_SYMBOLS)
        except OSError as e:
            notes.append(f"libixml unreadable at {lib_path}: "
                         f"{type(e).__name__}: {e}")
    if any(s in lib_syms for s in ("nvmlDeviceCreateGpuInstance",
                                   "nvmlGpuInstanceCreateComputeInstance")):
        notes.append(f"{lib_path} carries MIG-style C-API symbols "
                     f"(nvmlDeviceCreateGpuInstance[WithPlacement]/"
                     f"nvmlGpuInstanceCreateComputeInstance + matching *Destroy) "
                     f"and vGPU query APIs — C-API evidence only, no CLI "
                     f"wrapper found on this machine")

    # -- verdict + no-experiment audit line
    if vgpu_capable is False:
        markers = [f"{l.get('flag')}:{'unsupported_mode' if l.get('unsupported_mode') else 'no_types x' + str(l.get('no_types_markers'))}"
                   for l in listings]
        notes.append("vgpu_capable=false as observed from inside this "
                     "container/host: " + "; ".join(markers) +
                     " — vGPU provisioning is host-level and 0 types are "
                     "visible here; host-side state may differ")
    if not has_reversible_pair(itr_caps):
        notes.append("controlled create→destroy experiment NOT performed: no "
                     "tool's own documentation exposes a reversible "
                     "segmentation path (irreversible/unclear territory — "
                     "capabilities recorded only)")

    slicing_method = None
    if vgpu_capable is True:
        slicing_method = "vgpu (vendor mdev-style instances via /dev/itrctl ioctls)"

    return {"tools": tools,
            "vgpu_capable": vgpu_capable,
            "slicing_method": slicing_method,
            "notes": notes,
            "dev_channels": dev_channels,
            "lib_api_symbols": lib_syms,
            "lib_path": lib_path}


# --------------------------------------------------------------- selftest
# Pure functions only (no network, no filesystem, no subprocess). Covers the
# segmentation section's parsers incl. absent tolerance — real command
# outputs captured 2026-10-17 on bi150/bi100 are pinned as fixtures.

BI150_VGPU_S_SAMPLE = """GPU: 00000000:8D:00.0
No vGPUs found on this device
GPU: 00000000:90:00.0
No vGPUs found on this device
"""

BI100_VGPU_S_SAMPLE = "Not supported devices in vGPU mode\n"

VGPU_POPULATED_SAMPLE = """GPU: 00000000:8D:00.0
    71   Iluvatar vGPU BI-4C
    72   Iluvatar vGPU BI-4C
"""

VGPU_ACTIVE_TABLE_SAMPLE = """Timestamp    Sun Oct 18 00:05:17 2026
+---------------------------------------------------------------------------------+
|      IX-ML: 4.4.0                     Driver Version: 4.4.0                     |
|-------------------------------------+------------------------------+------------+
| GPU  Name                           | Bus-Id                       | GPU-Util   |
| 0   Iluvatar BI-V150                | 00000000:8D:00.0             | 0%         |
+-------------------------------------+------------------------------+------------+
"""

VGPU_ACTIVE_Q_SAMPLE = """GPU: 00000000:8D:00.0
Active vGPUs                                : 0
GPU: 00000000:90:00.0
Active vGPUs                                : 0
"""

PROC_DEVICES_SAMPLE = """Character devices:
  1 mem
  5 /dev/tty
236 itrlink
237 itrctl
238 iluvatar
239 aux
"""


def cmd_selftest(_args: argparse.Namespace) -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if cond:
            print("ok   %s" % name)
        else:
            failures.append(name)
            print("FAIL %s %s" % (name, detail))

    # -- parse_proc_devices
    pd = parse_proc_devices(PROC_DEVICES_SAMPLE)
    check("proc_devices.majors", pd.get("itrctl") == 237 and pd.get("itrlink") == 236
          and pd.get("iluvatar") == 238, str(pd))
    check("proc_devices.skips_headers",
          all("Character" not in k and "devices" not in k for k in pd)
          and all(isinstance(v, int) for v in pd.values()), str(pd))
    check("proc_devices.absent_none", parse_proc_devices(None) == {})
    check("proc_devices.absent_empty", parse_proc_devices("") == {})

    # -- parse_help_capabilities
    check("help_caps.ixsmi_vgpu_section",
          parse_help_capabilities("GRID vGPU:\n  vgpu   Displays vGPU info",
                                  SEG_IXSMI_HELP_TABLE) == ["vgpu.subcommand"])
    check("help_caps.absent_none", parse_help_capabilities(None, SEG_IXSMI_HELP_TABLE) == [])
    check("help_caps.absent_empty", parse_help_capabilities("", SEG_VGPU_FLAG_TABLE) == [])
    vh = ("-q,--query    Display information\n"
          "  -s,--supported  Display supported vGPU types\n"
          "  -c,--creatable  Display creatable\n"
          "  -x,--xylophone  unrelated")
    check("help_caps.vgpu_flags_matched_only",
          parse_help_capabilities(vh, SEG_VGPU_FLAG_TABLE) ==
          ["vgpu.query", "vgpu.supported_list", "vgpu.creatable_list"])
    itr_help = "usage: itrctl [OPTIONS]\n\n  create DEVICE  make a vgpu\n  destroy ID  remove it\n"
    check("help_caps.itrctl_create_destroy",
          parse_help_capabilities(itr_help, SEG_ITRCTL_HELP_TABLE) ==
          ["create", "destroy", "vgpu"])

    # -- has_reversible_pair (the experiment gate)
    check("revpair.both", has_reversible_pair(["create", "destroy", "vgpu"]) is True)
    check("revpair.create_only", has_reversible_pair(["create"]) is False)
    check("revpair.neither", has_reversible_pair(["vgpu", "slice"]) is False)
    check("revpair.empty", has_reversible_pair([]) is False)

    # -- parse_vgpu_listing
    bi150 = parse_vgpu_listing(BI150_VGPU_S_SAMPLE)
    check("vgpu_listing.bi150_zero_types",
          bi150["cards"] == 2 and bi150["no_types_markers"] == 2
          and bi150["type_rows"] == 0 and bi150["unsupported_mode"] is False
          and bi150["other_lines"] == [], str(bi150))
    bi100 = parse_vgpu_listing(BI100_VGPU_S_SAMPLE)
    check("vgpu_listing.bi100_unsupported_mode",
          bi100["unsupported_mode"] is True and bi100["cards"] == 0, str(bi100))
    pop = parse_vgpu_listing(VGPU_POPULATED_SAMPLE)
    check("vgpu_listing.populated_type_rows",
          pop["cards"] == 1 and pop["type_rows"] == 2
          and pop["no_types_markers"] == 0, str(pop))
    act = parse_vgpu_listing(VGPU_ACTIVE_TABLE_SAMPLE)
    check("vgpu_listing.table_chrome_ignored",
          act["cards"] == 0 and act["type_rows"] == 0
          and len(act["other_lines"]) >= 1
          and all("GPU-Util" in ln or "BI-V150" in ln or "IX-ML" in ln
                  for ln in act["other_lines"]), str(act))
    q = parse_vgpu_listing(VGPU_ACTIVE_Q_SAMPLE)
    check("vgpu_listing.active_count_parsed",
          q["active_vgpus_total"] == 0 and q["other_lines"] == []
          and q["cards"] == 2, str(q))
    check("vgpu_listing.absent_none",
          parse_vgpu_listing(None)["cards"] == 0)
    check("vgpu_listing.absent_empty",
          parse_vgpu_listing("   \n")["no_types_markers"] == 0)

    # -- decide_vgpu_capable
    check("decide.absent_unknown",
          decide_vgpu_capable([]) is None)
    check("decide.empty_listings_unknown",
          decide_vgpu_capable([parse_vgpu_listing(None)]) is None)
    check("decide.zero_types_false",
          decide_vgpu_capable([parse_vgpu_listing(BI150_VGPU_S_SAMPLE)]) is False)
    check("decide.unsupported_mode_false",
          decide_vgpu_capable([parse_vgpu_listing(BI100_VGPU_S_SAMPLE)]) is False)
    check("decide.active_zero_false",
          decide_vgpu_capable([parse_vgpu_listing(VGPU_ACTIVE_Q_SAMPLE)]) is False)
    check("decide.bi150_trio_false",
          decide_vgpu_capable([parse_vgpu_listing(BI150_VGPU_S_SAMPLE),
                               parse_vgpu_listing(BI150_VGPU_S_SAMPLE),
                               parse_vgpu_listing(VGPU_ACTIVE_Q_SAMPLE)]) is False)
    check("decide.populated_true",
          decide_vgpu_capable([parse_vgpu_listing(VGPU_POPULATED_SAMPLE)]) is True)
    check("decide.uninterpretable_unknown",
          decide_vgpu_capable([parse_vgpu_listing(VGPU_ACTIVE_TABLE_SAMPLE)]) is None)
    check("decide.mixed_any_true_wins",
          decide_vgpu_capable([parse_vgpu_listing(BI100_VGPU_S_SAMPLE),
                               parse_vgpu_listing(VGPU_POPULATED_SAMPLE)]) is True)

    # -- symbol_scan
    blob = b"\0nvmlDeviceCreateGpuInstance\0nvmlSetVgpuVersion\0"
    check("symbols.found", symbol_scan(blob, SEG_LIB_SYMBOLS) ==
          ["nvmlDeviceCreateGpuInstance", "nvmlSetVgpuVersion"])
    check("symbols.absent_data", symbol_scan(None, SEG_LIB_SYMBOLS) == [])
    check("symbols.absent_empty", symbol_scan(b"", SEG_LIB_SYMBOLS) == [])

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


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
    segmentation = probe_segmentation(hardware.get("vendor_tools") or [])
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
        "segmentation": segmentation,
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
    ap.add_argument("--selftest", action="store_true",
                    help="pure-function self-test (segmentation parsers); "
                         "exit 0 iff zero failures")
    args = ap.parse_args(argv)

    if args.selftest:
        return cmd_selftest(args)

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
    seg = report.get("segmentation") or {}
    print(f"probe/1: accel=[{acc}] engines=[{eng}] "
          f"inference_services={[s['port'] for s in svc]} egress=[{egr}] "
          f"seg[vgpu_capable={seg.get('vgpu_capable')}]",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
