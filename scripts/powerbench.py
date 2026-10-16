#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bicameral power-aware inference benchmark against a RUNNING llama-server.

Closes the paradigm gap "功耗（有 tegrastats/ixsmi 则采，无则标 null）"
(docs/paradigm.md, bench/1 PerfRecord): drives chat completions against an
OpenAI-compatible local endpoint while a power sampler (ixsmi on bi150,
tegrastats on Jetson) runs alongside, then assembles a bench/1-style record.

RED LINE — read-only use of the serving process: the script only ever sends
GET /health, GET /v1/models and POST /v1/chat/completions to --base. It never
starts, restarts, reconfigures or otherwise touches the server.

Per prompt x run:
  - streaming (default): TTFT = latency of the first chunk carrying content or
    reasoning_content; decode tok/s = usage.completion_tokens / (last content
    chunk time - first content chunk time); an e2e tok/s over the whole
    round-trip is recorded as a cross-check. Reasoning models may spend the
    whole max_tokens budget on reasoning_content and return an empty body —
    that is recorded as-is (usage + finish_reason), never judged away.
  - non-streaming (--no-stream): ttft_ms holds the TOTAL latency (marked as
    such); if usage carries any recomputation field it is noted verbatim.

Power: the --sampler command is spawned in the background before the first
request (shell string, "{out}" is replaced by the raw sample file path) and
stopped after the last one. One line per --sample-interval seconds is assumed.
Parsing is deliberately tolerant (pure numeric extraction):
  ixsmi csv    "gpu.power.draw [W]" / "power.draw [W]" headers, rows "37 W"
               or "37 W, 38 W" (one cell per GPU), "[N/A]" cells skipped
  tegrastats   "... VDD_IN 5000mW ..." or "VDD_IN 5123/5021mW" -> watts

Sampler default per --device:
  bi150   LD_LIBRARY_PATH=/usr/local/corex/lib:/usr/local/iluvatar/lib
          /usr/local/corex/bin/ixsmi --query-gpu=gpu.power.draw --format=csv
          -l {interval} -f {out}
          (the literally-specified field "power.draw" is REJECTED by this
          ixsmi — "Field \"power.draw\" is not a valid field to query",
          measured 2026-10-16; gpu.power.draw is the equivalent real field)
  jetson  tegrastats --interval {interval_ms} > {out}

Usage:
  python3 scripts/powerbench.py --base http://127.0.0.1:8960 \
      --device bi150 --model-label Qwen3-27B \
      --out results/2026-10-16-power-bench
  python3 scripts/powerbench.py --selftest    # pure functions, no network

Exit codes: 0 measured; 2 serving endpoint unreachable / unhealthy (an honest
powerbench-error.json/.md is written, never a fabricated record).
"""

import argparse
import http.client
import json
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_BASE = "http://127.0.0.1:8960"
DEFAULT_OUT = "results/2026-10-16-power-bench"
DEFAULT_SAMPLERS = {
    "bi150": ("LD_LIBRARY_PATH=/usr/local/corex/lib:/usr/local/iluvatar/lib "
              "/usr/local/corex/bin/ixsmi --query-gpu=gpu.power.draw "
              "--format=csv -l {interval} -f {out}"),
    "jetson": "tegrastats --interval {interval_ms} > {out}",
}
BUILTIN_PROMPTS = [
    "The capital of France is",
    "Write a haiku about rain.",
    "Explain what a hash table is in one sentence.",
    "用一句话介绍冒泡排序。",
    "List three primary colors.",
    "Summarize the plot of Romeo and Juliet in two sentences.",
]
WARMUP_PROMPT = "Reply with exactly: ok"
RE_VDD = re.compile(r"VDD_IN (\d+)(?:/(\d+))?mW")


def fail(msg):
    sys.exit("powerbench: " + msg)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# pure functions (covered by --selftest; no I/O, no clocks, no network)
# --------------------------------------------------------------------------- #

def parse_power_samples(text):
    """Tolerant parse of a raw sampler log -> dict.

    Returns {"format": "ixsmi-csv"|"tegrastats"|None, "watts": [float...],
    "gpus_seen": int|None, "skipped_lines": int}. Mixed logs: tegrastats
    VDD_IN wins for its lines; every other line goes through the numeric
    ixsmi-csv path.
    """
    watts, skipped, fmt, gpus = [], 0, None, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "VDD_IN" in line:
            fmt = fmt or "tegrastats"
            m = RE_VDD.search(line)
            if m:
                watts.append(float(m.group(1)) / 1000.0)
            else:
                skipped += 1
            continue
        low = line.lower()
        if ("power.draw" in low or not any(c.isdigit() for c in line)
                or "[na]" in low or "[n/a]" in low or "not supported" in low):
            skipped += 1                       # header / non-numeric / N/A row
            continue
        vals = []
        for cell in line.split(","):
            cell = cell.strip()
            if cell.lower().endswith("w"):
                cell = cell[:-1].strip()
            try:
                vals.append(float(cell))
            except ValueError:
                continue                       # tolerant: drop non-numeric cell
        if not vals:
            skipped += 1
            continue
        if gpus is None:
            gpus = len(vals)                   # cells per row == GPUs per sweep
        fmt = fmt or "ixsmi-csv"
        watts.extend(vals)
    if fmt is None and watts:
        fmt = "ixsmi-csv"
    return {"format": fmt, "watts": watts, "gpus_seen": gpus,
            "skipped_lines": skipped}


def power_block(parsed, sampler_cmd, window_s, raw_name, err_tail):
    """power section of the record; paradigm rule: 采不到就如实 null。"""
    watts = parsed["watts"]
    return {
        "mean_w": round(sum(watts) / len(watts), 2) if watts else None,
        "peak_w": round(max(watts), 2) if watts else None,
        "sampler": sampler_cmd,
        "format": parsed["format"],
        "samples": len(watts),
        "gpus_seen": parsed["gpus_seen"],
        "window_s": round(window_s, 2) if window_s is not None else None,
        "skipped_lines": parsed["skipped_lines"],
        "raw_file": raw_name,
        "sampler_stderr_tail": err_tail,
    }


def decode_tps(completion_tokens, first_s, last_s):
    """completion_tokens / generation window (first..last content chunk)."""
    if (completion_tokens is None or first_s is None or last_s is None
            or last_s <= first_s or completion_tokens <= 0):
        return None
    return completion_tokens / (last_s - first_s)


def agg(vals, nd=2):
    """mean/median/min/max block; empty -> all None."""
    if not vals:
        return {"mean": None, "median": None, "min": None, "max": None, "n": 0}
    return {"mean": round(sum(vals) / len(vals), nd),
            "median": round(statistics.median(vals), nd),
            "min": round(min(vals), nd), "max": round(max(vals), nd),
            "n": len(vals)}


def assemble_record(device, model_label, model_id, engine, base, protocol,
                    prompts, rows, power, notes):
    """bench/1-style record; carries the flat keys the paradigm requires."""
    ok_rows = [r for r in rows if r.get("error") is None]
    ttfts = [r["ttft_ms"] for r in ok_rows if r.get("ttft_ms") is not None]
    decodes = [r["decode_tps"] for r in ok_rows if r.get("decode_tps") is not None]
    ctoks = [r["completion_tokens"] for r in ok_rows
             if isinstance(r.get("completion_tokens"), int)]
    empty = [r for r in ok_rows
             if r.get("content_chars") == 0 and r.get("error") is None]
    rec = {
        "schema": "bench/1",
        "device": device,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "generated_at": now_iso(),
        "model": {"label": model_label, "server_id": model_id},
        "engine": engine,
        "ttft_ms": agg(ttfts)["mean"],
        "decode_tps": agg(decodes)["mean"],
        "prompts_n": len(prompts),
        "power": power,
        "protocol": protocol,
        "per_prompt": rows,
        "summary": {
            "ttft_ms": agg(ttfts),
            "decode_tps": agg(decodes),
            "completion_tokens": agg(ctoks, nd=1),
            "runs_total": len(rows),
            "runs_ok": len(ok_rows),
            "runs_failed": len(rows) - len(ok_rows),
            "runs_with_empty_content": len(empty),
            "content_chars_total": sum(r.get("content_chars", 0) for r in ok_rows),
            "reasoning_chars_total": sum(r.get("reasoning_chars", 0) for r in ok_rows),
        },
        "notes": notes,
    }
    return rec


def render_markdown(rec):
    """Human-readable twin of the record (Chinese, repo doc style)."""
    eng = rec.get("engine") or {}
    p = rec.get("protocol") or {}
    pw = rec.get("power") or {}
    s = rec.get("summary") or {}
    out = []
    out.append("# power-%s — bench/1 实测记录（%s，带功耗采样）"
               % (rec.get("device"), rec.get("date")))
    out.append("")
    out.append("- **设备**: %s　**base**: `%s`" % (rec.get("device"), eng.get("endpoint")))
    out.append("- **模型**: %s（server_id `%s`）　**引擎**: %s"
               % ((rec.get("model") or {}).get("label"),
                  (rec.get("model") or {}).get("server_id"), eng.get("name")))
    out.append("- **协议**: `POST /v1/chat/completions`，stream=%s，max_tokens=%s，"
               "temperature=%s，每 prompt %s 次，%s 条 prompt，warmup 1 次不计入"
               % (p.get("stream"), p.get("max_tokens"), p.get("temperature"),
                  p.get("runs_per_prompt"), rec.get("prompts_n")))
    out.append("- **TTFT 口径**: 首 content/reasoning_content chunk 时延"
               + ("（非流式：ttft_ms 为总时延）" if not p.get("stream") else "")
               + "；**decode** = usage.completion_tokens / 生成窗口")
    out.append("")
    t = s.get("ttft_ms") or {}
    d = s.get("decode_tps") or {}
    out.append("## 汇总")
    out.append("")
    out.append("| 指标 | 值（均值；中位/最小/最大） |")
    out.append("|---|---|")
    out.append("| TTFT ms | %s（%s / %s / %s，n=%s） |"
               % (_f(t.get("mean"), 2), _f(t.get("median"), 2),
                  _f(t.get("min"), 2), _f(t.get("max"), 2), t.get("n")))
    out.append("| decode tok/s | %s（%s / %s / %s，n=%s） |"
               % (_f(d.get("mean"), 2), _f(d.get("median"), 2),
                  _f(d.get("min"), 2), _f(d.get("max"), 2), d.get("n")))
    out.append("| completion tokens/run | 均值 %s |"
               % _f((s.get("completion_tokens") or {}).get("mean"), 1))
    out.append("| 正文为空的 run | %s / %s（推理模型上限截断现象，如实记录） |"
               % (s.get("runs_with_empty_content"), s.get("runs_ok")))
    out.append("")
    out.append("## 功耗（%s）" % (pw.get("format") or "未采到"))
    out.append("")
    out.append("| 均值 W | 峰值 W | 样本数 | GPU 数 | 窗口 s |")
    out.append("|---:|---:|---:|---:|---:|")
    out.append("| %s | %s | %s | %s | %s |"
               % (_f(pw.get("mean_w"), 2), _f(pw.get("peak_w"), 2),
                  pw.get("samples"), pw.get("gpus_seen"), pw.get("window_s")))
    out.append("")
    out.append("采样器：`%s`" % pw.get("sampler"))
    out.append("")
    out.append("## 逐 prompt")
    out.append("")
    out.append("| # | run | prompt（截断） | TTFT ms | decode tok/s | ctok | 正文 | reasoning | finish |")
    out.append("|---:|---:|---|---:|---:|---:|---:|---:|---|")
    for i, r in enumerate(rec.get("per_prompt") or []):
        prev = (r.get("prompt") or "").replace("|", "\\|")
        if len(prev) > 32:
            prev = prev[:32] + "…"
        out.append("| %d | %s | %s | %s | %s | %s | %s | %s | %s |"
                   % (i + 1, r.get("run"), prev,
                      _f(r.get("ttft_ms"), 1), _f(r.get("decode_tps"), 2),
                      r.get("completion_tokens"), r.get("content_chars"),
                      r.get("reasoning_chars"), r.get("finish_reason")))
    out.append("")
    if rec.get("notes"):
        out.append("## 注意事项")
        out.append("")
        for i, n in enumerate(rec["notes"], 1):
            out.append("%d. %s" % (i, n))
        out.append("")
    return "\n".join(out)


def _f(v, nd=2):
    return "-" if v is None else ("%." + str(nd) + "f") % v


def render_error_md(err):
    """Human-readable twin of powerbench-error.json."""
    out = []
    out.append("# powerbench 实测失败记录（%s，%s）" % (err.get("device"), err.get("date")))
    out.append("")
    out.append("- **base**: `%s`" % err.get("base"))
    out.append("- **失败类别**: %s" % (err.get("error") or {}).get("kind"))
    out.append("- **细节**: %s" % (err.get("error") or {}).get("detail"))
    out.append("- **探针证据**: %s" % json.dumps(err.get("probes"), ensure_ascii=False))
    out.append("")
    for n in err.get("notes", []):
        out.append("- %s" % n)
    out.append("")
    out.append("按约定如实记 error，不修饰、不补测、不编造。")
    out.append("")
    return "\n".join(out)


def selftest():
    """Assert the pure-function layer; exit 0/1. No network, no sampler."""
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name
              + ("" if cond else " | " + str(detail)))
        if not cond:
            ok = False

    # --- power parsing: ixsmi csv ("123.45 W"), incl. header + [N/A] + 8-GPU rows
    txt = ("gpu.power.draw [W]\n"
           "123.45 W\n"
           "[N/A]\n"
           "37 W, 38 W\n"
           "\n"
           "power.draw [W]\n")
    p = parse_power_samples(txt)
    check("ixsmi watts extracted", p["watts"] == [123.45, 37.0, 38.0], p)
    check("ixsmi format detected", p["format"] == "ixsmi-csv", p)
    check("ixsmi header/NA skipped", p["skipped_lines"] == 3, p)
    check("ixsmi gpus_seen = first row cells", p["gpus_seen"] == 1, p)
    p8 = parse_power_samples("gpu.power.draw [W]\n37 W, 39 W, 39 W, 39 W, 44 W, 46 W, 44 W, 45 W\n")
    check("ixsmi 8-GPU row", p8["watts"] == [37.0, 39.0, 39.0, 39.0, 44.0, 46.0, 44.0, 45.0]
          and p8["gpus_seen"] == 8, p8)
    pb = parse_power_samples("41.82\n40.10\n")   # bare numeric tolerance
    check("bare numeric rows", pb["watts"] == [41.82, 40.10], pb)

    # --- power parsing: tegrastats ("VDD_IN 5000mW")
    tg = ("RAM 2000/15000MB (lfb 4x4MiB) SWAP 0/7600MB (cache 100MB) "
          "CPU [1%@102,0%@102,0%@102] GR3D_FREQ 0% "
          "VDD_IN 5000mW VDD_GPU_SOC 1500mW cv0-0-cpu 39C\n")
    pt = parse_power_samples(tg)
    check("tegrastats VDD_IN -> 5.0 W", pt["watts"] == [5.0], pt)
    check("tegrastats format detected", pt["format"] == "tegrastats", pt)
    pt2 = parse_power_samples("VDD_IN 5123/5021mW \nVDD_IN 4800mW\n")
    check("tegrastats cur/avg + bare", pt2["watts"] == [5.123, 4.8], pt2)

    # --- power block: empty parse -> honest nulls (paradigm: 无则标 null)
    blk = power_block({"format": None, "watts": [], "gpus_seen": None,
                       "skipped_lines": 0}, "cmd {out}", 1.0, "f.csv", [])
    check("power block nulls when unsampled",
          blk["mean_w"] is None and blk["peak_w"] is None, blk)
    blk2 = power_block(parse_power_samples("100 W\n200 W\n"), "cmd", 9.0, "f.csv", [])
    check("power block mean/peak", blk2["mean_w"] == 150.0 and blk2["peak_w"] == 200.0, blk2)

    # --- TTFT / decode computation
    check("decode 64 tok over 1.0 s", decode_tps(64, 0.5, 1.5) == 64.0)
    check("decode fractional", abs(decode_tps(30, 0.0, 2.0) - 15.0) < 1e-12)
    check("decode zero window -> None", decode_tps(64, 1.0, 1.0) is None)
    check("decode missing tokens -> None", decode_tps(None, 0.0, 1.0) is None)
    check("decode negative window -> None", decode_tps(64, 2.0, 1.0) is None)
    check("decode non-positive tokens -> None", decode_tps(0, 0.0, 1.0) is None)

    # --- record assembly: required flat keys + null-power path
    rows = [
        {"prompt": "p1", "run": 0, "mode": "stream", "ttft_ms": 120.0,
         "decode_tps": 10.0, "completion_tokens": 64, "prompt_tokens": 10,
         "content_chars": 5, "reasoning_chars": 300, "chunks": 64,
         "finish_reason": "length", "error": None},
        {"prompt": "p1", "run": 1, "mode": "stream", "ttft_ms": 130.0,
         "decode_tps": 20.0, "completion_tokens": 64, "prompt_tokens": 10,
         "content_chars": 0, "reasoning_chars": 320, "chunks": 64,
         "finish_reason": "length", "error": None},
        {"prompt": "p2", "run": 0, "mode": "stream", "ttft_ms": None,
         "decode_tps": None, "completion_tokens": None, "prompt_tokens": None,
         "content_chars": 0, "reasoning_chars": 0, "chunks": 0,
         "finish_reason": None, "error": "HTTP 500: boom"},
    ]
    pw = power_block(parse_power_samples("100 W\n"), "sampler-cmd", 5.0, "f", [])
    rec = assemble_record(
        "bi150", "Qwen3-27B", "qwen-id", {"name": "llama-server"},
        "http://127.0.0.1:8960", {"stream": True, "max_tokens": 64},
        ["p1", "p2"], rows, pw,
        ["note about empty content phenomenon"])
    for key in ("schema", "device", "model", "engine", "ttft_ms", "decode_tps",
                "prompts_n", "power", "date", "notes"):
        check("record has %s" % key, key in rec, sorted(rec))
    check("record schema bench/1", rec["schema"] == "bench/1")
    check("record ttft mean", rec["ttft_ms"] == 125.0, rec["ttft_ms"])
    check("record decode mean", rec["decode_tps"] == 15.0, rec["decode_tps"])
    check("record prompts_n", rec["prompts_n"] == 2)
    check("record power flat keys",
          rec["power"]["mean_w"] == 100.0 and rec["power"]["peak_w"] == 100.0
          and rec["power"]["sampler"] == "sampler-cmd", rec["power"])
    check("record empty-content runs counted",
          rec["summary"]["runs_with_empty_content"] == 1
          and rec["summary"]["runs_ok"] == 2
          and rec["summary"]["runs_failed"] == 1, rec["summary"])
    check("record keeps per-prompt detail", len(rec["per_prompt"]) == 3)

    # --- markdown rendering carries the key numbers
    md = render_markdown(rec)
    for frag in ("bench/1", "TTFT", "decode tok/s", "峰值 W", "sampler-cmd",
                 "125.00", "15.00", "注意事项", "empty content phenomenon",
                 "推理模型上限截断现象"):
        check("md contains %r" % frag, frag in md)

    # --- error record rendering
    emd = render_error_md({"device": "bi150", "date": "2026-10-16",
                           "base": "http://127.0.0.1:8960",
                           "error": {"kind": "unreachable", "detail": "refused"},
                           "probes": {"models": None}, "notes": ["n1"]})
    check("error md carries kind/detail", "unreachable" in emd and "refused" in emd)

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# HTTP plumbing (read-only: GET probes + POST /v1/chat/completions, nothing else)
# --------------------------------------------------------------------------- #

def http_get(base, path, timeout=6):
    """GET base+path -> (status|None, headers-dict, body-str). Never raises."""
    url = base.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return None, {}, "%s: %s" % (type(e).__name__, e)


def url_host_port(base):
    m = re.match(r"^https?://([^/:]+)(?::(\d+))?/?$", base.strip())
    if not m:
        fail("bad --base %r (need http://host:port)" % base)
    host, port = m.group(1), m.group(2)
    return host, int(port or 80)


def find_recompute_keys(obj, prefix=""):
    """All (path, value) whose key mentions recomputation (non-stream note)."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = "%s.%s" % (prefix, k) if prefix else str(k)
            if re.search(r"recomput", str(k), re.I):
                hits.append((kp, v))
            hits.extend(find_recompute_keys(v, kp))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(find_recompute_keys(v, "%s[%d]" % (prefix, i)))
    return hits


def chat_once(host, port, payload, timeout, stream):
    """One measured chat completion. Returns a per-run row dict.

    Streaming: TTFT = first content/reasoning chunk latency; generation window
    = first..last content chunk; decode = usage.completion_tokens / window
    (falls back to counting chunks when the server omits usage). Non-stream:
    ttft_ms = total latency (mode marked); usage recomputation noted verbatim.
    """
    mode = "stream" if stream else "non-stream"
    row = {"mode": mode, "ttft_ms": None, "decode_tps": None,
           "decode_tps_e2e": None, "completion_tokens": None,
           "completion_tokens_source": None, "prompt_tokens": None,
           "content_chars": 0, "reasoning_chars": 0, "chunks": 0,
           "finish_reason": None, "recompute_fields": None,
           "saw_done": False, "error": None}
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    t0 = time.perf_counter()
    try:
        body = json.dumps(payload).encode("utf-8")
        conn.request("POST", "/v1/chat/completions", body=body,
                     headers={"Content-Type": "application/json",
                              "Accept": "text/event-stream" if stream
                              else "application/json"})
        rsp = conn.getresponse()
        if rsp.status != 200:
            raw = rsp.read().decode("utf-8", "replace")
            row["error"] = "HTTP %s: %s" % (rsp.status, raw[:300])
            return row
        if not stream:
            obj = json.loads(rsp.read().decode("utf-8", "replace"))
            total = time.perf_counter() - t0
            row["ttft_ms"] = round(total * 1000.0, 2)   # non-stream: total only
            row["chunks"] = 1
            usage = obj.get("usage") or {}
            ct = usage.get("completion_tokens")
            if isinstance(ct, int):
                row["completion_tokens"] = ct
                row["completion_tokens_source"] = "usage"
                row["decode_tps"] = decode_tps(ct, 0.0, total)
                row["decode_tps_e2e"] = row["decode_tps"]
            pt = usage.get("prompt_tokens")
            if isinstance(pt, int):
                row["prompt_tokens"] = pt
            ch = obj.get("choices") or []
            if ch:
                row["finish_reason"] = ch[0].get("finish_reason")
                msg = ch[0].get("message") or {}
                row["content_chars"] = len(msg.get("content") or "")
                row["reasoning_chars"] = len(msg.get("reasoning_content") or "")
            hits = find_recompute_keys(obj)
            if hits:
                row["recompute_fields"] = hits[:8]
            return row

        usage, first_s, last_s = None, None, None
        for raw in rsp:                                 # SSE, line by line
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                row["saw_done"] = True
                break
            try:
                obj = json.loads(data)
            except ValueError:
                continue
            now = time.perf_counter() - t0
            if isinstance(obj.get("usage"), dict):
                usage = obj["usage"]
            ch = obj.get("choices") or []
            if not ch:
                continue
            delta = ch[0].get("delta") or {}
            piece = delta.get("content")
            rpiece = delta.get("reasoning_content")
            if piece or rpiece:
                if first_s is None:
                    first_s = now
                last_s = now
                row["chunks"] += 1
                if piece:
                    row["content_chars"] += len(piece)
                if rpiece:
                    row["reasoning_chars"] += len(rpiece)
            if ch[0].get("finish_reason"):
                row["finish_reason"] = ch[0]["finish_reason"]
        total = time.perf_counter() - t0
        if first_s is not None:
            row["ttft_ms"] = round(first_s * 1000.0, 2)
        ct = usage.get("completion_tokens") if isinstance(usage, dict) else None
        if isinstance(ct, int):
            row["completion_tokens"] = ct
            row["completion_tokens_source"] = "usage"
        elif row["chunks"]:
            ct = row["chunks"]                          # ~1 tok/chunk fallback
            row["completion_tokens"] = ct
            row["completion_tokens_source"] = "chunk_count(usage absent)"
        if isinstance(usage, dict):
            pt = usage.get("prompt_tokens")
            if isinstance(pt, int):
                row["prompt_tokens"] = pt
        if first_s is not None and row["completion_tokens"] is not None:
            row["decode_tps"] = decode_tps(row["completion_tokens"], first_s, last_s)
            row["decode_tps_e2e"] = decode_tps(row["completion_tokens"], 0.0, total)
        if first_s is None and row["error"] is None:
            row["error"] = "no content/reasoning chunk received (empty stream)"
        return row
    except Exception as e:
        row["error"] = "%s: %s" % (type(e).__name__, e)
        return row
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# sampler plumbing
# --------------------------------------------------------------------------- #

def start_sampler(cmd_rendered, err_path):
    errf = open(err_path, "wb")
    proc = subprocess.Popen(cmd_rendered, shell=True,
                            stdout=subprocess.DEVNULL, stderr=errf,
                            start_new_session=True)
    return proc, errf


def stop_sampler(proc, errf):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    errf.flush()
    errf.close()
    return proc.returncode


def load_prompts(path):
    if not path:
        return list(BUILTIN_PROMPTS)
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if isinstance(obj, dict):
        obj = obj.get("prompts")
    if not isinstance(obj, list) or not obj or \
            not all(isinstance(x, str) and x.strip() for x in obj):
        fail("--prompts file must hold a JSON list of non-empty strings "
             "(or {\"prompts\": [...]})")
    return obj


def write_error_record(out_dir, device, base, kind, detail, probes, extra_notes):
    os.makedirs(out_dir, exist_ok=True)
    rec = {
        "schema": "powerbench-error/1",
        "device": device,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "generated_at": now_iso(),
        "base": base,
        "model_label": None,
        "error": {"kind": kind, "detail": detail},
        "probes": probes,
        "notes": list(extra_notes) + [
            "按约定如实记 error：8960 不可达等远程失败不修饰、不重试补测、不产出 bench/1 实测数字"],
    }
    jpath = os.path.join(out_dir, "powerbench-error.json")
    mpath = os.path.join(out_dir, "powerbench-error.md")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with open(mpath, "w", encoding="utf-8") as f:
        f.write(render_error_md(rec) + "\n")
    print("powerbench: wrote %s and %s" % (jpath, mpath), file=sys.stderr)
    return jpath, mpath


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args():
    ap = argparse.ArgumentParser(
        description="power-aware chat benchmark vs a RUNNING llama-server "
                    "(read-only: health/models probes + chat completions only)")
    ap.add_argument("--base", default=DEFAULT_BASE,
                    help="llama-server base, e.g. http://127.0.0.1:8960")
    ap.add_argument("--prompts", default=None,
                    help="JSON file with the prompt list (default: 6 built-in "
                         "short prompts)")
    ap.add_argument("--max-tokens", type=int, default=64)
    ap.add_argument("--runs", type=int, default=2,
                    help="measured runs per prompt")
    ap.add_argument("--sampler", default=None,
                    help="background sampler command; \"{out}\" is replaced by "
                         "the raw sample file path (default depends on "
                         "--device: bi150 ixsmi gpu.power.draw / jetson "
                         "tegrastats)")
    ap.add_argument("--sample-interval", type=float, default=1,
                    help="sampler interval s (renders {interval}/{interval_ms} "
                         "in the default sampler commands)")
    ap.add_argument("--device", default="bi150")
    ap.add_argument("--model-label", default="Qwen3-27B")
    ap.add_argument("--model", default=None,
                    help="model id for the request (default: first id from "
                         "GET /v1/models, else --model-label)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--no-stream", action="store_true",
                    help="non-streaming requests (ttft_ms = total latency, "
                         "recomputation in usage noted)")
    ap.add_argument("--timeout", type=float, default=300,
                    help="per-request timeout s")
    ap.add_argument("--no-warmup", action="store_true")
    ap.add_argument("--note", action="append", default=None,
                    help="extra verbatim note carried into the record "
                         "(repeatable; used to preserve session evidence)")
    ap.add_argument("--selftest", action="store_true",
                    help="pure-function assertions, exit; no network")
    return ap.parse_args()


def main():
    args = parse_args()
    if args.selftest:
        return selftest()
    if args.runs < 1 or args.max_tokens < 1:
        fail("--runs and --max-tokens must be >= 1")
    prompts = load_prompts(args.prompts)
    base = args.base.rstrip("/")
    host, port = url_host_port(base)
    stream = not args.no_stream
    os.makedirs(args.out, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    cli_notes = list(args.note or [])

    # ---- preflight: honest failure if the serving endpoint is unreachable
    hstat, hhdr, hbody = http_get(base, "/health")
    mstat, mhdr, mbody = http_get(base, "/v1/models")
    probes = {
        "health": {"status": hstat, "server_header": hhdr.get("Server"),
                   "body_head": hbody[:200]},
        "v1_models": {"status": mstat, "server_header": mhdr.get("Server"),
                      "body_head": mbody[:400]},
    }
    print("powerbench: probe /health -> %s | /v1/models -> %s"
          % (hstat, mstat))
    model_id = None
    if mstat == 200:
        try:
            data = json.loads(mbody).get("data") or []
            if data and isinstance(data[0], dict):
                model_id = data[0].get("id")
        except ValueError:
            pass
    engine = {
        "name": "llama-server" if (hstat == 200 or mstat == 200) else "unknown",
        "endpoint": base,
        "api": "POST /v1/chat/completions",
        "server_header": mhdr.get("Server") or hhdr.get("Server"),
        "probes": probes,
    }
    if mstat is None and hstat is None:
        detail = ("both GET /health and GET /v1/models failed (transport): "
                  "health=%s models=%s" % (hbody[:120], mbody[:120]))
        write_error_record(args.out, args.device, base, "unreachable", detail,
                           probes, [
                               "远程失败（8960 不可达等）如实返回 error，不修饰；未发送任何 chat 请求，"
                               "在跑服务零触碰（红线：绝不重启/改配置）"] + cli_notes)
        return 2
    if mstat != 200 and hstat != 200:
        detail = ("serving endpoint not OK: /health=%s /v1/models=%s "
                  "bodies: health=%r models=%r"
                  % (hstat, mstat, hbody[:150], mbody[:150]))
        write_error_record(args.out, args.device, base, "unhealthy", detail,
                           probes, [
                               "服务端口可连但探针非 200：只读探针，未重启/未改配置；不产出 bench/1 实测数字"] + cli_notes)
        return 2

    # ---- sampler first, so it covers warmup + the whole measured window
    sampler_cmd = args.sampler
    if sampler_cmd:
        rendered = sampler_cmd.replace("{out}", os.path.join(args.out, "power-samples-%s.csv" % ts))
        rendered = rendered.replace("{interval_ms}", str(int(args.sample_interval * 1000)))
        rendered = rendered.replace("{interval}", str(args.sample_interval))
    else:
        tpl = DEFAULT_SAMPLERS.get(args.device)
        if tpl is None:
            fail("no default sampler for --device %r; pass --sampler "
                 "(\"{out}\" placeholder)" % args.device)
        rendered = (tpl.replace("{interval_ms}", str(int(args.sample_interval * 1000)))
                       .replace("{interval}", str(args.sample_interval))
                       .replace("{out}", os.path.join(args.out, "power-samples-%s.csv" % ts)))
    err_path = os.path.join(args.out, "sampler-%s.stderr" % ts)
    raw_name = "power-samples-%s.csv" % ts     # == the {out} substitution below
    try:
        proc, errf = start_sampler(rendered, err_path)
    except OSError as e:
        write_error_record(args.out, args.device, base, "sampler-failed",
                           "cannot start sampler %r: %s" % (rendered, e), probes, cli_notes)
        return 2
    t_start = time.perf_counter()
    print("powerbench: sampler started (pid %s): %s" % (proc.pid, rendered))

    notes = list(cli_notes)
    time.sleep(1.2)                       # let the first sample land
    if proc.poll() is not None:
        notes.append("采样器启动即退出 rc=%s —— 本轮 power 将如实记 null（tegrastats/ixsmi 不可用）"
                     % proc.returncode)
        print("powerbench: WARNING sampler exited early rc=%s" % proc.returncode)
    if "gpu.power.draw" in rendered:
        notes.append("任务规格字面给的 --query-gpu=power.draw 被该机 ixsmi 拒绝"
                     "（实测报错 Field \"power.draw\" is not a valid field to query，"
                     "CoreX 4.4.0 同款怪癖），改用等价实测字段 gpu.power.draw")

    model = args.model or model_id or args.model_label
    protocol = {
        "endpoint": "POST /v1/chat/completions",
        "stream": stream,
        "max_tokens": args.max_tokens,
        "temperature": 0.0,
        "runs_per_prompt": args.runs,
        "prompts": prompts,
        "prompts_source": "file" if args.prompts else "builtin-6",
        "model_request_id": model,
        "warmup": None if args.no_warmup else WARMUP_PROMPT,
        "prompt_variant_suffix": None,
        "request_timeout_s": args.timeout,
        "read_only_redline": "只发 GET /health、GET /v1/models、POST /v1/chat/completions；绝不重启/改配置",
    }
    rows = []
    try:
        # ---- warmup (unrecorded)
        if not args.no_warmup:
            wrow = chat_once(host, port, {
                "model": model,
                "messages": [{"role": "user", "content": WARMUP_PROMPT}],
                "max_tokens": min(args.max_tokens, 16),
                "temperature": 0.0, "stream": stream}, args.timeout, stream)
            if wrow["error"]:
                stop_sampler(proc, errf)
                write_error_record(args.out, args.device, base, "warmup-failed",
                                   "warmup chat completion failed: %s" % wrow["error"],
                                   probes, ["服务可达但 chat 请求失败——按约定如实报错，不产出实测数字"]
                                   + cli_notes)
                return 2
            print("powerbench: warmup ok (ttft %s ms)" % wrow["ttft_ms"])

        # ---- measured loop: prompts x runs, temperature 0, unique suffix per
        #      run so a server-side prompt cache cannot flatter the TTFT
        n = 0
        for pi, prompt in enumerate(prompts):
            for run in range(args.runs):
                suffix = "\n\n(variant %d-%d-%s)" % (pi, run, ts)
                payload = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt + suffix}],
                    "max_tokens": args.max_tokens,
                    "temperature": 0.0,
                    "stream": stream,
                }
                row = chat_once(host, port, payload, args.timeout, stream)
                row.update({"prompt": prompt, "prompt_index": pi, "run": run})
                rows.append(row)
                n += 1
                print("powerbench: [%d/%d] p%d run%d ttft=%s ms decode=%s tok/s "
                      "ctok=%s content=%d reasoning=%d finish=%s err=%s"
                      % (n, len(prompts) * args.runs, pi, run,
                         row["ttft_ms"], _f(row["decode_tps"]),
                         row["completion_tokens"], row["content_chars"],
                         row["reasoning_chars"], row["finish_reason"],
                         row["error"]))
    except KeyboardInterrupt:
        stop_sampler(proc, errf)
        print("powerbench: interrupted", file=sys.stderr)
        return 130

    # ---- stop sampler, parse power series
    t_stop = time.perf_counter()
    rc = stop_sampler(proc, errf)
    window_s = t_stop - t_start
    raw_path = os.path.join(args.out, "power-samples-%s.csv" % ts)
    raw_text = ""
    if os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
            raw_text = f.read()
    parsed = parse_power_samples(raw_text)
    err_tail = []
    if os.path.exists(err_path):
        with open(err_path, "r", encoding="utf-8", errors="replace") as f:
            err_tail = [l.strip() for l in f.readlines()[-5:] if l.strip()]
    power = power_block(parsed, rendered, window_s, os.path.basename(raw_path), err_tail)
    if not parsed["watts"]:
        notes.append("功耗未采到样本（sampler rc=%s，stderr 尾部：%s）——按范式如实记 null"
                     % (rc, err_tail or ["<empty>"]))
    else:
        notes.append("功耗为 warmup+测窗全程采样（%s 格式，%d 样本，均值含非推理间隙；"
                     "峰值为单 GPU 单样本最大值）" % (parsed["format"], len(parsed["watts"])))

    # ---- honest note about the reasoning-model empty-body phenomenon
    ok_rows = [r for r in rows if r.get("error") is None]
    empty = [r for r in ok_rows if r["content_chars"] == 0]
    if empty:
        notes.append("Qwen3 27B 为推理模型：max_tokens=%d 内 %d/%d 个 run 正文为空"
                     "（预算被 reasoning_content 占用/截断），如实记录 usage 与 finish_reason，不改判定"
                     % (args.max_tokens, len(empty), len(ok_rows)))
    if any(r.get("completion_tokens_source", "").startswith("chunk_count")
           for r in ok_rows):
        notes.append("部分 run 服务端未回 usage，completion_tokens 以 chunk 计数估计（已在逐行标注）")
    if any(r.get("mode") == "non-stream" for r in rows):
        notes.append("非流式：ttft_ms 为总时延；usage 带 recomputation 字段时已逐行注明")
    notes.append("红线遵守：仅向 %s 发送探针 GET 与 chat 请求；未重启/未改配置；"
                 "产物限于本输出目录" % base)

    record = assemble_record(args.device, args.model_label, model_id, engine,
                             base, protocol, prompts, rows, power, notes)
    jpath = os.path.join(args.out, "power-%s.json" % args.device)
    mpath = os.path.join(args.out, "power-%s.md" % args.device)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with open(mpath, "w", encoding="utf-8") as f:
        f.write(render_markdown(record) + "\n")
    print(render_markdown(record))
    print("powerbench: wrote %s and %s" % (jpath, mpath))
    return 0


if __name__ == "__main__":
    sys.exit(main())
