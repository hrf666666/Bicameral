#!/usr/bin/env python3
"""bench8: fixed 8-prompt TTFT/prefill/decode measurement — llama.cpp native /completion.

Mirrors perf-jetson methodology exactly (results/2026-10-14-probe-bench/perf-jetson.json):
  endpoint     POST /completion, stream=true
  params       n_predict=128, temperature=0.0, cache_prompt=false
  ttft_ms      client wall clock: t(first SSE chunk with non-empty content) - t(request sent)
  prefill_tps  server-reported timings.prompt_per_second (final chunk)
  decode_tps   server-reported timings.predicted_per_second (final chunk);
               cross-checked client-side

stdlib-only. Usage:
  python3 bench8.py --base-url http://127.0.0.1:29600 --prompts prompts-8.json \
      --out bench_raw.json [--repeats 1] [--tag bi150]
"""
import argparse, json, statistics, time, urllib.request


def stream_once(base, prompt, n_predict, timeout=600):
    body = json.dumps({"prompt": prompt, "n_predict": n_predict,
                       "temperature": 0.0, "cache_prompt": False,
                       "stream": True}).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/completion", data=body,
        headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    ttft = None
    n_chunks = 0
    timings = None
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                ev = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(ev.get("timings"), dict):
                timings = ev["timings"]
            if ev.get("content"):
                if ttft is None:
                    ttft = time.perf_counter() - t0
                n_chunks += 1
    total = time.perf_counter() - t0
    return {"ttft_s": ttft, "total_s": total, "n_chunks": n_chunks,
            "timings": timings}


def rec_from_run(prompt, m):
    t = m["timings"] or {}
    ttft = m["ttft_s"]
    rec = {"prompt": prompt,
           "ttft_ms": round(ttft * 1000, 2) if ttft else None,
           "prompt_n": t.get("prompt_n"),
           "prompt_ms": t.get("prompt_ms"),
           "prefill_tps": t.get("prompt_per_second"),
           "predicted_n": t.get("predicted_n"),
           "predicted_ms": t.get("predicted_ms"),
           "decode_tps": t.get("predicted_per_second"),
           "client_decode_tps": (round(m["n_chunks"] / (m["total_s"] - ttft), 2)
                                 if ttft and m["total_s"] > ttft else None)}
    return rec


def stat_block(vals):
    return {"mean": round(statistics.fmean(vals), 2),
            "median": round(statistics.median(vals), 2),
            "min": round(min(vals), 2), "max": round(max(vals), 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--n-predict", type=int, default=None)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--tag", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.prompts) as f:
        pf = json.load(f)
    prompts = pf["prompts"]
    gp = pf.get("genParams", {})
    n_predict = args.n_predict or gp.get("n_predict", 128)

    meta = {"tag": args.tag, "base_url": args.base_url,
            "prompts_file": args.prompts, "prompts": prompts,
            "endpoint": "POST /completion (native, stream=true)",
            "n_predict": n_predict, "temperature": gp.get("temperature", 0.0),
            "cache_prompt": False, "repeats": args.repeats,
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    w = stream_once(args.base_url, prompts[0], 16)
    meta["warmup"] = {"prompt_head": prompts[0], "n_predict": 16,
                      "ttft_ms": round(w["ttft_s"] * 1000, 2) if w["ttft_s"] else None}
    print("warmup:", meta["warmup"], flush=True)

    rows = []
    for i, p in enumerate(prompts):
        for r in range(args.repeats):
            m = stream_once(args.base_url, p, n_predict)
            rec = rec_from_run(p, m)
            rec = {"idx": i, "repeat": r, **rec}
            rows.append(rec)
            print(rec, flush=True)

    ok = [r for r in rows if r["ttft_ms"] and r["prefill_tps"] and r["decode_tps"]]
    summary = {
        "n_runs": len(rows), "n_ok": len(ok),
        "ttft_ms": stat_block([r["ttft_ms"] for r in ok]) if ok else None,
        "prefill_tps": stat_block([r["prefill_tps"] for r in ok]) if ok else None,
        "decode_tps": stat_block([r["decode_tps"] for r in ok]) if ok else None,
    }
    out = {"schema": "bench8-raw/1", "meta": meta, "summary": summary, "runs": rows}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print(json.dumps(summary, indent=1), flush=True)


if __name__ == "__main__":
    main()
