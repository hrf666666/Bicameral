#!/usr/bin/env python3
"""strata-jetson: power/energy analysis from a tegrastats CSV captured during benchmark runs.

Reads the CSV written by power_sampler.py, reports total-window and per-phase stats:
average rail power (mW), energy (J), and with a tokens file (--tokens N --seconds S)
an energy-per-token figure.  Without those, prints the power distribution only.
"""
import argparse, csv, statistics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--tokens", type=int, default=0, help="tokens generated in the window")
    ap.add_argument("--seconds", type=float, default=0.0, help="wall seconds of the generation window")
    ap.add_argument("--label", default="window")
    args = ap.parse_args()

    rows = []
    with open(args.csv) as f:
        for r in csv.DictReader(f):
            try:
                p = int(r["power_mw"])
            except (ValueError, KeyError):
                continue
            rows.append({"mw": p, "ram": int(r["ram_used_mb"] or 0), "gr3d": int(r["gr3d_pct"] or 0)})
    if not rows:
        print("no power rows")
        return
    mw = [r["mw"] for r in rows]
    w = [x / 1000 for x in mw]
    span_s = len(rows) * 0.2  # sampler interval
    print(f"[{args.label}] samples={len(rows)} (~{span_s:.0f}s)")
    print(f"  power W: mean {statistics.mean(w):.2f}  median {statistics.median(w):.2f}  "
          f"p95 {sorted(w)[int(len(w)*0.95)]:.2f}  max {max(w):.2f}  min {min(w):.2f}")
    print(f"  GPU (GR3D) busy %: mean {statistics.mean(r['gr3d'] for r in rows):.1f}")
    print(f"  RAM used MB: mean {statistics.mean(r['ram'] for r in rows):.0f}")
    if args.tokens and args.seconds:
        e_j = statistics.mean(w) * args.seconds
        print(f"  window: {args.tokens} tokens in {args.seconds:.0f}s -> "
              f"{e_j:.0f} J total, {e_j/args.tokens:.2f} J/token, {args.tokens/e_j*1000:.1f} tok/kJ")


if __name__ == "__main__":
    main()
