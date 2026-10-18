# Bicameral

> Master-edge permission and orchestration layer for LLM agent fleets: HMAC capability tokens, an ordered default-deny chain, a self-x node agent (sense / diagnose / adapt / self-check), and a tiered deployment policy (GPU-first → Strata for VRAM overflow → CPU fallback). Standard library only.
>
> 中文说明见 [README.zh-CN.md](README.zh-CN.md) · 设计文档 [docs/architecture.md](docs/architecture.md) · 范式 [docs/paradigm.md](docs/paradigm.md)

**Bottom line**: three heterogeneous devices ONLINE as one governed fleet (x86_64 + aarch64; Iluvatar CoreX + NVIDIA CUDA); the same task/1 executed on every device through its own permission layer with schema-identical, judge-scored delivery; a bare node reached READY autonomously in 310 s (zero-touch: toolchain self-install, native build, self-check); a Qwen3.8-27B diagnosis brain self-repaired unknown failures in 1 round each. ~14,700 lines of stdlib Python across nine components; three red-team rounds + four review rounds (~60 findings fixed); every number in this README traces to an audited record in `results/`.

## 1. What problem it solves

A master LLM session can wake agents on edge devices and hand them tools. Handing tools to agents fails in four ways, and prompt-time controls **fail open**:

| Failure mode | Typical form | Bicameral's control |
|---|---|---|
| Privilege escalation | agent calls a tool outside its grant; path escapes the data scope | per-call HMAC verification + tool allow-list + realpath scope check |
| Injection | instructions smuggled in task text; poisoned file contents reach the LLM | payload injection scan + NUL rejection + response-side smuggle stripping on every channel |
| Replay / forgery | stolen token replayed (even across restarts); payload tampered; attacker-signed tokens | HMAC verify + persisted per-jti nonce partition + strict TTL + device-side audit digests |
| Overflow | unbounded calls, oversized payloads, runaway LLM spend | 3-dimension budget ledger (calls / llm_calls / bytes) + size caps + per-model token caps |

The principle: **the constraint lives at the execution gate, not in the prompt.** Every tool call is checked against a signed capability token (`cap/3`) and an ordered deny-chain of sixteen checks (D1–D16, first match rejects); anything that fails to verify is rejected fail-closed and written to a hash-chained audit log with an externally anchorable tail.

## 2. Components

| Component | What it does |
|---|---|
| `bicameral/server.py` | the permission layer: control plane (`/issue`, `/audit`, `/capabilities`, `/healthz`; token-authed, TLS/mTLS optional) + agent plane (`/agent/invoke`, D1–D16 deny-chain); ledger persistence; `/no_think` + token-cap controls for reasoning models |
| `bicameral/probe.py` | device self-inventory (probe/1): hardware, accelerator vendors, runtimes, installed engines/models, listening services, install-state, segmentation capability |
| `bicameral/install.py` | governed installs: engine tarballs + model shards (streaming sha256, mirror fallback, flock, rollback, idempotent dedup) |
| `bicameral/nodeagent.py` | the self-x layer: sense → diagnose (rule table) → adapt (apt self-install, native build) → verify → escalate; one command takes a bare node to READY |
| `bicameral/fleet.py` | pull-mode heartbeat + ONLINE/STALE/OFFLINE registry; `daemon` subcommand + systemd units; audit-tail anchoring |
| `bicameral/pipeline.py` | the original-vision closed loop: task/1 → ROUTE → per-device execution → 27B judge against quality_bar → delivery/1 |
| `scripts/repair.py` | LLM-driven repair brain for unknown failures: typed JSON plans, policy gate, bounded rounds, full audit |
| `scripts/powerbench.py` / `qualitybench.py` / `bench.py` | measured power (vendor samplers), GSM8K-mini quality sampling, concurrency sweeps |

## 3. Measured (not claimed)

Full matrix in [results/2026-10-17-ucb/](results/2026-10-17-ucb/); per-round evidence in `results/` (14 dated directories) and [docs/redteam/](docs/redteam/).

| Dimension | Result |
|---|---|
| Permission-chain throughput | 1,433.7 req/s @ concurrency 1 (p50 0.68 ms, zero errors) through the full deny-chain |
| Tiered deployment | Jetson CUDA GPU tier 67.48 tok/s (0.6B); bi150 Strata tier 2.41 tok/s (Flash-Next, 0 NaN); bi150 CPU tier 5.21 tok/s (27B) |
| Quality sampling (GSM8K-mini 20) | 27B 100%; 0.6B 0% first-digit / 95% last-digit (rubric documented) |
| Concurrency sweep (27B) | aggregate decode 5.23 → 12.65 tok/s (c1→c4, ×2.42 sublinear); single-stream 5.5 → 3.2 |
| 27B power | 330.3 W flat (CPU inference; GPU idle — the objective data) |
| Red team | round 1: 14 attacks (3 breached → fixed); round 2: 17 retested (16 as designed); capability round: supply-chain/traversal/injection blocked |

## 4. Quick start

```bash
# 30-second end-to-end verification (spawns an isolated instance, 7 steps)
python3 examples/quickstart.py

# run the layer; control-plane auth is fail-closed — set a token
BICAMERAL_ADMIN_TOKEN=$(openssl rand -hex 16) python3 bicameral/server.py

# issue a capability token (control plane requires the admin token)
curl -s -X POST http://127.0.0.1:18000/issue -H 'Content-Type: application/json' \
  -H "X-Admin-Token: $BICAMERAL_ADMIN_TOKEN" \
  -d '{"agent":"agent-ro","task_id":"t1","tools":["fs.read"],"ttl_s":600,
       "budget":{"calls":10,"llm_calls":0,"bytes":65536}}'

# carry it on every call; a repeated nonce is rejected as a replay
curl -s -X POST http://127.0.0.1:18001/agent/invoke \
  -H 'Content-Type: application/json' -H 'X-Capability-Token: <token>' \
  -d '{"nonce":"n-1","tool":"fs.read","params":{"path":"/tmp/bicameral/data/notes.txt"}}'
```

Autonomous onboarding of a bare node (self-installs the toolchain, builds natively, self-checks to READY):

```bash
python3 bicameral/nodeagent.py bootstrap --appspec examples/appspec-qwen3-0.6b-q8_0.json \
  --sandbox /tmp/bicameral-node --engine-source-tgz /path/to/llama-src.tgz
```

## 5. Deploy & operate

```bash
ADMIN_TOKEN=<token> [NO_THINK=1] [LLM_MAX_TOKENS=512] [TLS_CERT=… TLS_KEY=…] \
  HOST=<host> PORT=22 USER=root ./scripts/deploy.sh     # fingerprint-asserted deploy
python3 scripts/live_check.py --admin-token <token> \
  --expect-sha $(sha256sum bicameral/server.py | cut -c1-16)   # 25-check regression
make bench                                              # throughput bench against a running instance
```

The deployment fails loudly unless the remote instance's `build_sha` equals the local `sha256sum` — this assertion has caught real version drift. `fleet.py daemon` (systemd units in `deploy/systemd/`) keeps the device registry fresh and anchors the audit tail every cycle.

## 6. Boundaries — status

Resolved: control-plane auth (token; mTLS optional), ledger persistence, throughput measured, encrypted data plane (TLS/mTLS), audit-tail anchoring automation, engine-level installs, card-segmentation probing (definitive: not available in-container on current driver), reasoning-model support.

Still boundaries:

- Schema-valid ≠ semantically correct: factual accuracy of LLM output stays out of scope for the permission layer; the governed `judge` subject, task/1 `quality_bar`, and the 27B evaluation brain are the hooks.
- The regex injection scan is best-effort; NUL payloads are rejected at schema, and the deny-chain remains the real gate.
- Fleet registry rendering shows a pre-update age column (data on disk is fresh); mTLS client rollout beyond the server side is v2.

## 7. Design docs

- [docs/architecture.md](docs/architecture.md) — the permission layer (tokens, deny-chain, budgets, audit, three red-team rounds).
- [docs/paradigm.md](docs/paradigm.md) — the orchestration paradigm: device sensing (§3.1), capability (§3.2), benchmark (§3.3), governed installs (§3.4), unified tasks (§3.5), autonomy layer (§10), model-driven repair (§11), original-vision closure (§12–13).

## License

[MIT](LICENSE)
