# Bicameral

> Master-edge permission layer for LLM agent orchestration: HMAC capability tokens and an ordered default-deny chain gate every tool call an edge agent makes. Single Python file, standard library only.
>
> 中文说明见 [README.zh-CN.md](README.zh-CN.md) · 设计文档 [docs/architecture.md](docs/architecture.md)

**Bottom line**: third-round red team **16/17**, live regression **24/24** on the deploy host (including the real-LLM path). Privilege escalation, token forgery and tampering, nonce replay, prompt injection (including indirect injection end-to-end through a real LLM), 2 MB payload overflow, call- and LLM-budget exhaustion, and token burning after repeated probing — all blocked. 1,006 lines, zero dependencies.

## 1. What problem it solves

A master LLM session can wake agents on edge devices and hand them tools. Handing tools to agents fails in four ways, and the common controls (prompt-time constraints, framework-built-in permissions) **fail open**: the constraint lives in the prompt, and an injection can talk its way past it.

| Failure mode | Typical form | Bicameral's control |
|---|---|---|
| Privilege escalation | agent calls a tool outside its grant; path escapes the data scope | per-call HMAC verification + tool allow-list + realpath scope check |
| Injection | instructions smuggled in task text; poisoned file contents read into the LLM | payload injection scan (D12) + response-side smuggle stripping on **every** channel |
| Replay / forgery | stolen token replayed; payload tampered; attacker-signed tokens | HMAC verify + per-jti nonce partition + strict TTL |
| Overflow | unbounded calls, oversized payloads, runaway LLM spend | 3-dimension budget ledger (calls / llm_calls / bytes) + size caps |

The principle: **the constraint lives at the execution gate, not in the prompt.** Every tool call is checked against a signed capability token (`cap/3`) and an ordered deny-chain of sixteen checks (first match rejects); anything that fails to verify is rejected fail-closed and written to a JSONL audit log that reconstructs the whole chain by `(task_id, jti)`.

## 2. Components

| Component | What it does |
|---|---|
| Control plane `:18000` | `POST /issue` issues capability tokens; `GET /audit /capabilities /healthz` |
| Agent plane `:18001` | `POST /agent/invoke` — verify, enforce, execute, audit |
| Capability token `cap/3` | payload + HMAC-SHA256: agent / task / tool allow-list / TTL / budget / policy version / tool fingerprints |
| 3-dimension budget | calls / llm_calls / bytes debited atomically; 429 carries `dim=<exhausted dimension>` |
| Inference proxy | `llm.complete` forwards to a local OpenAI-compatible backend as a governed tool: probe-driven degrade/recover, independent budget |
| Token burning | after 3 policy denials on one token (unknown tool, escalation, escape, injection), the token is void — every further call is rejected |


### The deny-chain

Every rejected call returns `reason_code = <code>/<constant>`. Sixteen checks run in a fixed order; the first match rejects:

| Code | Rejected because… |
|---|---|
| `D1` | token signature doesn't verify (forged or tampered) |
| `D2` | token expired — strict, no grace window |
| `D3` | the one-time nonce was reused (replay) |
| `D4` | token used on the wrong plane (control token on the agent plane) |
| `D16` | token burned: 3 policy denials on the same token |
| `D11` | token was issued under an older policy version |
| `D9` | body over the 64 KiB cap |
| `D5` | tool not in the registry |
| `D6` | tool not in this token's allow-list |
| `D15` | tool definition changed since the token was signed (fingerprint mismatch) |
| `D8` | parameters violate the tool's schema, or carry forbidden keys (`actions`/`tool_calls`) |
| `D12` | parameters match an injection pattern |
| `D10` | budget exhausted — 429 with `dim=` the exhausted dimension |
| `D7` | path resolves outside the token's data scope |
| `D13` | the inference backend this tool depends on is down (fail-closed, nothing forwarded) |
| `D14` | anything else threw — denied by default |

## 3. Evidence

Red-team rounds are published under [docs/redteam/](docs/redteam/) with per-case evidence:

| Round | Cases | Result |
|---|---|---|
| [v0.1 red team](docs/redteam/2026-10-14-v0.1-redteam/) | 14 attacks | 10 blocked / 3 breached / 1 env-limited → drove 10 fixes |
| [v0.2 retest](docs/redteam/2026-10-14-v0.2-retest/) | 17 | **16/17 as designed**; the one open item is a testability issue (reasoning model exhausting `max_tokens`), not a breach |
| Live regression (`scripts/live_check.py`) | 24 checks | **24/24** on the deploy host, including the real-LLM path |

Test environment: Ubuntu 24.04 container, 112 cores / 1 TB RAM, 8× Iluvatar CoreX BI-V150; inference backend llama.cpp (Qwen3 27B GGUF).

## 4. Quick start

```bash
# 30-second verification: normal round-trip + 5 attacks, each rejected at the gate
python3 examples/quickstart.py
```

```bash
# run the layer (control :18000, agent :18001); set a real master key outside experiments
python3 bicameral/server.py

# issue a read-only capability token
curl -s -X POST http://127.0.0.1:18000/issue -H 'Content-Type: application/json' \
  -d '{"agent":"agent-ro","task_id":"t1","tools":["fs.read"],"ttl_s":600,
       "budget":{"calls":10,"llm_calls":0,"bytes":65536}}'

# carry it on every call; a repeated nonce is rejected as a replay
curl -s -X POST http://127.0.0.1:18001/agent/invoke \
  -H 'Content-Type: application/json' -H 'X-Capability-Token: <token>' \
  -d '{"nonce":"n-1","tool":"fs.read","params":{"path":"/tmp/bicameral/data/notes.txt"}}'
```

## 5. Deploy & verify

```bash
HOST=<host> PORT=22 USER=root ./scripts/deploy.sh   # upload, restart, fingerprint check
python3 scripts/live_check.py                        # 24-check regression on the deploy host
```

`/healthz` exposes `build_sha` (the running source's fingerprint). A deployment counts as good only when the remote `build_sha` equals the local `sha256sum` — this has already caught one silent version drift.

## 6. Boundaries (not solved here)

- Schema-valid ≠ semantically correct: the factual accuracy of LLM output is out of scope for the permission layer.
- The control plane (`/issue`, `/audit`) is unauthenticated by design in this release; production needs a trusted network segment or mTLS (see design doc §7).
- Budget and nonce ledgers are in-memory: restart clears them (fail-closed direction), no persistence yet.
- Throughput is unmeasured; all results above are functional and boundary verification.

## 7. Design doc

[docs/architecture.md](docs/architecture.md) — the permission layer: token format, deny-chain, budget defense, audit, three red-team rounds, residual risks.
[docs/paradigm.md](docs/paradigm.md) — the next layer (design draft): device sensing, capability probing, on-device benchmarking, automated install, and the unified task protocol across heterogeneous devices.

## License

[MIT](LICENSE)
