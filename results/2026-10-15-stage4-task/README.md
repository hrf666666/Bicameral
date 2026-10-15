# 阶段 4 实证归档：task/1 统一任务 + 路由 PoC（2026-10-15）

**验收门**（`docs/paradigm.md` §6，Bicameral 仓）：同一 task 在两台设备各执行一次：结果 schema 一致，`ROUTE` 审计含候选与理由。

**判定：达成**（依据见 §5–§7；判定所依赖的每项检查均在本归档会话实跑，命令与输出见 §8）。

---

## 1. 实现文件清单（Bicameral 仓，本归档时未提交）

| 文件 | sha256（本机实测） | 内容 |
|---|---|---|
| `bicameral/task.py` | `c182e7b0d6db63b4…05ae48` | task/1 schema 校验（:96-175，fail-closed，未知字段即错）+ `normalize_result()`/`validate_result()`（:197-261，result/1 契约权威）+ `execute-local`（:347-388，设备端 `/issue` → `/agent/invoke` → stdout 单行信封）；`--selftest` |
| `bicameral/router.py` | `e9b929b58a888f7c…1b6b036` | devices/1 + bench/1 校验（:87-175）、评分 `decide()`（:182-208）、ROUTE/RESULT/EXECUTE_FAIL 事件（:211-233, :398-411）、`route`/`execute` 子命令；**不 import task.py**，result/1 契约镜像于 :251-279，两侧 selftest 共同钉死 |
| `examples/task-qa.json` | `35b61103dacd7fee…b9bde` | 统一任务定义（type:qa，interactive，egress:none） |
| `examples/devices.json` | `6bc59acfe1b3b736…7bd74791` | devices/1 双机清单：jetson（local）/ bi150（ssh `-p 31451 root@10.70.251.39`，run=`python3 /root/bicameral/task.py execute-local`），各带 perf/audit_ref |

bi150 远端副本 `/root/bicameral/task.py` 与本机同哈希（`c182e7b0…`，scp 前后一致，备车记录）。

## 2. task 定义

原任务（两机同源，`examples/task-qa.json`）：

```json
{"schema":"task/1","task_id":"qa-ability-token-001","type":"qa",
 "input":{"prompt":"用一句话说明什么是能力令牌"},
 "latency_class":"interactive","constraints":{"egress":"none"}}
```

**jetson 变体（如实注记）**：本机实际执行文件为 `/tmp/task-qa-nothink-jetson.json`——同一定义、两处差量：`task_id` 加 `.jetson` 后缀（便于审计对账，合 `task.py:68` 白名单）、prompt 加 ` /no_think` 后缀。缘由是既证环境约束：`LLM_MAX_TOKENS_CAP=64`（`task.py:65`）下 Qwen3 thinking 会把 token 耗尽在 reasoning，content_summary 落空；`/no_think` 实测有效。两文件均过 `task.py validate`（本会话实跑，exit 0）。

## 3. ROUTE 决策（首个实测路由决策）

命令：`python3 bicameral/router.py route examples/task-qa.json`（Bicameral 仓根，默认 `--devices examples/devices.json --bench-dir results/2026-10-14-probe-bench`）。

策略（`router.py:72-73`，写入事件本体）：`interactive: min ttft_ms.mean, then max decode_tps.mean`。

审计事件（`route-audit.jsonl` 第 1 行，逐字）：

- 候选与评分：**bi150**（viable，decode_tps=100.55 tok/s，ttft=23.57 ms，score=23.57）、**jetson**（viable，decode_tps=67.48 tok/s，ttft=29.77 ms，score=29.77），各自带 `perf_ref`；`load:null`（未采样，如实记 null，不编造——`router.py:219`）。
- 选中：`bi150`；理由（逐字）：`interactive: min ttft_ms.mean -> bi150 [bi150 decode_tps=100.55 tok/s ttft=23.57 ms; jetson decode_tps=67.48 tok/s ttft=29.77 ms]`。

**门条件「ROUTE 审计含候选与理由」由本行满足**（本会话程序化解析确认：2 条 ROUTE 事件的 candidates 结构与 reason 均非空，见 §8）。

## 4. route-audit.jsonl 事件清单（4 行，本仓与 Bicameral 仓副本逐字节一致）

| 行 | 事件 | 要点 |
|---|---|---|
| 1 | ROUTE | 双候选 + 评分 + 理由，选中 bi150（§3） |
| 2 | RESULT | device=bi150，latency=31806.9 ms，model_id=Qwen3.8-27B-UD-Q4_K_M，envelope_sha256_16=`26d3fc4f91c32dd3`。**对应更早一次 router `execute` 全链路（经 ssh）**，该信封走 stdout 取回、未另存文件 |
| 3 | ROUTE | 单候选（仅 jetson），selected=jetson |
| 4 | EXECUTE_FAIL | device=jetson，detail=`device run exit 3: task: DENY D13/CAPABILITY_DEGRADED`——彼时 jetson 默认 18000/18001 由 10-14 启动的降级 poc-master 实例持有（pid 3899788，`/healthz strata_state=degraded`），DENY 属实而非缺陷（task.py 退出码 3 = 权限层拒绝，`task.py:37-38`） |

**归档口径（如实）**：§5 的两份归档信封来自后续的专项双机 `execute-local` 实测（各一次真实 LLM 调用），不是第 2 行那次 router 驱动的运行——故 RESULT 事件的 sha16（`26d3fc4f…`，对 canonical `json.dumps(sort_keys=True)` 计算，`router.py:408-410`）与归档信封文件哈希（§5，对文件字节计算）不同源，勿混对。本文件中无 jetson 的 RESULT 事件。

## 5. 双机执行信封对照（result/1）

同一任务定义、每台设备各执行一次、exit 0：

| 字段 | bi150（`result-bi150.json`） | jetson（`result-jetson.json`） |
|---|---|---|
| schema | `result/1` | `result/1` |
| task_id | `qa-ability-token-001` | `qa-ability-token-001.jetson` |
| device | `bi150` | `jetson` |
| engine.model_id（活事实，GET /capabilities） | `/private/models/Qwen3.8-27B-UD-Q4_K_M.gguf` | `/home/nvidia/code/strata-jetson/work/zoo/gguf/Qwen3-0.6B-Q8_0.gguf` |
| engine.backend | `llama-server x4 @ 127.0.0.1:8960-8963` | `llama.cpp CUDA b11062 (llama-server)` |
| perf_ref | `results/2026-10-14-probe-bench/perf-bi150.json` | `results/2026-10-14-probe-bench/perf-jetson.json` |
| audit_ref | `/tmp/bicameral/audit.jsonl` | `/tmp/bicameral-jetson/audit.jsonl` |
| result.content_summary | `能力令牌是一种代表特定`（64-token 上限处截断，如实取回） | `能力令牌是一种用于验证和授权用户访问特定资源或服务的数字凭证。`（完整句） |
| result.usage | {completion:64, prompt:58, total:122, cached:54} | {completion:22, prompt:18, total:40, cached:17} |
| latency_ms | 31131.9 | 359.2（≈ 1/86.7） |
| 文件 sha256_16（字节级） | `9d852d3c4b562eb4` | `21e91b99d9bba07f` |

**模型漂移注记**：bi150 PerfRecord（perf-bi150.json）记录的实测模型是 Qwen3-0.6B（阶段 2 四同档），而其权限层活模型已是 Qwen3.8-27B——信封把 `perf_ref`（PerfRecord 事实）与 `engine.model_id`（活事实）并列呈现，漂移**可见而非掩盖**（设计意图达成）；端到端延迟因此与路由预测反转（PerfRecord 上 bi150 更快，实测慢 86.7×）。复测/重 pin PerfRecord 属运维事项，本阶段不掩盖、不改动 perf 文件。

## 6. 程序化 schema 比对（门条件一）

对两份信封递归比较键集合与值类型（type skeleton），并用仓内契约校验器 `task.validate_result`（`task.py:228-261`）复验：

- 两侧 `validate_result` 均 **VALID**；
- 全层键集合与类型骨架**逐字段一致**：顶层 8 键，`engine`={model_id,backend}，`result`={content_summary,usage}，usage 含 3 token 计数 + `prompt_tokens_details.cached_tokens`，`latency_ms` 双方 float；
- 值差异恰合预期：12 个叶值全异（device/engine/usage/latency/task_id 等），唯一同值字段是 `.schema`（`result/1`）。

脚本本体与完整输出见 §8；exit 0。

## 7. 审计引用

- **bi150**：`/tmp/bicameral/audit.jsonl` 第 1017-1018 行，jti=`66c07f164813198c`：ISSUE（budget calls:1/llm_calls:1）→ ALLOW（tool=llm.complete，result_keys=[content_summary,usage]，est_bytes=39）；ALLOW.ts−ISSUE.ts=31.133 s ≈ 信封 latency_ms 31131.9（本会话 ssh 只读 grep 实证）。
- **jetson**：`/tmp/bicameral-jetson/audit.jsonl` 第 7-8 行，jti=`a640ff30f9fe587b`：ISSUE（budget calls:1/llm_calls:1）→ ALLOW（tool=llm.complete，result_keys=[content_summary,usage]，est_bytes=49）（本机 grep 实证）。
- 脱敏：ROUTE/RESULT 事件只含 task_id、decode_tps、理由、信封 sha256_16（`router.py:403-411` 注释即承诺），**无 prompt/答案文本**；`/issue` 响应壳（jti 等）不进信封（selftest `normalize.invoke_wrapper_stripped` 钉死）。

## 8. 本归档会话实跑的检查（命令与结果）

| 检查 | 命令 | 结果 |
|---|---|---|
| 门条件一：信封 schema 程序化比对 | heredoc python3：`skel()` 递归键集+类型比较 + `task.validate_result` + route-audit 解析 | exit 0；VALID×2；骨架逐层一致；仅 `.schema` 同值；2 ROUTE 均含候选与理由 |
| 门条件二佐证：selftest 复跑 | `python3 bicameral/task.py --selftest`；`python3 bicameral/router.py --selftest` | 均 `selftest: 0 failure(s)`、exit 0 |
| task 定义校验 | `python3 bicameral/task.py validate examples/task-qa.json`；同法验 `/tmp/task-qa-nothink-jetson.json` | 两文件均 exit 0 |
| bi150 审计引用 | `ssh -o BatchMode=yes -p 31451 root@10.70.251.39 "grep -n '66c07f164813198c' /tmp/bicameral/audit.jsonl"` | 第 1017-1018 行 ISSUE→ALLOW 如上 |
| jetson 审计引用 | `grep -n a640ff30f9fe587b /tmp/bicameral-jetson/audit.jsonl` | 第 7-8 行 ISSUE→ALLOW 如上 |
| 归档完整性 | `sha256sum` 三方（两信封 + route-audit 双仓副本） | route-audit 副本 sha256 同为 `f9a6fce1156d0559…`，逐字节一致 |

## 9. 已知边界（如实，不构成门阻断）

1. bi150 模型漂移（§5 注记）：路由按「硬规则只认 PerfRecord」做出的事实已过时；教训归 §5 攻击面「PerfRecord 时效」，修复（复测/重 pin）属运维。
2. jetson 变体差量（§2）：`/no_think` 后缀 + task_id 后缀，缘由 64-token 上限 × Qwen3 thinking 的既证约束；任务 schema 与意图同一。
3. `examples/devices.json` 中 jetson 的 `audit_ref` 写的是默认实例路径 `/tmp/bicameral/audit.jsonl`，而成功的本机执行实际走独立实例（18100/18101，数据目录 `/tmp/bicameral-jetson`）——信封 `audit_ref` 记录的是实际路径（权威）；若未来用 router `execute` 路由到 jetson，devices.json 该项需先对齐实例拓扑（18000/18001 现被降级 poc-master 占用，见 §4 第 4 行）。
4. router 全链路（route→ssh→execute→RESULT 落盘）在 bi150 已走通（§4 第 1-2 行），jetson 方向在真机上止于 D13（彼时后端降级），后经独立实例直连 execute-local 成功——router 对 jetson 的全链路成功路径未在本归档内复现，属 §4 事件记录的如实呈现。
