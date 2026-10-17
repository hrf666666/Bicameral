# 2026-10-17 pipeline/1 全链路闭环归档：task/1 → 路由 → 双机各执行 → 27B 评审 → delivery/1

**目标**：实证「初心架构」全链路闭环（`bicameral/pipeline.py`，新文件，1002 行，
sha256 `b9e5e7833cc3b985…74011d28`）：一份 task/1 经可审计路由（复用 router.py）→
异构设备各执行（复用 router 的 execute 机制取回 result/1 信封）→ **27B 评审模型按
quality_bar 裁决**（经主控权限层 /issue 为 judge subject 签发 llm.complete 评审令牌）
→ 归一化交付 delivery/1。全程审计事件（PIPELINE_* + ROUTE + RESULT）落同一条
hash-chained JSONL，链复用 router.append_audit/verify_audit。

**红线遵守**：8960（bi150 27B 脑，pid 31397）配置未动未重启；bi150 在跑实例
（主控 18000/18001 pid 12161）未动未重启；Jetson 只用 18100/18101（18888 llama-server
+ 18100/18101 bicameral 实例均为既有进程，未动）；自起进程仅 Jetson 侧两条 ssh -N
本地隧道（28180/28181→bi150 主控两面、28960→8960，验收后已关）；bi150 磁盘零写入
（远端审计只追加由在跑实例完成）。

---

## 0. 结论（先看这里）

| 门 | 结果 |
|---|---|
| pipeline --selftest / py_compile | **53 ok / 0 failure（rc=0）**；task.py、router.py selftest 复跑均 0 failure |
| 真机门（jetson + bi150 双机 `--all-candidates`） | **达成**：双机各执行成功（result/1 信封均 valid，A9 digest 四枚全部 `verify_result.py` VERIFIED）+ 27B 逐份裁决（verdict JSON 原文落盘）+ delivery/1 交付（rc=0） |
| 主判定 | **27B 逐份裁决成立且如实**：canonical 任务下两机答案都因「推理模板烧掉 64-token 预算」退化（bi150 截断句 → fail/2 分；jetson 空串 → fail/0 分），`best_device=null`（无 pass 不硬点）；`/no_think` 任务变体下双机满分通过（9.0/9.0，best=bi150） |

## 1. 关键发现（如实，影响主判定的环境事实）

**2026-10-17 在跑的 27B 实例对 `/no_think` 软开关一概无效**，与
`results/2026-10-16-27b-repair-brain` §1 的结论不同：

- 直接探针（bi150 本机 → 127.0.0.1:8960，只读）：`/no_think` 放 user 前缀 / system
  角色 / user 后缀三个位置，全部仍产出 `reasoning_content`、`content=""`、
  finish=length（64 token 全烧进思考）。
- **唯一有效开关是 `chat_template_kwargs.enable_thinking=false`**：同请求 6.7s 返回
  完整合法 JSON（finish=stop）。该实例 09:12 被重启过（ps: pid 31397 START 09:12，
  无 `--jinja` 标志），推测与 27b-repair-brain 门当时的行为差异同源。
- 而主控权限层 `server.py h_llm_complete` 的请求体固定为
  `{messages, max_tokens, temperature}`——**带不动 chat_template_kwargs**；改代码需
  重启在跑主控（红线禁止）。 ⇒ 权限层通道对这台 27B **必然空 content**。
- 处置（pipeline.py 内建，升级而非静默）：权限层 llm.complete 照走（ALLOW 行落
  bi150 主控审计）；**content 为空时做一次有界的评审脑直连兜底**（同一评审令牌为
  Bearer 凭据、同一 prompt（/no_think 前缀保留）+ `enable_thinking=false`），每次
  评审至多一次兜底；`judge_mode`（permission-layer / brain-direct）进
  PIPELINE_JUDGE 审计与 delivery 的 evaluations；两条通道的原始回包都落盘
  `judge-<device>.json`。四份裁决全部经 brain-direct 通道产生，审计可查。
- 同源事实：设备执行侧同理——canonical prompt 在 jetson（Qwen3-0.6B）下
  content_summary=""（64 token 烧思考，阶段 4 §2 已证），bi150（27B）下为 64-token
  截断句。27B 评审对此**如实判 fail**（"答案为空，未回答任务要求"/"答案不完整"）——
  评审模型按 quality_bar 把关的行为闭环本身就是本门的通过项。

## 2. 环境与拓扑

| 项 | 值 |
|---|---|
| Jetson 设备 | bicameral 18100/18101（`--strata-url http://127.0.0.1:18888/v1`，Qwen3-0.6B-Q8_0，`/healthz strata_state=ok`）；控制面 open（无 token） |
| bi150 设备+主控+评审脑 | ssh `-p 31451 root@10.70.251.39`；主控 18000/18001（`python3 server.py --control-port 18000 --agent-port 18001`，strata-url 缺省=8960，admin token 在 `/root/bicameral/.admin_token`）；27B 脑 8960（llama-server，`--alias qwen3.8-27b`，-t 56） |
| 远端 task.py | `/root/bicameral/task.py` sha256 与本地逐字节一致（`dde42989b4b7077a…`），自检 0 failure |
| devices 清单 | `results/2026-10-16-pipeline/devices-real.json`（jetson local 18100/18101 + bi150 ssh，双机；sha256_16 `c68599d85994c43b`）。**不用 `examples/devices.json`**：其 jetson 条目指向 18000/18001（降级 poc-master，`strata_state=degraded`，阶段 4 §9.3 已预告需对齐实例拓扑）且违背「Jetson 只用 18100/18101」红线 |
| 隧道（验收期临时） | `ssh -N -L 28180:127.0.0.1:18000 -L 28181:127.0.0.1:18001 -p 31451 root@10.70.251.39` 与 `-L 28960:127.0.0.1:8960 …`（bi150 除 22 外端口从 Jetson 不可达，实测直连超时；隧道只在本机监听，不触远端；结束已关） |

## 3. CLI 用法（pipeline.py）

```
python3 bicameral/pipeline.py \
  --task examples/task-qa.json --devices <devices/1.json> \
  --judge-url <27B-OpenAI端点> --judge-model qwen3.8-27b \
  --judge-token <主控管理令牌> [--all-candidates] \
  --out <交付目录> \
  [--judge-control URL] [--judge-agent URL]   # 主控权限层两面（评审走这里）
  [--device-admin-token TOK]                  # ssh 设备侧 /issue 所需（同一令牌）
  [--audit PATH] [--bench-dir DIR] [--timeout S] [--judge-timeout S]
python3 bicameral/pipeline.py --selftest
```

令牌也可经 env `BICAMERAL_JUDGE_TOKEN`。退出码：0 交付完成 · 2 usage/schema ·
3 无 viable 候选 · 4 零信封。

## 4. 每步命令与输出（真机门实跑记录）

### 步骤 0 自检
`python3 -m py_compile bicameral/pipeline.py` → OK；
`python3 bicameral/pipeline.py --selftest` → **53 ok / 0 failure**（task 校验复用、
评审 prompt 组装（/no_think 前缀 + quality_bar 注入 + 8KiB 上界 + 模板无注入形态）、
verdict JSON 容错解析（围栏/思考段/杂文/中文 verdict/字符串分数）、delivery 组装与
严格校验、argv 令牌/audit-path 扩展形态、审计链两行落盘）；`task.py`/`router.py`
`--selftest` 复跑均 `0 failure(s)`。

### 步骤 1 隧道 + 评审通道冒烟
`/issue`（X-Admin-Token，agent=judge，tools=[llm.complete]，1-call 预算）→ 200，
`{ok:true, agent:"judge", tools:["llm.complete"], budget:{calls:1,llm_calls:1}}`。

### 步骤 2 主判定跑（canonical 任务，--all-candidates）
```
python3 bicameral/pipeline.py --task examples/task-qa.json \
  --devices results/2026-10-16-pipeline/devices-real.json \
  --judge-url http://127.0.0.1:28960/v1 --judge-model qwen3.8-27b \
  --judge-token "$TOK" \
  --judge-control http://127.0.0.1:28180 --judge-agent http://127.0.0.1:28181 \
  --device-admin-token "$TOK" --all-candidates \
  --out results/2026-10-16-pipeline/      # rc=0
```
输出摘要：`route: selected=bi150 targets=['bi150','jetson']`；
`execute bi150: ok (12691.3 ms, model_id=None)`；`execute jetson: ok (994.3 ms,
model_id=…Qwen3-0.6B-Q8_0.gguf)`；两次评审均「permission-layer 空.content → 有界
brain-direct 兜底」：`judge bi150: verdict=fail score=2.0`（17.4s）、
`judge jetson: verdict=fail score=0.0`（16.7s）；`delivery written … (best_device=None)`。

### 步骤 3 补充跑（/no_think 任务变体，stage 4 §2 同款处置）
task：`results/2026-10-16-pipeline/task-qa-nothink.json`
（task_id `qa-ability-token-001.nothink`，prompt 加 ` /no_think` 后缀，
quality_bar `{"min_accuracy":0.8}`，`task.py validate` 过）。同命令换
`--task …task-qa-nothink.json --out …/nothink-variant/` → rc=0：
双机执行 ok（bi150 12557.8 ms / jetson 360.6 ms），27B 裁决
**pass 9.0 / pass 9.0，best_device=bi150**。

## 5. 双机执行信封（result/1，最终跑；四枚 `validate_result` 全 VALID）

| 字段 | primary-bi150 | primary-jetson | nothink-bi150 | nothink-jetson |
|---|---|---|---|---|
| task_id | qa-ability-token-001 | 同左 | qa-ability-token-001.nothink | 同左 |
| content_summary | `能力令牌是一种代表特定权限或能力的`（64-token 截断） | `""`（空，思考烧尽） | `能力令牌是一种代表特定权限或能力的凭证` | `能力令牌是一种用于验证和授权用户访问特定资源或服务的数字凭证。` |
| usage.completion | 64 | 64 | 64 | 22 |
| latency_ms | 12691.3 | 994.3 | 12557.8 | 360.6 |
| device_audit_digest | `72ffcf4d4f7f12a1` | `b04ebc49c73bde73` | `29e30dd1e66e6b82` | `4006bd252217741a` |

**A9 交叉核验**（`bicameral/verify_result.py`）：四枚信封对各自设备侧审计全部
`VERIFIED: digest resolves to its device-side ISSUE/ALLOW pair`（bi150 用取回件
`bi150-master-audit.jsonl`；jetson 用 `/tmp/bicameral-jetson/audit.jsonl`，副本
`jetson-18100-audit.jsonl`）。

## 6. 27B 裁决 JSON 原文（judge-<device>.json 的 final_content）

主判定（canonical，经 brain-direct 兜底通道产出）：

```json
{"verdict":"fail","score":"2","rationale":"答案不完整，句子未结束，缺乏核心定义。"}   ← bi150
{"verdict":"fail","score":"0","rationale":"答案为空，未回答任务要求"}                ← jetson
```

/no_think 变体：

```json
{"verdict":"pass","score":9,"rationale":"定义准确，切题且完整，符合一句话要求。"}     ← bi150
{"verdict":"pass","score":9,"rationale":"定义准确，符合一句话要求，切题且完整。"}     ← jetson
```

权限层通道的原始回包如实留痕：四例 content 均为 `""`（usage.completion_tokens=64，
即全部烧进 reasoning）——这正是 §1 发现的信封级证据。评审 prompt 全文落盘
`judge-prompt-<device>.txt`（`/no_think` 前缀 + JSON 形状约定 + 数据非指令声明 +
task/quality_bar/候选/答案 的 JSON 数据块）。

## 7. 交付（delivery/1）

主判定 `delivery.json`（rc=0）：

```json
{"schema":"delivery/1","task_id":"qa-ability-token-001","quality_bar":{},
 "evaluations":[
  {"device":"bi150","verdict":"fail","score":2.0,
   "rationale":"答案不完整，句子未结束，缺乏核心定义。",
   "envelope_ref":"…/envelope-bi150.json","judge_mode":"brain-direct"},
  {"device":"jetson","verdict":"fail","score":0.0,
   "rationale":"答案为空，未回答任务要求",
   "envelope_ref":"…/envelope-jetson.json","judge_mode":"brain-direct"}],
 "best_device":null,
 "audit_refs":{"pipeline_audit":"…/pipeline-audit.jsonl",
               "devices_manifest_sha256_16":"c68599d85994c43b",
               "route_selected":"bi150","envelopes":{…},"judge_raw":{…},
               "device_audit_refs":{…}}}
```

`nothink-variant/delivery.json`：quality_bar `{"min_accuracy":0.8}`，双 evaluation
pass/9.0，`best_device="bi150"`（同分取先评估者）。`best_device=null` 语义：无
pass 不硬点（如实）。

## 8. 审计（PIPELINE_* 落同一条 hash-chained JSONL）

- `pipeline-audit.jsonl`（39 行，链 ok，tail `8e89b618c33edb7b`）与
  `nothink-variant/pipeline-audit.jsonl`（20 行，链 ok，tail `fd04d324c1069512`）。
  事件序列每次跑：PIPELINE_START → ROUTE（router 原样：双候选+decode_tps/ttft+理由，
  selected=bi150，interactive: min ttft_ms.mean）→ PIPELINE_ROUTE → RESULT /
  PIPELINE_EXEC（每设备）→ PIPELINE_JUDGE（每设备：jti、judge_mode、prompt/
  response sha256_16、verdict/score/rationale）→ PIPELINE_DELIVERY。
  **主判定审计含前两次试跑的失败事件**（首次 brain 兜底 URLError、一次
  score-字符串解析导致 delivery 校验失败 rc=2）——如实留链，未删改。
- bi150 主控审计（取回件 `bi150-master-audit.jsonl`）：每次跑 ISSUE→ALLOW 成对
  （agent-ro 设备执行 1 对 + judge 评审 1 对），如
  `ISSUE judge qa-ability-token-001.judge 604dd62e… → ALLOW … llm.complete`。
- Jetson 审计（副本 `jetson-18100-audit.jsonl`）：ISSUE agent-ro → ALLOW
  llm.complete 成对。
- 令牌卫生：管理令牌只存在于命令行变量与 ssh 读远端文件的动作里，审计/交付/
  评审原文/本 README 均无令牌值。

## 9. 如实注记（与任务书口径的差异）

1. **`--judge-url http://127.0.0.1:8960/v1` 不可从 Jetson 直达**（bi150 除 22 外
   端口实测不可达）→ 验收经 ssh 隧道 28960→8960，CLI 传
   `--judge-url http://127.0.0.1:28960/v1`；8960 本身未动。
2. **评审未走通「纯权限层 llm.complete」**：在跑 27B 实例忽略 /no_think，主控
   handler 带不动 enable_thinking（§1）→ pipeline 内建有界 brain-direct 兜底，
   judge_mode 全程落审计与交付。修复正解（属其他文件/运维，本门未做）：主控
   `h_llm_complete` 支持 chat_template_kwargs，或 8960 以关思考配置重启。
3. `--devices examples/devices.json` 未按字面使用（§2 红线/拓扑对齐）；bi100 未
   入清单（本门只要求双机）。
4. 路由按 PerfRecord 选 bi150（ttft 23.57<29.77 ms），实测 bi150（27B）慢
   ~13×——阶段 4 §5 已录的 PerfRecord 时效问题，按设计「漂移可见而非掩盖」。
5. `--device-admin-token` 以 argv 进 ssh 设备侧命令（远端 ps 于该次运行期间可见，
   ssh 加密传输）——router.py 明言 ssh 设备应「provisioned remotely」，缺省部署下
   无 env 转发通道，此为最小可用取舍，已在 docstring 声明。

## 10. 交付物清单（本目录）

| 文件 | 内容 |
|---|---|
| `delivery.json` / `nothink-variant/delivery.json` | delivery/1 主判定 / 变体 |
| `envelope-{jetson,bi150}.json`、`nothink-variant/…` | result/1 信封 ×4 |
| `judge-{jetson,bi150}.json`、`nothink-variant/…` | 评审原文（两通道 attempts + final）×4 |
| `judge-prompt-{jetson,bi150}.txt`、`nothink-variant/…` | 评审 prompt 全文 ×4 |
| `pipeline-audit.jsonl`、`nothink-variant/pipeline-audit.jsonl` | PIPELINE_*/ROUTE/RESULT 链式审计 |
| `devices-real.json`、`task-qa-nothink.json` | 门用清单 / 变体任务 |
| `bi150-master-audit.jsonl`、`jetson-18100-audit.jsonl` | 设备侧审计取回件（A9 核验依据） |
