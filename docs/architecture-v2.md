# strata-jetson「主控唤醒边缘 Agent」六层架构（v2 · 评审修订稿）

> **修订说明**：v1 初稿经独立评审 26 条意见逐条处理后修订为本 v2。处置：**接受并修订 24 条**（其中问题 2、9、22 为部分接受）、**反驳 1 条的结论**（问题 22 的「砍掉近半复杂度」，反驳理由写在 §2 L5 对应位置）；问题 9 的事实争议以本会话实测命令裁决。逐条处置记录见 §9。文档为自含完整稿，非 diff。

---

## 0. 事实基座（本会话读文件/跑命令核实）

设计不建立在口号上。以下事实均在本会话确认：

| # | 事实 | 出处（已核实） |
|---|---|---|
| 1 | Strata 125B MoE(Q2_0)：decode **6.31 tok/s**（`--pool-workers 3`）/ 默认 3.96；TTFT **18.0s@128 / 50.5s@2048**；14.4W；≈2.3 J/token；专家缓存 5060/24576，命中率 **59%→85%** | `README.md:41-52` |
| 2 | 非专家权重+KV+专家缓存 ≈**11 GiB** 驻留 16GB 统一内存；专家经 NVMe mmap 流式（PLE 直读不入内存）；Strata 盘上资产 = GGUF 双分片 61.8GB + pack 34GB，**常驻磁盘** | `README.md:51-52`、`docs/edge-slimming.md:34-36` |
| 3 | 同机 20 个开源小模型（0.27B–9B）+ Strata：decode **6.3–190.8 tok/s（30×）**、GSM8K **0.00–0.96**、TTFT 亚秒↔50.5s | `README.md:63-84` |
| 4 | `summary_quality.csv` 共 **21 行**，其中 1 行是 `smoke` 冒烟残留（n=6）；`strata` 行 n_gsm=25 / n_arc=50；`summary_perf.csv` 仅 19 行 zoo、**无 Strata 行** | `results/summary_quality.csv:21-22`、`results/summary_perf.csv` |
| 5 | Strata 服务 `127.0.0.1:8080/v1`（OpenAI 兼容）；llama-server 评测走 `:8091`，且 `run_zoo.py` 内含 llama-server 的**拉起与停止**代码 | `scripts/edge_deploy.sh:32`、`scripts/run_zoo.py:194-207` |
| 6 | run_zoo.py「fetch→bench→eval→评完即删权重、失败保留」是 **bench 卫生逻辑**（防盘满），权重现拉现删、无常驻服务 | `scripts/run_zoo.py:228-239` |
| 7 | 功耗链路：tegrastats 采样器（默认 200ms）→ CSV，**绑定 tegrastats** | `scripts/power_sampler.py:6-13` |
| 8 | `serve/mcp.py`（676 行）存在但从未启用；`responses.py` **31 处耦合**、`mcp.py` 11 处调用点 | `work/Strata/serve/mcp.py`、`docs/unused-parts-analysis.md:23`、`docs/edge-slimming.md:44-53` |
| 9 | 边缘部署物**已携带 `serve/structured.py`** | `scripts/edge_deploy.sh:17-19` |
| 10 | `results/raw/` 不入库（.gitignore），入库只有汇总 CSV；`edge_deploy.sh` 产出物只含引擎+serve 模块+配置/tokenizer，**不含 results/** | `.gitignore`、`scripts/edge_deploy.sh:13-28` |
| 11 | 评测已知限制：Qwen3.5 家族 GSM8K 为格式遵循下限；思考型 ARC=0 是 512 token 预算耗尽；`bench_perf.py` 支持 `--buckets` 多 prompt 档位（README 示例 `--buckets 128,2048`） | `README.md:157-158`、`README.md:148` |
| 12 | **（本轮实测）本会话工作目录所在主机即 Jetson 目标机**：`uname -a` → `Linux nvidia-desktop 5.15.148-tegra aarch64`；`ls results/raw/ \| grep -i strata` → **`perf_strata_pw3.json`、`perf_strata_default.json`、`power_strata_default.csv`、`quality_strata_pw3.json` 存在**（raw 目录共 56 个文件） | 本会话第二轮 Bash 实测 |

来自纪要、本地未复核的外部事实（采用纪要口径，落地前按官方 spec 复核）：A2A v1.0（2026-03）九态生命周期与三 binding；MQTT LWT/birth/retained/persistent-session 语义；FrugalGPT/RouteLLM/CaMeL 等方案的量化结论；Strata 冷启动（66GB pack 就绪检查+加载）为**分钟级**。

---

## 1. 总览：痛点 → 层映射（v2 修订）

| 痛点 | 主责层 | 核心机制（每条都有对应组件与接口，见 §2） |
|---|---|---|
| ① 速度异构（TTFT 亚秒↔50.5s） | L3 + L4 | 提交即返回 task_id 的全异步任务 + **两级分流**：前置静态路由（risk_tier/任务族实测/延迟预算在派发前定主路）是主机制；置信度触发的升级是**质量兜底而非提速**，显式计价（全额 TTFT+重生成，可携带 transcript 降耗）+ admission/EDF 队列 + 逐 token 流式 + 诚实 ETA（含排队等待与 TTFT 裕度） |
| ② 能力异构（GSM8K 0.00–0.96） | L2 + L3 | **任务族实测优先**：每任务族建探针集（50–100 题）+ 生产滑动窗口（accept/abstain/escalate 率）作路由主轴；gsm8k/arc 降为「淘汰性弱代理」；manifest 静态单写者 + 云侧 observed 旁表融合 + bench 周期刷新 |
| ③ 边界泄漏（越权/越界/注入） | L5（+L6c） | **工具分两类裁决参数权**：derived（服务端按 payload 派生，LLM 不可改写）与 authored（边缘 LLM 填参，过 policy default-deny + **taint 数据流标记** + 参数语法三重约束）——同时保住多步自治与注入防御；per-task token+lease 续期；效果级幂等；v1 最小集分期落地 |
| ④ 幻觉 | L6 | GBNF 约束解码 + **claim 级**证据（引用核对+数值核对两道程序闸）+ **公式化**置信函数 + risk_tier 云端权威裁决（主控自报只升不降）+ abstain 一等公民 + HITL（含 approve/reject API） |
| （隐含）agent 挂掉/断网 | L1 + L3 twin | LWT+keepalive 双死亡检测；twin + (task_id, attempt) 对账；边缘自治（含**任务内多步 agent 循环**）；断网排队 + 过期任务拒执行 |

---

## 2. 分层设计

### L1 云边通道层（Channel）

**职责与组件**

| 组件 | 侧 | 职责 |
|---|---|---|
| MQTT broker | 云 | 唯一云→边入口；mTLS 或 per-device token + per-topic ACL；persistent session |
| edge-link | 边 | outbound 持久连接；birth（retained online）+ LWT；keepalive 心跳；指数退避+jitter 重连 |

**接口（topic 契约）**

```
edge/{id}/status    每 10s, QoS1   边→云  动态水位 {mem_free_mb, expert_cache_hot, temp_cpu, queue_depth, ts}
                                          ——(v2) 动态字段从 retained manifest 移出至此, 附时间戳
edge/{id}/tasks     QoS1          云→边  任务信封（含 attempt, 见 L3/L4）
edge/{id}/events    QoS0          边→云  {task_id, attempt, seq, type: token|progress|model_switch|eta|gap}
                                          token 事件按 ~16 token/250ms 合帧降丢损面
edge/{id}/results   QoS1          边→云  终态信封（**权威完整产物**；>256KB 走 artifact-store, 此处发 result_ref）
edge/{id}/telemetry QoS0, 批量    边→云  power_sampler CSV 片段
edge/{id}/audit     QoS1          边→云  权限审计
registry/{id}       retained      边→云  **静态** capability manifest（单写者=边缘, 见 L2）
```

**流式完整性语义（v2）**：事件网关检测 seq 缺号 → 等待 2s → 向主控会话插「…（片段丢失）」标记并继续（不卡死、不静默跳字）；最终以 QoS1 的 `results` 为准，流丢不损交付物。生成中断重跑 = 新 attempt（§4 故障1）。

**唤醒语义**：v1 不做设备休眠唤醒（Jetson 常驻供电）；「唤醒」= ①通道级：任务消息到达 edge-agent；②模型级：L4 换入权重（真正的热身成本，分钟级）。

### L2 能力注册与发现层（Registry & Manifest）

**v2 关键修订**：①manifest **静态化+单写者**；②skills 升级为**有测量机制的任务族**（回应「标签文学」批评）。

| 组件 | 侧 | 职责 |
|---|---|---|
| manifest-builder | 边 | 生成**静态** manifest：模型清单/量化/质量分/速度画像/skills 与任务族/工具清单。输入 = `results/summary_*.csv` + 本地 `results/raw/perf_strata_*.json`（**本机已实测存在**，见 §0 事实12；独立部署目标机上由 edge-deploy **打包画像快照**或在设备上跑 bench 生成，消除文件位置假设） |
| registry | 云 | 订阅 `registry/+`；**唯一写者是边缘**，ver 只随边缘发布递增；云侧不回写 |
| **observed 旁表** | 云 | 生产实测画像（云私有）：`observed_perf[agent_id][family] = {accept_rate, abstain_rate, escalate_rate, avg_service_time, sample_count, half_life}`。**融合规则**：sample_count≥20 → 以 observed×0.8 为主；否则以 manifest 基准为准。乱序/回滚问题因单写者而不存在 |
| 探针集构建器 | 云/边 | 每任务族 50–100 题本地探针（阶段1 为 summarize/telemetry 建立，复用 `bench_quality.py` 思路）；结果写 manifest `task_families[].probe`。**这是路由主轴的测量来源**——GSM8K/ARC 未测 summarize/telemetry，标签必须由测量背书 |
| 画像刷新器 | 云触发/边执行 | 建模为**特殊低优先级任务，走同一 admission**；仅在空闲窗口执行（队列空+无 in-flight 持续 15min，或显式维护窗口）；`bench_start/bench_end` 事件 → 路由对该 agent 进入保守模式。Strata 通道并发 1 使 bench 与 serving 天然互斥（回应「评测驱逐服务」批评） |

**接口（manifest 关键字段，v2）**

```json
{
  "agent_id": "orin-nx-01", "schema": "wake-manifest/1.1", "status": "online", "ver": 8,
  "models": [
    {"name": "qwen3vl-2b-ins", "quant": "Q4_K_M", "ctx": 8192, "resident": true,
     "quality": {"gsm8k": 0.75, "arc": 0.71, "n_gsm": 100, "n_arc": 100, "eval_date": "2026-10-13"},
     "perf":   {"pp128": 1579.4, "pp2048": 1719.3, "tg128": 43.5}},
    {"name": "strata-q2_0-125b", "resident": false, "load_cost": "swap-in: 分钟级",
     "quality": {"gsm8k": 0.96, "arc": 0.50, "n_gsm": 25, "n_arc": 50},
     "perf":   {"ttft_buckets": {"128": 17.97, "2048": 50.54}, "decode_tps": 6.31,
                "note": "仅两端点, 档间取上界档保守值, 补测前列为前置工作"}}
  ],
  "task_families": [
    {"tag": "summarize",
     "probe": {"n": 30, "pass_rate": 0.87, "eval_date": "2026-10-20"},
     "tools": ["fs.read"]},
    {"tag": "telemetry", "probe": {"n": 30, "pass_rate": 0.91}, "tools": ["telemetry.query"]}
  ],
  "tools":   [{"name": "fs.read", "class": "derived|authored", "side_effect": "read-only"}],
  "ver_note": "本 manifest 为静态能力; 动态水位见 edge/{id}/status (10s 周期)"
}
```

（v2：动态字段 `mem_free_mb/expert_cache_hot/temp_cpu` 已移入 `status` 通道；路由侧对 status 超过 **60s** 未更新者按「状态未知」处理，保守路由或跳过该 agent——retained 陈旧水位不再可能误导决策。）

### L3 编排与调度层（Orchestrator，云）

| 组件 | 职责 |
|---|---|
| task store | 权威任务表（twin）：`{task_id, attempt, ver, desired:{spec}, reported:{state, progress, result_ref, error}, updated_ts}`；落盘持久化 |
| risk 裁决器 | **（v2）risk_tier 权威在云**：`risk_final = max(主控自报, intent 分类表基线, 工具副作用评级)`；mutating/不可逆工具自动 ≥high；分类表固化于 orchestrator 配置。主控自报**只升不降**，低报无法绕过云 judge/一致性采样/高阈值 abstain |
| router | ① 硬门槛**分级**：任务族实测（探针或生产窗口，n≥30）优先；无任务族实测时 gsm8k/arc 仅作**淘汰性弱代理**（低于绝对下限才淘汰，不用于同族选优），决策记录显式标注 `quality_proxy: generic` ② 延迟预算：`est = queue_wait(通道深度×observed 平均服务时长) + TTFT_m(prompt_len)×1.5 + E[gen_len\|intent]/(decode_tps×0.8)`。**E[gen_len]** 取任务族经验中位数（缺省 512）——gen_len 是分布估计而非已知输入（v2 修正）；**TTFT×1.5 裕度**（缓存冷/温度方差最大项）；**queue_wait** 显式入式，空队时为 0 ③ 队列策略：每通道 **EDF**（deadline 最早优先）+ 老化防饿死；有界队列满即 shed |
| 降级器 | 三级链：边缘小模型 → Orin 上的 Strata → **cloud-executor**；per-agent circuit breaker，失败原因写 observed 旁表 |
| **cloud-executor** | **（v2 补全）**降级第三级执行体：调云端 LLM API；结果直接写 `reported{state:completed, executor:"cloud", degraded:true}`，对用户明示「此结果由云端生成」 |
| **artifact-store** | **（v2 补全）**云侧对象存储 + 预签名 URL（PUT/GET 单向、TTL、绑定 task_id）。出站：大产物必须**先过 egress filter** 再上传，上传动作入审计；入站：主控大 payload 先 PUT → 任务携带 `{payload_ref, sha256}` → 边缘经自身 outbound HTTPS GET 拉取（NAT 友好方向）并校验哈希 |
| grant 签发器 | 签发 token+**lease**（见 L5）；**静态校验：grant 工具域必须 ⊇ payload 引用路径**（防 v1 示例 `fs.read:/var/log/power/*` 盖不住 `/var/log/power.csv` 一类签发错误） |
| 事件网关 | (task_id, attempt) 开流、seq 重组、gap 处理（见 L1） |
| HITL 通道 | **（v2 补全）**`POST /v1/tasks/{id}/approve` / `POST /v1/tasks/{id}/reject`（approver 身份入审计）→ 下发 TaskResume/TaskCancel；HITL 挂起即状态 `input-required` |

**接口（对主控大模型会话）**

```
POST /v1/tasks {…, risk_tier(自报), deadline_s}
   → agent 在线:  201 {task_id, attempt:1, route, est_eta, eta_basis:"空队+补测曲线"}
   → agent 离线:  202 {state:queued_offline, eta:null, policy: queue|cloud|reject}   # (v2) 禁止无 eta 的 201
   → 策略拒绝:    409 {reason}
GET  /v1/tasks/{id}                    → twin 文档
GET  /v1/tasks/{id}/events             → SSE（按 attempt 分流）
POST /v1/tasks/{id}/cancel
POST /v1/tasks/{id}/approve | /reject  # HITL
```

**状态机**：v1 实现六态 submitted/working/input-required/completed/failed/cancelled（A2A 状态名）；A2A v1.0 其余态（rejected/auth-required 等）列映射表但 v1 不实现；`input-required` = HITL 挂起（不再无人使用）。

**升级/重派语义（v2，回应「升级无预算」）**：每任务带 `escalation_budget {max_attempts: 2, deadline_ext_s: 120, grant: 续签}`；升级 = 云端发 TaskReassign（attempt+1），**deadline 与 grant 随之一并显式延期一次**并重广播 ETA；二次升级需人工确认。超期处置矩阵：边缘发现超期 → 中止报 `failed{deadline_exceeded}`；云端超时未归 → 按任务策略转 cloud-executor / 失败明示。

### L4 边缘执行运行时（Edge Runtime，systemd 常驻 `edge-agent`）

| 组件 | 职责 |
|---|---|
| edge-link | 即 L1 |
| task dispatcher | 验签；**收包必检 deadline**（用收包时刻单调基准）：已过期 → 不执行，直接回 `results{state:failed, reason:expired}`（离线数小时后补投的积压任务不会被照常执行）；**受理去重键 = (task_id, attempt)**：传输层重复投递（同 msg_id）直接丢弃；升级/重试/重跑 = 新 attempt，合法接收，不与去重冲突 |
| **agent loop（v2 新增执行模型）** | 任务内多步循环：上限 N=8 轮「LLM 生成 → (tool_call \| final)」；中间轮输出 `{thought?, action:{tool, args}}` 经 L5 强制点；final 必须满足 out_schema；循环耗尽未 final → `failed{loop_budget}`。**升级/重跑随重派携带 transcript（已执行轮次+工具结果），不从零重生成**；边缘可发 `input-required` 请求云端补资源/人工。跨任务会话状态（session_id）由 edge-agent 内存+spool 维护，历史是否跨任务下发由云决定 |
| admission control | Strata 通道 `Semaphore(1)`+队列(maxlen=4，EDF)；满→`busy{admission_full}`；小模型通道并发 2。依据：并发冲刷专家缓存 85%→59%、TTFT 雪崩（`README.md:48`） |
| model-manager | **进程托管（v2 补全）**：llama-server/strata 由 edge-agent 作为子进程拉起（泛化 `run_zoo.py:194-196` 的启动代码）→ 健康探测（GET /v1/models）→ 纳入服务；崩溃 → 退避重启 → 连续 3 次失败 → `agent_degraded` 事件+在跑任务 `failed{engine_died}` 并释放 admission 槽；生成中流中断/连接重置同判。**换入前内存预检**：mem_available ≥ 目标驻留量（含 KV），不足 → `busy{insufficient_mem}`（16GB 上换入 11GiB Strata 是 OOM killer 高发场景，主动规避）。**磁盘语义（v2 修正）**：serving 生命周期仅「卸载进程+释放统一内存（可选 drop page cache）」，**盘上权重（61.8GB 分片+34GB pack）是持久资产，永不删除**；「评完即删」仅保留在 bench 画像刷新路径（防盘满、仅可再生 zoo 权重）——v1 把 bench 卫生搬进 serving 系范畴错误，已修正 |
| **共存矩阵（v2 补全）** | Strata 驻留（~11GiB）时无法共存任何 zoo 模型；Strata 卸载后可驻 1–3 个小模型（如 qwen3vl-2b-ins 1.1GB + hunyuan-4b 2.6GB）。默认策略：小模型常驻 + Strata 按需换入；首批常驻集合为部署参数（openQuestions） |
| executor | OpenAI 兼容客户端打 `:8080/:8091`（引擎零改动）；stream=true；驱动 agent loop；per-task deadline 计时 |
| resource monitor | 采样内存/缓存热度/温度/队列深度 → `status`（10s）；供换入预检 |

### L5 工具与权限层（Tool Gateway & Policy）

**v2 核心裁决——工具参数权二分（回应「参数谁派生」的核心矛盾）**：

| 工具类 | 参数来源 | gateway 校验 |
|---|---|---|
| **derived** | 完全由 payload 派生（如 `fs.read(data_path)`） | `args ≡ payload 派生值`，边缘 LLM **不可改写**；注入对这类调用无从下手 |
| **authored** | 多步 agent loop 中由边缘 LLM 填写（如发现需再读另一文件） | 三重约束：① policy 路径前缀/参数域（**default-deny**）② **taint 规则**：参数值含被标记 untrusted 的 span（来自工具结果注入的内容）→ 直接拒绝 ③ 参数语法 schema/正则 |

**CaMeL 声明修订**：本架构实现的是 CaMeL 的**数据流标记子集**（untrusted 标记 + 特权操作阻断），不实现双 LLM（边缘 6.31 tok/s 不可承受）；云端 untrusted-normalizer 仍负责把外部内容先结构化再下发。authored 参数的注入**残余风险明示**，由审计、abstain/HITL 兜底。

**grant 结构（v2，回应 TTL 冲突）**：

```json
{"token": {"task_id": "t-…", "aud": "orin-nx-01", "tools": ["fs.read:/var/log/power*"],
           "ttl_s": 300, "ver": 1},
 "lease": {"renewals": 4, "max_total_s": 3600, "task_id": "t-…"},
 "sig": "ed25519:…"}
```

边缘用**单调时钟本地续期**（收包时刻为 t0 基准，不依赖墙钟/NTP；在线时 CONNECT 后校时，绝对时间语义允许 ±60s 偏差，断网天数级漂移列为残余风险）：单段 300s 短时效保爆炸半径小，lease 总预算 3600s 保长任务/Strata 升级不失权；超预算 → `failed{grant_exhausted}`（安全失败）。升级重派由云端签新 token（新 attempt）。

**效果级幂等（v2，诚实化）**：去重只保证**受理** at-most-once；QoS1 at-least-once 下「执行后、持久化前崩溃」窗口仍可能重复执行。因此：**mutating 工具必须携带幂等键（默认 (task_id, attempt)）并支持条件写（version/if-match）**，gateway 拒绝无幂等键的写调用；不支持条件写的不可逆操作强制走 HITL（人工审批本身单次有效）。fs.read 类只读工具不受影响。

**分期与范围（含对评审意见22的部分反驳）**：v1 最小集 = token 签发/验签 + policy default-deny + **低权用户运行** + 审计；v1.5 = Cedar 全表达、签名只读挂载、systemd 细粒度沙箱（seccomp/ProtectSystem）、egress filter。**反驳理由**：评审建议「若参数服务端派生则可砍掉近半 L5」——但参数权已在 v2 裁决为**两类并存**（derived 保安全、authored 保多步自治与断网自治），authored 参数下的注入威胁真实存在，验签+default-deny+低权运行是 authored 威胁下不可省的最小集，故不采纳「砍除」、只采纳「分期」。**egress filter 局限声明（v2）**：它只拦结构化泄漏（密钥格式/路径 pattern），**拦不住自然语言复述凭据**——这是公认弱机制，不能作为痛点③的收口；真正的收口是最小授权（derived 参数+窄白名单）与不可逆动作的 HITL。

### L6 质量与校验层（Quality Pipeline）

**边缘（廉价自检）**

| 组件 | 机制（v2 修订） |
|---|---|
| constrained decoding | 不变：GBNF/JSON Schema（llama-server `--grammar`；`serve/structured.py` 已部署）+ enum + 字段校验。只保证结构合法 |
| **claim 级证据闸（v2 扩窄口径）** | 每个结论字段（claim）必填 `evidence[{chunk_id, quote}]`。两道**零模型成本**程序闸：① 引用核对——chunk_id 必须在实际注入上下文中（拦「幻觉引用」）；② **数值核对**——claim 中的数字必须能在被引 chunk 中找到（拦「引对原文但数字编造」）。grounded 类 intent 的 schema 规定：无 evidence 的 claim 字段不得填写断言（拦「无引用自由发挥」）。**覆盖边界诚实声明**：仍拦不住「引对原文但结论推断错误」——那由复核与 abstain 兜底 |
| consistency-sampler | 不变：高风险任务 k=3~5，一致率作信号；「一致地错」盲区由 RAG 证据交叉验证兜底 |
| **置信函数（v2 公式化）** | `c_struct ∈ {0,1}`（门闸）；`c_cite = 通过引用+数值核对的 claim 比例`；`c_consist = 采样一致率（k=1 时恒 1）`；**`confidence = c_struct ? c_cite × c_consist : 0`**。示例自洽：7 个 claim 通过 6 个、k=1 → conf = 6/7 ≈ **0.86** ✓。阈值 low:0.6 / medium:0.75 / high:0.9 云端下发，阶段 4 标定 |
| abstention | 不变：低于阈值 → `{abstain: true, reason}`；risk_tier 已由 L3 权威裁决，自报低风险无法降低阈值 |

**云端（重复核）**

| 组件 | 机制 |
|---|---|
| untrusted-normalizer | CaMeL 语义：外部内容先在云端结构化，边缘只见结构化参数 |
| cloud judge | `{question, draft, evidence}` → verdict `accept/edit/escalate`；medium 触发（是否每答必评为 openQuestion）；judge 拒绝后的升级走 TaskReassign（预算见 L3） |
| HITL gate | 不可逆动作挂起至 `input-required`，`approve/reject` API 收口（见 L3）；协议带 `confidence`+`evidence` 供人工审计 |

**升级路径的数据流（v2）**：校验不过 → 云端 TaskReassign（attempt+1，deadline/grant 显式延期一次，重广播 ETA）→ 边缘新 attempt 重过 admission，**携带 transcript**（Strata 在草稿与已验证证据上继续，而非纯从零）→ 仍不过 → abstain/HITL/cloud-executor。

### 横切

- **X1 身份与密钥**：设备唯一凭证接 broker；主控 Ed25519 签 grant/lease、设备内置公钥验签；时钟策略见 L5。
- **X2 遥测与画像闭环（v2 修订）**：power_sampler → telemetry → 云算 J/token → **只写 observed 旁表**（不回写 manifest，保持单写者）→ 路由融合。bench 刷新受 admission 与空闲窗口约束（见 L2）。`power_sampler` 抽象为 **TelemetrySampler 接口**（tegra 实现=tegrastats；RK3588 需按平台另实现采样器，非开箱即用）。

---

## 3. 文字版架构图

```
┌─ 云端（主控域）─────────────────────────────────────────────┐
│  主控大模型会话                                              │
│    │ 意图→结构化任务            ▲ SSE 增量/ETA/终态          │
│    ▼ POST /v1/tasks (201/202/409 契约)         │             │
│  [L3] Orchestrator                                          │
│   ├ Router(任务族实测门槛/EDF 队列/诚实 ETA)                 │
│   ├ risk 裁决器(自报只升不降)                                │
│   ├ TaskStore(twin: task_id+attempt+ver)                    │
│   ├ 降级器(小模型→Strata→cloud-executor)+circuit breaker    │
│   ├ Grant 签发(token+lease, 域覆盖校验)                      │
│   ├ artifact-store(预签名 PUT/GET)  ├ HITL approve/reject   │
│   └ 事件网关((task_id,attempt) 分流, seq gap 处理)           │
│    │ 查询               ▲ manifest(静态, 单写者)             │
│  [L2] Registry ◄─────────┘  [observed 旁表(生产画像, 云私有)]│
│  [L6c] 云Judge │ untrusted-Normalizer │ 探针集构建器         │
│  [L1c] MQTT Broker（mTLS/ACL、persistent session、LWT）      │
└──────┬──────────────────────────────────────────────────────┘
       │ ▼ tasks(QoS1, 含 attempt)        ▲ events/results/telemetry/audit/registry
       │ ▲ status(10s 动态水位, 带 ts)
┌──────┴── 边缘 Jetson Orin NX 16GB ──────────────────────────┐
│  [L1e] edge-link：outbound│birth/LWT│心跳│退避+jitter        │
│  [L4] edge-agent(systemd)：deadline 过期过滤                │
│        │受理去重(task_id,attempt)│agent loop(≤8 轮工具循环)  │
│        │Admission(Strata=1, EDF)│ModelManager=引擎进程托管   │
│        │  (健康探测/OOM 预检/共存矩阵; 盘上权重永不删)          │
│  [L5] Gateway：两类工具(derived≡payload / authored 三重约束) │
│        │token+lease 续期(单调时钟)│效果级幂等键│审计          │
│  [L6e] GBNF│claim 级引用+数值核对│置信公式│abstain           │
│  推理引擎(接口不动, 进程受托管)：llama-server :8091(常驻)     │
│                  Strata :8080(按需换入, ~11GiB)              │
│  [L2e] manifest-builder(静态)◄─summary CSV+raw JSON+快照     │
│  [X2] TelemetrySampler(tegrastats) → telemetry               │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. 云边分工

| 决策/职能 | 放哪 | 依据 |
|---|---|---|
| 路由选择、risk_tier 权威裁决、升级/重派与预算 | **云 L3** | 全局视图；自报只升不降堵自报绕过 |
| 准入、换入换出、引擎进程托管、OOM 预检 | **边 L4** | 只有边缘知道 11GiB 驻留/缓存热度/进程死活（`README.md:48,51`） |
| 工具参数权裁决 | 云定类（grant 声明 derived/authored），边强制执行 | derived 防注入、authored 保自治，二分缺一不可 |
| 越权判定 | 边 L5 本地（default-deny+单调时钟续期） | 断网可判权 |
| 不可信内容结构化、judge、任务族探针 | **云 L6c/L2** | 边缘算力不可承受；探针集需要中立评测环境 |
| abstain | 边 L6e（阈值云下发） | 断网时自治拒答 |
| 任务状态权威 | 云 twin；边回 reported（按 attempt） | 平台验证过的 desired/reported 语义 |
| 动态水位 | 边 status 通道（10s+ts），云判新鲜度 | retained 陈旧状态不进路由 |

### 故障语义（v2 修订）

1. **edge-agent 进程挂**：systemd 拉起；LWT 置 offline；in-flight 从 spool 恢复 = **新 attempt 重跑**（半截生成不可续跑），events 按 (task_id, attempt) 开新流、旧流标 abandoned、reported 以最新 attempt 收敛；云端按 deadline/预算决策 pending/降级/失败。
2. **链路断**：边缘自治（含 agent loop 继续跑，本地工具不受影响）；结果本地落盘（带 attempt/ver）；重连先对账 `(task_id, attempt, ver)`，再收 persistent session 补投；**补投任务逐条过 deadline 过期检查**，过期直接回 `failed{expired}`；幂等语义见 L5（mutating 工具效果级幂等键）。
3. **推理引擎崩溃/OOM**：model-manager 托管重启；3 次失败 → `agent_degraded`+任务 `failed{engine_died}`；换入预检不足 → `busy{insufficient_mem}`。
4. **假在线**：keepalive 超时判死。
5. **过载**：admission busy → 云端 shed（小模型/cloud-executor/排队+ETA）。
6. **judge 不可达**：low 自检通过即交付；medium/high 安全失败（挂起/abstain）。
7. **broker 单点**：v1 接受，HA 为演进项。
8. **时钟**：TTL/续期用单调时钟（收包基准）；绝对 deadline 允许 ±60s 偏差；天数级断网漂移列为残余风险。

---

## 5. 典型任务完整生命周期（v2 修订）

场景：主控会话问「**总结这台设备过去 24h 的推理功耗，标出异常点**」（任务族 summarize，risk_tier 自报 low）。

1. **唤醒/接入**：edge-agent 常驻在线（retained online+LWT）。任务到达 `tasks` 即通道级唤醒；若需 Strata，模型级唤醒 = 换入（分钟级，先广播 `model_switch`+ETA）。
2. **注册/发现**：manifest-builder 已发布静态 manifest（ver=8，含 `task_families: summarize{probe: n=30, pass_rate:0.87}`）；status 通道 10s 级供动态水位，60s 新鲜度窗口内视为可信。
3. **分发**：主控结构化 → `POST /v1/tasks {intent:power.summary, family:summarize, min_pass:0.8, latency_budget:60s, risk_tier:low(自报), payload:{data_path:"/var/log/power.csv", window:"24h"}, deadline_s:120}`。云侧：risk 裁决 = max(low, 分类表 low, 工具副作用 read-only) = low ✓；router 查任务族实测 0.87 ≥ 0.8 ✓；延迟：`est = 0(空队) + TTFT(<1s)×1.5 + E[gen_len=300]/(43.5×0.8) ≈ 10s`（**标注：空队假设；est_eta 附 eta_basis**）；grant 签发：`tools:["fs.read:/var/log/power*"]`（签发器校验域覆盖 payload 路径 ✓）+ lease；`201 {task_id, attempt:1, est_eta:"~10s"}`。若 status 显示离线 → `202 {state:queued_offline, policy:queue}`。
4. **执行（agent loop）**：验签 → (task_id,1) 未见过 → 接纳。第 1 轮：derived 调用 `fs.read("/var/log/power.csv")`（args≡payload，直接放行）→ sandbox 低权进程读文件 → 内容以 untrusted 标记注入。第 2 轮：若发现需对照前一日窗口 → authored 调用 `fs.read("/var/log/power/prev.csv")`：policy 前缀 ✓、taint 检查（参数不含 untrusted span）✓ → 放行。流式：token 合帧过 GBNF → events（attempt=1, seq 递增）→ SSE，首 token 亚秒。
5. **校验**：final 满足 out_schema（c_struct=1）→ 7 个 claim 全带 evidence：引用核对 ✓、数值核对（异常时间点/瓦数值逐个在 chunk 中命中）✓ → c_cite=1.0（若仅 6/7 命中则 conf=6/7≈0.86）→ k=1 → **conf≈0.86–1.0 ≥ low 0.6** ✓ → 交付。失败则走 TaskReassign（attempt=2，deadline/grant 显式延期，transcript 随发）。
6. **返回**：egress filter（v1.5 前为最小 pattern 检查）剥除结构化敏感项 → `results{state:completed, attempt:1, evidence[], confidence}` → twin `reported` 收敛 → SSE 收尾，主控呈现带 claim 级出处的结论。
7. **回收**：若曾换入 Strata → model-manager **卸载进程+释放统一内存（可选 drop page cache），盘上权重不动**（持久资产）；grant 到期/lease 预算用尽自动失效；审计上云；本轮实测进 observed 旁表（sample_count+1）；task 归档，中间产物按 TTL 清理。

---

## 6. 分阶段落地路线（v2 修订）

**阶段 1 · 最小闭环**
- 建：Mosquitto；edge-agent v0（外联/birth/LWT/重连/persistent session/deadline 过滤）；**model-manager v0 提前至此**（泛化 `run_zoo.py:194-196` 的 llama-server 启停+健康探测——仓库现状是现拉现删的 bench 模式，常驻小模型服务是要新建之物，评审属实）；**选定首批常驻小模型**（建议 qwen3vl-2b-ins，1.1GB）权重持久驻盘；manifest-builder v0（summary CSV+raw JSON+**部署时画像快照打包**）；orchestrator v0（任务 API+风险裁决简化版+twin）；executor v0（单步任务，agent loop 留空位）；**探针集 v0**：为 summarize/telemetry 各建 30 题探针（复用 `bench_quality.py` 思路）。
- 复用：`edge_deploy.sh` 部署物与 8080 约定；`run_zoo.py` 启停逻辑；`power_sampler.py`；`bench_quality.py`。
- 验收：端到端首 token <3s（小模型）；拔网线 30s 恢复任务不丢且过期任务被拒；kill edge-agent → LWT 置 offline、任务转 pending；`kill llama-server` → 托管重启或 `engine_died` 上报。

**阶段 2 · 速度异构治理**
- **前置（v2）**：`bench_perf.py --buckets 128,512,1024,2048,4096,8192` 补测 Strata TTFT 曲线（脚本支持 buckets；只有 128/2048 两点不能「拟合」，只能端点连线——评审属实）；补测前档间取上界档保守值。
- 建：EDF 队列+排队等待入 ETA；TTFT×1.5/decode×0.8 裕度表；admission+shed；级联两级分流（前置静态路由为主，置信升级显式计价+transcript 传递）；SSE+gap 处理；task store 持久化。
- 验收：4 路并发 Strata 不雪崩；ETA 与实测偏差在裕度内；任务族主路亚秒首 token。

**阶段 3 · 权限层**
- v1 最小集：token+lease 签发验签、policy default-deny、**低权用户运行**、审计 topic、两类工具裁决（derived/authored+taint）。v1.5：Cedar 全表达、签名只读挂载、systemd 细粒度沙箱、egress filter（带局限声明）。MCP 接入见 openQuestions。
- 验收：越权 100% 拒绝+审计；taint 污染参数被拒；mutating 无幂等键被拒；token/lease 超预算即失效。

**阶段 4 · 质量层**
- 建：GBNF/schema；claim 级引用+数值双核对；置信公式落地；risk_tier 权威裁决；云 judge（medium 触发）；abstain+HITL（approve/reject API）；探针集扩至 50–100 题并入路由主轴。
- 验收：输出 100% schema 合法；幻觉引用与数字编造被程序拦截；risk_tier 低报无法绕过 high 闸；judge 不可达时 high 任务 abstain。

**阶段 5 · 运营与演进**
- 建：bench→manifest 刷新流水线（走 admission+空闲窗口）；observed 旁表半衰期与融合调参；TelemetrySampler 抽象（RK3588 按平台实现采样器——tegrastats 不可移植，评审属实）；A2A SDK 对接评估。

---

## 7. 主要风险（v2 修订）

- **基准代表性（收窄后仍存）**：任务族探针已把测量轴对齐决策轴，但探针集本身的代表性需持续回归；生产窗口（observed）是最终校正器。
- **画像漂移**：0.8/1.5 裕度表 + 自动刷新；TTFT 补测前插值为保守上界。
- **升级串行代价**：置信升级显式计价（全额 TTFT+重生成），transcript 传递仅降 decode 量不降 TTFT；硬实时任务必须前置静态路由，不依赖升级。
- **注入残余风险**：authored 参数的 taint 防线可被绕过的场景（拼接改写等）明示；egress filter 不拦语义复述；最终闸是 derived 参数化 + HITL。
- **幂等残余窗口**：「执行后、持久化前崩溃」在无条件写的 mutating 工具上仍可能重复；已用幂等键+HITL 收窄，未消除。
- **时钟**：天数级断网下单调时钟基准与真实时间脱钩，长 lease 与绝对 deadline 有偏差风险。
- **broker 单点**：v1 接受。
- **内存共存**：Strata 换入分钟级+缓存变冷是硬代价；首批常驻集合影响亚秒路径覆盖率（openQuestions）。

## 8. 对纪要的精确化修订（保留自 v1）

1. `summary_quality.csv` 21 行中 1 行是 `smoke` 残留（n=6），manifest 必须排除。
2. `summary_perf.csv` 无 Strata 行，Strata 画像须读本地 `results/raw/perf_strata_*.json`（**本机已实测存在**）；独立部署目标机需随 edge-deploy 打包画像快照。

## 9. 评审意见逐条处置记录（26 条）

| # | 处置 | 落点 / 理由 |
|---|---|---|
| 1 | 接受 | 任务族探针+生产窗口为主轴，gsm8k/arc 降为淘汰性弱代理（§2 L2/L3，§6 阶段1/4） |
| 2 | 接受 | 两级分流：前置静态路由为主机制，置信升级显式计价+transcript 传递，不再称「提前」（§1、§2 L3/L6） |
| 3 | 接受 | 工具两类裁决：derived（payload 派生）/authored（LLM 填参+三重约束），CaMeL 声明收窄为 taint 子集（§2 L5） |
| 4 | 接受 | claim 级双核对+覆盖边界声明；置信函数公式化（0.86 自洽）；risk_tier 云端 max() 裁决（§2 L6、L3） |
| 5 | 接受 | escalation_budget + deadline/grant 显式延期一次 + 超期处置矩阵（§2 L3） |
| 6 | 接受 | 去重键=(task_id, attempt)；msg_id 仅传输层；对账三元组（§2 L4、§4 故障2） |
| 7 | 接受 | 幂等诚实化：受理 at-most-once；mutating 工具强制幂等键+条件写，否则 HITL（§2 L4/L5） |
| 8 | 接受 | grant=token(300s)+lease(本地续期≤3600s)；升级由云端签新 token（§2 L5） |
| 9 | 部分接受 | **事实部分反驳（实测）**：本机即 Jetson，`ls results/raw\|grep -i strata` 确认 perf_strata_pw3.json 等存在（§0 事实12）。**机制部分接受**：独立部署目标机上文件确实不随 edge_deploy 分发，已补「画像快照打包/设备端生成」（§2 L2、§8.2） |
| 10 | 接受 | 动态水位移入 status 通道（10s+ts），60s 新鲜度规则（§2 L1/L2） |
| 11 | 接受 | manifest 单写者（边缘）；云侧实测画像入 observed 旁表+融合规则（§2 L2、X2） |
| 12 | 接受 | 合帧+gap 等待 2s+丢帧标记+QoS1 终态为权威（§2 L1/L3） |
| 13 | 接受 | 补全 cloud-executor、artifact-store（预签名+过 egress+审计）、HITL approve/reject API、入站 payload_ref（§2 L3） |
| 14 | 接受 | 引擎进程托管：拉起/健康探测/退避重启/流中断判定/OOM 预检（§2 L4、§4 故障3） |
| 15 | 接受 | ETA=排队等待+TTFT×1.5+E[gen_len\|family]；EDF+防饿死；示例标注空队假设（§2 L3/L4） |
| 16 | 接受 | 裕度表 TTFT×1.5、decode×0.8（§2 L3、§6 阶段2） |
| 17 | 接受 | 边缘收包必检 deadline，过期回 failed{expired}（§2 L4、§4 故障2） |
| 18 | 接受 | 单调时钟收包基准+±60s 偏差常量+在线 NTP 校时+残余风险声明（§2 L5、§4 故障8） |
| 19 | 接受 | 重跑=新 attempt；events 按 attempt 分流、旧流 abandoned、reported 收敛规则（§2 L4、§4 故障1） |
| 20 | 接受 | bench=低优先级任务走同一 admission+空闲/维护窗口+bench_start/end 保守模式（§2 L2） |
| 21 | 接受 | 新增执行模型：任务内 agent loop（≤8 轮）+session 状态+input-required 上行+transcript 随升级传递（§2 L4、§5 步骤4） |
| 22 | 部分接受+部分反驳 | 接受分期降载（v1 最小集 vs v1.5）与 egress 局限声明；**反驳「二者取一砍掉近半」**：参数权已二分，authored 威胁真实，验签+default-deny+低权运行不可省，仅 Cedar 全表达/细粒度沙箱等可后置（§2 L5 内反驳说明） |
| 23 | 接受 | model-manager v0 提前至阶段1，首批常驻小模型显式选定+共存矩阵（§6 阶段1、§2 L4） |
| 24 | 接受 | 磁盘语义修正：serving 仅卸载进程+释放内存，盘上权重持久不删；「评完即删」仅限 bench 路径（§2 L4、§5 步骤7） |
| 25 | 接受 | 阶段2 前置 buckets 补测；补测前档间取上界档（§6 阶段2、§2 L2/L3） |
| 26 | 接受（a–d 全部） | a: grant 域改 `power*`+签发器覆盖校验（§5 步骤3）；b: 六态为 v1 子集+input-required=HITL，其余态列映射不实现（§2 L3）；c: TelemetrySampler 抽象，RK3588 需平台适配（X2、§6 阶段5）；d: 离线提交 202/409 契约，禁止无 eta 的 201（§2 L3） |

## 10. 未验证声明

本 v2 仍为纸面设计：所有机制未实现、未压测，各阶段验收标准即验证计划。本轮新增实测仅两条：`uname -a`（输出 `Linux nvidia-desktop 5.15.148-tegra … aarch64`，确认主机即目标机）与 `ls results/raw/ | grep -i strata`（输出 perf_strata_default.json / perf_strata_pw3.json / power_strata_default.csv / quality_strata_pw3.json，共 56 个 raw 文件），用于裁决评审问题9；除此之外未运行任何检查。纪要中的外部结论（A2A/MQTT/FrugalGPT/RouteLLM/CaMeL）未逐篇复核原文，采用前请核对官方 spec。