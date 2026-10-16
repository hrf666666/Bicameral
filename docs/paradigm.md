# 两院范式扩展：跨设备、跨架构、跨模型的统一任务层（设计稿 v0）

> **定位**：Bicameral v0.x 是权限层（谁能在哪台设备上调用哪个工具）。本稿设计其上的范式层：
> 设备感知 → 能力边界探测 → 安装程度探测 → 性能边界实测 → 部署安装 → 统一任务。
> 目标是让「同一份任务定义」在任意架构（x86_64/aarch64/RISC-V）、任意加速卡（NVIDIA/天数/昇腾/海光/摩尔线程/CPU）、任意模型（GGUF/Safetensors、稠密/MoE）上可执行、可比、可信。
>
> **方法论声明**：全文每个关键论断标注 **[事实]**（本会话实测或仓库数据）、**[推断]**（由事实推导）、**[待测]**（必须在真机验证后才能作为路由依据）。本稿只定义协议与验收门，不假设任何厂商可用性。「不要想当然」由这三类标注强制执行。

---

## 0. 目标与非目标

**目标**：一份任务定义（task/1），投递到异构设备集合中的**合适者**执行；设备的能力与性能由探测和实测产生，而非人工登记；部署安装由系统完成且全程审计。

**非目标**：
- 不做通用设备管理平台（不替代 K8s/Ansible；本范式只管「与执行任务相关」的设备事实）；
- 不承诺跨厂商训练，只管推理与服务编排；
- 不做模型训练/微调分发。

---

## 1. 已知事实基座 **[事实]**

范式必须在这两台真机上先成立，才谈得上「远远超过」：

| 项 | Jetson Orin NX 16GB | bi150 pod |
|---|---|---|
| 架构 | aarch64，CUDA sm_87，JetPack 6.2 / CUDA 12.6 | x86_64，112 核 / 1 TB 内存 |
| 加速器 | 统一内存 GPU（MAXN_SUPER，14.4 W） | 8× 天数智芯 Iluvatar BI-V150（corex-4.4.0 + CUDA 10.2 兼容层） |
| 厂商工具怪癖 | `jetson_clocks`/tegrastats | `ixsmi` 实际在 `/usr/local/corex/bin/ixsmi`（不在 PATH，probe 经 corex 根搜索定位并注入 LD 后 run ok）**[事实]**：无 `LD_LIBRARY_PATH` 时 exit 127 缺 libixml.so；注入 `/usr/local/corex/lib`（→lib64 符号链）即 exit 0；**`/usr/local/iluvatar/lib` 是空目录**（libixml.so 在两处 lib64，md5 相同）——本表旧记载的 LD 路径已于 2026-10-14 受控实验（A–E 五组对照）勘误；lspci 厂商 ID `1e3e`（pod 容器内 lspci 零命中，发现靠 `/dev/iluvatar*` + 工具） |
| 推理栈 | llama.cpp CUDA 构建（0.4.1-dev b11062 3cf03257f，sha256_16 `8ea353d9d67439be`）；Strata NEON 移植（125B MoE Q2_0，6.31 tok/s 实测） | probe 实测 2026-10-14 **[事实]**：8960/8961/8962 三个 llama-server 在监听（/health + /v1/models 双 200，同一 `/private/models/Qwen3.8-27B-UD-Q4_K_M.gguf`），8963 盘点时刻未监听（bench 时刻又在监听——服务集是动态的）；服务跑在**同 pod 兄弟容器**（共享 netns、隔离 PID/fs：本容器引擎二进制 absent 而 /proc 只有 defunct）；旧记「4×、`-c 32768 -np 64`」参数探针未取证，不作为事实引用 |
| 网络 | HuggingFace 走 hf-mirror，GitHub 走 SSH-over-443 **[事实]**：出网路径不可假设统一 | pip 外网可用；外部仅映射 ssh 31451 |
| 已验证 | 20 模型性能/质量对照方法论（strata-jetson） | Bicameral 权限层 v0.2 + 红队三轮 |

这两行表已经暴露了范式的三个核心难题：**厂商工具不可假设在 PATH**、**出网路径不可假设统一**、**同一引擎在不同架构上是不同 port**（llama.cpp 在 sm_87 与 corex 上就是两个构建）。

---

## 2. 范式总览

```
                    ┌────────────────────────────────────────────┐
   task/1 ──────►  │ 主控：路由（能力×性能×权限×负载）→ 派发 → 结果归一 │
                    └───┬───────────▲──────────────┬──────────────┘
                        │           │ PerfRecord   │ DeviceReport
   appspec/1 ──►  ┌─────▼───┐  ┌────┴─────┐  ┌────┴─────┐
   （部署指令）      │ install │  │  bench   │  │  probe   │
                  │ .apply  │  │  (实测)   │  │  (盘点)   │
                  └────┬────┘  └────┬─────┘  └────┬─────┘
                       ▼            ▼             ▼
              ┌──────────────────────────────────────────┐
              │ 边缘设备：探针（stdlib 单文件，与 server.py 同哲学）│
              └──────────────────────────────────────────┘
```

四个协议全部版本化（`probe/1`、`bench/1`、`appspec/1`、`task/1`），schema 变更走版本号，不靠口头约定。探针是唯一部署到边缘的代码：**stdlib 单文件、只读、无 root 要求、无外网依赖**——与 bicameral/server.py 同一工程哲学。

---

## 3. 协议规范

### 3.1 probe/1 — 设备感知与安装程度

一条命令产出一份 `DeviceReport`，分四节：

1. **hardware**：CPU 架构/核数/内存/统一内存与否；加速器枚举——**探测顺序固定**：扫 `/dev` 节点（`nvidia*|davinci*|iluvatar*|xpu*|mthreads*|dri/*`）→ `lspci` 厂商 ID 表（`10de` NVIDIA、`1e3e` 天数、`19e5` 昇腾、`1002` 海光/AMD、`126f` 摩尔线程）→ 厂商管理工具（先 PATH，再常见安装根 `/usr/local/{nvidia,corex,ascend,hygon,mthreads,rocm}`，**并尝试注入各家的 LD_LIBRARY_PATH**——bi150 实测 ixsmi 不注入就跑不起来）。工具缺失记 `absent`，不算失败。
2. **stack**：OS/内核/容器标记；驱动与运行时版本（CUDA cc 值、ROCm、CANN、corex）；Python/venv 可用性；出网探测（pypi / hf 镜像 / github，各记通/断）。
3. **installed**：已装推理引擎探测（llama-server / vllm / strata 二进制 + `--version`）；本机模型文件清单（路径/大小/格式/量化，按目录约定扫描）；**已监听服务**（`ss -tln` 交叉 `GET /health`、`/v1/models`——bi150 的 4 个 llama-server 就是这么发现的）。
4. **install_state**：对主控下发的每条 AppSpec 给出 `absent / partial / ready / degraded` 四态。`partial` 必须写明缺什么（如「引擎已装、模型文件缺 3.2 GB」）。

**设计约束**：探针每次运行输出自包含 JSON（`schema: "probe/1"`），报告头部带设备指纹（机器 ID + 探针自身 sha256——沿用 build_sha 反版本漂移的教训 **[事实]**）。主控端把 DeviceReport 当**事实库存**，任何能力声明没有对应报告就是无效声明。

### 3.2 capability — 能力边界（推断层，标注 [推断]）

由 DeviceReport 推导「能装什么」，规则表公开可审：

- 后端矩阵：arch × 加速器类型 × 运行时 → 可用引擎构建（例：`aarch64+sm_87 → llama.cpp CUDA` **[事实] 2026-10-14**：在盘构建 0.4.1-dev b11062 端到端跑通 bench，-ngl 99 GPU offload 由 tegrastats 取证；`x86_64+corex4.4.0 → llama.cpp CUDA` **被否**：master 8c2134a8 编译失败，结构性缺口（cooperative_groups/reduce.h 缺失、cudaStreamWaitEvent 签名不匹配 ×5、inline asm llc 崩溃），SDK 无真 nvcc、真编译器 Iluvatar clang-18 ivcore11、设备编译期 `__CUDA_ARCH__=300` 与运行时 cc 7.1 不符（fp16 内核有被裁的静默数值风险）；`x86_64+corex → llama.cpp CPU` **[事实]**：同 commit CPU 构建可用，decode 100.55 tok/s @ Qwen3-0.6B Q8_0）;
- 模型档位：内存预算分档（≤4G / ≤16G / ≤64G / 海量 NVMe 流式——Strata 的专家流式就是第四档 **[事实]**）;
- 此层只生成「候选」，**路由永不直接采信**——必须等 3.3 实测。

### 3.3 bench/1 — 性能边界（实测层）

移植 strata-jetson 的测量方法论为标准套件：对每个 `(engine, model)` 档位测 TTFT / prefill / decode tok/s / 功耗（有 tegrastats/ixsmi 则采，无则标 null）/ 能效，质量抽测 GSM8K-mini + ARC-mini。产出 `PerfRecord`（`schema: "bench/1"`），必带：日期、模型指纹（sha256 前 16）、探针报告引用、上下文与并发参数。

**硬规则：路由只认 PerfRecord，不认型号与宣传值。** 同档跨机可比性由「同 prompt 集、同量化、同上下文、同并发」四同保证——这正是 strata-jetson 20 模型对照已经跑通的方法 **[事实]**。

### 3.4 appspec/1 — 部署与安装（变更层，走权限链）

声明式：

```json
{"schema":"appspec/1","engine":{"name":"llama.cpp","ref":"b<commit>","sha256":"…"},
 "model":{"repo":"…","file":"…","format":"gguf","sha256":"…"},
 "service":{"port":18010,"health":"/health","probe_period_s":30}}
```

安装 = Bicameral 的一个 **mutating 受控工具** `install.apply`（与 fs.write 同级：幂等键、沙箱目录、尺寸上限、审计），流程：下载（尊重设备出网事实，如 hf-mirror）→ 校验 sha256 → 隔离目录安装（venv/容器，绝不污染系统）→ 起服务 → 健康检查 → **强制重跑 probe/1** 刷新 install_state → 失败回滚目录。任何一步失败，install_state 落在 `partial` 并写明缺什么。

### 3.5 task/1 — 统一任务

```json
{"schema":"task/1","task_id":"…","type":"qa|extract|code|…",
 "input":{…},"quality_bar":{"min_gsm8k":0.85},"latency_class":"interactive|batch",
 "constraints":{"data_scope":"/…","egress":"none"}}
```

主控路由 = `capability（实测）× performance（PerfRecord）× permission（能力令牌）× load`，路由决策本身写入审计（`ROUTE` 事件：候选列表、各自 PerfRecord 摘要、选择理由）——**路由必须可复审**，否则异构性就是黑箱。结果归一封装：`{result, engine_fingerprint, perf_reference, audit_ref}`——调用方拿到的不仅是答案，还有「这个答案是在什么能力的设备上、以什么实测性能产生的」。

---

## 4. 与 Bicameral 权限层的整合点

- `REGISTRY` 从静态工具表扩展为 `tools + capabilities + devices` 三节，仍走工具指纹（D15）机制防注册表篡改；
- `install.apply`/`probe`/`bench` 本身是受控工具：签发即受预算与白名单约束（防止「探测」被滥用于扫描）;
- 审计事件扩展：`ISSUE/ALLOW/DENY/BURN/SMUGGLE_STRIP` 之外新增 `ROUTE / INSTALL / PROBE`；
- degrade/recover 机制从「单后端」推广为「设备级」：DeviceReport 停更 → 设备级 D13。

---

## 5. 攻击面预判（红队先行，照旧范式）

> **实装状态标注（2026-10-15 阶段 5 红队轮后）**：前四行是设计稿原预判；后三行是红队轮实攻新发现折入。实装状态以红队复测为准，逐项证据见本仓 `results/2026-10-15-stage5-redteam/README.md`。

| 攻击 | 预防 | 实装状态（2026-10-15） |
|---|---|---|
| 伪造 DeviceReport / PerfRecord 骗路由（「我是 4090」） | 报告带设备指纹+探针指纹；bench 由主控下发的探针现场跑，不接受设备自报数值 | **部分实装**：ROUTE 事件记录每个输入 perf 文件 `sha256_16` + CLI `--expect-perf-sha` pin（router.py:97-105, :177-216, :302-319），伪造文件指纹可见、pin 后 NOT_VIABLE（A1 复测 blocked）；**pin 为可选项**（不带 pin 仍被伪造数值导向，仅可见性）；「主控现场跑 bench」与 bench date 时效窗**未实装** |
| install 供应链投毒（模型/引擎替换） | appspec 双 sha256 + 下载后校验 + 安装目录指纹入审计 | **实装**（阶段 3）：A3 镜像替换、A6 无 pin 安装首轮 blocked，A3 复测回归 blocked；A4 挂起被 60s 读超时有界化（stall guard 覆盖慢滴漏变体） |
| probe/bench 滥用为内网扫描器 | 探测本身是受控工具，受白名单与预算约束 | **实装**：A7 三恶意 appspec（绝对 URL/异构 scheme/内网）全部被钉死 loopback、降级为本地 path，无 SSRF（blocked） |
| 路由退化攻击（压垮快设备使其降级，任务全部滑向弱设备） | PerfRecord 时效 + 负载采样 + 路由审计可复审 | **部分实装**：决策前 `health_url` 存活探测（不可达/strata_state≠ok → NOT_VIABLE，router.py:252-300）+ 路由审计可复审（ROUTE 事件+指纹）；**负载采样未实装**（load 如实记 null）、**PerfRecord 时效未实装**；失败后不自动回退次优候选 |
| **审计灭迹**（删行/伪造行，A2 红队发现） | 审计事件哈希链（seq+prev_sha256_16）+ 启动验链响亮告警 + tail_sha256_16 外部锚定 | **实装**（router.py:364-470, :562-580）：删中间行/原地改均 `AUDIT CHAIN BROKEN` 铁证告警（复测 blocked）；**残余**：删末行/末行原地改文件内不可见——外部锚定为运维动作，未自动化 |
| **信封伪造**（result/1 无中生有，A9 红队发现） | 信封携带 `device_audit_digest`（设备侧 ALLOW 行原始字节哈希）+ 归档核验（verify_result.py：digest→唯一 ALLOW 行→task_id→ISSUE/ALLOW 配对） | **实装**（task.py:243-310, :410-448；verify_result.py 新增）：伪造信封被 router 拒（缺字段 exit 4）、伪造 digest 被归档核验拒（复测 blocked）；**残余**：digest 绑定授权事件而非信封内容，需设备侧签名才能彻底闭合 |
| **engine.binary 解释器注入 / devices run 任意命令**（A5/A11 红队发现） | engine.binary 白名单化（拒解释器、args 模板枚举）；devices/1 清单指纹/签名 + run 白名单模板 | **已实装（2026-10-15 第二批修复）**：engine 白名单 `APPSPEC_ENGINE_BINARIES`（basename 必须 llama-server，解释器 schema 即拒 exit 2，A5 复测 proof 未生成）；devices 清单结构化白名单（自由 run 字段与未知字段拒绝、ssh 目的地结构化堵 -oProxyCommand、清单 sha256_16 入 ROUTE/RESULT，A11 复测 exit 3 零冒名行） |

---

## 6. 分阶段路线与验收门

| 阶段 | 交付 | 验收门（不达不进下一阶段） |
|---|---|---|
| 1 | probe/1 探针单文件 | 在 Jetson 与 bi150 各产出一份 DeviceReport；两份报告能互相解释对方的部署选项（如「bi150 能否跑 llama.cpp」由报告回答，不由我回答）——**达成 2026-10-14**：device-jetson（本仓 `results/2026-10-14-probe-bench/`，含 review-supplement 节）+ device-bi150（本仓同名目录），两机探针同一文件（sha256_16 `eb10063293b418a4` 可外部校验）；「bi150 能否跑 llama.cpp」由报告事实 + 攻坚实测回答：CUDA 被否 / CPU 可用；判定与逐项证据见 strata-jetson `results/2026-10-14-probe-bench/README.md` §5（局限注记：探针引擎扫描仅 PATH+安装根，在盘构建以 supplement 节分列） |
| 2 | bench/1 套件 | 同一模型档在两机产出可比 PerfRecord（四同原则）——**达成 2026-10-14**：Qwen3-0.6B Q8_0 双机 perf 记录（perf-jetson.json / perf-bi150.json，在 本仓 results/2026-10-14-probe-bench/），四同经程序化复验成立（8 条 prompt 逐字一致且逐条 prompt_n 相同、模型 sha256 全串相等、ctx 2048 双方服务端字段互证、并发 1 单 slot），对照表见同上 README §3；结果：bi150 CPU decode 100.55 tok/s ≈ 1.49× jetson CUDA 67.48；perf-jetson 内保留的 `comparable:false` 为流水线中途痕迹，最终以归档证据裁定可比 |
| 3 | appspec/1 + install.apply PoC | 一条指令把一台 `absent` 设备变 `ready`，全程审计可查、失败可回滚——**达成 2026-10-14**：install.py（stdlib 单文件 1254 行，与 server.py 同哲学）在 bi150 沙箱把 qwen3-1.7b-q8_0 从 `absent` 变 `ready`（hf-mirror 流式下载 1,834,426,016 B、sha256 逐块校验 `061b54da…`、/health 200 + /v1/models 双证 + 真实推理 44.9 tok/s CPU）；失败可回滚经两条真机路径实证：badsha（仅 model.sha256 首字符 0→f）`VERIFY_FAIL` 绝不落位→回滚 absent 且目录全清，引擎 pin 不符同样 `VERIFY_FAIL`(exit 3)——校验强制生效；幂等 dedup（name+model.sha256）零下载零新进程复用在跑服务。判定与逐项证据（含两处如实记录：examples 携带他机引擎指纹 `8ea353d9…` 在 bi150 必 VERIFY_FAIL（已于 2026-10-15 修正：示例不再 pin 引擎指纹）、`survived_sigkill` 对 zombie 误报）见 本仓 `results/2026-10-14-stage3-install/README.md`；审计链留 bi150 `/root/bicameral-sandbox/audit.jsonl` |
| 4 | task/1 + 路由 PoC | 同一 task 在两台设备各执行一次：结果 schema 一致，`ROUTE` 审计含候选与理由——**达成 2026-10-15**：task.py（stdlib 单文件 573 行：task/1 fail-closed 校验 + result/1 信封归一 + 设备端 execute-local：/issue 最小令牌 agent-ro/llm.complete/单次预算 → /agent/invoke → stdout 单行信封）+ router.py（618 行，不 import task.py、result/1 契约镜像两侧 selftest 互钉；评分策略写入事件本体 interactive=min ttft / batch=max decode_tps，不可行候选留事件注明缘由，load 未采样如实记 null）；同一 qa 任务双机各执行一次（各恰耗 1 次经权限层的 llm.complete），两份 result/1 信封程序化比对全层键集合与类型一致（12 叶值全异、仅 schema 同值）、双侧过仓内 validate_result；ROUTE 审计含双候选与理由（interactive: min ttft → bi150 23.57 ms < jetson 29.77 ms），双机审计各 ISSUE→ALLOW 一对、时差与信封 latency 吻合；归档与对照表见 strata-jetson `results/2026-10-15-stage4-task/README.md`（route-audit.jsonl 双仓副本 sha256_16 `f9a6fce1156d0559` 逐字节一致）。如实注记：① bi150 活模型已漂移为 Qwen3.8-27B（PerfRecord 实测是 Qwen3-0.6B）——信封以 perf_ref + 活 model_id 并列使漂移可见而非掩盖，端到端延迟因此与路由预测反转（31.1 s vs 0.36 s），复测/重 pin 属运维事项；② jetson 执行变体 prompt 带 /no_think、task_id 带 .jetson 后缀（64-token 上限 × Qwen3 thinking 耗尽上限的既证约束），schema 与意图同一；③ jetson 方向 router 全链路彼时正确 DENY D13（18000/18001 被降级 poc-master 持有并记 EXECUTE_FAIL），后经独立实例 18100/18101 execute-local 成功——router→jetson 真机全链路成功未在本阶段复现，事件如实留档 |
| 5 | 红队轮 | 按 §5 清单实攻，全部折入修复后才算 v1.0——**达成 2026-10-15（v1.0，5/5）**。门标准：确认的代码级漏洞全部修复且复测通过 → 达成；仍有 leaked → 不授予。首轮 12 攻击（6 blocked / 5 leaked / 1 bydesign），复核确认 5（A1/A2/A5/A9/A11）；修复面 A1/A2/A9（另加固 A10）后复测 blocked——perf 指纹+pin、审计哈希链+验链告警、device_audit_digest+verify_result 归档核验均被独立复测证实，回归 A3/A5穿越/A8 确认原防线未松动。缺口 A5/A11 于同日第二批修复并复测 blocked（A5：schema 白名单拒绝 exit 2、proof 未生成；A11：投毒清单 exit 3、零 RESULT 冒名行；回归 apply/route 语义完好，selftest install/router/task/verify_result 全 0 失败）——**v1.0 达成 2026-10-15（5/5 阶段门全过）**。残余如实注记：A2 删末行需外部锚定（运维动作未自动化）、A9 digest 绑授权事件非信封内容（需设备侧签名）、A1 pin 可选+bench 时效窗未实装、负载采样未实装（load:null 如实记）。归档：strata-jetson `results/2026-10-15-stage5-redteam/README.md`；修后工作树未提交（router.py `c96250cd210e6d5e` / task.py `aa9d5deeffae7b89` / verify_result.py `2efc9c0e6648ed57` / devices.json `0830d4e316007fa9`，基线 155f233） |

---

## 7. 明确不假设清单（「不要想当然」落款）

1. **不假设厂商 NPU 有可用推理引擎**——昇腾/CANN、摩尔线程、海光各自生态以 L1 探测 + L3 实测为准；bi150 的 corex 能否跑 llama.cpp 头号 **[待测] 已于 2026-10-14 改判：被否（CUDA）/ 事实（CPU）**——CoreX 4.4.0（CUDA 10.2 代、无真 nvcc、Iluvatar clang-18 `__CUDA_ARCH__=300`）无法编译 llama.cpp master 8c2134a8 的 GGML_CUDA 后端（结构性缺口），同 commit CPU 构建可用并已出实测成绩；复用配方与报错原文留档于 strata-jetson `results/2026-10-14-probe-bench/README.md` §2。
2. **不假设出网统一**——镜像、直连、代理按设备事实配置（Jetson 的 hf-mirror 是既成事实；2026-10-14 双机探针证实出网形态同构 **[事实]**：pypi/hf-mirror/ssh.github.com:443 通、hf/github 直连断，bi150 实测经 hf-mirror 拉到与 jetson 在盘逐字节一致的官方工件）。
3. **不假设性能可移植**——同模型换架构就是换了一个性能体，一切以 PerfRecord 为准。
4. **不假设安装环境干净**——venv/容器隔离 + sha256 + 回滚是默认路径，不是可选项。
5. **不假设设备长期在线**——一切状态可由探针重建，主控不保存不可复现的状态。

## 8. 命名

范式暂随仓库名「两院 Bicameral」：异构设备即构成、节奏、职权各异的「院」，task/1 是递交审议的「案」。若需独立命名，待范式经阶段 1–3 实测站住后再定——名字不领先于事实。


---

## 9. 能力增补（2026-10-16，v1.0 后第一轮）

针对五大能力盘点中的缺口，本轮三项增补（全部 selftest 驱动 + 真机实证）：

| 增补 | 关闭的缺口 | 实证 |
|---|---|---|
| **fleet.py 心跳/离线感知**（拉模式） | 感知设备的「常驻化」缺口：设备离线感知此前是「探针报不出来」而非「主控知道它离线」 | 双真机联调 2/2 ONLINE（jetson local + bi150 ssh）；三态状态机 ONLINE/STALE/OFFLINE；registry 原子写、报告 fail-closed 校验后才转正；selftest 覆盖时钟回拨/损坏容错/注入面（清单供值不供 flag）。拉模式取舍：bi150 外部仅映射 ssh，push 需设备持有回传凭据（信任倒置） |
| **install.py 引擎级安装** | 部署安装的「引擎级」缺口：此前引擎必须在盘 | appspec engine.install 节（tarball 下载→流式 sha256→防穿越解压→binary 解析）；bi150 真机门：引擎+模型**双从零 absent→READY**（引擎指纹与阶段 2 实测记录一致）；反例引擎 sha → ENGINE_VERIFY_FAIL → 回滚无残留；selftest 122 项 0 失败 |
| **powerbench.py 功耗采样** | 性能边界的「功耗未采样」缺口 | ixsmi `gpu.power.draw`（该机实测 `power.draw` 字段被拒——CoreX 4.4.0 怪癖再 +1）与 tegrastats 双格式解析；采样链在 bi150 实机验证（空闲 37–46W×8 出数正常）。**遗留**：27B 档功耗实测待 8960 服务恢复（本轮发现其再次下线——服务来去无常正是 degrade/install 存在的理由），error 记录已归档 |

**能力清单刷新**：感知设备 ~95%（+常驻化拉模式）、安装程度 ~90%、部署安装 ~95%（+引擎级）、性能边界 ~70%（+功耗采样链，-27B 档待测）、能力边界不变（多引擎/NPU 生态实测仍开放）。


### 9.1 第三台设备接入（2026-10-16 当日晚）

**bi100**（Ubuntu 22.04、x86_64、128 核/503G、**2× 天数智芯 Iluvatar**、无工具链无 pip 的裸节点）接入：
- probe/1 一次跑通：Iluvatar 卡识别、出网画像（pypi/hf-mirror/ssh-443 通、hf/github 直连断——与 bi150 同款不对称）、引擎全 absent、corex 用户态缺席（连 release-corex.txt 都如实 absent）；
- fleet 三机 ONLINE（jetson local + bi150 ssh + bi100 ssh），registry 含 manifest 哈希；清单 schema fail-closed 拒绝了非 schema 字段；
- 过程中 **bi150 pod 被平台重置**（authorized_keys/部署/构建全清）——`deploy.sh` 一条命令重供给 + 公钥重装，十 分钟内恢复 ONLINE：易逝设备的「一条命令重建」正是范式承诺；
- 新事实：①探针的 github_ssh_443 "up" 只是 TCP 可达（pod 重置后无 GitHub 注册密钥，clone 被拒）——egress 探测测的是可达性不是授权；②llama.cpp 源码经 Jetson https 通道克隆后打包转送（跨机工件搬运链）；③bi150（glibc 2.39）构建的引擎在 bi100（glibc 2.35）的可移植性待验——引擎工件按发行版分发的结论留待下一轮实证。
- 已知外观项：fleet check 表格的 age 列渲染自更新前的 registry 快照，磁盘数据本身新鲜正确。

### 9.2 bi100 引擎门（2026-10-16 当日晚，同日第二批）

①的可移植性定论落地为 ② 的原生路径，第三设备完整门通过：
- **跨发行版定论实测**：bi150（glibc 2.39）构建在 bi100（2.35）上 GLIBC_2.38/2.36 符号缺失——捆绑非 glibc 库无效，**引擎工件必须按目标发行版构建**（或源码构建）。该事实直接改写 engine.install 的工件分发约定：artifact 按 (arch, os-release) 分发。
- **bi100 完整门 PASS**：apt 装工具链 34s → jammy 原生构建 93s（`-DCMAKE_BUILD_RPATH_USE_ORIGIN=ON` 自包含工件）→ 打包 → 本地 mirror → install.apply 全流程（引擎 6.9MB + 模型 639MB hf-mirror）→ absent→READY，/health+/v1/models 双证 + 真实推理 23.01 tok/s（-t 32）；引擎 sha 反例 ENGINE_VERIFY_FAIL → 回滚无残留；hf-mirror 间歇 429 被重试策略消化。证据：`results/2026-10-16-bi100-engine-gate/`。
- 过程事实：hf-mirror 按客户端 IP 间歇 429（重试即过）；bi100 连 curl/ss 都没有——探针/安装器的 stdlib-only 约束在最小镜像上是必需品而非洁癖。


---

## 10. 自治层（2026-10-16，回应「四自做不到」的批评）

批评成立：此前感知/诊断/适配每一步都靠人。`bicameral/nodeagent.py`（2,221 行，stdlib）把四自收编为节点上的显式机制：

| 四自 | 机制 | 实证（bi100 裸节点→READY 全程零人工，206.7s→310.8s 含加固后重跑） |
|---|---|---|
| 自感知 | `sense`：探针+决策事实（os/glibc/工具链/包管理器/出网/引擎/端口） | 识别「无工具链裸节点」并驱动后续规划 |
| 自诊断 | 显式诊断规则表 + `classify_error` 纯函数：错误特征→根因→处置（GLIBC 符号缺失→本机构建、缺工具链→包管理器自装、429→退避换 mirror、目录缺失→先建） | hf-mirror 429×2 → 有界退避 20s → 复跑成功；规则穷尽 → NA_ESCALATE 结构化报告 exit 3（首跑真实暴露规则分派漂移，按设计升级而非静默） |
| 自适应 | 规则驱动的处置动作：apt 自装（包名白名单常量）、源码构建（RPATH $ORIGIN 自包含）、mirror 重排 | 工具链被移除后一条 bootstrap 自装 15.2s、本机构建 89.4s、READY |
| 自检 | `selfcheck` 7 项（健康/模型表/真实推理/healthz/审计可写/D3 重放/D10 预算），FAIL 必带诊断建议；bootstrap 结果以 selfcheck 为准（ready / ready_degraded exit 4） | 7/7 PASS；注入死端口 → exit 4 + 逐项 FAIL+建议 |

**自治的边界（同样显式）**：bootstrap 全程 flock 单实例；apt 包名与删除操作走常量白名单与 path_inside 门（root 永不删）；规则表覆盖有静态钉（逐规则 `action ==` 比较行 + 规划器反向断言）；源码通道强制 sha256 pin、clone 记 resolved commit；同规则双败无进展即升级。评审 1 HIGH + 4 MEDIUM + 3 LOW 全部修复，selftest 117 项 0 失败，bi100 正例（READY exit 0）与注入反例（exit 3/4）双验证。
