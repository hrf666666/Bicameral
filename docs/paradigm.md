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
| 厂商工具怪癖 | `jetson_clocks`/tegrastats | `ixsmi` **不在 PATH**，需 `LD_LIBRARY_PATH=/usr/local/corex/lib:…`；lspci 厂商 ID `1e3e` |
| 推理栈 | llama.cpp CUDA 构建；Strata NEON 移植（125B MoE Q2_0，6.31 tok/s 实测） | 4× llama-server（:8960-8963，Qwen3 27B GGUF，`-c 32768 -np 64`） |
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

- 后端矩阵：arch × 加速器类型 × 运行时 → 可用引擎构建（例：`aarch64+sm_87 → llama.cpp CUDA；x86_64+corex → 待测（CUDA 10.2 兼容层能否跑 llama.cpp 是 **[待测]** 头号问题）`）;
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

| 攻击 | 预防 |
|---|---|
| 伪造 DeviceReport / PerfRecord 骗路由（「我是 4090」） | 报告带设备指纹+探针指纹；bench 由主控下发的探针现场跑，不接受设备自报数值 |
| install 供应链投毒（模型/引擎替换） | appspec 双 sha256 + 下载后校验 + 安装目录指纹入审计 |
| probe/bench 滥用为内网扫描器 | 探测本身是受控工具，受白名单与预算约束 |
| 路由退化攻击（压垮快设备使其降级，任务全部滑向弱设备） | PerfRecord 时效 + 负载采样 + 路由审计可复审 |

---

## 6. 分阶段路线与验收门

| 阶段 | 交付 | 验收门（不达不进下一阶段） |
|---|---|---|
| 1 | probe/1 探针单文件 | 在 Jetson 与 bi150 各产出一份 DeviceReport；两份报告能互相解释对方的部署选项（如「bi150 能否跑 llama.cpp」由报告回答，不由我回答） |
| 2 | bench/1 套件 | 同一模型档在两机产出可比 PerfRecord（四同原则） |
| 3 | appspec/1 + install.apply PoC | 一条指令把一台 `absent` 设备变 `ready`，全程审计可查、失败可回滚 |
| 4 | task/1 + 路由 PoC | 同一 task 在两台设备各执行一次：结果 schema 一致，`ROUTE` 审计含候选与理由 |
| 5 | 红队轮 | 按 §5 清单实攻，全部折入修复后才算 v1.0 |

---

## 7. 明确不假设清单（「不要想当然」落款）

1. **不假设厂商 NPU 有可用推理引擎**——昇腾/CANN、摩尔线程、海光各自生态以 L1 探测 + L3 实测为准；bi150 的 corex 能否跑 llama.cpp 是阶段 1 的头号 **[待测]**。
2. **不假设出网统一**——镜像、直连、代理按设备事实配置（Jetson 的 hf-mirror 是既成事实）。
3. **不假设性能可移植**——同模型换架构就是换了一个性能体，一切以 PerfRecord 为准。
4. **不假设安装环境干净**——venv/容器隔离 + sha256 + 回滚是默认路径，不是可选项。
5. **不假设设备长期在线**——一切状态可由探针重建，主控不保存不可复现的状态。

## 8. 命名

范式暂随仓库名「两院 Bicameral」：异构设备即构成、节奏、职权各异的「院」，task/1 是递交审议的「案」。若需独立命名，待范式经阶段 1–3 实测站住后再定——名字不领先于事实。
