# 两院 Bicameral

> 面向主控-边缘 LLM agent 编排的权限与编排层：HMAC 能力令牌 + 有序 default-deny 拒绝链 + 节点四自代理（自感知/自诊断/自适应/自检）+ 分层部署策略（GPU 优先 → 爆显存上 Strata → CPU 兜底）。仅标准库。
>
> English see [README.md](README.md) · 设计文档 [docs/architecture.md](docs/architecture.md) · 范式 [docs/paradigm.md](docs/paradigm.md)

**结果一句话**：三台异构真机（x86_64 + aarch64；天数智芯 CoreX + NVIDIA CUDA）作为一个受治理集群在线；同一份 task/1 在每台设备经各自权限层执行，delivery/1 信封结构一致并经 Qwen3.8-27B 按 quality_bar 裁决；裸节点一条命令零人工 310 秒到 READY（自装工具链、本机构建、自检）；Qwen3.8-27B 诊断脑对规则表外的未知故障各 1 轮命中修复。九组件约 1.47 万行 stdlib Python；三轮红队 + 四轮评审约 60 项缺陷修复；本页每个数字都可回溯到 `results/` 里带审计的实测记录。

## 1. 解决什么问题

主控大模型会话能唤醒边缘设备上的 agent 并把工具交给它。交出去就有四类失控，而提示词约束与框架内建权限是 **fail-open** 的：

| 失控 | 典型形态 | 两院的收口 |
|---|---|---|
| 越权 | 调白名单外工具；路径逃出数据范围 | 逐调用 HMAC 验签 + 工具白名单 + realpath 范围校验 |
| 注入 | 任务文本夹带指令；投毒文件进入 LLM | 入参注入扫描 + NUL 拒绝 + 全通道响应走私剥离 |
| 重放/伪造 | 令牌截获重放（跨重启也防）；篡改；自签 | HMAC 验签 + 持久化 per-jti nonce 分区 + 严格 TTL + 设备侧审计摘要 |
| 溢出 | 无界调用、超大载荷、推理花费失控 | 三维预算账本（calls/llm_calls/bytes）+ 尺寸上限 + 按模型分档 token 上限 |

原则一句话：**约束不在 prompt 里，在执行口。** 每次工具调用独立对照签名令牌（cap/3）与十六道有序检查链（D1–D16，命中即拒），fail-closed，全过程写入哈希链审计（尾部可外部锚定）。

## 2. 构成

| 组件 | 职责 |
|---|---|
| `bicameral/server.py` | 权限层：控制面（/issue、/audit、/capabilities、/healthz；令牌鉴权、TLS/mTLS 可选）+ agent 面（/agent/invoke，D1–D16 拒绝链）；账本持久化；推理模型 `/no_think` 与 token 上限控制 |
| `bicameral/probe.py` | 设备自盘点（probe/1）：硬件、加速卡厂商、运行时、已装引擎/模型、监听服务、安装度、分割能力 |
| `bicameral/install.py` | 受控安装：引擎 tarball + 模型分片（流式 sha256、mirror 回退、flock、回滚、幂等） |
| `bicameral/nodeagent.py` | 四自层：sense → diagnose（规则表）→ adapt（apt 自装、本机构建）→ verify → 升级；一条命令裸节点到 READY |
| `bicameral/fleet.py` | 拉模式心跳 + ONLINE/STALE/OFFLINE 注册表；daemon 子命令 + systemd 单元；审计尾锚定 |
| `bicameral/pipeline.py` | 初心闭环：task/1 → ROUTE → 双机执行 → 27B 按 quality_bar 裁决 → delivery/1 |
| `scripts/repair.py` | 未知失败的 LLM 修复脑：类型化 JSON 规划、策略门、有界轮、全程审计 |
| `scripts/powerbench.py` / `qualitybench.py` / `bench.py` | 实测功耗（厂商采样器）、GSM8K-mini 质量抽测、并发扫描 |

## 3. 实测（非宣称）

完整矩阵见 [results/2026-10-17-ucb/](results/2026-10-17-ucb/)；逐轮证据在 `results/`（14 个带日期目录）与 [docs/redteam/](docs/redteam/)。

| 维度 | 结果 |
|---|---|
| 权限链吞吐 | 1,433.7 req/s @并发1（p50 0.68 ms，零错误，全拒绝码链） |
| 分层部署 | Jetson CUDA 层 67.48 tok/s（0.6B）；bi150 Strata 层 2.41 tok/s（Flash-Next，0 NaN）；bi150 CPU 层 5.21 tok/s（27B） |
| 质量抽测（GSM8K-mini 20 题） | 27B 100%；0.6B 首位 0% / 末位 95%（口径已文档化） |
| 并发扫描（27B） | 聚合 decode 5.23 → 12.65 tok/s（c1→c4，×2.42 亚线性）；单流 5.5 → 3.2 |
| 27B 功耗 | 330.3 W 持平（CPU 推理，GPU 闲置——客观数据） |
| 红队 | 第一轮 14 条攻击（3 打穿→修复）；第二轮 17 条复测（16 符合设计）；能力轮：供应链/穿越/注入全拦 |

## 4. 快速开始

```bash
# 30 秒端到端验证（自起隔离实例，7 步）
python3 examples/quickstart.py

# 启动；控制面鉴权 fail-closed——设令牌
BICAMERAL_ADMIN_TOKEN=$(openssl rand -hex 16) python3 bicameral/server.py

# 签发只读能力令牌（控制面需要管理令牌）
curl -s -X POST http://127.0.0.1:18000/issue -H 'Content-Type: application/json' \
  -H "X-Admin-Token: $BICAMERAL_ADMIN_TOKEN" \
  -d '{"agent":"agent-ro","task_id":"t1","tools":["fs.read"],"ttl_s":600,
       "budget":{"calls":10,"llm_calls":0,"bytes":65536}}'

# 每次调用都携带令牌；nonce 重复即判重放
curl -s -X POST http://127.0.0.1:18001/agent/invoke \
  -H 'Content-Type: application/json' -H 'X-Capability-Token: <token>' \
  -d '{"nonce":"n-1","tool":"fs.read","params":{"path":"/tmp/bicameral/data/notes.txt"}}'
```

裸节点自治引导（自装工具链、本机构建、自检到 READY，零人工）：

```bash
python3 bicameral/nodeagent.py bootstrap --appspec examples/appspec-qwen3-0.6b-q8_0.json \
  --sandbox /tmp/bicameral-node --engine-source-tgz /path/to/llama-src.tgz
```

## 5. 部署与运营

```bash
ADMIN_TOKEN=<token> [NO_THINK=1] [LLM_MAX_TOKENS=512] [TLS_CERT=… TLS_KEY=…] \
  HOST=<host> PORT=22 USER=root ./scripts/deploy.sh  # 指纹断言式部署
python3 scripts/live_check.py --admin-token <token> \
  --expect-sha $(sha256sum bicameral/server.py | cut -c1-16)  # 25 项实机回归
make bench                                           # 对在跑实例的吞吐基准
```

远端实例 `build_sha` 不等于本地 `sha256sum` 时部署判负——该断言已两次拦下真实版本漂移。`fleet.py daemon`（systemd 单元在 `deploy/systemd/`）保持设备注册表新鲜并逐周期锚定审计尾。

## 6. 边界——状态

已解决：控制面鉴权（令牌；mTLS 可选）、账本持久化、吞吐实测、加密数据面（TLS/mtls）、审计锚定自动化、引擎级安装、卡分割探测（定论：当前容器/驱动下不可用）、推理模型支持。

仍是边界：

- schema 合法 ≠ 语义正确：LLM 输出的事实性不在权限层收口；受治理的 `judge` subject、task/1 `quality_bar` 与 27B 评审脑是接入钩子。
- 正则注入扫描是尽力而为；NUL 已在 schema 拒绝，真正的门仍是拒绝码链。
- fleet 注册表 age 列渲染显示更新前快照（磁盘数据新鲜）；mTLS 客户端侧全量铺开归 v2。

## 7. 设计文档

- [docs/architecture.md](docs/architecture.md) — 权限层完整设计（令牌、拒绝链、预算、审计、三轮红队）。
- [docs/paradigm.md](docs/paradigm.md) — 编排范式：设备感知（§3.1）、能力（§3.2）、基准（§3.3）、受控安装（§3.4）、统一任务（§3.5）、自治层（§10）、模型驱动修复（§11）、初心闭环（§12–13）。

## License

[MIT](LICENSE)
