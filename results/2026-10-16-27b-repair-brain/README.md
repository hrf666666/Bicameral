# 2026-10-17 bi150 27B 诊断脑驱动的 LLM 自主修复（repair/1 两案例验收）

**目标**：在 bi150（ssh -p 31451 root@10.70.251.39，x86_64，112 核，1T 内存）实证「27B 诊断脑驱动的 LLM 自主修复」：把 nodeagent 规则穷尽升级的 `DIAGNOSIS_REPORT` 喂给 repair.py，由本机 8960 的 Qwen3.8-27B（llama-server，-t 56，eval ≈5.21 tok/s，推理模型）做有界自主修复——类型化规划 → harness 策略门 → 执行 → 有界验证，两案例：**端口被占** 与 **坏 mirror**。

**红线遵守**：22 端口 sshd 未动；主控 bicameral（18000/18001，pid 12161）与 27B 脑（8960，pid 31397）全程未动未重启；自起进程仅 python3 占位 socket（18010）、500-server（18099）、以及 install.apply 拉起的两个 llama-server（18011/18010，验收后已 kill）；写入限 /root/bicameral/ 与 /root/bicameral-sandbox/；结束已删 2×638MB 模型大文件并杀光自起进程，监听集回到 {22, 8960, 18000, 18001}，沙箱余 291M（既有源码树+构建 286M + 审计/证据 ≈5M）。

## 0. 环境与输入指纹

| 项 | 值 |
|---|---|
| 诊断脑 | `http://127.0.0.1:8960/v1`，model id `qwen3.8-27b`（Qwen3.8-27B-UD-Q4_K_M，-ngl 0 -t 56，全程在跑非本轮起） |
| repair.py（canonical） | 主仓 `scripts/repair.py` scp 至 /root/bicameral/，sha256 `2d37de9fbf488145…`（注意：scp 后主仓该文件又前进一步，远端以 sha256_16 `2d37de9f…` 记录） |
| repair.py --selftest | **112 ok / 0 failure（rc=0）**（`raw/repair-selftest.out`） |
| repair-27b.py（/no_think 变体） | 与 canonical 唯一差异一行：SYSTEM_PROMPT 尾加 `"/no_think"`（见 §2 发现）；sha256 `aa53d9d0927c6efb…`，selftest 同样 0 失败 |
| 引擎 | 复用沙箱既有本机原生构建 `/root/bicameral-sandbox/llama.cpp/build-cpu/bin/llama-server`（0.7.0-dev，x86_64，`--version` 通过），appspec 走 engine.binary 预构建形态（与 1.7B example 同款）；bi100 的 jammy tgz 为 x86_64 自包含工件，sha 沿用其记录值但本门未走 engine.install 路径 |
| 模型 | Qwen/Qwen3-0.6B-GGUF `Qwen3-0.6B-Q8_0.gguf`，sha256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`（抄自 bi100 门 appspec），639,446,688 B，hf-mirror 实测 ~9-21MB/s |
| appspec | `raw/appspec-27b-c1.json`（name=qwen3-0.6b-q8_0，port 18010，mirror=[hf-mirror, huggingface]）；`raw/appspec-27b-c2.json`（name=qwen3-0.6b-q8_0-m2，port 18010，mirror=[127.0.0.1:18099, huggingface]——两位全死，制造真实"下载耗尽"） |
| 出口事实 | hf-mirror.com 通（302/200）；huggingface.co 直连 `Errno 101 Network is unreachable`（er-case 的 ctx 如实记录 hf_mirror=up / hf=down） |

## 1. 关键发现：27B 推理模板 × repair.py json_schema 约束 = 恒空输出（案例一 attempt-1）

canonical repair.py 跑案例一，4 轮全部 `invalid_llm_output (plan must be a JSON object)` → `REPAIR_FAILED round_budget_exhausted`（425.3s LLM 时间全废）。直接探针定位（证据在 §3 轮次表 + 远端会话）：

- Qwen3.8 的 chat 模板默认开思考段；llama-server 在 `response_format=json_schema`（GBNF 语法约束）下，**整个 512 max_tokens 预算被写进 `reasoning_content`，`content` 恒为空串**（finish=length，~105s/轮）。
- **prompt 带 `/no_think` 软开关后**：同样的 json_schema 请求 68s 返回完整合法 JSON（328 token，finish=stop）。
- 处置：不改 canonical（其 attempt-1 失败全程存档为证据），部署仅加一行 `/no_think` 的 `repair-27b.py` 重跑两案例。**这是 27B 接入的必要条件，建议回流主仓（按模型族条件加 /no_think）或部署侧 `--reasoning-format none`。**

## 2. 案例轮次表

### 案例一「端口被占」（app qwen3-0.6b-q8_0，工作端口 18010→18011）

故障制造：`nohup python3` 裸 socket 占住 18010（pid 33051）；真实失败链：apply → DOWNLOAD ok 639MB → START pid=33070 → **HEALTH proc_exited=true returncode=1（llama-server bind 失败即退）** → `INSTALL_FAIL step=health exit_code=4` → ROLLBACK removed_dir=true。error-report：`raw/er-case1.json`（nodeagent/1 DIAGNOSIS_REPORT，error_class=unknown）。

**attempt-1（canonical repair.py）— REPAIR_FAILED：**

| 轮 | LLM 耗时 | 模式 | 诊断 | 动作 | 结果 |
|---|---|---|---|---|---|
| 1 | 114.9s | json_schema | （不可见——content 空） | 无 | invalid：`plan must be a JSON object`（reasoning 吃满 512 token，content=""） |
| 2 | 100.7s | json_schema | **「18010 端口已被占用，llama-server 启动后绑定失败并立即退出，导致 /health 无法返回 200」**（诊断正确！） | `adjust_appspec service.port→18011`（正确！） | invalid：JSON 写到 512 token 被截断，`plan must be a JSON object` |
| 3 | 105.4s | json_schema | （空） | 无 | invalid，同上 |
| 4 | 104.3s | json_schema | （空） | 无 | invalid → **REPAIR_FAILED round_budget_exhausted** |

LLM 计 425.3s，**诊断与方案在第 2 轮即正确，但输出无法在预算内落地**。

**attempt-2（repair-27b.py，/no_think）— REPAIR_REPAIRED（全程 2m11s）：**

| 轮 | LLM 耗时 | 诊断（原文） | 动作 | 策略门 | 验证 |
|---|---|---|---|---|---|
| 1 | 52.0s | 「appspec.service.port 18010 被占用（busy），导致 llama-server 启动失败或健康检查无法通过；端口 18011 空闲（free）。」 | `adjust_appspec service.port 18010→18011` | allowed | apply 复跑 → marker **ready**，rc=0 → **REPAIR_OK port=18011 rounds=1** |

双证：`ss` → llama-server pid 34001 LISTEN 127.0.0.1:**18011**（18010 仍被占位 socket 持有，对照成立）；`GET /health` → **200**；`GET /v1/models` → **200**（Qwen3-0.6B GGUF）。工作副本 `raw/work-appspec-c1-final.json` port=18011。

### 案例二「坏 mirror」（app qwen3-0.6b-q8_0-m2，端口 18010）

故障制造：18099 起 python3 http.server 恒返 500（pid 34209）；appspec mirror_urls=[`http://127.0.0.1:18099`, `https://huggingface.co`]（两位全不可用）。真实失败链：apply → **DOWNLOAD fail mirror=1 HTTP 500 ×2** → **DOWNLOAD fail mirror=2 Errno 101 ×2** → `INSTALL_FAIL step=download exit_code=3: all mirrors exhausted` → ROLLBACK。error-report：`raw/er-case2.json`。

**repair-27b.py — REPAIR_REPAIRED（全程 5m01s）：**

| 轮 | LLM 耗时 | 诊断（原文） | 动作 | 策略门 | 验证 |
|---|---|---|---|---|---|
| 1 | 70.1s | 「当前 appspec 配置的镜像源列表失效：首位本地代理 (127.0.0.1:18099) 返回 HTTP 500，次位官方源 (huggingface.co) 因网络不可达 (Errno 101) 失败。环境事实显示 egress 中 hf_mirror 状态为 up，而 hf 为 down，说明应使用 hf-mirror.com 作为可用镜像源。」 | `adjust_appspec model.mirror_urls ["http://127.0.0.1:18099","https://huggingface.co"]→["https://hf-mirror.com"]`（sha256 pin 未动） | allowed | apply 复跑 → DOWNLOAD ok 639MB（sha 全串相符）→ marker **ready** → **REPAIR_OK port=18010 rounds=1** |

双证：llama-server pid 34331 LISTEN 127.0.0.1:**18010**；`/health` → **200**；`/v1/models` → **200**；案例一服务（18011）全程不受影响（隔离性实证）。

### 全程无策略门拒绝、无 abort、无轮数浪费（attempt-2 口径）

adjust_appspec 两字段白名单各用一次，gate 全 allowed；模型 sha256 pin 全程未被触碰（换镜像不改字节来源校验，VERIFY_OK 全串相符为证）。

## 3. 质量对比观察（27B vs 1.7B 脑）

- **诊断深度**：27B 两案例均一轮命中且诊断引用具体证据（`port_checks 18010 busy/18011 free`；`mirror1 HTTP 500 / mirror2 Errno 101 / egress hf_mirror up→应用 hf-mirror.com`），动作一次到位零浪费。1.7B（bi100 casea 存档 `repair-casea.repair-session.json`）同样 1 轮修复，但诊断仅「未归类失败」级别的笼统话，本质是靠 harness 喂的端口占用脚手架猜对。
- **速度**：1.7B 一轮 19.4s；27B 一轮 52-70s（且 attempt-1 废轮 105s/轮）。诊断更深、更贵。
- **鲁棒性坑**：27B 推理模板是硬约束——不关思考则 json_schema 路径 content 恒空（本门实测 4/4 轮全废），`/no_think` 是必要条件；1.7B 未见此问题。
- **结论**：质量上限 27B 明显更高（证据引用、根因链、方案理由完整），但必须配 /no_think（或部署侧关思考），否则比 1.7B 更不可用——预算全烧在 reasoning_content。

## 4. 审计链摘录（源：bi150 /root/bicameral-sandbox/repair/repair-audit.jsonl + audit.jsonl，取回件 raw/）

```
repair-audit: REPAIR_START c1 → 4×REPAIR_ROUND valid=false err="plan must be a JSON object"(114.9/100.7/105.4/104.3s)
  → REPAIR_FAILED round_budget_exhausted(4) → REPAIR_START c1(/no_think) → round1 valid=true 52.0s
  action=adjust_appspec service.port 18010→18011 gate=allowed → REPAIR_ACTION done status=ok(old/new 入审计)
  → REPAIR_OK app=c1 port=18011 rounds=1。REPAIR_START m2 → round1 valid=true 70.1s
  action=adjust_appspec mirror_urls [18099,hf]→[hf-mirror] gate=allowed → REPAIR_OK app=m2 port=18010 rounds=1
install-audit: c1 INSTALL_FAIL step=health rc4 ×2 + ROLLBACK ×2 → READY port=18011；
  m2 INSTALL_FAIL step=download rc3 ×2 + ROLLBACK ×2 → READY port=18010（PROBE_REFRESH partial 为 probe 视角已知行为，marker 调和，两视角并存）
```

## 5. 清理记录（结束态核验）

- kill：占位 socket（18010）、500-server（18099）、c1/c2 apply 拉起的 llama-server（18011/18010）——自起进程清零。
- 删：/root/bicameral-sandbox/apps/（2×638MB 模型）、downloads/。
- 复核：18010/18011/18099 无监听；{22, 8960, 18000, 18001} 在位；`brain8960 /health=200`、`master18000 /health=401`（需 token，未动）。
- 留：/root/bicameral/（appspec×2、er/ctx×2、repair-*.out/err/session、repair.py.canonical、repair-27b.py、evidence-final.txt）、沙箱 audit.jsonl + repair/（repair-audit.jsonl + 两工作副本 appspec）。

## 6. 结论

**验收通过（attempt-2 口径，1 轮/案例）**：27B 诊断脑对两类规则穷尽失败均一轮给出正确根因 + 白名单内修复动作，策略门零拒绝，apply 复跑 READY 双证成立，全程审计完整、升级而非静默（attempt-1 的失败也是结构化 REPAIR_FAILED 而非静默）。**附带发现（高价值）**：27B 推理模型与 json_schema 语法约束互斥地吃空 token 预算，repair.py 对推理族模型必须带 /no_think——建议回流主仓。
