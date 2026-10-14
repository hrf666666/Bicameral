# 两院（Bicameral）：strata-jetson 主控-边缘权限层 v3（能力令牌 · default-deny 策略 · 同机 Strata 能力代理）

> **文档定位**：自含完整稿，不要求读者读过 v1/v2。v1→v2（`docs/architecture-v2.md`）建立六层云边架构并经 26 条评审修订；v3 聚焦其 L5（工具与权限层），以「cap/3 能力令牌 PoC + 红队实证」驱动修订：第一轮纸面设计 → 第二轮 PoC 实现（`poc-master/server.py`）与红队攻击 → 本稿把全部攻防结论折进设计 → 第三轮 v0.2 修复 10 项并复测 17 条（§8），架构定名**两院（Bicameral）**（§9）。
> **证据标记约定**：**[实测]**=红队/独立复核在本机隔离实例跑出过；**[代码证实]**=本会话对 `poc-master/server.py` 逐行核对过（核对方式见 §4.3）；**[推断]**=逻辑推演，未经实验；**[任务输入]**=勘察/调研材料给出的外部事实。

---

## 0. 场景与事实基座

### 0.1 场景

主控部署在 bi150（K8s pod：8×Iluvatar BI-V150、112 核/1007GB 内存），向边缘 agent（agent-ro 只读 / agent-rw 可写）下发任务。**主控大模型能力不模拟**：直接复用同机已部署的 Strata 推理服务，把「调用本机 Strata」注册为一种受控能力 `llm.complete`，与 `fs.read`/`fs.write` 一样过能力令牌、预算与策略检查；云侧 judge/复核同样通过受令牌约束的 `llm.complete` 完成。

### 0.2 bi150 勘察事实 **[任务输入，本轮未重新勘察]**

| 项 | 事实 | v3 处置 |
|---|---|---|
| 8080 | code-server（node，VS Code Web） | 红线：不动 |
| 8181 | JupyterLab（base_url `/ai-exp-zb2557126-bi150-service-jacr/`） | 红线：不动 |
| 127.0.0.1:8960-8963 | 4×llama-server（llama.cpp，`-c 32768 -np 64`，Qwen3 27B GGUF）＝Strata 推理服务本体 | **被复用依赖**：只发 `GET /health`、`GET /v1/models`、in-band `POST /v1/chat/completions`；不 restart/kill/改配置 |
| 18000/18001 | 空闲端口 | PoC 控制平面/agent 平面绑定端口（v3 改绑 127.0.0.1，见 §3.3） |
| 0.0.0.0:22 | sshd | 部署通道 |

**红队期间实测**：8960 当时无监听进程（连接拒绝），PoC 启动即 `DEGRADE(startup_probe_failed)` 且无 RECOVER——Strata 依赖当时不可用。这反向验证了降级路径的 fail-closed 行为（§4.1/#7），同时意味着**所有依赖真实推理输出的用例未在 bi150 走通**（§4.3）。

### 0.3 从 v2 继承什么、补什么

v2 L5（`docs/architecture-v2.md:154-178`，本会话已核对原文）已有：grant=token+lease（Ed25519 签名）、policy default-deny、derived/authored 工具参数权二分+taint、效果级幂等键（`:176`）、签发域覆盖校验（`:120`）。v3 确认方向成立 **[代码证实：v2 五洞在原文确实存在]**，并收口五个洞：

1. **预算只有时间维度**（ttl 300s+lease 3600s）→ v3 增加三维预算账本与尺寸上限（§2.3）；
2. **token 无 jti/nonce**（防重放只靠 dispatcher 层 (task_id,attempt) 去重，`:146`）→ v3 令牌内建 jti+per-jti nonce 分区（§2.1/§2.2）；
3. **无工具指纹 pinning**（对 tool poisoning / rug pull 无对策）→ v3 tools_fp 真指纹+热加载（§2.2 D15）；
4. **无尺寸上限/注入检测/统一 reason_code/审计 schema** → v3 D1-D16 规则链+审计规范（§2.2/§2.4）；
5. **白名单带路径通配**（`fs.read:/var/log/power*`，`:168`）→ v3 工具名精确匹配+data_scope realpath 前缀比对（§2.2 D6/D7）。

---

## 1. 分层总览（文字版架构图）

```
┌─ bi150（主控域：K8s pod，8×Iluvatar BI-V150，独立 netns）──────────────────────┐
│  ┌─ 主控进程（v3 准入：bind 127.0.0.1 · 低权用户 · systemd 沙箱 · 密钥文件 0600）─┐│
│  │                                                                              ││
│  │  控制平面 127.0.0.1:18000              agent 平面 127.0.0.1:18001             ││
│  │   ├ POST /issue     签发器：交叉验证+预算「认得才收」    POST /agent/invoke     ││
│  │   ├ GET  /audit /capabilities /healthz                       │                ││
│  │   └ 管理面鉴权（v3 阶段2）                                    ▼                ││
│  │  ┌───────────── 强制链 PDP（进程内、模型之外、default-deny、有序短路）────────┐ ││
│  │  │ D1验签→D2过期(skew)→D16熔断→D3重放(per-jti nonce)→D4 aud→D11 pol_ver      │ ││
│  │  │ →D9尺寸→D5注册→D6授权→D15指纹→D7 scope→D8 schema/走私键→D12注入          │ ││
│  │  │ →D10预算→handler(IO)→响应消毒→D13依赖降级 / D14异常兜底                    │ ││
│  │  └─────────────────────────────────────────────────────────────────────────┘ ││
│  │   ├ 预算账本 jti→{calls,llm_calls,bytes}（落盘持久化）                        ││
│  │   ├ 能力注册表 + 真指纹 fp=sha256(定义+schema+handler源码)（支持热加载）        ││
│  │   └ 审计 JSONL（param_digest 脱敏、1MiB×3 滚动、按 (task_id,jti) 重构链）      ││
│  └──────────────┬───────────────────────────────────────────────────────────────┘│
│                 │ 127.0.0.1:8960 唯一出站面（并发闸 Semaphore(1)+有界队列，快速 D13）│
│  ┌──────────────▼──────────────────────┐                                         │
│  │ Strata 推理服务（被复用依赖，红线）   │ 127.0.0.1:8960-8963 4×llama-server      │
│  │  GET /health 探针(2s)/30s 周期       │ POST /v1/chat/completions（OpenAI 兼容） │
│  └─────────────────────────────────────┘                                         │
│  [红线] 8080 code-server · 8181 JupyterLab · 8960-8963 Strata 本体：绝不触碰       │
└────────┬─────────────────────────────────────────────────────────────────────────┘
         │ 任务+令牌（生产走 v2 L1 MQTT 通道；PoC 为同机 HTTP）
┌────────▼── 边缘 agents ──────────────────────────────────────────────────────────┐
│  agent-ro（fs.read+llm.complete） · agent-rw（fs.read+fs.write）                  │
│  持令牌调 /agent/invoke；depth:0 禁止再委托；升级/复核由主控重签新令牌              │
│  judge（云侧，llm.complete only）——v3 要求独立部署（独立主机/网络，见 §3.3）       │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**信任边界的核心命题**（本方案最强点，实验支持见 §4.1/#4）：LLM 只有 `127.0.0.1:8960` 一个出站面；其输出回流必经响应消毒；权限判定全部发生在主控进程内的强制链上、**模型之外**——模型输出再恶意也只能撞 D1-D16，不存在「文本改写权限」的代码路径。

---

## 2. 权限层 v3 详解

### 2.1 能力令牌 cap/3.1（HMAC-SHA256 两段式）

格式：`b64url(payload_json) + "." + b64url(HMAC_SHA256(key, payload_b64))`。**没有 header/alg 字段**——alg=none / alg-confusion 攻击面从格式上不存在 **[实测+代码证实：`poc-master/server.py:230-242` 两段式 verify、`hmac.compare_digest` 常时比较；红队篡改保留签名→401、攻击者密钥自签→401 全部失败]**。验签失败（D1）时从 payload 解出 `claimed_jti` 记入审计并标注「未验签」（v3.1 新增，PoC 此前不记，`:570-573`）。

PoC 用 HMAC 对称密钥（stdlib 可实现）；生产升级为 v2 X1 的 Ed25519 非对称签名（`docs/architecture-v2.md:204`），字段不变。

| 字段 | 含义 | v3.1 相对 PoC 的修订 |
|---|---|---|
| `v` | `"cap/3.1"`，未知版本一律 D1 拒绝 | 版本号随字段演进递增 |
| `jti` | 全局唯一令牌 id | 预算账本/nonce 分区/熔断计数的键 |
| `sub` | agent-ro / agent-rw / judge | 令牌即身份；请求体不得再声明身份字段（D8） |
| `task` | task_id | 审计重构链的锚 |
| `aud` | `agent-plane` \| `control-plane` | **修订**：PoC 实现为 `"agent"` 单值（`:208-222`），v3 恢复两面绑定，与双监听面一一对应 |
| `tools` | 精确工具名数组，无通配 | 不变 |
| `tools_fp` | 所授权工具的真指纹集合 | **修订**：fp=sha256(注册表定义 JSON + 参数 schema + `inspect.getsource(handler)`)；PoC 只 hash 元数据（`:128-133`）防不住 handler 被改，且进程内常量注册表使 D15 永真——v3 要求注册表支持文件热加载并在 `/capabilities` 公布当前指纹，使 D15 可触发可验收（§6 阶段1） |
| `data_scope` | 允许触达的路径前缀列表（realpath 归一比对） | 不变 |
| `iat`/`exp` | TTL 默认 300s，上限 3600s | **修订**：PoC 默认 600s（`:695`）收敛回 300s |
| `skew` | 时钟容差秒数 | **新字段**：同进程签发/验证=0；确需分布式容差时按令牌逐个下发，而非全局常量 +30s（PoC `:579` 的全局容差被实测证明是约 30s 纯攻击窗口，§4.2/#5）；TTL≤60s 的短令牌强制 skew=0 |
| `budget` | `{calls, llm_calls, bytes}` 三维 | **修订**：键名以实现为准收敛为 `calls/llm_calls/bytes`（PoC `:75`），设计文档侧改齐；签发侧「认得才收」见下 |
| `depth` | 委托深度 | **修订**：PoC 令牌无此字段，v3 写入 `depth:0` 实字段（边缘禁止再委托；升级由主控重签新令牌，继承 v2 `:174` 语义） |
| `kid` | 密钥 id | 支持轮换 |

**签发侧两道闸**（`/issue`）：

1. **交叉验证**：`tools ⊆ SUBJECTS[agent] ∩ REGISTRY`，越权签发 403 **[实测+代码证实：`server.py:703-708`，红队确认]**；
2. **预算「认得才收」（fail-closed）**：请求 `budget` 出现未知键、或键名与权威表不符 → 拒绝签发 400，绝不静默落到默认上限 **[教训：PoC `clamp_budget`（`:135-144`）对未知键 `raw.get(name, cap)` 静默取默认 1000，红队按设计文档提交 `max_calls:3` 被忽略后放行 4 次调用，§4.2/#1]**。`/issue` 回显必须等于「请求按 caps 钳制后的值」，并把该断言写成部署冒烟检查。

**单一权威参数表**（normative，两版冲突时取更严值；CI 加「文档↔常量」一致性断言）：

| 参数 | v3 权威值 | 说明 |
|---|---|---|
| 请求体上限 | 64 KiB | 读流前按 Content-Length 短路 **[实测：2MB→413，不读流，`server.py:647-663`]** |
| llm prompt | 8 KiB | 取 PoC 值（更严；设计原 16KiB 放弃） |
| fs.write 内容 | 32 KiB | 取设计值（更严；PoC 256KiB 放弃，`:70`） |
| llm 回复摘要 | 512 B | `:73` |
| fs.read 返回 | sha256+size+truncated+**预览 ≤128B** | **v3 重设计**：正文不进模型上下文（§2.3/§4.2/#3） |
| llm max_tokens | 钳 64 | `:72` |
| TTL | 默认 300s，上限 3600s | `:58` TTL_MAX 不变，默认值收敛 |
| 预算 caps | calls 1000 / llm_calls 100 / bytes 1 MiB | `:75` |
| nonce | **per-jti 各 64 条**（替代全局 4096 FIFO `:57`） | 防跨令牌 nonce 驱逐（§7 R1） |

### 2.2 策略引擎拒绝规则（default-deny PDP，有序短路，任一命中即拒绝）

强制链在主控进程内、LLM 之外——「把 LLM 当不可信组件」（调研：CaMeL/Progent）的落点 **[实测：直接注入→422 D12 未触模型，同令牌后续 fs.write 仍 403 D6，文本无法改写令牌]**。异常路径统一走 D14，不存在任何 allow-on-error 路径。

| 序 | 规则 | 条件 | 响应 | v3 修订点 |
|---|---|---|---|---|
| D1 | 令牌缺失/格式错/HMAC 不符/版本未知 | verify 返回 None | 401 TOKEN_INVALID | 审计记 `claimed_jti`（标注未验签） |
| D2 | 过期 | now > exp + token.skew | 401 TOKEN_EXPIRED | **skew 从全局常量改为令牌字段**；同进程=0。教训：PoC 全局 +30s（`:579`）使 ttl=5 的令牌过期后 6s 仍可用 **[实测]** |
| D16 | 令牌已熔断 | jti 在 BURN 集内 | 403 TOKEN_BURNED | **新增（兑现既有承诺）**：jti→连续 DENY 计数（ALLOW 清零），≥5 → 清零该 jti 预算+审计 BURN+后续请求在 D2 后短路。PoC 未实现（grep 0 命中，实测 5 连拒后继续 ALLOW）。它同时是 nonce 洪泛驱逐链的唯一低成本闸门（§7 R1） |
| D3 | 重放 | (jti, nonce) 已见 | 401 REPLAY_DETECTED | **nonce 分区改造**：per-jti 有界集合（各 64），替代全局 FIFO——PoC 的全局 4096 槽（`:57,162-171`）可被一个合法令牌零成本灌满、驱逐他令牌的 nonce（§7 R1） |
| D4 | 面不匹配 | token.aud ≠ 监听面 | 403 AUD_MISMATCH | aud 值恢复两面 |
| D11 | 策略过期 | token.pol_ver ≠ 当前 | 409 POLICY_STALE | 注册表热加载时 pol_ver 递增，使本规则可触发 |
| D9 | 尺寸超限 | body/prompt/写内容超权威表 | 413 PAYLOAD_TOO_LARGE | 读流前短路 |
| D5 | 工具未注册 | ∉ REGISTRY | 403 TOOL_UNKNOWN | default-deny：注册表外一切拒绝 **[实测：shell.exec 403，5 连拒]** |
| D6 | 未授权 | ∉ token.tools | 403 TOOL_NOT_ALLOWED | **[实测：RO 令牌调 fs.write→403]** |
| D15 | 指纹失配 | token.tools_fp ≠ 注册表现值 | 409 TOOL_FINGERPRINT_MISMATCH | **真指纹化**（含 schema+handler 源码）；注册表热加载→存量令牌全拒→重签恢复，写入验收用例 |
| D7 | scope 逃逸 | realpath(参数路径) ∉ data_scope | 403 SCOPE_VIOLATION | **升为 PDP 规则**：enforce 链在 D8 前显式比对（PoC 在 handler 内抛 PermissionError→500 D14，`:456-460,609-610`，攻击与故障在审计里不可分）；handler 只做 IO |
| D8 | schema 违规 | 请求含 schema 外字段；任意嵌套深度出现 `actions`/`tool_calls`/`toolCalls`/`function_call` 键；mutating 工具缺幂等键 | 400 SCHEMA_VIOLATION | 请求侧对策 **[实测：`server.py:249-255` 任意深度检查成立；幂等三分支成立：缺 idem_key→400，同键同内容→200 deduplicated:true，同键异内容→拒绝]** |
| D12 | 注入嫌疑 | free-text 参数命中 pattern | 422 INJECTION_SUSPECTED | **pattern 集双语化**：PoC 仅 6 条英文（`:293-303`），v3 补中文（忽略以上/无视上述/扩权/给我权限/重签令牌）与 grant me / re-issue / escalate privilege；**定位是检测器不是防线**——真防线是 D5/D6/D8 与 §2.3 的摘要回传 |
| D10 | 预算耗尽 | calls / llm_calls / bytes 任一超 | 429 BUDGET_EXHAUSTED | **429 响应加 `dim` 字段**（PoC 缺失，`:601-602`），耗尽维度可定位 |
| D13 | 依赖降级 | llm.complete 且 Strata 状态 ≠ ok | 503 CAPABILITY_DEGRADED | fail-closed，绝不静默换目标（§3.2） |
| D14 | 内部异常 | 强制链/handler 任何异常 | 500 INTERNAL_DENY | **响应体去掉 `err=异常类型`**（PoC 泄漏 `PermissionError`，`:610`）；类型只进审计 |

### 2.3 预算与溢出防线

- **三维账本**：`{calls, llm_calls, bytes}`，服务端按 jti 记账，`budget_take` 原子扣减且**先于 handler** **[实测：D13 失败也扣减预算、llm 维第 2 次调用 9ms 内 429 且确定未出网（`server.py:601→174-191`）]**——重试风暴打不到 Strata。账本落盘持久化（v3 新增，§7 R2：重启清零曾造成 fail-open 重放窗口；预算方向丢失本身是 fail-closed `:179-180`）。
- **llm 并发闸**：`llm.complete` 加 `Semaphore(1)`+有界等待队列（对齐 v2 L4 admission，`docs/architecture-v2.md:148`），满→快速 D13/429。动机 **[推断，有部署实测佐证]**：LLM 超时 60s + ThreadingHTTPServer 无 worker 上限，Strata 变慢时线程与已扣不退的预算同步堆积。
- **摘要回传原则（v3 收敛为单口）**：**内容进入模型上下文的唯一通道是 `llm.complete`**。`fs.read` 降级为「指纹+元数据」通道：返回 `{path(realpath), size, truncated, sha256, preview≤128B(消毒后)}`，不再回传 4KiB 全文。根因 **[实测·三方一致]**：PoC 的 `strip_smuggle` 只挂在 llm.complete 回复上（`:545-548`），`h_fs_read` 的 summary 原样回传全文（`:463-479`），投毒文件的 `actions`/`tool_calls` JSON 越权回流，SMUGGLE_STRIP 计数 0（§4.2/#3）。llm.complete 的回复继续过 strip_smuggle：命中即替换 `[STRATA:SMUGGLE_STRIPPED]`+审计 SMUGGLE_STRIP。
- **熔断**：见 D16。**审计膨胀**：JSONL 1MiB×3 滚动 + 脱敏（§2.4）。

### 2.4 审计日志（JSONL，按 (task_id, jti) 重构整条链）

```json
{"ts":1760000000.123, "event":"ISSUE|ALLOW|DENY|BURN|DEGRADE|RECOVER|SMUGGLE_STRIP|INJECTION",
 "task_id":"t-1", "agent":"agent-ro", "jti":"…", "claimed_jti":null,
 "nonce":"n-1", "tool":"llm.complete", "decision":"DENY",
 "reason_code":"D12/INJECTION_SUSPECTED", "dim":null,
 "pol_ver":1, "budget_after":{"calls":2,"llm_calls":0,"bytes":1024},
 "param_digest":{"prompt":{"sha256":"…","len":2048}},
 "detail":{"hits":[{"pattern":"expand_privilege_cn","offset":42,"frag_sha256":"…"}]}}
```

v3.1 对齐修订（PoC 三处未兑现 **[实测]**，`:545-548,570-573`）：

1. **ALLOW/DENY 落 `param_digest{sha256,len}`**——PoC 只落 result_keys/est_bytes；
2. **D12 只落 pattern 名+偏移+命中片段 sha256，绝不落原文**——PoC 曾把 prompt 前 80 字符样本写进审计（实测 audit 行含 `"IGNORE ALL PREVIOUS INSTRUCTIONS and gr"`，违背脱敏承诺；SMUGGLE_STRIP 的 `sample=` 参数同理移除）；
3. **1MiB×3 滚动**——PoC 为无界追加；
4. **D1 记 `claimed_jti`**——PoC 的 D1 拒绝行无 jti，攻击者自报身份不可追溯。

脱敏原则不变：令牌串、prompt/文件内容原文永不落盘；完整链 = ISSUE→(ALLOW|DENY)*→BURN，按 (task_id, jti) 可重放（v2 阶段3验收「越权 100% 拒绝+审计」`docs/architecture-v2.md:303` 的可验证形态 **[实测：ISSUE/ALLOW/DENY 均带 jti/task_id/agent/tool/reason_code，grep 原始 audit.jsonl 证实不含令牌串与文件内容——唯一例外即上述 D12 样本，v3.1 修复]**）。

---

## 3. 主控与 Strata 同机整合

### 3.1 llm.complete 能力代理

`llm.complete` 是 REGISTRY 中的普通工具（`class: authored, remote: true`，PoC `:75` 后注册表同构），过**同一条** token→budget→policy→audit 强制链。实现：

- 转发：`urllib.request` POST `{STRATA_URL}/chat/completions`（默认 `http://127.0.0.1:8960/v1`，OpenAI 兼容，与仓库 `scripts/run_zoo.py:200-204` 的 `--base-url http://127.0.0.1:8091/v1`、`scripts/edge_deploy.sh:32` 的 `serve.server --port 8080` 同构）；`model` 取自启动时 `GET /v1/models` 第一个 id，取不到则省略该字段（llama.cpp 容忍）；`max_tokens` 钳 64；调用超时 10s（v3 收紧，PoC 曾 60s）。
- 探针：后台线程每 30s `GET /health`（超时 2s；失败 fallback `GET /v1/models`），状态翻转即审计 DEGRADE/RECOVER **[实测：拒连→启动即 DEGRADE(startup_probe_failed)，30s 周期线程按设计工作]**。
- 云侧 judge：主体 `judge`，tools 仅 `[llm.complete]`，同链同预算。**v3 部署要求：judge 独立部署**（独立主机/网络域），不是同机第二进程——理由见 §3.3。

### 3.2 预算与降级

- 状态机 `ok ↔ degraded`：探针失败或调用超时/连接拒绝 → degraded；此后 llm.complete 一律 503 D13，**fs.read/fs.write 完全不受影响** **[实测：Strata 拒连时 llm.complete 503、文件工具正常]**。下次探针成功自动恢复，审计 RECOVER。
- **不做静默 fallback** 到别的端口/模型——那等于绕过预算与审计面。
- D13 也扣预算（budget_take 先于 handler）**[实测：第 1 次 503 已扣 llm 维，第 2 次直接 429 D10，9ms 返回]**——慢依赖打不出重试风暴。

### 3.3 架构决定：同机保留，但设三类隔离为 v3 准入条件

**决定**：主控与 Strata 同机（bi150）保留。

**理由**（实验支持）：信任边界成立且是本方案最强点——强制链在主控进程内，LLM 仅有 127.0.0.1 单一出站面，模型输出再恶意也只能撞 D1-D16（红队注入链断裂 + D13 fail-closed 为证，§4.1/#4/#7），同机共置不破坏「LLM 是不可信组件」假设。故障域分析 **[推断，由 D13/D14 行为外推]**：同机=单故障域，OOM/驱动故障同打权限面与推理面；fail-closed 语义下「一起死」是安全方向（拒而不放）。代价是可用性与安全共用故障域——这正是云侧 judge 必须独立部署的原因：主控域降级时复核能力必须还活着。

**三类隔离（必改，PoC 的 v3 准入条件）**：

1. **绑定面**：两平面从 `0.0.0.0`（`server.py:853-855`）改绑 `127.0.0.1`。PoC 仅靠部署网络隔离（外部仅 ssh 隧道）未暴露，v3 不再依赖部署巧合。
2. **密钥横向暴露** **[推断，机制明确]**：同 UID 下 Strata 或任何同机进程被 RCE，可经 `/proc/<pid>/environ` 读到 `POC_MASTER_KEY`（`server.py:824-825` 走 env），把「模型被攻破」升级为「权限根被攻破」、伪造任意令牌。缓解：主控低权用户运行 + v2 v1.5 已列的 systemd 沙箱（`ProtectSystem`/seccomp）；密钥改走 0600 密钥文件（或凭据代理），不进环境变量。
3. **资源争抢**：LLM 超时 60s + 无 worker 上限的线程堆积 **[推断，部署实测 26.8s 慢往返为据]** → §2.3 的 llm 并发闸 + 快速 D13。

---

## 4. PoC 实证结论

方法：PoC 部署于 bi150（18000/18001）后由红队攻击；独立复核在本机隔离实例复测（端口 19100/19101，`--strata-url` 指向关闭端口复现 degraded；`py_compile` 通过，Python 3.11.14）；测试后实例已停、临时目录已清理，机器上预存的 18000/18001 实例未触碰。**本节行号均指 `poc-master/server.py`（本地副本，sha256 前缀 b20a9683），本会话已逐处核对。**

### 4.1 拦截住的（9 项，全部 [实测]，行号 [代码证实]）

| # | 防线 | 实证 |
|---|---|---|
| 1 | 令牌防伪 | 篡改 payload 保留签名→401 D1；攻击者密钥自签→401；两段式无 header/alg，alg-confusion 攻击面不存在（`:230-242` 常时比较） |
| 2 | 重放防护 D3 | 字节级相同请求二次提交→401 REPLAY_DETECTED，(jti,nonce) 原子查插（`:162-171`） |
| 3 | 最小授权双闸 | RO 令牌调 fs.write→403 D6；未注册 shell.exec→403 D5（5 连拒）；/issue 交叉验证拒绝越权签发（`:703-708`）；请求信封只收 `{nonce,tool,params}`、任意深度走私键→D8（`:249-255`） |
| 4 | 强制点在模型外 | 直接注入→422 D12 未触模型；同令牌后续 fs.write 仍 D6——「文本无法改写令牌」被实验支持 |
| 5 | 三维预算账本 | calls:3→3×200→第 4 次 429→令牌死亡；llm_calls 独立计数；D13 失败也扣减；第 2 次调用 9ms 429、确定未出网（budget_take 先于 handler，`:601→174-191`） |
| 6 | 入口尺寸 D9 | Content-Length 预检短路不读流（`:647-663`）；2MB payload→413、目标文件未生成 |
| 7 | fail-closed D13/D14 | Strata 拒连→llm.complete 503、fs.read/fs.write 不受影响、探针 DEGRADE（→恢复路径 RECOVER）；路径逃逸（/etc/passwd、审计文件自身、**symlink→/etc/passwd** 红队加测）全部 PermissionError→500 D14，落盘未发生（realpath+os.sep 前缀比对，`:456-460`） |
| 8 | fs.write 幂等 | 缺 idem_key→400 D8；同键同内容同路径→200 deduplicated:true；同键异内容→拒绝（fail-closed） |
| 9 | 审计链+脱敏主体 | ISSUE/ALLOW/DENY 带 jti/task_id/agent/tool/reason_code，(task_id,jti) 可串链；grep 原始 audit.jsonl 无令牌串与文件内容（唯一例外 D12 样本，见 §4.2/#6） |

另 **[代码证实]**：设计文档对 v2 的全部引用核实无误（`docs/architecture-v2.md:156-163` 参数权二分/taint、`:165-174` grant+lease+Ed25519、`:176` 幂等、`:204` X1、`:120` 签发域校验、`:146` 去重、`:303` 阶段3验收、`:178` egress 局限）——v2 五洞清单成立，加固方向对应的洞在 v2 原文确实存在。

### 4.2 被打穿的（8 项 broken；其中 4 项经独立复核 confirmed）

每项按「现象→根因→v3 修订」给出：

| # | 现象（[实测]，4 项经独立复核 confirmed） | 根因（[代码证实]） | v3 修订 |
|---|---|---|---|
| 1 | 按设计文档提交 `budget.max_calls:3` 被静默忽略→`/issue` 回显 `{calls:1000}`→4 次调用全 200 无 429；llm 维同样（`max_llm_calls:1`→100） | 预算键名 spec↔impl 漂移：实现只认 `{calls,llm_calls,bytes}`（`:75`），`clamp_budget` 对未知键静默取默认（`:135-144`）；429 体无 dim（`:601-602`） | §2.1 预算键名统一+「认得才收」；§2.2 D10 加 dim |
| 2 | 5 连拒后同令牌继续 ALLOW，全程 BURN=0 | 熔断/BURN 未实现（grep 0 命中） | §2.2 D16 熔断（含 nonce 洪泛闸门职责） |
| 3 | 投毒文件 `smuggle.json` 经 fs.read→200，`actions`/`tool_calls` 全文越权回流；SMUGGLE_STRIP 前后计数均 0 | strip_smuggle 只挂 llm.complete（`:545-548`），h_fs_read 原样回传 4KiB（`:463-479`） | §2.3 摘要回传单口化：fs.read 只回 sha256+size+128B 预览；llm 回复继续 strip |
| 4 | 路径逃逸被拦但报 500 D14、响应体泄 `err=PermissionError`——攻击与故障不可分 | D7 未做成 PDP 规则，检查在 handler 内抛异常（`:456-460,609-610`） | §2.2 D7 升 PDP 规则 403；D14 去 err |
| 5 | ttl_s=5 令牌：t+6s（已过期）仍 200，t+36s 才 401——约 30s 纯可用窗口 | 全局 +30s 容差 `now>exp+30`（`:579`）；签发验证同进程无时钟差 | §2.1/§2.2：skew 改令牌字段，同进程=0，短 TTL 禁容差 |
| 6 | 审计三处未兑现：D12 落 prompt 80 字符原文样本；param_digest 不存在；无滚动、audit.jsonl 无界追加。另 D1 不记攻击者自报 jti | （`:545-548,570-573` 等） | §2.4 四条对齐修订 |
| 7 | tools_fp 弱且不可触发：fp 只 hash 注册表元数据（`:128-133`）防不住 handler 被改；进程内常量+同进程签发使 D15（`:593`）逻辑永真，从未被测试行使 | 真指纹需含 schema+handler 源码；注册表需热加载路径 | §2.1 tools_fp 真指纹化+`/capabilities` 公布指纹+热加载；§6 阶段1 加「改注册表→存量令牌全拒→重签恢复」用例 |
| 8 | 参数表/令牌结构与设计发散：fs_write 256KiB vs 32KiB、prompt 8KiB vs 16KiB、TTL 默认 600 vs 300、无 depth 字段、aud 单值、D12 仅 6 条英文（`:293-303,695,70-75` 等） | 两份规范不可互换，验收基准存疑 | §2.1 单一权威参数表（冲突取更严值）+CI 文档↔常量断言；补双语 pattern |

### 4.3 证据效力声明（哪些结论可信到什么程度）

- **真实 Strata 路径的覆盖几乎为零**：红队期间 bi150 上 8960 无监听（连接拒绝），`llm.complete` 相关用例实际走的是「启动即 degraded→503 D13」的降级分支；「第 1 次 200 真打 8960」不可复现 **[实测·独立复核 confirmed]**。真实推理输出上的正向链（真实输出→strip→摘要回传）仅一次部署冒烟（STRATA_POC_OK）证据；间接注入「pattern 未命中→200 仅摘要」分支从未走通。→ §6 阶段1 验收要求在 Strata 恢复后重打这组用例。
- **版本一致性**：本地副本 sha256=`b20a9683…`（本会话 `sha256sum` 复核一致）与部署报告声称的 `ef418afd52ad…` 不一致（本地 mtime 晚于部署，疑似部署后本地又有改动）。红队引用的 9 处行号与本地副本逐一吻合，故代码层结论以本地副本为准；**不排除远端运行版本差异**。
- **测试形态**：全部黑盒复测在本机隔离实例完成（19100/19101，Python 3.11.14）；全部测试串行，并发/竞态零数据（§7 R4）。
- **本会话（文档撰写轮）实际执行**：`ls poc-master/`、`sha256sum poc-master/server.py`（→`b20a9683147f0d2d6a7e28a0e3d5aaa0a3d7e98b723b9db5ecd458615a210556`，873 行）、对 `:57,:58,:70-80,:109-133,:135-144,:162-191,:230-242,:249-255,:283-303,:456-479,:545-548,:570-579,:596-610,:647-663,:695-720,:820-830,:850-856` 的 sed 逐段核对与 grep——**未重跑任何攻击用例**；上述 [实测] 结论引自红队/独立复核报告（任务输入）。

---

## 5. 典型任务生命周期（v3 语义）

场景：主控要求 agent-ro 总结设备日志 `/tmp/strata-poc/data/power.log` 的异常点。

1. **签发**：主控 `POST /issue {"agent":"agent-ro","task_id":"t-sum-1","tools":["fs.read","llm.complete"],"ttl_s":300,"budget":{"calls":8,"llm_calls":2,"bytes":65536}}`。签发器交叉验证 tools ⊆ SUBJECTS∩REGISTRY；预算「认得才收」（若提交未知键如 `max_calls` → 400，**这是 §4.2/#1 的回归断言**）；回显=钳制后值；审计 ISSUE。
2. **定位文件**：agent-ro 持令牌 `POST /agent/invoke {"nonce":"n1","tool":"fs.read","params":{"path":"/tmp/strata-poc/data/power.log"}}`。强制链走 D1→D16→D3→D4→D11→D9→D5→D6→D15→D7→D8→D12→D10 全绿→handler。**v3 返回的是 `{realpath,size,truncated,sha256,preview≤128B}`**——正文不进模型上下文（§4.2/#3 修复后的形态）。
3. **真实推理**：agent-ro 把「文件 sha256+由主控注入的原文（走 artifact 通道，生产语义）」构成 prompt，`llm.complete` 调用。并发闸放行→POST `127.0.0.1:8960/v1/chat/completions`（max_tokens≤64，10s 超时）→回复过 strip_smuggle→`{content_summary≤512B, usage}` 回传。若 Strata 慢：并发闸排队；若不可达：503 D13（llm 维预算已扣），**fs.read 不受影响**。
4. **攻击插曲（应被全部拦下）**：攻击者截获令牌后 ① 原样重放→401 D3；② 改 payload 保签名→401 D1（审计记 claimed_jti）；③ 同令牌连发 5 次非法工具→D16 熔断，令牌死亡；④ 灌 nonce 洪水→per-jti 分区使洪水只影响攻击者自己的 jti，且熔断先到。
5. **云侧复核**：judge 独立部署域持 `judge` 令牌（tools=[llm.complete]，独立预算）对草稿做 accept/edit/escalate——主控域降级时 judge 域仍可用（§3.3 故障域分离）。
6. **回收与重构**：grant 到期/预算耗尽自动失效；审计按 (task_id="t-sum-1") 一键重构 ISSUE→ALLOW×N→（攻击者的 DENY×5+BURN）完整链；audit.jsonl 滚动保留 3 卷。

---

## 6. 分阶段落地路线

**阶段 1 · 修复包（把 8 项 broken 清零）**
落地 §2 全部修订：预算键名+认得才收+dim；D16 熔断；fs.read 指纹化回传；D7 升 PDP；skew 字段化同进程=0；审计四条对齐+滚动；tools_fp 真指纹+热加载；权威参数表+CI 断言；D12 双语 pattern；per-jti nonce 分区。
**验收（全部可执行）**：① §4.2 的 4 个 leaked 用例回归——smuggle.json 经 fs.read 返回体不含 actions/tool_calls（或该通道已无正文）；`max_calls:3` 第 4 次 429 且带 `dim:"calls"`；过期令牌 t+1s 即 401；llm 维第 2 次 429 带 `dim:"llm_calls"`。② D15 用例：改注册表一项→存量令牌全拒 409→重签恢复。③ 双令牌 nonce 洪泛时序实验（§7 R1 的验证）。④ **在 bi150 上 8960 恢复监听后重打真实路径组**：间接注入「未命中→仅摘要」分支、正向 strip 链、真实超时 D13。

**阶段 2 · 生产化隔离（§3.3 三类隔离）**
bind 127.0.0.1；低权用户+systemd 沙箱；密钥文件 0600（env 清零）；审计滚动上线；管理面鉴权（/issue 签发鉴权、/audit /capabilities 需管理令牌——PoC 实测 /capabilities 无令牌可 200 并泄漏注册表/指纹/limits/strata_state）。
**验收**：`ss -tln` 两平面仅 127.0.0.1；`/proc/<pid>/environ` 无密钥；无管理令牌访问三端点均 401。

**阶段 3 · 并发与长稳**
预算并发扣减原子性（2 并发×3 次 vs 预算 3 的竞态测试）；degraded 状态翻转竞态；慢 Strata（>10s）下线程堆积与并发闸行为；1h 长稳观察降级振荡（慢→D13→30s RECOVER→再慢）与探针/调用超时不对称；审计磁盘占用曲线。
**验收**：并发下账本终值一致；振荡有抑制（连续 N 次 D13 后延长退避）。

**阶段 4 · 回接 v2 六层**
v3 强制链替换 v2 L5 的 grant 结构（token 字段映射、Ed25519 换 HMAC）；幂等键与 (task_id, attempt) 联动（v2 `:176`）；D12 漏报残余由 v2 L6 的 HITL/abstain 兜底；审计 topic 接 v2 L1 `edge/{id}/audit`。

---

## 7. 残余风险（9 项，含状态与责任阶段）

| # | 风险 | 依据 | 状态/缓解 | 责任 |
|---|---|---|---|---|
| R1 | nonce 洪水驱逐→跨令牌重放：被拒请求也消耗 nonce 且不耗预算（budget_take 在 D5 之后），合法令牌可灌满全局 FIFO 驱逐他 jti 的 nonce，配合 TTL 窗口内截获请求实现跨令牌重放 | **[实测：D5 拒后同 nonce 二次提交变 D3；`server.py:169-170` FIFO]** | v3 双闸：per-jti nonce 分区（结构性消除跨令牌驱逐）+D16 熔断（低成本闸门）；双令牌时序实验未做 | 阶段1 |
| R2 | 重启 fail-open 窗口：nonce/预算纯内存（`:109-113`），重启后 TTL 未过令牌的已用 nonce 清零→截获请求可重放一次（预算丢失方向是 fail-closed `:179-180`） | **[代码证实，未测]** | 预算账本落盘为 v3 必改；nonce 窗口以短 TTL+审计告警补偿 | 阶段1/2 |
| R3 | D12 漏报率与 strip_smuggle 有效性零证据：6 条英文正则对多语言/语义改写几乎必然漏报，漏报后唯一兜底 strip 从未在真实模型输出上被测 | **[实测：8960 无监听致真实路径未走通]** | 多层兜底已结构性加强（fs.read 无正文通道）；阶段1 要求真实路径重打 | 阶段1 |
| R4 | 并发/竞态全部未测：预算扣减原子性、状态翻转竞态、慢调用线程堆积 | **[实测：全部测试串行]** | 并发闸+阶段3 测试计划 | 阶段3 |
| R5 | D15/pol_ver 演进零覆盖：PoC 内 D15 永真、pol_ver 恒 1，「注册表/策略变更后存量令牌处置」整体未验证 | **[代码证实]** | 热加载+专用用例 | 阶段1 |
| R6 | 管理面裸奔：/issue 无鉴权（设计已声明不计入被测防线）+ /audit /capabilities 无鉴权（实测无令牌 200 泄漏注册表/指纹/limits/model_id/strata_state）+ 0.0.0.0 绑定 | **[实测]** | 三件事缺一不可 | 阶段2 |
| R7 | 幂等写只测了基本三分支：与 (task_id,attempt) 默认键联动、idem 目录膨胀、「写后崩 marker 缺失→重复执行」（v2 `:176` 自认的 at-least-once 窗口）未覆盖 | **[实测范围声明]** | 阶段4 联动 v2 语义 | 阶段4 |
| R8 | 长时运行行为：审计无界增长（滚动修复前）、探针对「hang 而非拒连」的 Strata（探针 2s vs 调用 60s 不对称，v3 已收紧调用超时）、降级振荡 | **[推断，未观察]** | 阶段3 长稳 | 阶段3 |
| R9 | 证据版本效力：本地副本与部署报告 sha256 不一致，不排除远端运行差异；bi150 不可直达（仅 ssh 隧道），黑盒复测全在本机隔离实例 | **[实测·本会话 sha256sum 复核]** | 部署验收以「部署机 sha256sum + 本文行号核对」为准 | 阶段1 前置 |

**边界声明（不堵的）**：schema 合法≠语义正确；Strata 返回内容的事实性；自然语言复述凭据的 egress 泄漏（v2 `:178` 已声明 egress filter 是弱机制）；上述均由最小授权（D5/D6/D7）+ 摘要回传单口 + HITL/abstain（v2 L6）分层兜底，不在权限层收口。

---

## 8. v0.2 修复与复测实证（第三轮，2026-10-14）

### 8.1 修复清单（10 项，全部 **[实测]**：本地 24 项冒烟全过后部署）

针对第二轮红队 4 条 confirmed 泄露/异常与反思者 2 条推断链，`poc-master/server.py` v0.2（1006 行，`build_sha=e24ff5fbc7141498`）修复：

| # | 修复 | 对应问题 |
|---|---|---|
| 1 | D2 严格过期，删除 `exp+30s` 容差 | 过期令牌约 30s 可用窗口 |
| 2 | 预算接受 `max_calls` 等别名；未知键/非整数/别名重复 → 400 | 预算键被静默忽略 |
| 3 | D10 429 体带 `dim=<耗尽维度>` | 告警不可定位 |
| 4 | `strip_result` 覆盖**所有**工具结果字符串通道 | fs.read 摘要通道走私外带 |
| 5 | 同令牌 3 次策略拒绝（D5/D6/D7/D12）→ 烧毁（新增 D16/TOKEN_BURNED） | 连打未知工具无熔断 |
| 6 | 路径逃逸专属 403 D7/SCOPE_VIOLATION | 误入 500 D14 |
| 7 | nonce 表按 jti 分区（各 256 槽，至多 1024 个 jti） | 跨令牌 nonce 驱逐→重放链（反思者推断） |
| 8 | D1 拒绝回显未验证 `jti_claim` | 伪造攻击无法取证 |
| 9 | `/issue` 信封未知字段 → 400 | 接口契约 fail-open |
| 10 | `/healthz` + START 审计带 `build_sha` | 部署版本漂移无法核对（§7/R9 关闭） |

部署核验：bi150 运行实例 `/healthz` 返回 `build_sha=e24ff5fbc7141498`，与本地 `sha256sum` 逐位一致 **[实测]**。

### 8.2 复测结果：16/17 符合预期 **[实测，复测员在 bi150 执行]**

第二轮 4 条未过用例全部转绿：B 严格 TTL（t+3s → 401 D2）、C 预算别名（3×200 → 429 `dim=calls`）、D fs.read 走私剥除（summary 变 `[STRATA:SMUGGLE_STRIPPED]` + SMUGGLE_STRIP 审计）、E llm_calls 预算（**首次真实打穿 Strata**：第 1 次 200 真实推理 28.6s，第 2 次 429 `dim=llm_calls`）。10 项回归全过，含：F 间接注入端到端（投毒文件→fs.read→真实 Strata → 422 D12，注入未执行）、J 熔断（3×D5 → 401 D16）、N 路径逃逸（403 D7，事后确认 /etc/passwd 未动）、O nonce 分区（令牌 A 洪水 300 次后令牌 B 重放仍 401 D3）、P 降级隔离（llm 503 D13 与 fs.read 200 互不影响）。

**唯一未判定项 H（诱导走私输出，error）**：4 次尝试均 200 但 `content_summary=""`——Qwen3 思考型模型把 `max_tokens=64` 上限全部耗在思考上，正文始终为空；无 JSON 泄漏也无 SMUGGLE_STRIP，llm 通道剥除**无法端到端确认**。这不是安全失守，是测试可行性问题；**遗留动作**：推理模型接入时调大 `llm_max_tokens` 或关闭思考模式后重测 H（计入 §7 待办）。

### 8.3 复测后的残余风险（更新 §7）

R1（nonce 洪水跨令牌驱逐）已由 per-jti 分区结构性关闭 **[实测 O]**；R9（版本效力）已由 build_sha 关闭 **[实测]**。仍开放：D12 正则漏报多语言/语义改写注入（兜底 strip 已全通道化但 H 未端到端确认）、管理面鉴权、并发竞态、重启 nonce 窗口、审计无界增长。推理模型 `max_tokens` 配置新计入。

---

## 9. 架构命名：两院（Bicameral）

三种风格共提名 6 个候选（古典意象 / 英文词根 / 地质隐喻），逐一 WebSearch 查重后，按「异构协作 → 调和 → 统一结果」的命名主线定名：

## 两院（Bicameral）

**隐喻**：两院制——两个**构成、节奏、职权都不同**的院，各自审议同一事项，经协调调和为一案。

**对应**：
- 参众两院 = 异构 agent 群体：不同模型（能力不同）、不同选区与规则（职责边界不同）、不同议程节奏（推理速度不同）——本架构四个痛点中的「能力异构」「速度异构」直接写进了名字；
- 两院审议、协调委员会调和 = 多模型结果的审议与调和；
- 一案经两院通过方成其法 = 统一结果须全链校验方为有效，呼应 fail-closed 门禁（「未经签署不生效」）。

**认知学彩蛋**：Julian Jaynes《二分心智的崩塌》（The Origin of Consciousness in the Breakdown of the Bicameral Mind）——「意识」正是诞生于两腔心智的对话；多 agent 协作涌现统一认知，是这个名字对 AI 的天然互文。

**中文彩蛋**：「两院」在中文语境自带「两院院士」联想——科学院与工程院，两个顶尖而专长迥异的专家集体。

**查重**：bicameral 在 GitHub 仅零星同名微型项目，英文属罕见词、反而易独占；中文「两院」无技术产品占用。备选名查重记录：勘合/Countersign（双侧干净）、左契/Zuoqi（干净）、冠岩/Caprock（同域 18★ 小项目）、节度/Mandate（干净）、司契/Siqi（干净）；另排除撞名方案 Warrant（WorkOS 收购同名授权服务）、Signet（googleapis/signet）、虎符（奇安信「数据虎符」）、Gateward（PyPI MCP 网关）、Congress（被美国政治数据项目海洋淹没，检索不可占有）。

**落选记**：勘合（Countersign）曾为初选名——明代勘合制「各执半符、勘同乃合」与 HMAC 验签同构，但用户裁定协作隐喻优先；其查重与论证存档于 git 历史。
