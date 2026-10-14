# 两院 Bicameral

> 面向主控-边缘 LLM agent 编排的权限层：HMAC 能力令牌 + 有序 default-deny 拒绝链，约束边缘 agent 的每一次工具调用。Python 单文件，仅标准库。
>
> English see [README.md](README.md) · 设计文档 [docs/architecture.md](docs/architecture.md)

**结果一句话**：第三轮红队复测 **16/17**，部署实例实机回归 **24/24**（含真实 LLM 路径）。越权调用、令牌伪造与篡改、nonce 重放、prompt 注入（含经真实 LLM 的间接注入端到端）、2 MB 载荷溢出、调用与推理预算耗尽、探测后熔断——全部拦截。单文件 1,006 行，零依赖。

## 1. 解决什么问题

主控大模型会话能唤醒边缘设备上的 agent 并把工具交给它。交出去就有四类失控，而常见手段（提示词约束、框架内建权限）是 **fail-open** 的：约束写在 prompt 里，注入就能绕过去。

| 失控 | 典型形态 | 两院的收口 |
|---|---|---|
| 越权 | agent 调白名单外工具；路径逃出数据范围 | 逐调用 HMAC 验签 + 工具白名单 + realpath 范围校验（D6/D7） |
| 注入 | 任务文本夹带指令；投毒文件内容经读文件进入 LLM | 入参注入扫描（D12）+ **全通道**响应侧走私剥离 |
| 重放/伪造 | 令牌截获重放；payload 篡改；攻击者自签 | HMAC 验签 + per-jti nonce 分区 + 严格 TTL（D1/D2/D3） |
| 溢出 | 无界调用、超大载荷、推理花费失控 | 三维预算账本（calls/llm_calls/bytes）+ 尺寸上限（D9/D10） |

原则一句话：**约束不在 prompt 里，在执行口。** 每次工具调用独立对照签名令牌（cap/3）与有序拒绝码链 D1–D16（任一命中即拒），fail-closed，全过程写入 JSONL 审计，可按 `(task_id, jti)` 重构整条链。

## 2. 构成

| 组件 | 职责 |
|---|---|
| 控制平面 `:18000` | `POST /issue` 签发能力令牌；`GET /audit /capabilities /healthz` |
| agent 平面 `:18001` | `POST /agent/invoke`：验签→拒绝码链→执行→审计 |
| 能力令牌 cap/3 | payload + HMAC-SHA256：agent / task / 工具白名单 / TTL / 预算 / 策略版本 / 工具指纹 |
| 三维预算 | calls / llm_calls / bytes 原子扣减；429 携带 `dim=<耗尽维度>` |
| 推理代理 | `llm.complete` 作为受控工具转发本地 OpenAI 兼容后端：探针 degrade/recover，预算独立计数 |
| 令牌熔断 | 同一令牌 3 次策略拒绝（D5/D6/D7/D12）→ D16/TOKEN_BURNED |

## 3. 实证

红队各轮带逐条证据发布在 [docs/redteam/](docs/redteam/)：

| 轮次 | 用例 | 结果 |
|---|---|---|
| [v0.1 红队](docs/redteam/2026-10-14-v0.1-redteam/) | 14 条攻击 | 10 拦截 / 3 打穿 / 1 环境受限 → 驱动 10 项修复 |
| [v0.2 复测](docs/redteam/2026-10-14-v0.2-retest/) | 17 条 | **16/17 符合预期**；唯一未判定项是推理模型耗尽 `max_tokens` 的测试可行性问题，非安全失守 |
| 实机回归（`scripts/live_check.py`） | 24 项 | 部署实例上 **24/24**，含真实 LLM 路径 |

测试环境：Ubuntu 24.04 容器，112 核 / 1 TB 内存，8× 天数智芯 Iluvatar CoreX BI-V150；推理后端 llama.cpp（Qwen3 27B GGUF）。

## 4. 快速开始

```bash
# 30 秒验证：一次正常往返 + 5 类攻击，逐一被拦在执行口
python3 examples/quickstart.py
```

```bash
# 启动（控制面 :18000，agent 面 :18001）；实验之外务必设置真实主控密钥
python3 bicameral/server.py

# 签发只读能力令牌
curl -s -X POST http://127.0.0.1:18000/issue -H 'Content-Type: application/json' \
  -d '{"agent":"agent-ro","task_id":"t1","tools":["fs.read"],"ttl_s":600,
       "budget":{"calls":10,"llm_calls":0,"bytes":65536}}'

# 每次调用都携带令牌；nonce 重复即判重放
curl -s -X POST http://127.0.0.1:18001/agent/invoke \
  -H 'Content-Type: application/json' -H 'X-Capability-Token: <token>' \
  -d '{"nonce":"n-1","tool":"fs.read","params":{"path":"/tmp/bicameral/data/notes.txt"}}'
```

## 5. 部署与验证

```bash
HOST=<host> PORT=22 USER=root ./scripts/deploy.sh   # 上传、重启、指纹核对
python3 scripts/live_check.py                        # 部署机上的 24 项回归
```

`/healthz` 暴露 `build_sha`（运行源码指纹）。远端指纹与本地 `sha256sum` 逐位一致才算部署成功——该机制已经抓到过一次静默版本漂移。

## 6. 边界（不解决的问题）

- schema 合法 ≠ 语义正确：LLM 输出内容的事实性不在权限层收口。
- 本版管理面（`/issue`、`/audit`）无鉴权，生产需置于可信网段或加 mTLS（见设计文档 §7）。
- 预算与 nonce 账本在内存：重启即清（fail-closed 方向），尚无持久化。
- 吞吐未测：以上均为功能与边界验证。

## 7. 设计文档

[docs/architecture.md](docs/architecture.md) — 完整设计：令牌格式、拒绝码链、预算防线、审计、同机推理整合、三轮红队实证、残余风险。

## License

[MIT](LICENSE)
