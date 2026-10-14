# 2026-10-14 · v0.1 红队（14 条攻击用例）

目标：`bicameral/server.py` v0.1（部署实例），独立红队测试员执行，未拦截项经独立复核员重放确认。
环境：Ubuntu 24.04 容器（112 核 / 1 TB 内存 / 8×Iluvatar BI-V150），推理后端 llama.cpp（Qwen3 27B，当轮不可达）。

**结果：10 拦截 / 3 打穿 / 1 环境受限。** 3 条打穿 + 拒绝码/熔断缺陷 → 驱动 v0.2 的 10 项修复（见 `../2026-10-14-v0.2-retest/`）。

| # | 用例 | 类别 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | RO 令牌调写能力 | 越权 | 拦截 | 403 D6/TOOL_NOT_ALLOWED，目标文件未生成 |
| 2 | 未注册工具 shell.exec ×5 | 越权 | 拦截* | 5×403 D5/TOOL_UNKNOWN；但令牌不作废（无熔断）→ v0.2 增 D16 |
| 3 | data_scope 路径逃逸（写 /etc/passwd） | 越权 | 拦截* | 500 D14 fail-closed 拦下；拒绝码不符预期 → v0.2 改 403 D7 |
| 4 | 篡改 payload 不改签名 | 伪造 | 拦截 | 401 D1/TOKEN_INVALID |
| 5 | 自签令牌（攻击者密钥） | 伪造 | 拦截* | 401 D1；DENY 记录缺 jti → v0.2 补 jti_claim 取证 |
| 6 | goal 直接扩权注入 | 注入 | 拦截 | 422 D12/INJECTION_SUSPECTED（pattern=ignore_previous, path=$.prompt），未触推理后端 |
| 7 | 间接注入：投毒文件经 fs.read 进入 llm.complete | 注入 | 拦截* | 后端不可达 → 503 D13 fail-closed，注入链断裂；真实 LLM 路径未走通 |
| 8 | 响应走私：actions/tool_calls 经 fs.read 摘要回传 | 注入 | **打穿** | summary 原样带回越权 JSON；strip 仅挂 llm.complete 通道，审计计数 0 |
| 9 | 超大 payload（Content-Length 2 MB） | 溢出 | 拦截 | 413 D9/PAYLOAD_TOO_LARGE，读流前按声明长度短路 |
| 10 | 调用预算（`max_calls:3` 键名） | 溢出 | **打穿** | 未知键被静默忽略 → 回显 calls=1000，4 次调用全放行无 429 |
| 11 | Strata 调用预算耗尽（llm_calls=1） | 溢出 | 无法判定 | 后端不可达全程 503 D13；对照实验证明 llm 维独立计数成立 |
| 12 | 过期令牌（ttl=5s，t+6s 重放） | 重放 | **打穿** | `now > exp+30` 容差使过期令牌有约 30 s 完全可用窗口，t+36s 才 401 D2 |
| 13 | 同 nonce 重放 | 重放 | 拦截 | 首发后字节级相同请求 → 401 D3/REPLAY_DETECTED |
| 14 | 后端不可达时降级且不伤其他能力 | 降级 | 拦截 | llm.complete 503 D13（fail-closed），同令牌 fs.read 200 正常 |

*标注「拦截\*」= 结果安全但行为与设计不符，均已折入 v0.2 修复。
