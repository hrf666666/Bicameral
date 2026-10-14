# 两院 Bicameral

> 主控-边缘 LLM agent 编排的**权限层**：HMAC 能力令牌（cap/3）· default-deny 策略引擎 · 三维预算 · per-jti 防重放 · fail-closed 审计 · 同机 Strata 推理服务能力代理。

不同架构、不同模型、不同速度的 agent 像两院一样各自审议、调和为一案；**未经全链校验的结果不放行**。

## 命名

**两院（Bicameral）**：两个构成、节奏、职权都不同的院，各自审议、调和为一案——对应异构 agent 群体（能力异构、速度异构直接写进名字）；协调调和对应多模型结果调和；「一案经两院通过方成其法」呼应 fail-closed 终审门禁。

彩蛋：Julian Jaynes《二分心智的崩塌》——意识诞生于两腔心智的对话；以及中文「两院院士」的顶尖异构专家集体联想。

## 架构一页图

```
┌─────────────────────────── 主控（bi150 级服务器）───────────────────────────┐
│  控制平面 :18000                  agent 平面 :18001                        │
│  POST /issue 签发能力令牌          POST /agent/invoke 逐调用验符执行        │
│  GET  /audit /capabilities        ┌──────── enforce 链（有序短路）───────┐  │
│  GET  /healthz(build_sha)         │ D1签名 D2过期 D16烧毁 D3重放 D4受众  │  │
│                                   │ D11策略版本 D9尺寸 D5未知工具 D6越权 │  │
│  能力注册表 + 工具指纹 (D15)        │ D8schema D12注入 D10预算 → handler  │  │
│  三维预算账本 calls/llm/bytes      │ (D7范围 D9超限 D13降级 D14兜底)     │  │
│  per-jti nonce 分区（防重放）       │ 响应侧走私剥离 strip_result         │  │
└─────────────────────────────────┤ HMAC-SHA256 能力令牌 cap/3 ├──────────┘
                                  │ 同机 Strata 推理服务（受控能力 llm.complete，  │
                                  │ degrade/recover，预算独立计数）               │
                                  └──────────────────────────────────────────┘
                                              ▲ 能力令牌（边缘 agent 持有）
                          ┌───────────────────┼───────────────────┐
                     agent-ro(只读)      agent-rw(可写)         judge(评审)
```

一次调用的生命周期：主控 `/issue` 签发**能力令牌**（agent / task / 工具白名单 / TTL / 预算）→ 边缘 agent 携令牌+nonce 调 `/agent/invoke` → enforce 链任一环不过即拒（fail-closed，写入审计）→ 通过则执行工具并**全通道剥离走私载荷** → 返回白名单字段。

## 红队实证（摘要）

14 条攻击用例（v0.1）→ 修复 10 项 → 17 条复测 **16/17 符合预期**（唯一未判定项为推理模型思考耗尽 max_tokens 的测试可行性问题，非安全失守）。已验证的拦截：越权调用、令牌伪造/篡改、nonce 重放、路径逃逸、prompt 注入（含间接注入端到端：投毒文件 → fs.read → 真实 Strata 推理 → D12 拦截）、2MB 溢出、预算耗尽（calls 与 llm_calls 独立计数）、令牌熔断（3 次策略拒绝 → D16/TOKEN_BURNED）、nonce 洪水跨令牌驱逐、降级隔离（Strata 挂掉时 llm.complete 503 而 fs.read 正常）。

完整攻防过程与设计推导见 [docs/architecture-v3.md](docs/architecture-v3.md)（自含完整稿，含前两轮红队实证）。

## 快速开始

Python 3.11+，仅标准库，单文件，无任何依赖：

```bash
python3 bicameral/server.py --control-port 18000 --agent-port 18001
```

签发一枚只读令牌并调用：

```bash
# 1. 签发（agent 清单见 SUBJECTS：agent-ro=[fs.read,llm.complete], agent-rw=[fs.read,fs.write]）
curl -s -X POST http://127.0.0.1:18000/issue \
  -H 'Content-Type: application/json' \
  -d '{"agent":"agent-ro","task_id":"t1","tools":["fs.read"],"ttl_s":600,
       "budget":{"calls":10,"llm_calls":0,"bytes":65536}}'
# → {"ok":true,"token":"<payload>.<hmac>","jti":"…","budget":{"calls":10,…}}

# 2. 携令牌调用（每次调用用不同 nonce，重放即拒）
curl -s -X POST http://127.0.0.1:18001/agent/invoke \
  -H 'Content-Type: application/json' \
  -H 'X-Capability-Token: <token>' \
  -d '{"nonce":"n-1","tool":"fs.read","params":{"path":"/tmp/bicameral/data/notes.txt"}}'

# 3. 被拒时给出拒绝码：D1 签名 D2 过期 D3 重放 D5 未知工具 D6 越权 D7 范围
#    D8 schema D9 尺寸 D10 预算(dim=耗尽维度) D12 注入 D16 烧毁 …
```

安全要求：生产环境务必设置 `POC_MASTER_KEY`（64 位十六进制 = 32 字节主控密钥，默认 dev key 仅供本机试验）。

## 测试

```bash
# 本地冒烟（自起隔离实例，24 项检查）
python3 tests/test_smoke.py

# 对运行中的实例做实机回归（在目标机上执行）
python3 scripts/live_check.py --base http://127.0.0.1:18000 --agent http://127.0.0.1:18001 \
  --scope /tmp/bicameral/data --expect-sha e24ff5fbc7141498
```

## 部署

```bash
# 以 bi150 为例：上传 → 重启 → 校验指纹（build_sha 与本地 sha256 逐位一致才算部署成功）
scp -P 31451 bicameral/server.py root@<host>:/root/bicameral/server.py
ssh -p 31451 root@<host> 'pkill -f "serve[r].py"; cd /root/bicameral && \
  setsid nohup python3 server.py >poc.log 2>&1 </dev/null & sleep 2; \
  curl -s http://127.0.0.1:18000/healthz'   # 对照本地 sha256sum 前 16 位
```

`/healthz` 暴露 `build_sha`（运行源码指纹），根治「部署版本漂移无法核对」。

## 文档

- [docs/architecture-v3.md](docs/architecture-v3.md) — 两院权限层完整设计（自含）：能力令牌 cap/3、拒绝码链、预算防线、审计、同机 Strata 整合、三轮红队实证、残余风险
- [docs/architecture-v2.md](docs/architecture-v2.md) — 前身：六层云边架构（26 条评审修订）

## License

[MIT](LICENSE)
