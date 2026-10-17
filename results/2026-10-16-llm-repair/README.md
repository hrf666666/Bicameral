# 2026-10-16 LLM 驱动自主修复层（repair.py）—— bi100 + Qwen3-1.7B 基线双案例实证

**目标**：实现 `scripts/repair.py`（repair/1）——把 zcode workflow 模式（有界循环 /
类型化工具结果 / 策略门 / 审计 / 升级）嫁接到节点自治：nodeagent 规则引擎升级
（exit 3 + DIAGNOSIS_REPORT）后，repair.py 以本地 LLM 为规划脑接管未知名失败，
在策略门内完成诊断与修复。仅标准库、仅新建 `scripts/repair.py`（import 同目录
install.py / probe.py 复用函数，不复制逻辑，不改其他文件）；bi100 真机双案例实证。

**红线遵守**：22 端口 sshd 未动（结束监听集回到 `[22]`）；一切写入限于
`/root/bicameral-sandbox/`（/root/bicameral-fleet/ 未写）；自起实例全部 rollback、
占位/500 进程全部 kill、无大文件残留（沙箱 21M，其中 ~20M 为既有 engines/ 树）。

**与 27B 并行门的关系**：本目录是 **1.7B 规划脑基线**（bi100 自装
Qwen3-1.7B-Q8_0 修自家故障）；同仓 `results/2026-10-16-27b-repair-brain/` 是
bi150 + Qwen3.8-27B 的并行验证（其提交 d20323a 亦把 `/no_think` 一行回放进
canonical repair.py——本门两次案例实跑用当时的部署版 `20f4d52d6a5049a3`，最终版
`fd2b0d3ea2ca4e38` 仅多该前缀，行为无差，selftest 复验 0 失败）。

## 0. 产物指纹

| 产物 | 指纹 |
|---|---|
| `scripts/repair.py`（最终版=本地=bi100 部署版） | sha256 `fd2b0d3ea2ca4e38…`，**1585 行**；案例实跑版：case A 第一次 `e34530a97d0f4a6f`（启用 enable_thinking 修复后）、case A 第二次与 case B `20f4d52d6a5049a3`（+REPAIR_ROUND 带 app 字段） |
| 修复脑 | qwen3-1.7b-q8_0（install.apply 装，engine.binary=沙箱引擎 c8be70d331ae7428，模型 Qwen3-1.7B-Q8_0.gguf sha16 `061b54daade076b5` 全串相符，服务 18010，`-c 8192 -t 32`），结束已 rollback |
| repair 审计（31 行） | `repair-audit-bi100.jsonl`，sha256 `ddaf000ac864eb54…`（REPAIR_* 全程） |
| install 侧审计 / 规则引擎侧审计 | `install-audit-bi100.jsonl`（286 行）/ `nodeagent-audit-bi100.jsonl`（237 行） |
| appspec（brain / casea / caseb） | `6f602ed2e5032d91` / `2cc595c4e84d7ddd` / `304b676f17c29873`；adjust 后工作副本 `*.repair-appspec.after.json`（端口/镜像变更的落盘证据） |
| 注入工具 | `port_placeholder.py`（python 裸 socket 占 18011，accept 不应答）、`bad500.py`（18099 恒返 500） |
| LLM 端点 | `http://127.0.0.1:18010/v1`（自家范式装的 1.7B，OpenAI 兼容，response_format json_schema → llama.cpp 语法约束，`chat_template_kwargs.enable_thinking=false`） |

## 1. CLI 用法

```
python3 scripts/repair.py --error-report <DIAGNOSIS_REPORT.json> \
  --context <sense facts.json> --llm http://127.0.0.1:18010/v1 \
  [--model <id，缺省取 /v1/models 第一个>] [--max-rounds 4] \
  --sandbox /root/bicameral-sandbox --appspec <appspec.json> \
  [--admin-token t（LLM Bearer，只进请求头，审计/回喂一律 redact）] \
  [--health-timeout 180] [--audit-path F] [--out F]
python3 scripts/repair.py --selftest
```

四要件实现：**类型化规划**（每轮 prompt = 修复工程师人格 + 四类 action 工具目录 +
策略声明 + 证据：error-report/appspec 现状/端口占用/最新失败事实/已试动作历史；
response_format=json_schema 约束，输出必须过 `validate_llm_plan` 严格 schema，
失败/超 schema 当轮无效且拒绝原因回喂）；**策略门**（harness 执行：shell 二进制
白名单、apt 仅 install/update 且包名白名单 build-essential/cmake/ca-certificates/
libgomp1、rm 仅沙箱内且不含 ..、python3 仅 -c 只读探查、argv 列表化 shell=False、
cwd 钉死沙箱、每条命令超时有界、adjust_appspec 仅 service.port /
model.mirror_urls 两白名单字段、执行前后审计 REPAIR_ACTION 含 prompt/response
sha256_16 与完整动作、URL/令牌 redact）；**有界验证**（每轮动作后重跑进入时捕获
的失败检查 = install.apply 幂等重跑，通过即 REPAIR_OK）；**升级而非静默**
（拒绝记档回喂、abort/轮尽 → 结构化 REPAIR_FAILED 含全部轮次证据 exit 3）。

## 2. 案例 A（未知名失败：端口被裸 socket 占住）

1. 注入：case-A appspec（repair-casea，0.6B 模型）service.port=18011，python 裸
   socket 先占 18011（accept 不应答）→ health 永远超时。
2. 规则引擎快路径：`nodeagent bootstrap` → 2 轮 apply_install 同样失败
   （`no HTTP 200 on /health within 45.0s`，class=**unknown** 规则表无名）→
   no_progress → **NA_ESCALATE exit 3**（266.2s）。证据：`diagnosis-casea.json`、
   `bootstrap-casea-stderr.log`。
3. repair.py（第一attempt，如实记录）：rounds 1-2 输出超 schema 被拒（1.7B 把
   curl 塞进 probe.argv），round 3 输出被 max_tokens=512 截断，round 4 HTTP 400
   （prompt 2050 tokens > 脑 -c 2048）→ REPAIR_FAILED exit 3（92s）。**harness
   侧修复**：脑重启 -c 8192；llm_max_tokens 512→768；input_clip 2400→1200；
   被拒原因显式置顶回喂（last_round_feedback）；系统提示明确 probe 不带 argv。
4. repair.py（第二attempt）：entry 失败检查复现（rc=4）→ **round 1**：json_schema
   模式 19.4s，LLM 输出 `{"type":"adjust_appspec","field":"service.port",
   "port":18012}`（rationale 引用 port_checks：18011 busy）→ 策略门放行 → 落盘 →
   失败检查重跑 = apply → **READY port=18012**（REPAIR_RC=0，全程 98s，1 轮）。
5. 双证：/health 200 `{"status":"ok"}`；/v1/models=0.6B gguf；真实 /v1/chat
   0.3s 应答。install status：`repair-casea ready 18012 ready`。

## 3. 案例 B（download_exhausted：首 mirror 500 + 次 mirror 出口封锁）

1. 注入：case-B appspec（repair-caseb，port 18013——18012 已被案例 A 修复实例
   占用）model.mirror_urls 首位 `http://127.0.0.1:18099/`（本地恒 500 的 http），
   次位 huggingface.co（bi100 出口封锁，Errno 99/104）。
2. 规则引擎快路径：bootstrap → 6 次 apply_install 失败 + 4 次有界退避
   （20/40/80/160s）→ round 10 no_progress → **ESCALATE exit 3**（1140.3s，
   class=**download_exhausted**）。证据：`diagnosis-caseb.json`。
3. repair.py：entry 失败检查复现（rc=3，install 审计事实给出两个 mirror 的
   500/Errno99 与 redacted URL）→ **round 1**：json_schema 模式，LLM 输出
   `{"type":"adjust_appspec","field":"model.mirror_urls",
   "mirror_urls":["https://hf-mirror.com"]}` → 策略门放行（facts egress
   hf_mirror=up）→ apply 经 hf-mirror 下载 639,446,688B sha16 `9465e63a22add535`
   全串相符 → **READY port=18013**（REPAIR_RC=0，全程 138s，1 轮）。
4. 双证：/health 200；/v1/models=0.6B gguf；adjust 前后镜像表入审计
   （`*.repair-appspec.after.json` + REPAIR_ACTION outcome old/new）。

## 4. 审计链摘录（≤500 字符）

```
repair-audit-bi100.jsonl 31行: REPAIR_START casea→run1 r1-3 invalid(probe.argv×2/截断) r4 HTTP400 ctx2050>2048 REPAIR_FAILED llm_unreachable→脑重启-c8192→run2 r1 json_schema valid GATE allowed adjust_appspec 18011→18012→REPAIR_RESULT ok→REPAIR_OK 18012；caseb REPAIR_START→entry rc3→r1 valid GATE allowed mirror_urls→[hf-mirror.com]→READY 18013 REPAIR_OK；每事件含 prompt/response sha256_16+完整动作(URL/令牌redact)
```

## 5. selftest

`python3 -m py_compile scripts/repair.py` OK；`--selftest` → **112 项断言
0 失败**（本地与 bi100 部署版各跑一遍均 0）。覆盖：schema 校验拒绝畸形 LLM
输出（34 例：缺/多字段、未知 action.type、argv 非列表/超界、port 非法、镜像
scheme/数量非法、abort 无 reason 等）；策略门各拒绝分支（白名单外包名、无 -y、
apt remove、rm -rf /、含 .. 删除、沙箱外删除、curl/bash/sh/sudo、带路径二进制、
python3 无 -c/subprocess/os.system/rmtree、find -delete/-exec、未知
action.type、越权 adjust 字段）与允许分支；退避计算与轮次上限；prompt 组装
（证据/历史/策略白名单/镜像对照表在场、URL redact）；adjust 落盘过
validate_appspec；install 审计失败事实提取（ts 过滤 + URL redact）；终态报告
形状。全程无网络、无 LLM。

## 6. LLM（1.7B 小模型）规划质量——如实评价

- **能成事**：两案例最终都在第 1 轮给出策略门内、类型正确的修复动作
  （adjust 端口 / adjust 镜像），json_schema 语法约束下 JSON 合法率 100%
  （修复后），并且 action 的字段值与证据一致（18012 恰为 port_checks 里的
  free 端口；hf-mirror 恰为 egress up 的镜像）。
- **明显弱点（案例 A 第一次 attempt 全记录在审计里）**：
  1. **不改错**：同一畸形输出（把 curl 塞进 probe.argv——本质想走私白名单外
     二进制）连续两轮原样重复，对回喂的拒绝原因不敏感；靠 harness 侧
     last_round_feedback 置顶 + 脑扩容后才纠正。
  2. **长输出失控**：max_tokens=512 时 JSON 被截断（round 3），以及思考模板
     在 reasoning_content 里不受语法约束、会把 max_tokens 烧光导致 content
     为空（须 enable_thinking=false，此坑已写进 llm_chat 并回放进
     canonical 版的 /no_think）。
  3. **诊断文本偷懒**：diagnosis 字段常照抄升级报告的「未归类失败/根因」，
     rationale 质量尚可但不稳定；对比 27B 门（其 README：诊断显式引用证据、
     明显更强），1.7B 属「动作可用、解释薄弱」。
  4. 结论：**1.7B 可作基线**——在 harness 给足结构化事实（端口占用、审计
     失败链、egress 表）+ schema 约束 + 拒绝回喂下能完成这两类修复；但它的
     可靠性主要来自 harness 的脚手架而非模型本身的规划力，复杂多步场景
     预期需要更大模型。
- harness 侧两个真 bug 也是这次暴露的：规划脑 -c 2048 装不下修复 prompt
  （round 4 HTTP 400，已按 REPAIR_FAILED 有界失败，未越界）。

## 7. 如实注记

1. **案例 A 的端口不是 18010**：任务原文「appspec.service.port=18010 + 占位
   裸 socket」与「--llm http://127.0.0.1:18010/v1（规划脑）」物理互斥（18010
   已被规划脑监听）。先按 18010 实跑发现 install.py 既有边界：**端口被健康
   实例占住时 apply 反而假 READY**（health 200 由脑应答，wait_health 不校验
   应答者是被启动子进程；证据 `bootstrap-casea-falseready-stderr.log`，已
   rollback 记档）。故按任务机制原样（python 裸 socket 占位）在 18011 注入，
   修复后落 18012。--llm 端点严格保持 18010。
2. **adjust_appspec 的镜像语义是「整表替换」而非严格置换**：install 的
   download 按序回退镜像，列表里只要有一个可用镜像首次 apply 就会成功——
   严格「只许换序」时案例 B（首位 500 + 次位被封）在数学上不可修复。策略门
   放行整表替换的安全性由 appspec 的模型 sha256 pin 保证（任何镜像的错误
   字节都过不了 VERIFY），且字段仍在白名单内；README 与系统提示均如实写明。
3. **规则引擎在案例 B 花了 19 分钟**（4 次退避 20/40/80/160s + 6 次 apply）
   才升级——这是规则表的既定行为（download_exhausted 走有界退避），也正好
   说明 LLM 层的价值：repair 1 轮 138s 收尾。
4. repair.py 在本门过程中迭代了三个版本（2d37de9f 初版 → e34530a9
   thinking 修复 → 20f4d52d 审计字段），每次均过 py_compile + selftest 后
   重新部署；两次案例实跑的审计与 stderr 均保留在本地。
5. bi100 无 ss/lsof，端口与进程核查全用 python3 stdlib（bind 探测 +
   /proc/net/tcp inode→pid 映射，避免 pgrep -f 自匹配）。
6. 结束清理后 `busy ports: [22]`（仅 sshd），apps/ 仅剩 3 个 mutex .lock
   （install.py 设计如此），沙箱无大文件。
