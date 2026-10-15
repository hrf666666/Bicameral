# 阶段 5 红队轮归档：首轮攻击 → 复核 → 修复 → 复测（2026-10-15）

**验收门**（`docs/paradigm.md` §6，Bicameral 仓）：确认的代码级漏洞全部修复且复测通过 → v1.0 达成；仍有 leaked → 未达成并写明缺口。

**判定（初判）：v1.0 未达成。**（同日 A5/A11 第二批修复后改判达成，见 §8） 复核确认 5 项代码级漏洞（A1/A2/A5/A9/A11），其中 3 项（A1/A2/A9）已修复且复测 blocked；**A5（engine.binary 任意解释器注入）与 A11（devices/1 run 任意命令串→RESULT 冒名）不在本轮预期修复面、未修，复测仍 leaked**——按门标准不授予 v1.0。缺口与残余见 §5。

首轮 12 项攻击：**6 blocked**（A3/A4/A6/A7/A8/A10）、**5 leaked**（A1/A2/A5/A9/A11，复核全部 confirmed）、**1 bydesign**（A12）。修复后复测：A1/A2/A9 → blocked；A5/A11 → leaked；回归 A3/A5穿越半场/A8 → blocked（防线未松动）。

---

## 0. 仓库定位与代码状态

- 受影响与被修代码在 **Bicameral 仓**（`/home/nvidia/code/Bicameral`，基线 commit `155f233`），strata-jetson 只存产出归档。依据：红队复核记录 router.py sha `e9b929b5…` 与修前 `sha256sum` 一致；strata-jetson 仓内无 router.py/task.py。
- 修复为**未提交工作树改动**（本归档时 `git status`：`M router.py` `M task.py` `M examples/devices.json`，`?? verify_result.py`；`git diff --stat`：router +444/-32 区间、task +120、devices ±3）。本轮未要求 commit。
- 修后指纹（**本归档会话实测**，`sha256sum` 前 16）：

| 文件 | sha256_16 | 行数 | 修前（阶段 4 归档值） |
|---|---|---|---|
| `bicameral/router.py` | `c96250cd210e6d5e` | 1026 | `e9b929b58a888f7c` / 618 行 |
| `bicameral/task.py` | `aa9d5deeffae7b89` | 667 | `c182e7b0d6db63b4` / 573 行 |
| `bicameral/verify_result.py` | `2efc9c0e6648ed57` | 243 | （新增；红队材料记 246 行，实测 243，如实注记） |
| `examples/devices.json` | `0830d4e316007fa9` | — | `6bc59acfe1b3b736` |

- install.py / probe.py / server.py **未被本轮修复触碰**（git status 无改动）——其首轮 blocked 结论与复测回归（A3/A5穿越/A8）对应同一代码。
- 本归档会话对 Bicameral 仓**零写入**：`route-audit.jsonl` 双仓副本 md5 仍为 `89f04d2c91dfdb78`（会话前后一致）；全部复验在 `/tmp/stage5-archive-verify` 沙箱完成。

## 1. 攻击矩阵（首轮 → 修复 → 复测）

| # | 攻击 | 类别 | 首轮 | 复核 | 修复面 | 复测 | 残余 |
|---|---|---|---|---|---|---|---|
| A1 | perf-bi150 伪造数值骗路由（99999 tok/s / 0.1 ms，正反向均得手） | 路由投毒 | **leaked** | confirmed | **已修**：ROUTE 事件记录输入 perf 文件 sha256_16 + `--expect-perf-sha` pin | **blocked** | pin 为 CLI 可选项（不带 pin 仍被导向，仅可见性）；bench date 时效窗未实装 |
| A2 | route-audit 删行 + 伪造行 | 审计灭迹 | **leaked** | confirmed | **已修**：seq+prev_sha256_16 哈希链、启动验链响亮告警、tail_sha256_16 锚定点 | **blocked** | 删末行/末行原地改文件内不可见 → 外部锚定为运维动作（未自动化） |
| A3 | 假 mirror 首位供垃圾字节 | 供应链 | blocked | — | 无需 | 回归 **blocked**（VERIFY_FAIL→逐出→次位 verify ok） | — |
| A4 | mirror accept 后永不响应 | 供应链 | blocked | — | 无需 | 未单列复测（代码未触碰；60s 读超时封顶有界） | stall guard 覆盖慢滴漏变体的注记见 §4 |
| A5 | model.file=../.. 穿越 + engine.binary=/bin/sh 注入 | 路径穿越 | **leaked**（穿越半场 blocked，注入半场得手） | confirmed | **未修**（不在预期修复面） | **leaked**（注入半场）；穿越半场回归 blocked | engine.binary 仅验绝对路径，`sh -c` 命令已执行且回滚不撤销 |
| A6 | 删除 model.sha256 无 pin 安装 | 供应链 | blocked | — | 无需 | 未单列复测（install.py 未触碰；schema 强制 64hex） | — |
| A7 | service.health 绝对 URL/异构 scheme/内网（SSRF） | 扫描滥用 | blocked | — | 无需 | 未单列复测（probe.py 未触碰） | — |
| A8 | prompt 注入 + actions 键 + NUL 变体 | 任务注入 | blocked | — | 无需 | 回归 **blocked**（D12 DENY / schema 拒 actions 键 / NUL 达 LLM 但无执行面） | NUL 可绕 D12 正则（本轮无副作用） |
| A9 | device=bi150 信封无中生有 | 信封伪造 | **leaked** | confirmed | **已修**：device_audit_digest（/issue jti→ALLOW 行原始字节哈希）+ verify_result.py 归档核验 | **blocked** | digest 绑定授权事件而非信封内容；同时改真信封并保其 digest 仍过检（需设备侧签名） |
| A10 | 推理后端不可达仍派发 | 路由退化 | blocked（DENY D13 失败响亮） | — | **加固**：devices/1 `health_url` + 决策前存活探测，不可达/不健康 → NOT_VIABLE | 修复侧验证 4 场景通过；红队复测轮无独立重放条目（如实注记） | 不自动回退次优候选（失败即失败）；负载采样未实装 |
| A11 | devices/1 清单投毒→任意命令+信封冒名（自选） | 路由投毒 | **leaked** | confirmed | **未修**（不在预期修复面） | **leaked**（A9 修复顺带拦原 payload；加伪造 digest 适配后仍得手） | run 仍为任意命令串，路由级冒名 RESULT 已落审计（verify_result 归档核验可拒但行已在） |
| A12 | file:// mirror 任意本地路径供包（自选） | 供应链 | **bydesign** | — | 无需 | — | selftest `urls.file_scheme` 钉死接受；sha256 pin 全程强制 |

## 2. 确认漏洞攻防细节（复核 confirmed 的 5 项）

### A1 perf 文件伪造骗路由（已修，复测 blocked）

- **攻**（首轮）：副本改 `decode_tps=99999 / ttft=0.1` 后 `router.py route` 照单采信，ROUTE 事件逐字记录 `bi150 decode_tps=99999.00 tok/s ttft=0.10 ms`；反向投毒（0.5/5000 ms）使决策从 bi150 翻转为 jetson。`load_perf` 只验 schema/device/数值，事件只记 perf_ref 路径——无输入文件哈希、无时效字段（bench/1 的 date 不校验）。
- **修**（Bicameral 仓，行号为修后现状）：`sha256_16()` 指纹助手 + `SHA16_RE` + `HEALTH_TIMEOUT_S` 常量（router.py:97-105）；`load_perf` 改读字节、facts 携带 `perf_sha256_16`（:177-216）；`apply_expect_perf_sha` pin 不匹配 → NOT_VIABLE（:302-319）；CLI `--expect-perf-sha DEVICE=SHA16` 可重复、格式错前置校验 exit 2（:982-984, :1086-1092）；`route_event` 每候选记录 `perf_sha256_16` + `health`（:323-361）。
- **复测**（红队轮）：篡改副本 sha16=`6fd7f177d3aff3e6` ≠ 归档 `bcd501d0150a7130`，加 pin → `bi150 NOT_VIABLE (perf sha mismatch: …)`、选择翻转 jetson、exit 0。
- **本归档会话复验**（/tmp 沙箱，实跑）：① 不带 pin：伪造值仍使 selected=bi150，但 ROUTE 事件携带 `perf_sha256_16: 4844e975916c6fe5`（伪造文件指纹入审计，可见性成立）；② 加 `--expect-perf-sha bi150=bcd501d0150a7130`：事件 reason 逐字 `interactive: min ttft_ms.mean -> jetson [jetson decode_tps=67.48 tok/s ttft=29.77 ms; bi150 NOT_VIABLE (perf sha mismatch: expected bcd501d0150a7130, got 4844e975916c6fe5)]`，exit 0。归档 perf-bi150.json sha256_16 实测 `bcd501d0150a7130`（双仓一致）。
- **残余**：pin 是可选 CLI 参数——操作者不带 pin 时伪造数值仍能导向决策（可见但未阻断）；fixHint 的 bench date/generated_at 时效窗未实装。

### A2 审计灭迹：删行 + 伪造行（已修，复测 blocked）

- **攻**（首轮）：对 audit 副本 sed 删中间 RESULT 行、追加伪造 ROUTE（task_id=totally-fabricated-task）后重跑 route：exit 0 无任何告警，伪造行与真实事件不可区分。`append_audit` 纯追加不读，router/install 无任何 hash-chain/prev_hash 机制。
- **修**：审计哈希链 `audit_line_sha`/`chain_link`/`verify_audit_lines`/`verify_audit`（router.py:364-470）；`append_audit` 每行加 `seq` + `prev_sha256_16`（链入上一行**原始字节**哈希）；`_route_once` 启动验链：断链 stderr 响亮 `AUDIT CHAIN BROKEN — <铁证>` 后照常追加（告警不阻断=声明设计），完好时打印 `audit chain ok … tail_sha256_16=`（外部锚定点）（:562-580）。legacy 无链行可共存（向后兼容，链从下次追加起算）。
- **复测**（红队轮）：3 行链 sed 删 row2 + 追加伪造行 → `row 2: seq 3 does not follow 1 (row(s) deleted or reordered)`；原地改字段 → `row 3: prev_sha256_16 … does not match the previous line … (content altered)`；均 exit 0（告警不阻断）。
- **本归档会话复验**（实跑）：干净链 3 行删中间行 → stderr 逐字 `router: AUDIT CHAIN BROKEN — row 2: seq 3 does not follow 1 (row(s) deleted or reordered) (audit=/tmp/stage5-archive-verify/audit.jsonl tail_sha256_16=0ff16d1b0e4dc3e8)`；干净 2 行链原地改 row1 字段（seq 不动）→ `router: AUDIT CHAIN BROKEN — row 2: prev_sha256_16 'c088c932f56f52c5' does not match the previous line 'b777d5549cba1c41' (content altered)`；两例均 exit 0。**意外实证了残余**：对仅 2 行的链删末行 → 无告警（剩余单行是合法链尾）——即文档声明的「删末行文件内不可见」。
- **残余**：文件内链原理上检不出删末行/末行原地改——启动打印的 `tail_sha256_16` 即外部锚定点，fixHint 的「定期外部锚定（只读副本）」属运维动作，未自动化。

### A5 appspec 穿越 + engine.binary 解释器注入（**未修，复测 leaked**）

- **攻**（首轮+复核）：穿越半场 blocked——`../../escape.gguf` → INSTALL_FAIL schema `model.file must not contain empty/./.. path parts` exit 2（install.py:364→1084）。注入半场得手——`engine.binary=/bin/sh`（过 schema，仅要求绝对路径 install.py:340）+ `service.args=['-c','touch A5-SHELL-PROOF && id >>…']` → START 事件 pid 实启 `/bin/sh -c …`，proof 文件生成且含 id 输出（组含 sudo/docker）；随后 health 失败回滚，**但命令已执行、回滚不撤销**。复核确认：`resolve_engine:682` 直用 binary（engine.name 不校验 APPSPEC_ENGINE_BINARIES），Popen argv 数组无 shell 拼接面（:862）但攻击者自带解释器使其无意义。
- **复测**（红队轮，小型 fixture 800B 本地镜像）：`DOWNLOAD ok → START pid=4024848 binary=/bin/sh args=["-c","touch …A5-SHELL-PROOF && id >>… && sleep 300"]` → proof 文件生成含 id 输出，exit 4（health 超时回滚但命令已执行）。对照：穿越半场仍拦（exit 2，三候选落点均无 escape.gguf）——**同一攻击一拦一漏，未修面即注入半场**。
- **fixHint（未实施）**：engine.binary 白名单化——engine.name 必须命中 APPSPEC_ENGINE_BINARIES 且 binary basename 与映射一致（或设备侧许可清单），拒绝解释器；service.args 改模板枚举。

### A9 result/1 信封无中生有（已修，复测 blocked）

- **攻**（首轮）：伪造 device=bi150 信封（答案/usage 全新造，latency 24187.5）同时通过 task.py 与 router.py 的 validate_result（仅形状校验）；router RESULT 事件只记 envelope_sha256_16，无来源核验。仅带外人工交叉可破（与归档同 task_id 矛盾 + bi150 审计无对应 ISSUE/ALLOW 对）。
- **修**：`extract_allow_digest`——从设备侧 audit 取该 jti+task_id 的 ALLOW 行**原始字节** sha256_16，取不到如实 null（task.py:243-273）；`normalize_result` 增 `device_audit_digest`，`validate_result`（权威）要求存在且 null 或 16 位小写 hex（:275-310）；`execute-local` 提取 digest 写入信封（task.py:410-448），新增 `--audit-path`；router 侧 validate_result 镜像同步、RESULT 事件携带 digest（router.py:473-497, :676-685）；新增 `verify_result.py`（243 行）：信封形状（import task 权威）→ digest 存在且 16hex → 解析到唯一 ALLOW 行 → task_id 绑定 → ISSUE/ALLOW 配对，exit 0/1/2。
- **复测**（红队轮）：原伪造信封过 router execute → `envelope invalid: missing field(s): device_audit_digest` exit 4、0 RESULT 行；伪造 digest=deadbeefdeadbeef 过形状但归档核验 `FAILED: no ALLOW row … hashes to deadbeefdeadbeef` exit 1；正控真执行 digest=`b02bae4ea7dfe105` → VERIFIED（未伤真流程）。
- **本归档会话复验**（实跑）：修前形状的归档信封 `results/2026-10-15-stage4-task/result-bi150.json` → `verify_result: FAILED: envelope invalid: missing field(s): device_audit_digest`，真实 exit=1（旧信封不再过新契约，向后不兼容是声明语义）。
- **残余**：digest 绑定的是**授权事件**（存在性 + task_id + ISSUE 配对），非信封内容本身——能同时改真信封并保留其 digest 的攻击者仍过检；彻底闭合需设备侧对信封签名（超出本轮修复面）。

### A11 devices/1 清单投毒 → 任意命令 + 信封冒名（**未修，复测 leaked**）

- **攻**（首轮+复核）：自建 devices 清单（name=bi150 + local=true + run=`python3 -c 打印伪造 result/1` + 真 perf 路径）→ `router.py execute --devices 该清单` exit 0，审计新增 RESULT device=bi150 model_id=Qwen3.8-27B envelope_sha256_16——实为**本机命令产物**；只读 ssh 查真 bi150 审计 0 条相关。devices/1 的 run 字段是任意命令串，无指纹/签名/白名单——与 paradigm §4「D15 工具指纹防注册表篡改」不对位（D15 实际只护工具表，server.py:763）。
- **复测**（红队轮）：原 payload 被 A9 修复**顺带拦下**（信封缺 device_audit_digest → exit 4）；一行适配加 `digest=deadbeefdeadbeef` 后 exit 0——审计新增 RESULT device=bi150 … digest=deadbeefdeadbeef。**路由级冒名得手**：verify_result 归档核验可拒该 digest，但伪造 RESULT 行已落入审计。
- **fixHint（未实施）**：devices/1 引入 D15 式指纹/签名校验，run 字段改白名单模板（execute-local 固定 argv 形状），禁自由命令串。

## 3. 首轮即 blocked 的防线（防守成立，复测回归确认未松动）

| # | 攻击 | 防守成立点（首轮实测） | 复测回归 |
|---|---|---|---|
| A3 | 假 mirror 首位供 49152B 垃圾 | 双 sha256 pin：`VERIFY_FAIL final=false ×2`（got ≠ pin）→ 逐出坏 mirror → 次位 DOWNLOAD→VERIFY_OK→PLACE→HEALTH→READY exit 0，坏内容零落位（paradigm §5 双 sha256 行兑现） | **回归 blocked**：TAMPERED 镜像 vs pin → `VERIFY_FAIL … exit 3`，models/ 零落盘；同代码路径 honest 镜像 ok——流式哈希校验未松动 |
| A4 | mirror accept 后永不响应 | 两次尝试均封顶 60s socket 读超时，总 2m18s 后回退好 mirror → READY——挂起不可能拖死安装。如实注记：实际触发 `download_read_timeout_s=60`（先于 120s stall guard），stall guard 覆盖慢滴漏变体——两道界均使攻击有界 | 未单列复测（install.py 未触碰） |
| A6 | 删除 model.sha256 无 pin 安装 | `INSTALL_FAIL step=schema 'model missing field(s): sha256'` exit 2，零下载零落位；短 sha/非 hex 变体纯函数复验均 REJECTED——ungoverned 安装不可能 | 未单列复测（install.py 未触碰） |
| A7 | service.health SSRF（169.254.169.254 / 内网 IP / ftp scheme） | `http_get_local`（probe.py:791-819）把 host 钉死 loopback，恶意串只能进 path：金丝雀收到的全是 `GET /http://169.254.169.254/…`、Host:127.0.0.1——无 SSRF | 未单列复测（probe.py 未触碰） |
| A8 | prompt 注入 + actions 键 + NUL 变体 | 注入 prompt → 权限层 `DENY D12/INJECTION_SUSPECTED` exit 3，DENY 落审计、/tmp/A8-PWN 未创建；actions 作 KEY 被 task schema 先拒（forbidden key exit 2） | **回归 blocked**：a8b exit 2；a8-inject DENY exit 3 零字节信封；a8c（NUL 混淆）绕 D12 到达 LLM 但 summary 为空、无文件生成（executor 固定 llm.complete 单次预算、无工具执行面） |
| A10 | kill llama-server 后仍派发 | 派发确实发生（路由前无活性检查），但权限层即时 `DENY D13/CAPABILITY_DEGRADED` → exit 3 → router exit 4 + EXECUTE_FAIL 落审计——失败响亮不静默、无假结果 | 首轮已 blocked，本轮**加固**：devices/1 增可选 `health_url`（http(s) 绝对 URL 校验），决策前对配了 health_url 的存活候选探测（GET、超时封顶，HTTP 200 且 strata_state==ok 才算活），不可达/不健康 → NOT_VIABLE、perf 事实清零。修复侧验证：死端口→`unreachable: URLError`、降级层（strata_state=degraded，正是 A10 残余场景）→`unhealthy: strata_state=degraded`、双双 NOT_VIABLE exit 3 全程 0.16s；健康层正常选中。**本归档会话实跑** route 默认流程，jetson 候选 `"health": "ok"` 入事件（存活探测 happy path 实证）。如实注记：红队复测轮无 A10 独立重放条目 |

## 4. bydesign 边界清单（记为边界而非缺陷）

- **A12**：`mirror_urls=[file:///…]` 端到端 READY——install 接受任意本地路径当 mirror。install.py selftest `urls.file_scheme`（:1456-1458）明确钉死接受 file scheme，且 model.sha256 pin 与 VERIFY 全程仍强制。
- **A2 告警不阻断**：断链后照常追加（新行如实链到所见证的字节、保留证据）是声明设计——审计链的可恢复性优先于阻断写入。
- **A4 注记**：挂起场景实际触发 60s 读超时而非 120s stall guard；stall guard 针对慢滴漏变体；两道界均使攻击有界。
- **A5 回滚语义**：安装失败回滚目录不撤销已被启进程执行过的命令——回滚的承诺边界是文件系统，不是进程副作用（该语义在 A5 未修状态下成为注入损失的放大器）。

## 5. 遗留与未实现防线（如实声明）

1. **A5（leaked → ✅ 已修复，见 §8）**：engine.binary 仍只验绝对路径，任意解释器注入可执行任意命令；proof 文件实证命令已执行且回滚不撤销。修复需 engine.binary 白名单化 + service.args 模板枚举。
2. **A11（leaked → ✅ 已修复，见 §8）**：devices/1 run 字段仍为任意命令串，路由级 RESULT 冒名可行（A9 的 digest 核验只能事后拒绝归档核验、拦不住伪造行落审计）。修复需 devices 清单指纹/签名 + run 模板白名单。D15 指纹机制现状只护工具表（server.py:763），与 paradigm §4 的注册表保护承诺存在**实现差距**。
3. **A2 残余**：删末行/末行原地改文件内不可见；`tail_sha256_16` 外部锚定是启动打印的运维动作，未自动化。
4. **A9 残余**：digest 绑定授权事件存在性而非信封内容；需设备侧对信封签名才能彻底闭合。
5. **A1 残余**：`--expect-perf-sha` 为可选参数，不带 pin 时伪造数值仍导向决策（可见性而非阻断）；bench date/generated_at 时效窗未实装。
6. **paradigm §5「负载采样」未实装**：路由评分无 load 项，事件 `load:null`（如实记 null、不编造）；「PerfRecord 时效」同样未实装（A10 修复覆盖的是**活性**探测，不是时效/负载）。§5 该行三项防线中仅「路由审计可复审」完整落地。
7. **A8 残余观察面**：NUL/控制字符可绕 D12 正则到 LLM（本轮无副作用：单工具单次预算、无执行面）；可考虑 schema 层拒绝含 `\u0000` 的 prompt。
8. **A10 如实注记**：修复后行为由修复侧验证 4 场景 + 本归档会话 happy-path 实跑佐证；红队复测轮未出独立 A10 重放条目。
9. **验证边界**：A4/A6/A7/A12 复测轮未单列重放——其代码面（install.py/probe.py）本轮零改动且首轮 blocked 证据充分；此为覆盖面取舍而非遗漏声明豁免。

## 6. 本归档会话实跑的检查（命令与结果）

| 检查 | 命令 | 结果 |
|---|---|---|
| 编译 | `python3 -m py_compile bicameral/{router,task,verify_result,server,install,probe}.py examples/quickstart.py scripts/live_check.py` | 8/8 OK exit 0 |
| router selftest | `python3 bicameral/router.py selftest` | 50 ok / `selftest: 0 failure(s)` exit 0 |
| task selftest | `python3 bicameral/task.py selftest` | 45 ok / `selftest: 0 failure(s)` exit 0 |
| verify_result selftest | `python3 bicameral/verify_result.py --selftest` | 9 ok / `selftest: 0 failure(s)` exit 0 |
| 归档 perf 指纹 | `sha256sum results/2026-10-14-probe-bench/perf-bi150.json`（双仓） | `bcd501d0150a7130` 双仓一致，与复测记录吻合 |
| A1 无 pin | 沙箱篡改副本(99999/0.1)→`router.py route --devices 副本 --audit /tmp/…` | selected=bi150（仍被导向），事件 `perf_sha256_16=4844e975916c6fe5` 入审计（可见性） |
| A1 加 pin | 同上 + `--expect-perf-sha bi150=bcd501d0150a7130` | `bi150 NOT_VIABLE (perf sha mismatch: expected bcd501d0150a7130, got 4844e975916c6fe5)`，翻转 jetson，exit 0 |
| A2 删中间行 | 3 行链 `sed '2d'` → 重跑 route | `AUDIT CHAIN BROKEN — row 2: seq 3 does not follow 1 (row(s) deleted or reordered)`，exit 0 |
| A2 原地改 | 干净 2 行链原地改 row1 字段 → 重跑 route | `AUDIT CHAIN BROKEN — row 2: prev_sha256_16 'c088c932f56f52c5' does not match the previous line 'b777d5549cba1c41' (content altered)`，exit 0 |
| A2 删末行（残余实证） | 2 行链 `sed '2d'` → 重跑 route | 无告警（剩余单行为合法链尾）——§5.3 残余成立 |
| A9 旧信封 | `verify_result.py results/2026-10-15-stage4-task/result-bi150.json` | `FAILED: envelope invalid: missing field(s): device_audit_digest`，exit 1 |
| A10 happy path | 默认 route（examples/devices.json，jetson 带 health_url） | jetson 候选 `"health": "ok"` 入 ROUTE 事件 |
| 归档完整性 | `md5sum` route-audit.jsonl 双仓 | `89f04d2c91dfdb78` 一致（本会话零写入 Bicameral） |
| 修后文件指纹 | `sha256sum` router/task/verify_result/devices.json | §0 表（router `c96250cd210e6d5e` 等） |

**未在本会话实跑、引自红队轮材料**（沙箱与实机环境由前置会话搭建）：A5/A11 复测（leaked 判定）、A9 正控 VERIFIED（digest=`b02bae4ea7dfe105`，涉真实 LLM 调用）、A10 修复侧 4 场景（死端口/降级层/健康层/默认清单）、A3/A5穿越/A8 回归。本归档引用时逐条标注出处。

## 7. 对 paradigm.md 的回写

- §5 攻击面表：每行补「实装状态（2026-10-15）」列，并新增红队轮发现的 3 类攻击行（审计灭迹 / 信封伪造 / engine.binary 与 devices run 注入=缺口）。
- §6 阶段 5 行：判定 **v1.0 未达成** + 缺口（A5/A11）与残余注记，指向本归档。


## 8. 判定更新（2026-10-15 · A5/A11 第二批修复后）

两条 v1.0 缺口已由第二批修复关闭，修复员+主会话双重复测：

**A5 engine 白名单**（install.py `APPSPEC_ENGINE_BINARIES`，basename 必须 llama-server，解释器与 look-alike schema 即拒）：
复刻原攻击（800B fixture、`binary=/bin/sh`、`args=[-c, touch proof && id >> …]`）→ `INSTALL_FAIL step=schema: engine.binary basename 'sh' is not a whitelisted executable … (A5)` **exit 2，proof 文件未生成**，零下载零进程零目录；正控 basename=llama-server 正常进 engine 解析。selftest 新增 10 用例（sh/bash/python3.11/perl/evil-lookalike 全拒，合法路径接受）。

**A11 devices 清单结构化白名单**（router.py）：自由 `run` 字段与未知字段一律拒绝（fail-closed），ssh 目的地结构化 `{user,host,port}`（连 `-oProxyCommand` 注入面一并堵死）；`devices_manifest_sha256_16` 进入 ROUTE/RESULT 事件（冒名可检测）。复刻投毒清单（含伪造 digest）→ **exit 3，audit 0 字节 0 条 RESULT 冒名行**。selftest 新增 21 用例（含固定 argv 逐字节 pin 渲染）。

**回归**：正常 apply（openelm-270m 176MB file:// 镜像 + 白名单引擎）→ READY → rollback 干净；正常 route 保持阶段 4 语义（interactive min-ttft → bi150，A1 perf 指纹、A10 health 状态入事件）。`py_compile` 8/8；selftest install/router/task/verify_result 全 0 失败。

**改判：v1.0 达成（2026-10-15，范式 5/5 阶段门全过）。**
残余注记（不阻塞 v1.0，记入后续）：A2 删末行需外部锚定自动化；A9 digest 绑授权事件存在性、信封内容级需设备侧签名；A1 pin 目前 CLI 可选 + bench 时效窗未实装；负载采样/故障转移为最小实现；管理面鉴权归 v2。
