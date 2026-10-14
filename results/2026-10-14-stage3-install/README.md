# 2026-10-14 appspec/1 + install.apply 实证归档（范式阶段 3）

> 归档员整理，2026-10-14。覆盖范式（`/home/nvidia/code/Bicameral/docs/paradigm.md` §3.4、§6 阶段 3）的实证：一条指令把一台 `absent` 设备变 `ready`，全程审计可查、失败可回滚。
> 证据分三类，行文逐条标注：**✅ 本会话复跑**（本机 jetson、user nvidia，命令与输出如实给出）；**「验收记录」**＝bi150 验收材料原文（本账号无权限读 `/root/bicameral-sandbox/`，`ls` 报「权限不够」，审计原文无法在此二次打开，摘录按验收材料原样引用）；**「交付说明」**＝交付方实现自述（仅作背景，判定不依赖）。

## 0. 产物清单

| 产物 | 位置 | 指纹 |
|---|---|---|
| `install.py`（appspec/1 受控安装工具，stdlib 单文件，1254 行） | Bicameral 仓 `bicameral/install.py`（未提交，`git status` 为 `??`） | sha256 `3bd046b0cfa4a0cd9735b6ed24ef5406d9f147a02057babb4ba146a122025bd7` ✅ |
| 正例 appspec | Bicameral 仓 `examples/appspec-qwen3-1.7b-q8_0.json` | sha256 `8d900a1019aad4fe934d279924fac04d7052920dd288c5be4f427d71b96f51dd` ✅ |
| 坏例 appspec（仅 model.sha256 首字符 0→f） | Bicameral 仓 `examples/appspec-badsha.json` | sha256 `b5f2ef538ac30a6141f8ff233332b195c0a571f1e10252fb05f8ed67be10bbbf` ✅ |
| 审计流水 | bi150 `/root/bicameral-sandbox/audit.jsonl`（验收记录称 8KB） | 本机不可读（权限），摘录见 §2/§3 代码块 |

两份 appspec 的等价性 ✅：本会话用程序化逐键 diff 验证——除 `/model/sha256`（`061b…cb1a` → `f61b…cb1a`，仅首字符 0→f）外**零差异**；`install.py selftest` 内置检查 `examples.badsha_differs_only_in_sha` 同样通过。

## 1. appspec 示例与双 sha256 语义

正例原文（`examples/appspec-qwen3-1.7b-q8_0.json`，✅ 本会话读取）：

```json
{
  "schema": "appspec/1",
  "name": "qwen3-1.7b-q8_0",
  "engine": {
    "name": "llama.cpp",
    "ref": "b11062",
    "binary": "/home/nvidia/code/strata-jetson/work/llama-build/bin/llama-server",
    "sha256": "8ea353d9d67439bea8ad6af8270c6fa2066f3adf3da7710bdfa190d072d684a8"
  },
  "model": {
    "repo": "Qwen/Qwen3-1.7B-GGUF",
    "file": "Qwen3-1.7B-Q8_0.gguf",
    "format": "gguf",
    "sha256": "061b54daade076b5d3362dac252678d17da8c68f07560be70818cace6590cb1a",
    "mirror_urls": ["https://hf-mirror.com", "https://huggingface.co"]
  },
  "service": {
    "port": 18010,
    "health": "/health",
    "args": ["-m", "{model}", "--host", "127.0.0.1", "--port", "{port}", "-ngl", "99"]
  }
}
```

双 sha256 语义（实现于 `install.py` 文档串 47–56 行与 `resolve_engine` install.py:530-572）：

- **model.sha256 强制**：下载即流式逐块哈希（`download_model` install.py:586-643），不符即 `VERIFY_FAIL` 且 `.part` 立即删除（install.py:621-629）、**绝不落位**（`os.replace` 仅在 `VERIFY_OK` 之后，install.py:955-958）；
- **engine.sha256 可选**：给了 pin 就必须精确匹配，否则 `VERIFY_FAIL`（install.py:553-558）；没给 pin，实得指纹仍记入 `ENGINE_FOUND` 事件（install.py:870-877 note）——指纹是事实，pin 是约束，两者分离。

schema 校验 fail-closed：未知字段拒绝、路径穿越拒绝（name/file/repo 逐段查 `..`）、`actions/tool_calls` 禁用键（同 server.py D8 哲学），selftest 覆盖 26 例拒绝。

## 2. apply 全流程：absent → ready（bi150 实证）

前置（验收记录）：scp 后 `python3 bicameral/install.py status qwen3-1.7b-q8_0` 输出 `{"app":"qwen3-1.7b-q8_0","state":"absent"}`；`selftest` 在 bi150 上 0 failure(s)；端口 18010 空闲；磁盘 10T 可用。

事件链与代码对应（✅ 代码引用为本会话通读 install.py 所得；事件序列按验收记录摘录）：

| 步骤 | 事件 | 代码 |
|---|---|---|
| 读 appspec + 严格校验 | `INSTALL_START{dedup_key, appspec_sha256_16}` | install.py:857-859（校验 243-370） |
| 前置 install_state | `STATE{phase:pre}`（marker+文件系统+服务事实，语义同 probe.eval_appspec） | install.py:878-881、450-483 |
| 幂等决策 | `STATE{phase:decision, action:fresh, why}` | install.py:884-886、486-506 |
| 引擎解析 | `ENGINE_FOUND{binary, sha256_16, ref_matched, pin_matched}` | install.py:865-877 |
| 流式下载 | `DOWNLOAD{ok, mirror, attempt, url(脱敏), bytes, sha256_16}` | install.py:586-643 |
| 校验 | `VERIFY_OK{model, sha256 全串, bytes}` | install.py:955-956 |
| 落位 | `PLACE{path, bytes}`（沙箱内原子 replace） | install.py:958-959 |
| 起服务 | `START{pid, binary, port, args(每参截断 200)}` | install.py:660-673 |
| 健康检查 | `HEALTH{200, attempts, elapsed_ms}` | install.py:704-722 |
| 强制重跑 probe/1 | `PROBE_REFRESH{probe_state, probe_missing, probe_sha256_16, note}` | install.py:735-779 |
| 终态 | `READY{port, install_dir, dedup, install_state, model_sha256_16, engine_binary}` | install.py:976-995 |

审计摘录（FRESH，验收记录原文）：

```
FRESH: INSTALL_START{dedup_key:…:061b54da…} DOWNLOAD{ok,bytes:1834426016} VERIFY_OK{model,061b54da…cb1a} PLACE{…/Qwen3-1.7B-Q8_0.gguf} START{pid:3874817,port:18010} HEALTH{200,4007ms} PROBE_REFRESH{partial} READY{install_state:ready}
```

审计格式与 server.py 对齐（`{ts, event, …非None摘要}` JSONL 追加写，install.py:191-219）；URL 一律脱敏为 `scheme://host/path`（`redact_url` install.py:154-161，query 中的 token 进不了日志）。边界全部有界（install.py:98-114）：每镜像 2 次重试、单次尝试 900s 墙钟、模型 32 GiB 硬顶、health 总预算 180s、probe 刷新 180s；exit code 0/2/3/4/5（文档串 58-59 行）。

## 3. 失败可回滚：badsha 用例与引擎 pin 用例

**用例 A（badsha，model 校验失败）**：对已 ready 的同名 app apply `appspec-badsha.json`。同名异 sha → 决策 `superseded`（install.py:500-501）→ 先回滚旧版再全新安装（install.py:889-892）；新下载真文件、流式哈希与 pin 不符 → `VERIFY_FAIL`、绝不落位、回滚至 `absent`。审计摘录（验收记录原文）：

```
badsha: STATE{superseded,marker model_sha256 differs} ROLLBACK{superseded_by_new_model_sha256,removed_dir:true} VERIFY_FAIL{model,want:f61b54da…,got:061b54daade076b5} INSTALL_FAIL{download,exit_code:3} ROLLBACK{failed:download,state:absent}
```

残留核验（验收记录）：模型大文件无需手动 rm——两段回滚已把已落位模型与 `.part` 全部清除，`apps/` 目录为空，全沙箱无 `Qwen3-1.7B*.gguf`/`*.part` 残留；沙箱内其余 gguf 为 llama.cpp 仓库自带 vocab 测试文件与上一轮 Qwen3-0.6B，非本次产物。

**用例 B（引擎 pin 强制生效，验收记录 notes 原文）**：按原样 apply（engine.binary 经 sed 指向沙箱 CPU 构建后）先复现 `VERIFY_FAIL(what=engine)`→`INSTALL_FAIL exit_code=3`→`ROLLBACK(absent)`——交付版 appspec 声称 `engine.sha256=8ea353d9…/ref=b11062` 为在盘实测，但 bi150 沙箱内唯一 llama-server 实测 `sha256_16=d59eab76dfbb7e8e`（--version 自报 `build 1, commit 8c2134a`），两者不匹配，pin 校验拒绝安装。随后从两份 appspec **副本**剥掉可选的 `engine.sha256`/`engine.ref`（设计明确允许缺省，实得指纹仍入 `ENGINE_FOUND`），`model.sha256` 强制语义原封未动，正例才通过。**注意：Bicameral 仓内两份 examples 至今仍是带 pin 原文**（✅ 本会话读取核实，§1 代码块即原文），交付方应修正示例或 paradigm §1 的指纹记载（见 §7）。

回滚的杀进程安全设计（本会话通读确认）：START 时把渲染后完整 argv 记入 marker（install.py:968），kill 前按 `/proc/<pid>/cmdline` 精确匹配，不匹配即 `skipped_unverified`，杜绝误杀回收 pid（install.py:676-701、804-811）；rm -rf 仅在 `path_inside` realpath 包含判定下执行（install.py:813-816，164-168）。

## 4. 幂等验证

决策表（`decide_resume` install.py:486-506，selftest 七例 `decide.*` 覆盖）：

| marker | model 文件 | 服务 | 动作 |
|---|---|---|---|
| 无 | — | — | `fresh` |
| 同 name+sha256 | ✓ | 健康 | `dedup_ready`（零下载、**零新进程**，复用在跑服务，marker 保留原 pid，install.py:924-933） |
| 同 name+sha256 | ✓ | 不健康 | `restart`（只重启服务，不下载） |
| 同 name+sha256 | 缺/损坏 | — | `resume`（仅补下载） |
| 异 sha256 | — | — | `superseded`（先回滚再全新安装） |

bi150 证据（验收记录原文）：

```
幂等: DEDUP{same name+model sha256, service healthy} READY{dedup:true}
```

dedup 键 = `name + model.sha256`（install.py:388-390）；同 sha 文件损坏仅 resume 补下载；URL 构建按 HF 约定 `{mirror}/{repo}/resolve/main/{file}`、镜像按序回退（install.py:373-385）。

✅ 本会话复跑（本机 jetson，工作区未提交版本）：

```
$ cd /home/nvidia/code/Bicameral
$ python3 -m py_compile bicameral/install.py bicameral/probe.py bicameral/server.py   # 三文件编译通过
$ python3 bicameral/install.py selftest      # 输出末三行：
ok   examples.badsha_schema_valid
ok   examples.badsha_differs_only_in_sha
selftest: 0 failure(s)     # 退出码 0
```

即交付说明所称 45 项 selftest（schema 26 例拒绝、URL/dedup/决策表/脱敏/containment）在归档时刻的代码上复现通过；bi150 上的 selftest 0 failure(s) 来自验收记录。交付说明另称本地有界 e2e 32/32 通过（假镜像+假引擎、`--sandbox-root` 重定向）——**归档员未复跑该 e2e**，按交付说明如实转记，不作为判定依据（判定依据是 bi150 验收记录）。

## 5. 服务与真实推理（双证 + 真推理）

验收记录原文要点（服务现已停止，不留常驻）：

- llama-server 监听 `127.0.0.1:18010`，`/health` 200（4007ms 内就绪）；模型 `/root/bicameral-sandbox/apps/qwen3-1.7b-q8_0/models/Qwen3-1.7B-Q8_0.gguf`（1,834,426,016 B，sha256=061b54daade076b5…，流式校验通过）；引擎 = 沙箱 CPU 构建 `/root/bicameral-sandbox/llama.cpp/build-cpu/bin/llama-server`（实测 sha256_16=d59eab76dfbb7e8e，已记入 `ENGINE_FOUND`）。
- 双证：`/health` 200 + `/v1/models` 返回模型清单；真实推理：`/v1/chat/completions`（`/no_think`）content=`Paris.` finish=stop；裸 `/completion` "The capital of France is" → 真实文本，44.9 tok/s。
- 红线核验：验收结束 8080/8181/8960-8963/18000/18001 全部原样在监听，存活 llama-server 仅红线服务自身（`/private/models` Qwen3.8-27B，端口 8960-8963）；18010 无监听；/tmp 中间日志已删，一切限于 `/root/bicameral-sandbox/`。
- 附带事实：首测 chat completion content 为空，是 Qwen3 thinking 模式把 max_tokens=32 耗在 reasoning_content 且 `finish_reason=length` 截断，非服务故障；关 thinking（`/no_think`）后才有 content。对 task/1 统一任务的 prompt/参数约定是硬约束。

## 6. 如实记录的瑕疵与局限（不推翻判定，均已定位）

1. **引擎指纹跨机不符（交付物缺陷，需交付方修正）**：examples 两份 appspec 的 `engine.sha256=8ea353d9…/ref=b11062` 是 jetson 在盘构建的指纹，在 bi150 上必然 `VERIFY_FAIL`（§3 用例 B）。engine pin 可选、缺省时指纹照记，设计本身自洽；但「示例声称在盘实测」与 bi150 实情矛盾——修正 examples 或 paradigm §1 指纹记载，二选一。
2. **engine.binary 的 sed**：验收时把交付版路径 `/home/nvidia/code/strata-jetson/work/llama-build/bin/llama-server`（bi150 不存在）sed 为沙箱 CPU 构建路径，系红线（一切限于 `/root/bicameral-sandbox/`）所必需；仓内示例保持交付原文。
3. **survived_sigkill 误报（实现瑕疵）**：`pid_alive` 用 `os.kill(pid,0)`（install.py:434-439），zombie/defunct 进程会被判活——badsha superseded 回滚时 pid 3874817 报 `survived_sigkill`（`stop_process` install.py:701），实际进程已死（18010 无监听、连接拒绝，仅剩未收尸 zombie）。防误杀的 cmdline 精确匹配设计本身生效；建议 `pid_alive` 改读 `/proc/<pid>/stat` 排除 Z 状态。
4. **PROBE_REFRESH 视角 partial（已知局限，与交付声明一致）**：probe 引擎/模型扫描仅 PATH+安装根（`extra_bin_dirs` probe.py:220-231，引擎经 find_binary 于 probe.py:234-240），看不到自定义 `engine.binary`；模型在安装目录也报 `found outside appspec path`（probe.py:845）。install 终态因此强制以子进程重跑 `probe.py --appspec` + 本侧 sha256/health 事实 reconcile（install.py:767-769 有明文 note），probe 视角 partial 与 reconciled 终态 `install_state=ready` 两视角并存入审计——不装假。
5. 归档员本会话**未能**做的事：读 `/root/bicameral-sandbox/audit.jsonl` 原文（本账号权限不足）、在 bi150 复跑 apply（服务已停、环境在远端）。§2–§5 的 bi150 事实全部溯源自验收材料。

## 7. 验收门判定（§6 阶段 3）

> 门：**一条指令把一台 `absent` 设备变 `ready`，全程审计可查、失败可回滚。**

**判定：达成（2026-10-14）。** 逐项：

- *一条指令 absent→ready* ✅（验收记录）：`install.py apply` 单命令把 bi150 沙箱内 `qwen3-1.7b-q8_0` 从 `state:absent` 变 `READY{install_state:ready}`，含 1,834,426,016 B 真下载、流式 sha256 校验、/health 200 双证、44.9 tok/s 真实推理；终态经强制重跑 probe/1。
- *全程审计可查* ✅：`INSTALL_START→STATE→ENGINE_FOUND→DOWNLOAD→VERIFY_OK→PLACE→START→HEALTH→PROBE_REFRESH→READY` 全链事件落 `/root/bicameral-sandbox/audit.jsonl`，摘录见 §2；URL 脱敏。
- *失败可回滚* ✅：两条失败路径都在真机复现——引擎 pin 不符 `VERIFY_FAIL→INSTALL_FAIL(3)→ROLLBACK(absent)`；badsha `VERIFY_FAIL(模型, 绝不落位)→ROLLBACK(absent)` 且目录/`.part` 全清、端口无残留。
- *幂等*（同门精义）：re-apply 零下载、零新进程，`READY{dedup:true}`。

瑕疵（§6 节）均不否定门本身：#1 是示例数据错误而非安装器缺陷（pin 拒绝恰恰证明校验强制）；#3 是回滚**结果报告**的误报，进程确死、目录确清；#4 已在审计中如实两视角并存。阶段 4（task/1 + 路由）解锁前应先修 #1 与 #3。

## 8. 应回写范式的新事实（摘要）

1. 双 sha256 语义已实证：model.sha256 强制（流式即哈希、不符绝不落位）；engine.sha256 可选、无 pin 时实得指纹仍入 `ENGINE_FOUND`（指纹是事实，pin 是约束）。
2. 引擎指纹是**每机事实**，不可跨机复用：bi150 沙箱 llama-server（CPU 构建 8c2134a）sha256_16=d59eab76dfbb7e8e ≠ §1 表 jetson 在盘构建 8ea353d9（b11062）；appspec 示例携带他机引擎 pin 会 VERIFY_FAIL。
3. 探针与 install 的联动缺口：probe 扫描面（PATH+安装根）看不到 appspec.engine.binary 自定义路径与安装目录内模型，`PROBE_REFRESH` 只能两视角并列（probe partial + install reconciled ready）；范式若要「终态以 probe 为准」，需先扩探针扫描面或定义 reconcile 规则。
4. `pid_alive`（os.kill(pid,0)）不排除 zombie → `survived_sigkill` 可误报；修法：读 `/proc/<pid>/stat` 排除 Z 态。
5. Qwen3 thinking 会把小 max_tokens 耗尽在 reasoning_content（content 空、finish=length）——task/1 的推理参数约定必须显式关 thinking 或给足 tokens。
6. hf-mirror 经 `{mirror}/{repo}/resolve/main/{file}` 拉到 1.83 GB 官方工件且 sha256 与 pin 逐字节一致——§7.2「出网按设备事实配置」在安装层可执行。
