# 2026-10-16 nodeagent — 节点自治代理（四自）bi100 真机门

**目标**：回应「架构做不到四自」——新建 `bicameral/nodeagent.py`（1870 行，仅标准库，import 同目录 probe.py/install.py 复用其函数，不复制逻辑，不改其他文件），在 bi100（ssh -p 46026 root@10.70.250.26，Ubuntu 22.04.5 jammy，x86_64，128 核，503G）上验证：**先 `apt-get remove` 掉 gcc/g++/make/cmake/cpp 制造无工具链裸节点，然后一条命令** bootstrap 全程零人工到 READY + selfcheck 全 PASS。

**红线遵守**：一切写入限 `/root/bicameral-sandbox/`（/root/bicameral-fleet/ 未写）；结束 rollback + 删大目录 + kill 实例（监听集回到 `[22]`，sshd 未动）；沙箱终态 696K（状态 + 双审计 + appspec + 脚本保留）。

## 0. 产物指纹

| 产物 | 指纹 |
|---|---|
| `bicameral/nodeagent.py`（最终版，本地=bi100 部署版） | sha256 `81a1ce07f6b11681…`（16 位），**1870 行** |
| bootstrap 实跑版本 | `7f7b47b274ff0d1a`（其后修复仅涉 selfcheck 的 invoke 面推导，bootstrap 流程零改动，见 §5-2） |
| install.py / probe.py（沙箱部署副本） | `4c93527d88b02844…` / `a2ce9db92eff2fb7…`（与主仓及 bi150/bi100 门记录一致） |
| server.py（本机控制面演示用） | `7cafc8cfac6f65f5` |
| 源码包 llama-src.tgz（38MB，llama.cpp 0.7.0-dev，上轮门同源重放） | sha256 `b983afe633095c97…`（scp 双侧一致；bootstrap 另以 `--engine-source-sha256` 钉死校验） |
| 引擎工件（nodeagent 自动打包） | `nodeagent/artifacts/llama-ubuntu22.04-x86_64.tgz`，6,898,321 B，sha256 `aed446d7237b88c4…`，成员 `bin/llama-server`+6 .so，RUNPATH `$ORIGIN`（roundtrip --version 实证自包含） |
| 引擎二进制（install 后） | `engines/llama.cpp/bin/llama-server` sha256_16 `c8be70d331ae7428` |
| 模型 | Qwen3-0.6B-Q8_0.gguf 639,446,688 B，sha256 全串 `9465e63a…bb031` 相符 |
| 本目录文件 | `appspec-nodeagent-qwen3.json`（输入，huggingface.co 故意排首位）、`apply-spec-generated.json`（agent 自动组装）、`nodeagent-audit.jsonl`（83 行全量）、`install-audit.jsonl`、`nodeagent-state.json`、`selfcheck.json`、`status.json`、`bootstrap-stderr.log` |

## 1. 子命令清单（nodeagent.py）

| 子命令 | 功能 |
|---|---|
| `sense [--port] [--no-egress] [--sandbox]` | 探针 + 提炼决策事实 JSON：os_id/os_version/arch/glibc/cores/mem_gb/toolchain{gcc,g++,cmake,make,git}/pkg_mgr(apt/dnf/none)/egress{pypi,hf,hf_mirror,github_https}/engines/port_free |
| `bootstrap --appspec F --sandbox D [--strategy auto/artifact/source] [--engine-source-tgz P --engine-source-sha256 H] [--health-timeout S] [--selfcheck-agent URL --selfcheck-admin-token T --selfcheck-agent-plane URL --selfcheck-agent-data-scope D]` | 零人工 sense→plan→act→verify 有界循环（≤12 轮）到 install_state=ready，每轮一条 NA_DIAGNOSE {observed, diagnosis, action, outcome}；规则穷尽→NA_ESCALATE 结构化 DIAGNOSIS_REPORT，exit 3 |
| `selfcheck --base [--port] [--agent URL] [--agent-plane URL] [--admin-token T] [--agent-data-scope D] [--sandbox]` | 逐项 PASS/FAIL/SKIP：/health、/v1/models、一次真实 /completion；控制面（可选）：/healthz、审计可追加、nonce 表（重放第二次必须 D3）、预算表（耗尽必须 D10）；任何 FAIL 带诊断建议 |
| `status [--sandbox D] [--state F]` | 读 nodeagent-state.json（最近 sense 快照、DIAGNOSE 历史、bootstrap 结果、selfcheck 摘要） |
| `--selftest` | 84 项纯函数断言：error_text→诊断分类（19 例）、规则表选择（17 例）、退避计算、镜像按出网排序、apply-spec 组装、信封组装、ldd/glibc 解析、jsonl 尾读、规则表↔分派覆盖一致性等；无 ssh/无网络 |

审计事件：NA_SENSE / NA_DIAGNOSE / NA_ACTION（破坏性动作**动前**记录，删除动作过 install.path_inside 沙箱门）/ NA_VERIFY / NA_ESCALATE / NA_BOOTSTRAP。

## 2. bootstrap 各阶段耗时（裸节点 → READY，总 206.7s，7 轮）

| 轮次 | 规则 | 动作 | 耗时/结果 |
|---|---|---|---|
| 1 | install_toolchain | apt-get update+install build-essential cmake（NA_ACTION 动前记 argv） | **15.2s** ok |
| 2 | acquire_source | 本地 tgz（sha 钉死校验）→ install.extract_engine_tgz 沙箱内解包 | ~7.8s ok |
| 3 | build_engine | cmake -S -B（GGML_NATIVE、RPATH $ORIGIN、-j128）+ --version + ldd 零未解析 | **89.4s** ok，`0.7.0-dev (build 0, commit unknown)` |
| 4 | package_artifact | 打包工件 + roundtrip 自检 + 组装 apply-spec（模型镜像按出网自动重排：hf down→hf-mirror 置先） | ~8.5s ok |
| 5 | apply_install | install.py apply：ENGINE_DOWNLOAD ok(file:// 6.9MB)→ENGINE_FOUND→模型 hf-mirror **429×2** + huggingface SSL×2→INSTALL_FAIL→ROLLBACK | fail（5.2s） |
| 6 | backoff_retry | 有界指数退避 20s（base 20, cap 240, ≤4 次） | ok |
| 7 | apply_install | 复跑：**ENGINE_DOWNLOAD skip（出处幂等）**→DOWNLOAD ok 639,446,688B（hf-mirror 302→xethub 落点）→VERIFY_OK→PLACE→START pid=6511→HEALTH 200（2005ms）→**READY fresh** | **50.0s** ok |

内嵌 selfcheck（bootstrap 末尾自动跑）：base 三项（/health、/v1/models、真实 /completion）全 PASS；agent 四项 SKIP（bootstrap 未被赋予控制面参数，如实标注，见 §3 独立 selfcheck）。

## 3. 独立 selfcheck（7/7 PASS，exit 0）

控制面：`server.py --control-port 18000 --agent-port 18001 --strata-url http://127.0.0.1:18010/v1 --data-dir …/server-data --admin-token …`（strata_state=ok，直连 llama-server /v1）。

```
base_health          PASS  200 {"status":"ok"}
base_models          PASS  200 [Qwen3-0.6B-Q8_0.gguf]
base_completion      PASS  " Paris. The capital of France is also the capital of the Republic of France."
                           predicted_per_second=33.92
agent_healthz        PASS  200 build_sha=7cafc8cfac6f65f5 pol_ver=1
agent_audit          PASS  /audit 2条 → /issue 200 → 3条（可追加）
agent_nonce_replay   PASS  第2次同 nonce → 401 D3/REPLAY_DETECTED
agent_budget         PASS  超预算 → 429 D10/BUDGET_EXHAUSTED
7 checks: 7 PASS, 0 FAIL, 0 SKIP
```

`status` 双证：install `ready/pid_alive/health_now/live_state=ready`；nodeagent `bootstrap=ready rounds=7 elapsed=206.7`。

## 4. DIAGNOSE 事件序列（原文摘录，≤600 字符）

```
round1 install_toolchain pkg_install_toolchain→ok(elapsed 15.2s); round2 acquire_source→ok;
round3 build_engine build→ok(version 0.7.0-dev, ldd unresolved=[], 89.4s);
round4 package_artifact package→ok(bytes 6898321); round5 apply_install apply→fail(HTTPError
429 Too Many Requests ×2 | URLError [SSL] unknown error ×2 | all mirrors exhausted, rc3);
round6 backoff_retry backoff→ok(20s); round7 apply_install apply→ok(marker state=ready,
pid 6511) ⇒ NA_BOOTSTRAP done status=ready rounds=7 elapsed_s=206.7
```

事件直方图（全程两跑累计）：NA_SENSE×19、NA_DIAGNOSE×19、NA_ACTION×17、NA_VERIFY×24、NA_ESCALATE×1、NA_BOOTSTRAP×3。

## 5. 如实注记（不符/插曲）

1. **第一次 bootstrap 升级（NA_ESCALATE，exit 3）——实现 bug 被真机暴露**：RULES 动作名 `pkg_install_toolchain` 与分派器动词 `install_toolchain` 漂移，12 轮全部 `outcome: "unknown action pkg_install_toolchain"`，agent 按设计**结构化升级而不是静默**（DIAGNOSIS_REPORT 留存于审计）。修复后 selftest 新增 `rules.dispatch_covered`（inspect 静态断言每条规则的 action 必有分派分支）钉住此类漂移。见 nodeagent-audit.jsonl 前 60 行。
2. **selfcheck 首跑 agent 两项 FAIL（404）——`--agent` 语义修正**：/agent/invoke 在 invoke 面（control+1），首版误发控制面。修复：`--agent` 明确为控制面（/healthz /audit /issue），invoke 面默认同 host control+1（`derive_agent_plane`，可 `--agent-plane` 覆盖），404 时 FAIL 建议给出该诊断；selftest 加 derive 断言。bootstrap 实跑版本 `7f7b47b2` 与最终 `81a1ce07` 的差异仅此（bootstrap 主流程零改动）。
3. **hf-mirror 间歇 429 + huggingface.co SSL 错误**（上轮门同款已知行为）：重试由两层承担——install.py 镜像内重试（2s×2）+ nodeagent 有界退避（20/40/80/160s），本轮一次退避即恢复；huggingface.co 出口实际不通（Errno 99/SSL unknown error），agent 的镜像重排（hf down → hf-mirror 置先）在 apply-spec 中生效（先试 hf-mirror）。
4. **bootstrap 内嵌 selfcheck 的 agent 四项 SKIP**：bootstrap 不负责拉起控制面（主控通常在边侧）；赋予 `--selfcheck-agent/--selfcheck-admin-token` 即全量。本轮以独立 selfcheck 全 PASS 补证。
5. **策略 1（预构建工件）→GLIBC 不可移植→切策略 2 的回退路径未在 bi100 真机演示**（bi100 既有工件均为 jammy 原生，--version 自检必过，无从制造跨发行版失败）：该路径由纯函数级自测钉住（`plan.artifact_probe_first` / `plan.artifact_unportable_switch`）。策略 1 的下载→解包→--version 自检机械与策略 2 共用（act_probe_artifact 复用 install.download_model/extract_engine_tgz）。
6. **PROBE_REFRESH partial**：probe 扫描面看不到沙箱 engines/ 与 app 目录内模型，由安装 marker 调和——install.py 既有已知行为（stage3/bi150/bi100 门一致），READY 判定不受影响。
7. 清理时 `pkill -f server.py` 自匹配致首个 ssh 会话自杀（exit 255，上轮门同款小插曲）：rollback 已生效（`killed_pid_outcome=terminated removed=true state=absent`），改用 /proc 遍历 + /proc/net/tcp 复核：监听集 `[22]`，无残留进程。

## 6. 清理与留存

- rollback qwen3-0.6b-q8_0 → terminated/removed/absent；kill server.py（18000/18001）与 llama-server（18010）。
- 删 llama-src.tgz、nodeagent/{src,build,artifacts,scratch}、engines/llama.cpp、apps 残留。
- 保留（696K）：`nodeagent/nodeagent-state.json`（748 行：最近 sense 快照、19 条 DIAGNOSE 历史、bootstrap 结果、selfcheck 摘要）、`nodeagent/nodeagent-audit.jsonl`（83 行）、`audit.jsonl`（70 行 install 侧全史）、3 个 appspec、bicameral/ 脚本、downloads/（空）。监听集 `[22]`。
