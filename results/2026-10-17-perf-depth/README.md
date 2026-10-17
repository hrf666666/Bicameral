# 性能边界深测（四件套）— 2026-10-17

四件套实测：质量抽测（GSM8K-mini）、并发档位扫描、27B 功耗档、Strata spec 对齐尝试（lite）。
所有测量仅用标准库脚本（`scripts/qualitybench.py`、`scripts/bench.py`、`scripts/powerbench.py`，本轮新建）；
未改动 `bicameral/*.py`；bi150 红线服务（22/8080/8181、18000/18001、8960）未触碰。

## 0. 结果速览

| 项 | 结果 |
|---|---|
| GSM8K-mini（20 题固定，首数字 exact match，温度 0，max_tokens 512） | bi150 27B：**20/20 = 100%**；Jetson 0.6B 直连：**0/20 = 0%**（末数字口径 19/20 = 95%）；Jetson 0.6B 经权限层（max_tokens 64 上限）：0/20（末数字口径 7/20 = 35%） |
| 并发扫描（bi150 8960，--duration 20，/no_think，max_tokens 64） | c1 **0.082 rps**；c2 **0.142 rps**（×1.73）；c4 **0.198 rps**（×2.42）。聚合解码 5.23 → 9.05 → 12.65 tok/s；单流 5.5 → ~4.5 → ~3.2 tok/s |
| 27B 功耗档（--max-tokens 256 --runs 2，ixsmi gpu.power.draw + board.power.draw） | 解码 **5.52 tok/s**（server timings，两 run 5.511/5.527）；ixsmi 8 卡 gpu.power.draw 合计：空闲 330.6 W vs 运行 330.3 W（**无可见增量**——推理在 CPU，-ngl 0 -t 56）；board 合计 876-878 W 持平；单卡运行均值 41.3 W、峰值 46 W。「27B 功耗档待测」缺口以"GPU 侧功耗无增量"的客观数据关闭，主机无 RAPL/CPU 功耗表可采 |
| Strata spec 对齐（lite） | **未完成**：引擎在 banner 之后、`PCIe probe` 之前挂起（CUDA 初始化路径）。本轮 **10 次尝试**（含隔离 CUDA_VISIBLE_DEVICES=0、多 GPU、长短 prompt、有无 --dump-routing、最长 45 分钟窗口）全部挂起；历史上 gate4/gate3b 同样挂起，仅 gate3/gate3c（22:14/22:24，另一 tenant 的 drude 负载 23:57 启动之前）成功过。routing trace 无法产出，make_profile 重生成与前后对比未能执行；`drafts accepted` 基线 0/45（gate3c）无可比新数据 |

## 1. 质量抽测 GSM8K-mini（scripts/qualitybench.py）

套件：20 道固定 GSM8K 风格题硬编码于脚本（gold 答案经独立脚本复算核验，见 §5）；覆盖两位数乘加（g01/g02/g08/g09/g14/g15/g16/g18）、比率与分数（g03/g12/g17）、百分比（g04/g05/g10/g19/g20）。
协议：`/no_think ` 前缀 + 题面 + “Answer with only the final numeric result.”；温度 0；max_tokens 512；逐题 `/v1/chat/completions`；**主口径=回复中首个数字** exact match；另记末数字口径（次要，因两个模型都会复述题面）。

| 目标 | transport | 首数字（主口径） | 末数字（次要） | 逐题延迟 |
|---|---|---|---|---|
| bi150 Qwen3.8-27B（ssh 本地 127.0.0.1:8960，t56 CPU） | 直连，未经权限层 | **100%**（20/20） | 100% | 均 11.1 s/题 |
| Jetson Qwen3-0.6B Q8_0（llama-server 18888，-ngl 99） | 直连，未经权限层 | 0%（首数字全落在复述题面的数字上） | **95%**（19/20，仅 g17 错） | 均 1.49 s/题 |
| 同上 | **经权限层**（18100 /issue → 18101 /agent/invoke llm.complete，agent-ro 能力令牌，jti=47ba559f…） | 0% | **35%**（7/20） | — |

经权限层退化归因（客观）：该实例以默认 `--llm-max-tokens 64` 运行，请求 512 被权限层 D8 拒绝（`max_tokens out of range 1..64`），按 64 重跑；0.6B 的分步作答在 64 token 处截断，答案丢失（如 g07 截断于公式行）。12/20 题直连对、经权限层错（g02/g03/g06/g07/g09/g12/g13/g15…）。**同一模型、同一提示，权限层 64-token 上限使末数字正确率 95% → 35%**——权限层成本的一次客观量化。

文件：`gsm8k-bi150-27b.{json,md}`、`gsm8k-jetson-06b-direct.{json,md}`、`gsm8k-jetson-06b-permlayer.{json,md}`。

## 2. 并发档位扫描（scripts/bench.py --kind llm）

bi150 8960（Qwen3.8-27B，-t 56 CPU 解码），流式，温度 0，/no_think，max_tokens 64，每档 --duration 20：

| 并发 | rps | 延迟 mean/p50/p95 (s) | TTFT mean (s) | 聚合 decode tok/s | 完成/失败 |
|---|---|---|---|---|---|
| 1 | 0.082 | 12.23 / 11.73 / 12.73 | 0.836 | 5.23（server 5.51-5.54/流） | 2/0 |
| 2 | 0.142 | 14.14 / 14.39 / 14.58 | 1.179 | 9.05 | 4/0 |
| 4 | 0.198 | 20.14 / 20.24 / 20.24 | 2.444 | 12.65 | 4/0（第 5 条在窗口截停） |

衰减曲线读数：c1→c4 聚合吞吐 ×2.42（远低于线性 ×4），单流 5.5 → 3.2 tok/s（×0.58），TTFT ×2.9。20 s 窗口内 c1/c2 完成数少（2/4 条）——小样本如实注记，趋势（亚线性扩展 + 延迟抬升）明确。c1 数字与既知 eval 5.21 tok/s 一致。

文件：`conc-bi150-27b.json`。

## 3. 27B 功耗档（scripts/powerbench.py）

sampler（先例口径）：`LD_LIBRARY_PATH=/usr/local/iluvatar/lib64 /usr/local/iluvatar/bin/ixsmi --query-gpu=index,gpu.power.draw,board.power.draw --format=csv,noheader`，间隔 1 s；空闲基线 5 s；预热 1 次不计；2 个计量 run（max_tokens 256，温度 0，/no_think）。

| 指标 | 数值 |
|---|---|
| decode tok/s（server timings） | run1 5.527，run2 5.511，**mean 5.519**（256/256 tokens 全跑满，finish=length） |
| 8 卡 gpu.power.draw 合计 | 空闲 mean/peak 330.6/331.0 W；运行 mean 330.3 W（两 run 相同）；运行期单卡 mean 41.28 W、peak 46.0 W |
| 8 卡 board.power.draw 合计 | 空闲 876.8 W；运行 876.1 W |
| GPU 侧功耗增量 | **≈ 0**（推理在 CPU：`-ngl 0 -t 56`；ixsmi 采到的是近空闲的卡） |

如实注记：任务指定的 sampler 只能看到 GPU/板级功耗；该部署推理在 CPU，GPU 侧数字是"无增量"的客观数据；bi150 主机无 RAPL/tegrastats 等 CPU/插座功耗表可采（Xeon + 天数智芯栈），CPU 侧功耗本档缺采，非忽略。

文件：`power-bi150-27b.json`（bench/1 风格：`summary.decode_tps.mean`、`summary.ttft_ms.mean` 为 router 兼容事实，power 节为附加）。

## 4. Strata spec 对齐尝试（lite）— 未完成，如实记录

目标路径：带 `--dump-routing` 的 generate（--spec 4 --expert-profile /root/strata/profile-default.bin，分片 /root/exp-sideload/shard/）→ trace 喂 `tools/make_profile.py`（按其文档：shipped base 已排满 24576 对，必须 `--reorder` trace 才生效）→ 新 profile 复跑 --spec 4 → 对比 `drafts accepted`（基线 gate3c：**0 of 45**）。

实际：**引擎挂起，无法取得 routing trace**。
- 命令形态与 gate3c 对齐（同 pack/native/PLE 分片、--spec 4、--expert-profile、--gpu 0；首次含 --prefill 与 1024-token 提示，其后 7-token 与 gate3c 同形、--max-new 16、含/不含 --dump-routing 各试过）。
- 每次都打印首行 banner 后停在 `PCIe probe` 之前；进程 2 线程、主线程 hrtimer_nanosleep、RSS ~25 MB（未开始加载 pack）、持全部 8 个 /dev/iluvatar* fd；SIGTERM 无效（timeout 240 到点后进程仍存活，需 SIGKILL）。
- 对照证据（本轮实测）：`bandwidthTest` 单卡 0-7 号全部能初始化（6 号卡初始化拖到分钟级，其余瞬时）；`strata --tokens "1,2,3"`（缺 --ple-gguf）立即 exit=2——参数期正常；内存 981 GB 可用；无其他进程持卡（fuser）；dmesg 有本机历史 XID 22/24/47 与 strata 段错误记录（远早于本轮）。
- 时间线相关性（如实，因果未证）：成功的 gate3（22:14）/gate3c（22:24）都在另一 tenant 的 drude 批处理（8×~100% CPU，`research/spatial1/drude_ball_ledger_batch_driver_v1.py`，23:57:13 启动）之前；其后 10 次尝试全挂。该负载不持 GPU、内存占用小，CPU 总负载 ~10/112 核——挂起机理未定位。
- 红线遵守：未暂停/未杀死他人 drude 作业；所有自起 strata 进程以 SIGKILL 清理；未与其他服务冲突。

结论：`accepted_before`=0/45（gate3c 历史基线）；`accepted_after`=**无数据**（本档未能产生新 run）。提升/未提升的对比未达成，缺口保持开放，复测建议：在 drude 批次结束后的空载窗口重试（命令与全部现场已存 `strata-spec-attempt.log`）。

## 5. 环境与如实注记

1. Jetson 阶段 4 本地栈**未重起**：发现其仍在运行且健康（llama-server pid 4016512 @127.0.0.1:18888，Qwen3-0.6B-Q8_0；bicameral pid 4005600 @18100/18101，--data-dir /tmp/bicameral-jetson，/healthz strata_state=ok），本轮直接复用并健康验证；未重启以免扰动在跑服务。
2. GSM8K 主口径按任务定义取「首个数字」；因两模型均复述题面，首数字口径对 0.6B 恒错（复述里的第一个数字必然≠答案），故并行记录末数字口径——README 两口径并列，返回 JSON 的 `gsm8k.jetson_06b_acc` 按任务主口径如实报 0.0，并在 notes 说明。
3. bi150 为共享租户盒：本轮全部 bi150 测量期间有 8 个 drude CPU 作业在跑（23:57 起）。llama-server t56 的 c1 解码 5.51-5.54 tok/s 与既知 5.21 tok/s 一致，负载影响有限；strata 一节的相关性已如实记录。
4. gold 答案核验：`(5+3)*24=192`、`4*12+15=63`、`8*3/2=12`、`80*75%=60`、`45*1.2=54`、`60*3+80*2=340`、`250-15*12=70`、`3*(8+4)=36`、`4*12+5*7=83`、`90*30%=27`、`8*9-40=32`、`24/3*5=40`、`450*8/100=36`、`3*14=42`、`45*7*4=1260`、`4*9=36`、`50-10-10=30`、`17*6+23*4=194`、`200+200*5%*3=230`、`300*80%=240` —— 脚本复算 20/20 一致。
5. 权限层组 issue 了 agent-ro 能力令牌（预算 calls=40/llm_calls=40），全程未触碰 admin token；bi150 主控（18000/18001）未动。
6. 清理：见 README 末「清理记录」。

## 6. 产物清单

| 文件 | 内容 |
|---|---|
| `gsm8k-bi150-27b.json/.md` | 27B 逐题对错表（20/20） |
| `gsm8k-jetson-06b-direct.json/.md` | 0.6B 直连（未经权限层） |
| `gsm8k-jetson-06b-permlayer.json/.md` | 0.6B 经权限层（64-token 上限） |
| `conc-bi150-27b.json` | c1/c2/c4 并发记录（conc-bench/1） |
| `power-bi150-27b.json` | 带功耗的 bench/1 记录 |
| `strata-spec-attempt.log` | strata 尝试命令、9 次挂起证据、诊断时间线（verbatim 摘录） |
| 脚本 | `scripts/qualitybench.py`、`scripts/bench.py`、`scripts/powerbench.py`（stdlib-only，本轮新建；远端副本在 bi150 /root/perf-depth/，见清理记录） |

## 7. 清理记录

- bi150：全部自起进程已清理（strata 引擎 10 次尝试进程 + 重试循环脚本，均 SIGKILL；`pgrep` 复核无存活）；GPU 显存回落基线（各卡 68 MiB，0% util）；红线服务复核存活（8960 `{"status":"ok"}`、18000/18001 healthz ok、22/8080/8181 监听如常）；临时目录 `/root/perf-depth`（脚本 + 中间产物，已 scp 回本仓）与 `/tmp/strata-spec-exp`（提示 token 文件 + 日志，13 个小文件，无 >1 MB 大文件——routing trace 因挂起从未生成）已删除；`/root/strata/profile-default.bin` 与 `/root/strata/data/expert-profile.bin` 未被改动（196,632 B 原样，make_profile 未执行）。
- Jetson 本机：本轮未新起任何常驻进程（阶段 4 栈为 10-15 起的既有实例，健康复用、未重启）；本地无残留 bench 进程；结果产物仅本目录文件。
