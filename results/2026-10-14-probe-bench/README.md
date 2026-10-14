# 2026-10-14 双机 probe/bench 实证归档（范式阶段 1–2）

> 汇总员归档，2026-10-14。覆盖范式（`/home/nvidia/code/Bicameral/docs/paradigm.md`）阶段 1（probe/1 DeviceReport）与阶段 2（bench/1 PerfRecord）的双机实证。
> 产物分两仓：本目录（strata-jetson）持有 device-bi150、双机 perf 记录、prompt 契约与原始流数据；Bicameral 仓持有 device-jetson。
> 判定只依据「读了什么、跑了什么」：文件引用标注路径，本会话复跑的校验标注 ✅（命令见各节末）。

## 0. 产物清单

| 文件 | 位置 | 内容 |
|---|---|---|
| `device-jetson.json` / `.md` | `/home/nvidia/code/Bicameral/results/2026-10-14-probe-bench/` | jetson probe/1 报告（09:44:46Z 复核版 + review-supplement 节） |
| `device-bi150.json` / `.md` | 本目录 | bi150 probe/1 报告（09:41:25Z）+ 人读版 |
| `perf-jetson.json` / `.md` | 本目录 | jetson bench/1（10:40:37Z，llama.cpp CUDA） |
| `perf-bi150.json` / `.md` | 本目录 | bi150 bench/1（10:45:56Z，llama.cpp CPU） |
| `prompts-8.json` | 本目录 | bench-prompts/1 固定 8 条 prompt 契约（canon = perf-jetson protocol.prompts） |
| `bench8.py`、`bench_raw_bi150.json` | 本目录 | bi150 测量脚本（stdlib）与逐 chunk 原始数据（bench8-raw/1） |

## 1. 双机 DeviceReport 要点表

两份报告同为 `schema: "probe/1"`，探针同一文件（sha256_16 `eb10063293b418a4`，与 `sha256sum bicameral/probe.py` 一致 ✅），设备指纹不同（machine-id 不同）。

| 项 | jetson（Orin NX 16GB） | bi150（k8s pod 容器） |
|---|---|---|
| 指纹 | `5dbfb12414a3456d9014d88183e338b1-eb10063293b418a4` | `19978ab8db7445409398d3073395b467-eb10063293b418a4` |
| 主机 | nvidia-desktop · aarch64 · 8 核 · 15.3GiB | Xeon Gold 6330 ×112 核 · 1007.5GiB · `is_container=true`（containerd/kubepods） |
| 加速器 | 1× Orin nvgpu 统一内存 iGPU（driver 540.4.0，cc 8.7/sm_87；lspci 仅见 SoC PCIe 桥 10de:229e/229c，iGPU 身份由 /dev + nvidia-smi 证实） | 8× Iluvatar BI-V150 32GiB（`/dev/iluvatar0-7`；lspci 厂商表零命中——容器内不可见；ixsmi 经 corex 根搜索 + LD 注入后 run ok） |
| 统一内存 | `true`（tegra release + smi `[N/A]` + tegrastats RAM 样本三重佐证） | `null`（非统一内存） |
| 运行时 | CUDA 12.6（nvcc 12.6.68 真实可用） | CUDA 10.2.89（**nvcc 不存在**；CoreX 4.4.0，probe 误报 absent——漏搜 `release-corex.txt`） |
| Python | 3.11.14（miniconda）· venv ✓ · ensurepip ✓ | 3.12.3 · venv 可导入 · **ensurepip 不可导入**（venv 装包需预案） |
| 出网 | pypi up(206) · hf-mirror up(206) · **hf down** · **github https down** · ssh.github.com:443 up(73ms) | pypi up(206) · hf-mirror up(206) · **hf down** · **github https down** · ssh.github.com:443 up(89ms) —— 两机出网形态同构 |
| 引擎（安装语义） | llama-server/vllm/strata 全 absent（PATH+17 安装根目录） | 同全 absent（9 目录）；且本容器 /proc 只见 `[llama-server] <defunct>` |
| 引擎（在盘/在线事实） | **supplement 节**：llama.cpp CUDA 构建 0.4.1-dev (b11062, 3cf03257f) sha256_16 `8ea353d9d67439be` @ `work/llama-build/bin/`；strata 0.1.43 ×3（`1d12ee90…`、`141a9e85…` ×2，engine-cuda12 与 build-cuda12 **逐字节相同**＝部署副本） | 8960/8961/8962 三个 llama-server `/health`=200 且 `/v1/models`=200，服务 `/private/models/Qwen3.8-27B-UD-Q4_K_M.gguf`（raw curl 取回 `data[].id`）——实际跑在**同 pod 兄弟容器**（共享 netns、隔离 PID/fs）；8963 盘点时刻未监听（bench 时刻已在监听，服务集是动态的） |
| 模型（在盘） | 8 个 .gguf / 7.7GiB @ `work/zoo/gguf`（GGUF magic 全有效）；「20 模型」= run_zoo.py ZOO 19 条 + strata Q2_0，在盘仅 7 个 ZOO 文件 + 1 个非 ZOO（Qwen3-0.6B-Q8_0），其余 12 条目成绩留档、权重不在盘；在盘 ZOO 字节与 `summary_perf.csv` benched size 全部略大——**重新拉取副本，非当时受测字节** | 0 个（约定目录皆空；模型在兄弟容器 `/private/models`） |
| 监听服务 | 7 端口（22/53/111/631/18000/18001/34063）逐一交叉 GET /health+/v1/models，无推理服务（18000/18001 是 Bicameral server.py，两路径 404） | 8 端口：8960-8962 推理服务；8080/8181/18000/18001 HTTP 存活但 404（红线内未深挖） |
| jetson 复核性 | 09:37 与 09:44 两次独立运行除时延/时间戳外零结构差异；探针指纹前后一致 | 远端 probe.py 与本地 sha256 一致；执行方式与红线遵守记录在 device-bi150.md |

### 探针观察（回传 probe.py 作者的缺陷单，探针 sha256 不变前提下待修）

1. `/v1/models` 返回 200 时 `model_ids` 解析为空——`http_get_local` 把 body 截到 300 字符（probe.py:709-710），8960-8962 的 ollama 风格信封 `data[]` 落在截断之后，`json.loads` 失败。建议放宽截断或先按 4096B 原文解析。
2. `gpu_query_csv=null`——ixsmi 拒绝 `--query-gpu` 的 `compute_cap` 字段（`Field "compute_cap" is not a valid field to query`），probe.py:330 判 invalid 丢弃整行。建议失败后回退 `name,driver_version,memory.total` 子集。
3. corex 版本探测漏 `/usr/local/corex/release-corex.txt`（实测写着 CoreX SDK 4.4.0），现只搜 `corex*/version*` 故报 absent。
4. k8s 兄弟容器部署形态：检测到 defunct 同名进程 + 服务在线时，报告宜提示「疑似兄弟容器部署」。
5. paradigm §1 文档勘误（非探针问题）：`/usr/local/iluvatar/lib` 是空目录，libixml.so 在 `lib64`（受控实验 A–E 见 device-bi150.md「ixsmi 怪癖实测」节）。

## 2. CoreX 攻坚过程与结论（「bi150 能否跑 llama.cpp」的回答）

**结论：failed（CUDA 路径）/ ready（CPU 兜底）。** llama.cpp master `8c2134a8755d8a9…`（2026-10-14 clone via ghproxy.net；ghfast.top 连接超时 130s 已死）的 GGML_CUDA 后端在 CoreX 4.4.0 上**不可编译**；同 commit CPU 构建 ~120s 至 100% 无错误，`llama-server --version` = `0.6.0-dev (build 1, commit 8c2134a)`。攻坚产物全部限于 `/root/bicameral-sandbox/`，未启动常驻服务、未下载模型、未触碰在跑端口。

### 事实链（攻坚员实测，产物在 bi150 沙箱）

1. **工具链盘点**：ssh -p 31451 root@10.70.251.39 → gcc/g++ 13.3.0、cmake 3.31.8+corex.4.4.0、git 2.43.0；`/usr/local/corex -> corex-4.4.0/` 软链。
2. **nvcc 是桩**：`/usr/local/corex-4.4.0/bin/nvcc --version` 输出 `V10.2.89` 横幅 rc=0 但**不产出任何二进制**；cat 证实是仅打印横幅的 bash 桩脚本——CoreX 4.4.0 无真 nvcc。真设备编译器是 Iluvatar 定制 **clang-18**（`-x ivcore --cuda-gpu-arch=ivcore11`）。
3. **设备身份**：gcc + `libcudart`（仅 corex/lib64）→ `err=35`（driver insufficient）；`LD_LIBRARY_PATH=/usr/local/iluvatar/lib64:/usr/local/corex/lib64`（真 libcuda.so.1 16.6MB 在 iluvatar/lib64）→ deviceCount=8，8× BI-V150 **cc=7.1**、warp=64、SMs=16、32GiB。
4. **ivcore 工具链端到端验证**：`clang++ -x ivcore --cuda-gpu-arch=ivcore11 --cuda-path=/usr/local/corex hello2.cu` → 运行 cudaMalloc e=0、kernel launchErr=0、memcpy val=42 ✅；`ivcore20` → `err=98 (invalid device function)`——**ivcore11 才是 BI-V150 真身**；`sm_71` 被拒，合法架构 ivcore10/11/20（cmake 补丁 run_nvcc.cmake:232）。模板探针：设备编译期 `__CUDA_ARCH__=300`（ivcore11/20 相同），与运行时 cc 7.1 不符。
5. **Round 1**：`CMAKE_CUDA_COMPILER_ID=ILUVATAR cmake -B build-corex -DGGML_CUDA=ON -DCMAKE_CUDA_COMPILER=/usr/local/corex/bin/clang++ -DCMAKE_CUDA_ARCHITECTURES=ivcore11 -DCUDAToolkit_ROOT=/usr/local/corex` 配置通过（CUDA 编译器 id Clang 18.1.8，Toolkit 10.2.89，无版本闸门）；`cmake --build -j112` 失败：
   ```
   clang++: error: unknown argument: '-extended-lambda'
   ```
   （ggml/src/ggml-cuda/CMakeLists.txt:196 `set(CUDA_FLAGS -use_fast_math -extended-lambda)`，nvcc-only flags）
6. **Round 2**：补丁 :196 按 `CMAKE_CUDA_COMPILER_ID` 收窄（非 NVIDIA 时置空）→ 重建失败：
   ```
   common.cuh:592: 'no template named is_same_v in namespace std'
   ```
   （其工具链设备 pass 默认 C++14；手动对照实验证实 `-std=c++17` 可修）
7. **Round 3**：else 分支改 `set(CUDA_FLAGS -std=c++17)` → 撞上**结构性缺口**（flag 级已尽）：
   ```
   softmax.cu:9: fatal error: 'cooperative_groups/reduce.h' file not found   （cg::reduce 是 CUDA 11.0 API）
   allreduce.cu:393/634/668/676/689: no matching function for call to 'cudaStreamWaitEvent'
   <inline asm>:1:2: error: invalid instruction → llc command failed
   ```
   3 轮预算用尽，如实判 failed。补丁保留在 `/root/bicameral-sandbox/llama.cpp/ggml/src/ggml-cuda/CMakeLists.txt`。
8. **CPU 兜底**：`cmake -B build-cpu && cmake --build build-cpu -j112` → 约 120s `[100%]` 无错误；`llama-cli`/`llama-server` `--version` 均 rc=0。

### 补充判定依据（数值风险）

即使绕过编译缺口，CUDA 路径仍有静默错误风险：设备编译期 `__CUDA_ARCH__=300`（Kepler 代）而运行时 cc=7.1——ggml 内核 `#if __CUDA_ARCH__>=530` 的 half2/fp16 向量路径会被整体裁掉，运行时却按 cc 710 认为 fp16 可用。这是判 failed 的补充依据。e8m0 隐患已排除（common.cuh:831 有 `#if CUDART_VERSION >= 12080` 守卫，10.2.89 走可移植 fallback）。

### 复用配方（供后续老 tag 重试）

① `export CMAKE_CUDA_COMPILER_ID=ILUVATAR`（定制 cmake 的 CMakeDetermineCUDACompiler.cmake:5/38/130 据此启用 ivcore 路径，默认架构 ivcore11）② `-DCMAKE_CUDA_COMPILER=/usr/local/corex/bin/clang++ -DCMAKE_CUDA_ARCHITECTURES=ivcore11 -DCUDAToolkit_ROOT=/usr/local/corex` ③ 非 NVIDIA 编译器时 `CUDA_FLAGS=-std=c++17`（:196 补丁）④ 运行需 `LD_LIBRARY_PATH=/usr/local/iluvatar/lib64:/usr/local/corex/lib64`（**次序重要**，仅 corex/lib64 时 libcudart err=35）⑤ 选卡：ixsmi 实测 3/4/6/7 被兄弟容器占满（各 ~30.1GiB/32GiB），0/1/2/5 空闲；dev5 cudaMalloc 全程正常、dev1 挂起 30s 超时——建议 `CUDA_VISIBLE_DEVICES=5` 先小上下文试探。

## 3. 双机 PerfRecord 对照（bench/1，同档四同）

同档 = Qwen3-0.6B **Q8_0**（sha256 `9465e63a22add535…bb031`，639,446,688 B）/ 上下文 2048 / 并发 1 / native `POST /completion stream=true`、n_predict=128、temperature=0、cache_prompt=false、1 次 warmup。

| 指标（8 条均值） | jetson · llama.cpp 0.4.1-dev b11062 **CUDA**（-ngl 99，tegrastats GR3D 89–96% 取证；t=8） | bi150 · llama.cpp 0.6.0-dev 8c2134a **CPU**（GGML_CUDA=OFF；t=32，线程扫描 8/16/32/48/64→64.8/91.4/**105.1**/94.8/96.8 取峰） | bi150/jetson |
|---|---|---|---|
| TTFT | 29.77 ms（中位 26.98，25.11–50.38） | **23.57 ms**（中位 24.31，16.05–26.86） | ≈0.79× |
| prefill | 399.74 tok/s（中位 345.12，262.64–705.18） | **538.68 tok/s**（中位 514.22，373.52–730.05） | ≈1.35× |
| decode | 67.48 tok/s（±0.6%，67.23–67.79） | **100.55 tok/s**（±0.9%，99.31–101.05） | **≈1.49×** |

四同核对（汇总员程序化复验 ✅，命令见节末）：prompt 8 条三方逐字一致（perf-jetson ≡ perf-bi150 ≡ prompts-8.json）且逐条 prompt_n 相同（5/7/11/11/8/7/5/13）；模型 sha256 全串相等且 jetson 在盘文件 ✅ 实测同串同尺寸（bi150 侧文件本机不可达，依记录自述经 hf-mirror 下载与 jetson 逐字节一致）；n_ctx 2048 双方服务端字段互证；并发 1 单 slot（total_slots=1）。协议参数（endpoint/n_predict/temperature/cache_prompt/warmup）亦逐项相等。

记录口径：TTFT = 客户端首内容 chunk − 发包；prefill/decode = 服务端末 chunk `timings`；双方客户端互证偏差 <0.1%（jetson）/ ≈1%（bi150）。8 条均打满 128 tok 无 EOS。

**判定 comparable = true（汇总员裁定）**，两处记录内标注说明如下：

- perf-jetson.json 自带 `comparable: false`，原因是落笔时 bi150 的 prompts-8.json 处于流水线中途、内容与最终版不同。**最终在盘 prompts-8.json（canon 自述「以先完成的 perf-jetson 记录为准，bi150 侧逐字复用」）与两份 perf 记录的 prompt 集逐字一致**（✅ 程序化比对），该疑义已消解。
- perf-jetson.json notes 里「bi150 的 bench8.py 走 /v1/chat/completions（chat 模板+客户端推导指标）」针对的是 bench8.py 的**早期版本**；归档版 bench8.py:24-25 实为 native `/completion` + 服务端 timings（bench_raw_bi150.json meta `endpoint` 字段同证），且 prompt_n 与 jetson 逐条一致（chat 模板下不可能）——口径差异不存在。
- 四同之外的事实差异（是被测对象本身，不属四同）：llama.cpp 构建不同（b11062 vs 8c2134a）、后端不同（CUDA vs CPU）、线程数各自本地最优（8 vs 32）。
- prefill 离散大（双方 260–730）系每条仅 5–13 token 短窗计时；引用建议以 decode 与 TTFT 为准。
- 结论性事实：0.6B Q8_0 档位上，bi150 **纯 CPU**（Xeon 6330×112 核）decode 反超 jetson Orin iGPU 全 offload ≈1.49×——「同模型换架构/后端就是换了一个性能体」的直接实证（paradigm §7.3）。

复验命令（本会话执行）：`sha256sum /home/nvidia/code/Bicameral/bicameral/probe.py`（→ `eb10063293b418a4…`）；`sha256sum work/zoo/gguf/Qwen3-0.6B-Q8_0.gguf`（→ `9465e63a22add535…`，639446688 B）；python 比对两份 perf JSON 的 prompts/sha256/size/n_ctx/concurrency/协议参数（全部 True，比值 TTFT 0.792 / prefill 1.348 / decode 1.490）。

## 4. 对 docs/paradigm.md [待测] 项的逐条改判

（paradigm.md 实际位于 `/home/nvidia/code/Bicameral/docs/paradigm.md`；以下按其节号。本表为归档，正文改动同步落入该文件。）

| # | 原条目（位置） | 原状态 | 改判 | 依据 |
|---|---|---|---|---|
| 1 | §3.2：`x86_64+corex → 待测（CUDA 10.2 兼容层能否跑 llama.cpp 是头号问题）` | [待测] | **被否（CUDA）/ 事实（CPU）**：master 8c2134a8 的 CUDA 后端在 CoreX 4.4.0 编译失败，结构性缺口非 flag 级；同 commit CPU 构建可用并已出实测成绩 | §2 事实链 Round1–3 报错原文；perf-bi150.json engine.backend |
| 2 | §7.1：`bi150 的 corex 能否跑 llama.cpp 是阶段 1 的头号 [待测]` | [待测] | 同上改判，并留复用配方与 `__CUDA_ARCH__=300` 数值风险注记 | 同上 |
| 3 | §1 表「厂商工具怪癖」bi150 格：`ixsmi 不在 PATH，需 LD_LIBRARY_PATH=/usr/local/corex/lib:…`（含 `/usr/local/iluvatar/lib`） | [事实]（记载有误） | **勘误为事实**：ixsmi 实际在 `/usr/local/corex/bin/ixsmi`；无 LD 时 exit 127 缺 libixml.so；注入 `/usr/local/corex/lib`（→lib64 符号链）即 exit 0；**`/usr/local/iluvatar/lib` 是空目录**，libixml.so 在两处 lib64（md5 相同） | device-bi150.md 受控实验 A–E（LD_LIBRARY_PATH 五组对照） |
| 4 | §1 表「推理栈」bi150 格：`4× llama-server（:8960-8963，Qwen3 27B GGUF，-c 32768 -np 64）` | [事实]（口径粗糙） | **改判为 2026-10-14 探针事实**：盘点时刻 8960/8961/8962 三实例在监听（/health+/v1/models 双 200），8963 未监听（bench 时刻又在监听）；模型 id 实测 `/private/models/Qwen3.8-27B-UD-Q4_K_M.gguf`；`-c 32768 -np 64` 参数探针未取证，**不作为事实引用**；服务跑在同 pod 兄弟容器（本容器 /proc 只见 defunct，引擎二进制 absent 与服务在线并存） | device-bi150.json installed.services；device-bi150.md；bi150 bench notes（8963 复核） |
| 5 | §1 表「网络」：hf-mirror / SSH-over-443 选路（jetson 侧既有事实） | [事实]（单机） | **升级为双机事实**：两机探针独立给出同构出网形态（pypi/hf-mirror/ssh-443 up，hf/github down），且 bench 实际经 hf-mirror 拉取模型成功（bi150 侧）——「出网路径不可假设统一」之外，镜像+ssh-443 是两台设备的公共可用路径 | 两份 DeviceReport stack.egress；perf-bi150.json model.provenance |
| 6 | §1 表「已验证」jetson 格：「20 模型性能/质量对照方法论」 | [事实] | **口径精确化**：20 行 = run_zoo.py ZOO 19 开源模型 + strata Q2_0；在盘仅 8 gguf（7 ZOO + 1 非 ZOO），12 条目成绩留档权重不在盘；在盘 ZOO 字节与 summary_perf.csv benched size 全部略大——引用 bench 成绩不得默认等同在盘文件 | device-jetson.json supplement.model_zoo（caveat） |
| 7 | §3.2：`aarch64+sm_87 → llama.cpp CUDA` | [推断→事实] | 在盘构建 0.4.1-dev b11062 CUDA（sha256_16 8ea353d9d67439be）端到端跑通 bench（-ngl 99，GPU offload tegrastats 取证） | perf-jetson.json engine/server.gpu_offload_evidence |

## 5. 验收门判定（§6）

- **阶段 1（probe/1）——达成（2026-10-14）**。两机各产出一份指纹化 DeviceReport（schema probe/1，探针指纹一致可外部校验）；两份报告互相解释了对方的部署选项：bi150 报告解释了其 bench 为何走「容器内 CPU 自建 + hf-mirror 拉模 + 沙箱隔离」（引擎 absent、CoreX 10.2 代无 nvcc、ensurepip 坏、hf/github 断），jetson 报告（supplement 节）解释了其 bench 为何用「在盘 CUDA 构建 + 在盘模型免下载」（安装语义 absent 与在盘构建并存、egress 不对称、模型指纹可引）。「bi150 能否跑 llama.cpp」由报告事实 + 攻坚实测回答（failed CUDA / ready CPU），不由人断言。已注明局限：探针引擎扫描仅覆盖 PATH+安装根（无 --engine-dirs 扩展点），在盘构建以 supplement 节人取证据记录，两口径分列；探针缺陷三则已开单（§1 末）。
- **阶段 2（bench/1）——达成（2026-10-14）**。同一模型档（Qwen3-0.6B Q8_0）在两机产出可比 PerfRecord，四同由本会话程序化复验成立（§3）；perf-jetson 的 comparable=false 保留在记录中作为过程痕迹，最终裁定以归档证据为准 = 可比。未决事项：bi150 侧模型字节本机不可达，字节一致性依双记录 sha256 相等 + bi150 记录自述（hf-mirror 官方工件），jetson 侧已实测。
- 阶段 3–5 未动。

## 6. 应记入范式的新事实（摘要）

1. CoreX 4.4.0 = CUDA 10.2 代：无真 nvcc（bash 桩）；真编译器 Iluvatar clang-18（ivcore11＝BI-V150 真身，ivcore20→err=98）；设备编译期 `__CUDA_ARCH__=300` 与运行时 cc 7.1 不符 → 绕过编译缺口仍有 fp16 内核被裁的静默数值风险。
2. llama.cpp master CUDA 后端在 CoreX 4.4.0 编译失败三处结构性缺口（cooperative_groups/reduce.h 缺失、cudaStreamWaitEvent 无匹配签名 ×5、inline asm llc 崩溃）；flag 级两处可修（-extended-lambda/-use_fast_math、设备 pass 需 -std=c++17）；CPU 构建同 commit ~120s 成功。
3. bi150 运行时 LD 事实：真 libcuda.so.1 在 `/usr/local/iluvatar/lib64`，运行需 `LD_LIBRARY_PATH=/usr/local/iluvatar/lib64:/usr/local/corex/lib64`（次序重要）；`/usr/local/iluvatar/lib` 为空（paradigm §1 旧记载有误）。
4. bi150 = k8s pod 双容器形态：本容器引擎二进制 absent、/proc 只有 defunct，8960-8962 llama-server 在同 pod 兄弟容器（共享 netns）存活且服务同一 `Qwen3.8-27B-UD-Q4_K_M.gguf`；8963 服务集随时间变化（盘点缺席、bench 时在监听）。
5. BI-V150 实测：8× 32GiB、cc=7.1、warp=64、SMs=16；ixsmi 拒绝 --query-gpu compute_cap 字段；GPU 3/4/6/7 被占满、0/1/2/5 空闲；dev1 cudaMalloc 挂起、dev5 正常。
6. probe.py 缺陷三则（body 截断 300 致 model_ids 空、gpu_query_csv 整行丢弃、corex 版本漏 release-corex.txt）+ Ubuntu 24.04 python3.12 ensurepip 不可导入（venv 装包需预案）。
7. jetson「20 模型」精确口径与「在盘字节 ≠ 受测字节」告诫；jetson 在盘引擎指纹（llama.cpp 8ea353d9d67439be、strata 0.1.43 ×3，engine-cuda12≡build-cuda12）。
8. 双机出网同构（pypi/hf-mirror/ssh-443 up，hf/github down）且实测走通（bi150 经 hf-mirror 拉到与 jetson 逐字节一致的官方工件）；ghfast.top 死、ghproxy.net 可用。
9. 双机性能事实：Qwen3-0.6B Q8_0/c2048/并发 1 下 bi150 CPU decode 100.55 tok/s ≈ 1.49× jetson Orin iGPU CUDA 67.48；TTFT 23.57 vs 29.77 ms——小模型档 CPU 反超高分体 iGPU，路由不能按「有 GPU = 更快」假设。
