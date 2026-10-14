# perf-bi150 — bench/1 实测记录（2026-10-14）

- **设备**: bi150（x86_64，Xeon Gold 6330 ×112 逻辑核，1TiB RAM，k8s pod 容器；8× BI-V150 本轮**未用**）
- **日期**: 2026-10-14（实测窗口 ≈ 10:44–10:46 UTC）
- **配套 JSON**: `perf-bi150.json`（schema `bench/1`，逐 prompt 明细在该文件）；原始流式数据 `bench_raw_bi150.json`

## 引擎与构建

| 项 | 值 |
|---|---|
| 引擎 | llama-server（llama.cpp） |
| 版本/构建 | **0.6.0-dev (build 1, commit 8c2134a)**，`--version` 实测输出 |
| 二进制 | `/root/bicameral-sandbox/llama.cpp/build-cpu/bin/llama-server` |
| sha256 前 16 | `d59eab76dfbb7e8e` |
| 后端 | **CPU（GGML_CUDA=OFF）**——corex CUDA 构建同 commit 失败（攻坚员判定：cooperative_groups/reduce.h 缺失、cudaStreamWaitEvent 签名不匹配、inline asm llc 崩溃；CoreX 4.4.0 为 CUDA 10.2 代，无真 nvcc） |
| 编译器 | GNU 13.3.0 for Linux x86_64 |

## 模型

| 项 | 值 |
|---|---|
| 模型 | **Qwen3-0.6B** GGUF **Q8_0**（`/props` `model_ftype=Q8_0`） |
| 文件 | `/root/bicameral-sandbox/models/Qwen3-0.6B-Q8_0.gguf`（639,446,688 B） |
| sha256 前 8 | **`9465e63a`**（全串 `9465e63a22add535…bb031`，GGUF magic 校验通过） |
| 来源 | **本次经 hf-mirror 下载**（bi150 上 huggingface.co 不通，hf 直连未成走镜像）；与 jetson 侧在盘文件**逐字节一致**（同 sha256 同尺寸）——无换档 |

## 服务与协议（与 perf-jetson 完全一致）

```bash
llama-server -m /root/bicameral-sandbox/models/Qwen3-0.6B-Q8_0.gguf \
  --host 127.0.0.1 --port 29600 -c 2048 --parallel 1 -t 32
```

- **上下文**: 2048（server log `n_slots = 1, n_ctx_slot = 2048`）；**并发**: 1（total_slots=1，请求串行）
- **offload**: 无（CPU 构建，`n_gpu_layers=0`）；线程数 32——线程扫描 t=8/16/32/48/64 → decode
  64.8 / 91.4 / **105.1** / 94.8 / 96.8 tok/s，取峰值 32（更小欠并行、更大跨 socket 回落）
- **请求**: `POST /completion`（native，`stream=true`），8 条固定短 prompt 逐一请求
- **采样**: `temperature=0`（greedy）、`n_predict=128`（8 条全部打满 128 tok，未触发 EOS）、
  `cache_prompt=false`（每条都做完整 prefill）
- **warmup**: 计测前 1 次不计入
- **口径**: 与 jetson 侧同一定义——TTFT = 客户端首内容 chunk 时刻 − 发包时刻；
  prefill/decode tok/s = 服务端末 chunk `timings`（`prompt_per_second` / `predicted_per_second`）；
  客户端逐 chunk 速率与服务端互证（偏差 ≈1%，jetson 侧 <0.1%）

## 固定 8 条 prompt（逐字复用 perf-jetson `protocol.prompts`）

1. `The capital of France is`
2. `Write a haiku about rain.`
3. `Explain what a hash table is in one sentence.`
4. `1, 2, 3, 4,`
5. `Translate 'good morning' into French.`
6. `用一句话介绍冒泡排序。`
7. `List three primary colors.`
8. `Summarize the plot of Romeo and Juliet in two sentences.`

## 结果

### 汇总（8 条均值；括号内为中位/最小/最大）——对照 perf-jetson

| 指标 | bi150 (CPU, t=32) | jetson (CUDA, 全 offload) | bi150/jetson |
|---|---|---|---|
| TTFT | **23.57 ms**（中位 24.31 / 16.05 / 26.86） | 29.77 ms | ≈0.79× |
| prefill | **538.68 tok/s**（中位 514.22 / 373.52 / 730.05） | 399.74 tok/s | ≈1.35× |
| decode | **100.55 tok/s**（中位 100.78 / 99.31 / 101.05） | 67.48 tok/s | ≈1.49× |

### 逐 prompt

| # | prompt（截断） | prompt_n | TTFT ms | prefill tok/s | decode tok/s | 128 tok 用时 ms |
|---|---|---|---|---|---|---|
| 1 | The capital of France is | 5 | 16.05 | 373.52 | 99.31 | 1278.9 |
| 2 | Write a haiku about rain. | 7 | 23.48 | 483.93 | 100.97 | 1257.8 |
| 3 | Explain what a hash table… | 11 | 25.58 | 671.63 | 100.42 | 1264.7 |
| 4 | 1, 2, 3, 4, | 11 | 26.54 | 637.76 | 100.68 | 1261.4 |
| 5 | Translate 'good morning'… | 8 | 25.14 | 507.84 | 100.88 | 1259.0 |
| 6 | 用一句话介绍冒泡排序。 | 7 | 22.75 | 520.60 | 100.89 | 1258.8 |
| 7 | List three primary colors. | 5 | 22.17 | 384.08 | 101.05 | 1256.8 |
| 8 | Summarize the plot of… | 13 | 26.86 | 730.05 | 100.17 | 1267.9 |

prompt_n 5/7/11/11/8/7/5/13 与 jetson 侧**逐条一致**（同分词路径、双方均走 native /completion 无 chat template）。

## 可比性（comparable = true）

四同核对：

- **同 prompt 集** ✅ 8 条逐字复用 `perf-jetson.json protocol.prompts`（其 md 注明"供对端复用"）；逐条 prompt_n 相同
- **同量化** ✅ Q8_0，模型文件逐字节一致（sha256 `9465e63a…`，639,446,688 B 双方相同）
- **同上下文** ✅ 2048（双方 `-c 2048`，服务端字段互证）
- **同并发** ✅ 1（串行、单 slot）
- **四同之外的事实差异**（是被测对象本身，不属四同）：llama.cpp 构建不同（jetson b11062-3cf03257f vs
  bi150 master 8c2134a）；后端不同（CUDA vs CPU）；线程数各自本地最优（8 vs 32）

## 注意事项

1. **引擎是 CPU 兜底构建**：攻坚员结论 corex CUDA 构建 failed（结构性缺口），故本记录反映
   bi150 在"不碰在跑服务、不改 SDK"约束下的可用推理路径——纯 CPU llama.cpp。
2. **线程扫描留档**：t=8/16/32/48/64 → 64.8/91.4/105.1/94.8/96.8 tok/s（单 probe prompt ×2，96 tok）；
   正式记录取 t=32。
3. **客户端 decode ≈ 服务端 +1.5%**（101.5 vs 100.55，chunk 边界效应）；记录采用服务端 timings，
   与 jetson 侧同口径。
4. **红线遵守**：仅绑定 127.0.0.1:29600（已释放）；8080/8181/8960-8963/18000/18001 复核均在监听且
   未触碰（注意 8963 **本次已在监听**，盘点时刻它缺席）；全部产物限于 `/root/bicameral-sandbox/`。
5. 服务已按步骤收尾：**llama-server 已 kill，端口 29600 释放**。
