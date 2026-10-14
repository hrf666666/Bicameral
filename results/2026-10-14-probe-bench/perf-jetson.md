# perf-jetson — bench/1 实测记录（2026-10-14）

- **设备**: jetson（Jetson Orin，aarch64，1× 统一内存 iGPU，15.3GiB，JetPack R36.4.3）
- **日期**: 2026-10-14（实测窗口 ≈ 10:37–10:41 UTC）
- **配套 JSON**: `perf-jetson.json`（schema `bench/1`，逐 prompt 明细在该文件）

## 引擎与构建

| 项 | 值 |
|---|---|
| 引擎 | llama-server（llama.cpp） |
| 版本/构建 | **0.4.1-dev (build 11062, commit 3cf03257f)**，`--version` 实测输出 |
| 二进制 | `/home/nvidia/code/strata-jetson/work/llama-build/bin/llama-server` |
| sha256 前 16 | `8ea353d9d67439be`（本次 sha256sum 实测，与 probe 盘点一致） |
| 后端 | CUDA：`libggml-cuda.so.0.24.0`（进程 maps 证实已加载），libcudart.so.12，driver API 12.6（cuDriverGetVersion 实测） |
| 编译器 | GNU 11.4.0 for Linux aarch64 |

## 模型

| 项 | 值 |
|---|---|
| 模型 | **Qwen3-0.6B** GGUF **Q8_0**（`/props` `model_ftype=Q8_0`） |
| 文件 | `work/zoo/gguf/Qwen3-0.6B-Q8_0.gguf`（639,446,688 B） |
| sha256 前 8 | **`9465e63a`**（全串 `9465e63a22add535…bb031`，GGUF magic 校验通过） |
| 来源 | **已在盘**（盘点中的"非 ZOO 文件"，2026-10-12 落盘），本次未重新下载，无换档 |

## 服务与协议

```bash
llama-server -m work/zoo/gguf/Qwen3-0.6B-Q8_0.gguf \
  --host 127.0.0.1 --port 18888 -c 2048 -ngl 99 --parallel 1
```

- **上下文**: 2048（`/props` n_ctx=2048 实测）；**并发**: 1（total_slots=1，请求串行）
- **offload**: `-ngl 99` 全量上 GPU——tegrastats 取证：生成期间 `GR3D_FREQ 89%–96%`（空闲 0%），RAM 5021/15655MB
- **请求**: `POST /completion`（native，`stream=true`），8 条固定短 prompt 逐一请求
- **采样**: `temperature=0`（greedy）、`n_predict=128`（8 条全部打满 128 tok，未触发 EOS）、`cache_prompt=false`（每条都做完整 prefill）
- **warmup**: 计测前 1 次不计入
- **口径**: TTFT = 客户端首内容 chunk 时刻 − 发包时刻（含 HTTP+排队+完整 prefill）；prefill/decode tok/s = 服务端末 chunk `timings`（`prompt_per_second` / `predicted_per_second`）；客户端逐 chunk 解码速率与服务端互证（偏差 <0.1%）

## 固定 8 条 prompt（逐字，供对端复用）

1. `The capital of France is`
2. `Write a haiku about rain.`
3. `Explain what a hash table is in one sentence.`
4. `1, 2, 3, 4,`
5. `Translate 'good morning' into French.`
6. `用一句话介绍冒泡排序。`
7. `List three primary colors.`
8. `Summarize the plot of Romeo and Juliet in two sentences.`

## 结果

### 汇总（8 条均值；括号内为中位/最小/最大）

| 指标 | 均值 | 中位 | min | max |
|---|---|---|---|---|
| TTFT | **29.77 ms** | 26.98 | 25.11 | 50.38 |
| prefill | **399.74 tok/s** | 345.12 | 262.64 | 705.18 |
| decode | **67.48 tok/s** | 67.50 | 67.23 | 67.79 |

### 逐 prompt

| # | prompt（截断） | prompt_n | TTFT ms | prefill tok/s | decode tok/s | 128 tok 用时 ms |
|---|---|---|---|---|---|---|
| 1 | The capital of France is | 5 | 25.11 | 283.93 | 67.56 | 1879.8 |
| 2 | Write a haiku about rain. | 7 | 27.82 | 343.07 | 67.23 | 1889.1 |
| 3 | Explain what a hash table… | 11 | 50.38 | 262.64 | 67.45 | 1883.0 |
| 4 | 1, 2, 3, 4, | 11 | 26.09 | 610.13 | 67.32 | 1886.6 |
| 5 | Translate 'good morning'… | 8 | 29.28 | 368.54 | 67.55 | 1880.2 |
| 6 | 用一句话介绍冒泡排序。 | 7 | 27.88 | 347.17 | 67.58 | 1879.3 |
| 7 | List three primary colors. | 5 | 25.42 | 277.28 | 67.79 | 1873.5 |
| 8 | Summarize the plot of… | 13 | 26.15 | 705.18 | 67.36 | 1885.5 |

## 可比性（comparable = false）

四同核对：

- **同 prompt 集** ❌ **不满足**。bi150 实测员在本目录先行落盘了权威集 `prompts-8.json`（schema `bench-prompts/1`，mtime 18:38——出现在本流水线进行中：服务 ~18:37 起动、warmup 18:38:12、计测 18:39–18:40:37，我在 kill 服务后才首次读到）。该文件自身规则写明：bench 前未发现则"以其自选集为准"，双方全量引用各自 prompt 集**供汇总员判定四同**。两集合仅 `Translate 'good morning' into French.` 一条逐字相同，#1/#7/#8 近似改写，#2/#3/#4/#6 完全不同。
- **同量化** ✅ Q8_0（双方指令统一 Qwen3-0.6B GGUF Q8_0；若 bi150 拉到同一官方工件，sha256 应同为 `9465e63a`）
- **同上下文** ✅ `-c 2048`（`prompts-8.json` genParams.context 亦为 2048）
- **同并发** ✅ 1（串行、单 slot；双方一致）

> 三个维度按协议对齐，但 prompt 集不同 → 按四同规则填 **false**，交由汇总员按双方 perf-*.md 中的全量 prompt 集合议。

## 注意事项

1. **prefill tok/s 噪声大**（262–705）：每条 prompt 仅 5–13 token，服务端短窗计时；引用建议以 decode（±0.6%）与 TTFT 为准。
2. **在盘文件 ≠ csv 受测字节**：该文件与 `results/summary_perf.csv` 记录的 benched size 略有差异（重新拉取副本，盘点 surprises 已注明）；本记录成绩对应 sha256 `9465e63a` 的这份文件。
3. **方法论差异（供汇总员参考）**：bi150 的 `bench8.py` 走 `/v1/chat/completions`（chat 模板，Qwen3 默认带思考段），指标为客户端推导（prefill = prompt_tokens/TTFT、decode = completion_tokens/(总时长−TTFT)）；本记录走 native `/completion`（裸 prompt 无模板），用服务端末 chunk `timings`。即便 prompt 相同，两者数值口径也不同。
4. 服务已按步骤收尾：**pid 3935178 已 kill，端口 18888 释放**。
