# DeviceReport · device-jetson（probe/1）

> 由 `bicameral/probe.py` 在本机（Jetson Orin NX）生成，协议 `schema: "probe/1"`（docs/paradigm.md §3.1）。
> 原始 JSON：`results/2026-10-14-probe-bench/device-jetson.json`。探针只读、无 root、stdlib 单文件；
> 工具缺失一律记 `absent`（事实，不算错）。
> 本版为**完整性复核版**（2026-10-14 复跑 + 补齐）：模型清单经探针 `--model-dirs` 纳入在盘 zoo；
> 引擎构建的版本/指纹由复核命令取证后写入 JSON `supplement` 节（探针自身按安装语义仍记 `absent`，两节并存、口径分开）。

## 要点表

| 项 | 值 |
|---|---|
| schema / 生成时间 | `probe/1` · 2026-10-14T09:44:46Z（复核版；前版 09:37:17Z 结构相同，仅时延/时间戳差异） |
| 设备指纹 | machine-id `5dbfb12414a3456d9014d88183e338b1` + 探针自身 sha256_16 `eb10063293b418a4`（与 `sha256sum bicameral/probe.py` 外部校验一致，防版本漂移；两次复核运行间探针未变） |
| 主机 | nvidia-desktop · aarch64 · 8 核（ARMv8 rev 1）· 15.3 GiB 内存 |
| 平台 | jetson（`/etc/nv_tegra_release`: R36, REVISION 4.3）· **统一内存 = true**（tegra iGPU 共享系统 DRAM + nvidia-smi `memory.total=[N/A]` + tegrastats 样本 `RAM 4873/15655MB` 三重佐证） |
| 加速器（固定顺序枚举） | ① /dev：`nvidia0`/`nvidiactl`/`nvidia-modeset` + `dri/card0,card1,renderD128,renderD129` ② lspci：`10de:229e/229c`（均为 Orin SoC PCIe 桥——iGPU 不出现在 PCI 枚举，身份由 /dev+smi 证实）③ 工具：`nvidia-smi` 540.4.0，GPU = **Orin (nvgpu)，cc 8.7（sm_87）** |
| 厂商管理工具 | nvidia-smi ✓ · **tegrastats ✓**（`/usr/bin/tegrastats`，流式，采 5s 样本：`RAM 4873/15655MB`）· jetson_clocks ✓（需 root）· ixsmi / npu-smi / rocm-smi / hy-smi / musa-smi / mthreads-gmi = **absent** |
| OS / 内核 | Ubuntu 22.04.5 LTS · 5.15.148-tegra · 非容器（无 dockerenv/cgroup 标记/k8s env） |
| 运行时 | CUDA **12.6**（nvcc 12.6.68，`/usr/local/cuda/bin`）· ROCm / CANN / corex = absent |
| Python / venv | 3.11.14（miniconda3）· venv ✓ · ensurepip ✓ |
| 出网（§3.1 stack） | pypi **up**(206, 446ms) · hf-mirror **up**(206, 441ms) · huggingface.co **down**（Network unreachable）· github.com https **down**（timeout, 5214ms）· ssh.github.com:443 **up**(73ms) —— 与 paradigm §1 Jetson 既有事实（hf 走镜像、GitHub 走 SSH-over-443）完全吻合；两次复核运行结论一致 |
| 推理引擎（installed，安装语义） | llama-server / vllm / strata：**全部 absent**（搜索范围 = PATH + /usr/local/{bin,sbin} + ~/.local/bin + ~/bin + /snap/bin + /opt/*/bin，共 17 个目录；vllm 另查 python 包元数据） |
| 推理引擎（supplement，在盘构建） | **llama.cpp CUDA 构建**：`work/llama-build/bin/llama-server` = `0.4.1-dev (build 11062, commit 3cf03257f)`，aarch64 CUDA（libggml-cuda.so.0.24.0），sha256_16 `8ea353d9d67439be`（llama-cli `9e1615490d71f207`）· **strata 0.1.43** ×3：`work/Strata/build/strata` `1d12ee90ad4e5ef1`、`build-cuda12/strata` `141a9e851c5a0642`、`engine-cuda12/strata` `141a9e851c5a0642`（与 build-cuda12 **逐字节相同**，同一构建的部署副本） |
| 模型清单（installed.models） | **在盘 8 个 .gguf / 7.7GiB**，目录 `/home/nvidia/code/strata-jetson/work/zoo/gguf`（经 `--model-dirs` 纳入），GGUF magic 全部有效；文件名可辨量化仅 Qwen3-0.6B-Q8_0，其余不带量化后缀（run_zoo.py 约定 `{name}.gguf` 目标为 Q4_K_M，探针按名判读记 null 属预期） |
| 模型动物园口径 | 基准目录 = `scripts/run_zoo.py` ZOO 表 **19 个开源模型**（`results/summary_perf.csv` 19 行成绩）+ strata Q2_0 = README §3.3「20 模型对照」的 20 行；在盘 8 个文件中 **7 个属 ZOO 目录**（qwen35×3、openelm×4），1 个非 ZOO 条目（Qwen3-0.6B-Q8_0）；其余 12 个 ZOO 条目权重已按 fetch→bench→清理流程删除、成绩留档，复跑用 `run_zoo.py fetch <name>`（modelscope 优先 / hf-mirror 兜底）。**注意**：在盘 7 个 ZOO 文件与 CSV 记录的 benched size 全部略有不符（在盘稍大，系重新拉取/转换的副本，非当时受测字节），引用 bench 成绩不得默认等同在盘文件 |
| 监听服务 | 7 个端口：22(ssh)、53(dns)、111(rpc)、631(cups)、**18000/18001**、34063。逐端口交叉 `GET /health` + `GET /v1/models`：**无推理服务**（18000/18001 是 Bicameral 权限层 server.py，两路径均 404；22 返回 SSH banner） |
| install_state | `[]` —— standalone 运行无主控下发的 appspec/1。`--appspec` 求值路径已实现（absent/partial/ready/degraded 四态）；伪造 spec 冒烟验证返回 `absent` + 三条缺失明细（引擎/模型/服务） |

## 关键发现

1. **「安装语义 absent」与「在盘存在」是两个口径，本报告两者都给**：探针按 §3.1 语义如实记 llama-server/vllm/strata=absent、约定目录模型=0；但复核证实 `~/code/strata-jetson/work/` 下有完整可用构建（llama.cpp b3cf03257f CUDA、strata 0.1.43 ×3）与 8 个在盘 gguf。这就是 install_state「absent → ready」要覆盖的真实差距——主控的 appspec 指纹（§3.4 双 sha256）可直接引用 `supplement` 节的 sha256_16；把引擎纳入安装根或加 `--model-dirs` 后，后续探针可自动收敛这两个口径。
2. **模型动物园「20」的精确含义**：目录 = `work/zoo/gguf`；目录表 = 19 个开源模型（run_zoo.py ZOO）；README §3.3 的 20 行 = 19 zoo 模型 + strata Q2_0。在盘 8 个文件 = 7 个 ZOO 条目 + 1 个非 ZOO 文件，且在盘字节与受测成绩记录不完全一致（重新拉取副本）——capability 层引用时须写明「已 benched 且成绩留档，权重不在盘/非同一字节」。
3. **加速器身份要靠三源合并**：本机 lspci 只给出 SoC PCIe 桥（10de），iGPU 身份来自 /dev 节点 + nvidia-smi——印证 §3.1 固定三段枚举顺序的必要性。
4. **统一内存是可探测事实**：tegra release + smi `[N/A]` + tegrastats RAM 样本三角印证，capability 层（§3.2）的内存分档可直接引用。
5. **出网不对称是结构性的**：直连 hf 与 github https 双断、pypi/镜像/ssh-443 三通——部署层（appspec 下载）必须按设备事实选路（权重走 modelscope/hf-mirror，GitHub 走 SSH-over-443），不可假设统一。
6. **探针自身指纹外部可校验、两次运行可复现**：报告头 `probe_sha256_16` 与 `sha256sum` 一致；09:37 与 09:44 两次独立运行除时延/时间戳外零结构差异——§3.1「报告是事实库存」的验收点成立。

## 复现

```bash
cd /home/nvidia/code/Bicameral
python3 -m py_compile bicameral/probe.py
# 本报告的生成命令（--model-dirs 把在盘 zoo 纳入 installed.models）：
python3 bicameral/probe.py \
  --model-dirs /home/nvidia/code/strata-jetson/work/zoo/gguf \
  -o results/2026-10-14-probe-bench/device-jetson.json
# 裸跑（对照安装语义基线）：python3 bicameral/probe.py
# supplement 节（引擎版本/指纹）取证命令：
~/code/strata-jetson/work/llama-build/bin/llama-server --version
~/code/strata-jetson/work/Strata/build-cuda12/strata --version
sha256sum ~/code/strata-jetson/work/{llama-build/bin/llama-server,llama-build/bin/llama-cli,Strata/build/strata,Strata/build-cuda12/strata,Strata/engine-cuda12/strata}
# 可选：python3 bicameral/probe.py --appspec spec.json --verify-hashes
```
