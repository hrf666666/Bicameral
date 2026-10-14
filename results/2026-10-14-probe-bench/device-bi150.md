# device-bi150 — probe/1 盘点报告（2026-10-14）

- **设备**: bi150（容器主机名 `ai-exp-zb2557126-bi150-pod-jacr-5d95566cf-9xv6l`）
- **报告 JSON**: `results/2026-10-14-probe-bench/device-bi150.json`（schema `probe/1`）
- **指纹**: `fingerprint_id = 19978ab8db7445409398d3073395b467-eb10063293b418a4`
  （machine-id + probe 自身 sha256 前 16 位；本地与远端 probe.py sha256 一致 `eb100632…`）
- **生成时间**: 2026-10-14T09:41:25Z（probe 退出码 0）

## 执行方式

```bash
ssh -o BatchMode=yes -p 31451 root@10.70.251.39 'mkdir -p /root/bicameral-sandbox'
scp -P 31451 /home/nvidia/code/Bicameral/bicameral/probe.py root@10.70.251.39:/root/bicameral-sandbox/
ssh -o BatchMode=yes -p 31451 root@10.70.251.39 'cd /root/bicameral-sandbox && python3 probe.py -o device-bi150.json'
# stderr 摘要: probe/1: accel=[Iluvatar] engines=[none] inference_services=[8960, 8961, 8962]
#             egress=[pypi:up hf:down hf_mirror:up github:down github_ssh_443:up]
```

红线遵守：全程只读。probe 对已监听端口仅做 `GET /health`、`GET /v1/models`（其设计内的盘点手段）；
我在其外只追加了 8960-8962 的只读 `GET /v1/models`、ixsmi/ldd/LD_DEBUG 等 GPU 查询与只读文件命令。
未触碰任何在跑服务，未占用任何端口，远端唯一写盘是沙箱内的报告文件。

## 硬件

| 项 | 值 |
|---|---|
| CPU | Intel Xeon Gold 6330 @ 2.00GHz × 112 核 |
| 内存 | 1007.5 GiB |
| 加速器 | **8 × Iluvatar BI-V150，各 32768 MiB**（ixsmi 实测；Bus-Id 8D/90/96/99/A1/A4/AD/B0:00.0） |
| /dev 证据 | `/dev/iluvatar0` … `/dev/iluvatar7`（8 实例，probe 阶段1） |
| lspci | 工具存在，但厂商表零命中（容器内未见 1e3e 等设备行；GPU 只能靠 /dev 节点+工具发现） |
| 统一内存 | `value: null`（x86_64 服务器，非 Jetson，`platform: None`） |

## 栈

- OS: Ubuntu 24.04.2 LTS；kernel 5.4.0-144-generic（宿主内核）
- 容器: **is_container = true**（cgroup 命中 containerd/kubepods —— k8s pod 内）
- CUDA: 10.2.89（来源 `/usr/local/cuda-10.2/version.txt`；**nvcc 不存在**）
- CoreX: probe 报 `absent`，实测 `/usr/local/corex/release-corex.txt` 写着 **Iluvatar CoreX SDK 4.4.0**
  （probe 只搜 `corex*/version*`，漏掉 `release-corex.txt` → 改进建议见下）
- ixsmi 横幅: `IX-ML: 4.4.0  Driver Version: 4.4.0  CUDA Version: 10.2`
- Python: 3.12.3（/usr/bin/python3）；venv 可导入；**ensurepip 不可导入**（装 venv 内包会失败，除非 `--without-pip` 或先装 python3-venv）
- 出网: **pypi 通**（HTTP 206）、**hf-mirror 通**（206）、**ssh.github.com:443 通**（89ms）；
  **huggingface.co 不通**（Network is unreachable）、**github.com https 不通**（timeout）

## 已装（installed）

- **引擎二进制: llama-server / vllm / strata 均 absent**（PATH + 常规安装根 + /opt/*/bin 都没有）
  —— 但 8960-8962 三个推理服务活着。本容器 /proc 里可见的 llama-server 进程全是
  `[llama-server] <defunct>` 僵尸：服务实际跑在**同 pod 的兄弟容器**里（k8s 共享网络命名空间），
  本容器的文件系统/PID 视角看不到它们。
- **模型文件: 0 个**（只扫到 `/root/.cache/huggingface/hub` 且为空；模型在兄弟容器的 `/private/models`）
- **监听服务**（`ss -tln`，8 个）+ 交叉验证：

| 端口 | 监听地址 | /health | /v1/models | 结论 |
|---|---|---|---|---|
| 22 | 0.0.0.0 | —（SSH banner） | — | sshd |
| 8080 | 0.0.0.0 | 404 | 404 | HTTP 服务，非 llama.cpp 风格（红线内未深挖） |
| 8181 | 0.0.0.0 | 404 | 404 | 同上 |
| **8960** | 127.0.0.1 | **200** `{"status":"ok"}` | 200 | llama-server，服务 **`/private/models/Qwen3.8-27B-UD-Q4_K_M.gguf`** |
| **8961** | 127.0.0.1 | **200** | 200 | 同一模型 |
| **8962** | 127.0.0.1 | **200** | 200 | 同一模型 |
| 18000 | 0.0.0.0 | 404 | 404 | bicameral（红线内未深挖） |
| 18001 | 0.0.0.0 | 404 | 404 | bicameral（红线内未深挖） |

- ⚠️ **8963 未在监听**（与任务简报“8960-8963 四个 llama-server”不符，probe 时间点实况即如此，未做任何干预）
- install_state: `[]`（独立运行无 --appspec，符合设计）

## paradigm §1 ixsmi 怪癖实测（bi150 现场，全部只读）

| 实验 | LD_LIBRARY_PATH | 结果 |
|---|---|---|
| A | （空，复现 §1） | **exit 127**：`libixml.so: cannot open shared object file` |
| B | `/usr/local/corex/lib`（probe 注入集） | **exit 0** ✅ |
| C | `/usr/local/corex/lib64` | **exit 0** ✅ |
| D | `/usr/local/iluvatar/lib`（§1 记载的段） | **exit 127**（该目录为空：`total 0`） |
| E | `/usr/local/corex/lib:/usr/local/iluvatar/lib`（§1 全集） | exit 0（B 已足够，iluvatar/lib 无贡献） |

- 库真相：`libixml.so`（md5 `1dc5b7f4…`，474048 B）物理存在于
  `/usr/local/corex/lib64/libixml.so` 与 `/usr/local/iluvatar/lib64/libixml.so`（同 md5、不同 inode）；
  **`/usr/local/iluvatar/lib` 是空目录**。
- LD_DEBUG 证实 B 场景下 loader 从 `/usr/local/corex/lib/libixml.so` 成功加载
  （`/usr/local/corex/lib -> lib64` 符号链接）。
- **结论：探针自发现成功，无需修复。** probe 的 corex 根搜索 + LD 注入恰好覆盖最小充分集；
  paradigm §1 文档本身有误——`/usr/local/iluvatar/lib` 应为 `/usr/local/iluvatar/lib64`
  （或干脆只需 `/usr/local/corex/lib`）。
- 附带教训（我方工具，非探针问题）：`find /usr/local/corex …` 会**静默空结果**——
  `/usr/local/corex` 是指向 `corex-4.4.0/` 的符号链接，GNU find 不跟随命令行符号链接操作数；
  probe 用的是 `glob.glob`（跟随符号链接）所以不受影响。

## 回传给作者的探针观察（按重要性）

1. **`/v1/models` 的 model_ids 在 200 时解析为空**：`http_get_local` 把 body 截到 300 字符
   （probe.py:709-710 `clip(body, 300)`），8960-8962 返回的是 ollama 风格信封
   `{"models":[…],"object":"list","data":[{"id":"/private/models/…"}]}`，截断后
   `json.loads` 失败 → 报告里 `model_ids: []`。实测 raw body 里 `data[].id` 完整可取。
   建议：对该端点放宽截断或先对 `r.read(4096)` 原文解析。
2. **`gpu_query_csv` 为 null**：ixsmi 拒绝 `--query-gpu` 里的 `compute_cap` 字段
   （`Field "compute_cap" is not a valid field to query`）→ probe.py:330 判 invalid 丢弃。
   建议：失败后回退少字段子集（`name,driver_version,memory.total`）。
3. **corex 版本探测漏文件**：只搜 `corex*/version*`，漏 `/usr/local/corex/release-corex.txt`
   （本次实测 CoreX SDK 4.4.0 就写在那）。建议加入搜索模板。
4. **兄弟容器服务导致引擎"absent"而服务在线**：k8s pod 共享 netns、隔离 PID/fs，
   `ss` 能看到监听但 `probe_engines` 找不到二进制。可在报告中补一条提示
   （如检测到 defunct 同名进程时注明“疑似兄弟容器部署”）。
5. paradigm §1 文档修正（见上节）——探针代码本身不用改。
