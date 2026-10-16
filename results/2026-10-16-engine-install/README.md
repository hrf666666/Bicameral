# 2026-10-16 引擎级安装（engine.install 节）+ bi150 真机门复验

**功能**：`bicameral/install.py` 的 appspec engine 增加可选 `install` 节——engine.binary 缺省且引擎不在盘时，下载 pinned tarball（复用模型下载全套机制：mirror 回退 / 流式 sha256 / stall 检测 / 自适应 deadline）→ 逐成员路径穿越校验解压到沙箱 `engines/<engine.name>/` → `binary_inside` chmod 0755 → 以该路径作为 engine.binary 继续既有流程；引擎已就绪（含出处指纹匹配）则跳过（幂等）。仅标准库，只改 `bicameral/install.py` + 新增本目录与本例 `examples/appspec-engine-install.json`。

## 0. 产物指纹

| 产物 | 位置 | 指纹 |
|---|---|---|
| install.py（1699 → 2307 行，+651/-42） | Bicameral 仓 `bicameral/install.py`（未提交工作树改动） | sha256 `4c93527d88b028444bde8ffddec6705470a5cee49f251dc40c7f6cf2f4b00656` |
| 引擎级安装示例 appspec | Bicameral 仓 `examples/appspec-engine-install.json` | sha256 `ae091e765f6bbc1d30259de52bca8a7a492c246b6f3852484f90097d04c1cf70` |
| bi150 门实跑 appspec（正例） | 本目录 `appspec-engine-install-bi150.json` | appspec_sha256_16 `fdb30bbe39a7f3a8`（INSTALL_START 事件记录） |
| bi150 门反例 appspec（engine sha 首字符 e→f） | 本目录 `appspec-engine-install-bi150-badeng.json` | name=qwen3-0.6b-q8_0-badeng，port 18011 |
| 审计链摘录（本次门全程 41 行） | 本目录 `gate-audit-excerpt.jsonl` | 源：bi150 `/root/bicameral-sandbox/audit.jsonl`（门前后 62 → 104 行，原样保留） |
| 引擎工件 | （bi150，已清理）`/root/bicameral-sandbox/artifacts/llama-cpu.tgz`，5483 B，成员 `bin/llama-server`（17888 B） | sha256 `ef71661e28a33581f7e4d32ed2bfcc1006b8375ac04df9428c602ecb365343ad` |
| 门后部署副本 | bi150 `/root/bicameral-sandbox/bicameral/install.py` | 同上 `4c93527d…00656`（保留，为沙箱工作副本） |

## 1. 功能行号（install.py，修后 2307 行版）

- **schema**：`ENGINE_INSTALL_FORMATS`/`ENGINE_NOT_FOUND` 常量 :184-191；`_check_mirror_list` :353-372（model/engine 镜像共用）；`_validate_engine_install` :374-447（mirror_urls/sha256/format 必填、未知字段拒绝、strip_components 0..32 整数、binary_inside 相对+无 `..`+白名单 basename（A5））；`validate_appspec` engine 节接入与归一化 :455-520, :600-608。
- **引擎安装机制**：`dedup_urls` :564；`resolve_engine` NOT_FOUND 标记 :706-711；`_tar_member_error` :871-880；`extract_engine_tgz` :882-957（逐成员：绝对路径/`..` 拒绝、链接不得越界、仅目录/普通文件/链接、realpath 二次Containment、解压总量上限）；`_locate_engine_binary` :959-987（binary_inside 或唯一白名单名搜索，0/多命中 fail-closed）；出处标记 `read/write_engine_marker`+`engine_provenance_matches` :989-1017；`install_engine` :1020-1112（幂等跳过=二进制可解析**且**出处标记 archive_sha256 等于本 appspec pin；下载→ENGINE_VERIFY→解压→chmod 0755→ENGINE_PLACE→写出处→再 resolve）。
- **apply 接入**：`cmd_apply` :1515-1524（仅「binary 缺省 + ENGINE_BINARY_NOT_FOUND + 有 install 节」三种条件齐备才触发；其余引擎失败维持现状报错）。
- **selftest**：install 节 schema 26 项 + dedup_urls + 出处门 + NOT_FOUND 标记 :1876-1990；tar 穿越拒绝/strip/binary_inside 解析 13 项 :2131-2229；examples.engine_install_* :2251-2257。

## 2. bi150 门（ssh -p 31451 root@10.70.251.39，沙箱 /root/bicameral-sandbox/，服务 18010、镜像 127.0.0.1:18099）

红线遵守：8080/8181、8960-8963、18000/18001 全程未动（门前后 `ss -ltn` 监听集不变：4 个既有监听）；未写沙箱外任何路径。

- **a. 工件**：`cd build-cpu && tar czf ../artifacts/llama-cpu.tgz bin/llama-server`（按任务原文），sha256 `ef71661e…343ad`（5483 B）。
- **b. 镜像**：`python3 -m http.server 18099 --bind 127.0.0.1 --directory artifacts`，curl 预检 200/5483B。
- **c/d. absent → ready（正例，exit 0）**：全新 apps/（`apps/` 门前置空）；引擎 5483B 下载 → `ENGINE_VERIFY ok`（全串 ef71661e…343ad）→ `ENGINE_PLACE`（`binary_mode: 0755`，`engine.binary := /root/bicameral-sandbox/engines/llama.cpp/bin/llama-server`）→ `ENGINE_FOUND sha256_16=d59eab76dfbb7e8e`（与 perf-bi150.json 记录的构建指纹一致）；模型 Qwen3-0.6B-Q8_0.gguf 639,446,688 B 从 hf-mirror（xet CDN 302 落点）下载，流式 sha256 = pin `9465e63a…bb031` 逐字节相符 → `VERIFY_OK → PLACE → START pid=3981619 → HEALTH 200 → READY`。
  **双证**：`/health` → `{"status":"ok"}` HTTP 200；`/v1/models` → HTTP 200（Qwen3-0.6B，n_params 596,049,920，ftype Q8_0）；`status` → `"state": "ready"`、`pid_alive: true`、`health_now: true`、`live_state: "ready"`。
- **幂等复跑（exit 0）**：`ENGINE_DOWNLOAD status=skip`（记录 archive_sha256 全串）+ `DEDUP dedup_ready`，无重启。
- **e. 反例（exit 3）**：新 name `qwen3-0.6b-q8_0-badeng`（端口 18011），engine.install.sha256 首字符改 e→f（`ff71661e…`）→ 出处门判定不匹配 → 触发重装 → 2 次下载尝试均 mismatch（`ENGINE_VERIFY final=false ×2`，回退退避 2s）→ `ENGINE_VERIFY final=true` + **`ENGINE_VERIFY_FAIL`** → `INSTALL_FAIL step=engine exit_code=3` → `ROLLBACK removed_dir=true state=absent`。**无残留**：apps/ 无 badeng 目录（仅 mutex .lock，设计如此）、downloads/ 空、无 .part；共享 `engines/llama.cpp` 一并清空（出处不符的半装树不留），仍在运行的正例服务不受影响（health 200）；随后正例 appspec 一次复跑恢复（ENGINE_DOWNLOAD ok → PLACE → DEDUP → READY，exit 0，审计行 31-41）。
- **f. 清理**：`rollback qwen3-0.6b-q8_0 --reason gate-2026-10-16-cleanup`（`killed_pid_outcome=terminated removed_dir=true`）→ 删 `engines/llama.cpp`、`artifacts/`、kill 18099 镜像 → 复核：`status` apps=[]、18010/18099 释放、红线端口 4 监听原样、`audit.jsonl` 104 行保留。

## 3. selftest / 编译

- `python3 -m py_compile bicameral/install.py` → 0。
- `install.py selftest`：**122 项 0 失败**（本地与本轮部署的 bi150 各跑一次均 0 failure(s)）；新增 39 项：install 节 schema 白名单组合（必填缺失/未知字段/bad format/strip 非法/binary_inside 绝对·穿越·解释器 basename/mirror scheme/dedup_urls/出处门/NOT_FOUND 标记）+ tarfile 逐成员（`..`/绝对/符号链接逃逸/链接后写/绝对链接/fifo 拒绝，strip_components 归位，binary_inside 显式/唯一搜索/缺失/歧义）。

## 4. 如实注记

- `PROBE_REFRESH probe_state=partial`（probe/1 扫 PATH+install roots，看不到沙箱 engines/ 自定义路径；既有 note 声明该差异由安装 marker 调和，READY 判定不受影响——install.py 既有行为，非本轮引入）。
- 反例失败会把共享 `engines/<name>` 连同旧树一起清掉（出处不符的重装失败不留半装树）；运行中进程不受影响，正例 appspec 复跑即恢复（已实证）。
- 正例模型下载 URL 是 hf-mirror 302 到 cas-bridge.xethub.hf.co 的落点（https→https 重定向，非降级）；sha256 与 pin 精确相符。
- 仓库工作区另有他人未跟踪文件（`bicameral/fleet.py`、`scripts/powerbench.py`、`results/2026-10-16-power-bench/`），本轮未触碰；本目录证据同时镜像到 strata-jetson 仓 `results/2026-10-16-engine-install/`。
