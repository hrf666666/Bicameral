# 2026-10-16 bi100 引擎级安装完整门（目标发行版原生构建）

**目标**：第三台设备 bi100（ssh -p 46026 root@10.70.250.26，Ubuntu 22.04.5 jammy，x86_64，128 核，503G 内存）上跑通引擎级安装完整门：Jetson 交叉无涉——源码在 bi100 本地原生构建 → 打包 → 本地 mirror → install.py 全新安装 → READY → 真实推理 → 反例回滚 → 清理。

**红线遵守**：22 端口 sshd 未动（门后监听集回到 `[22]`，门中仅 +18010/+18099 均为本门实例）；一切写入限于 `/root/bicameral-sandbox/`（本机 /root/bicameral-fleet/ 未写，为他人既有目录）；结束 rollback + 删大目录 + kill 双端口；沙箱仅剩 328K（审计/appspec/脚本/README）。

## 0. 产物指纹

| 产物 | 指纹 |
|---|---|
| 源码包 llama-src.tgz（38MB，llama.cpp 主线 0.7.0-dev） | sha256 `b983afe633095c97ec9b1b4b00a0053c77e839f88c38867d68330dca00c070a7`（scp 后双侧一致） |
| 引擎工件 bi100 `artifacts/llama-jammy.tgz`（6,956,965 B，21 成员） | sha256 `eb78cff88e909fa3d73e5ed419043259fba8d13af36dd2108273c5cf7eae22dd` |
| 引擎二进制（解压后） | `engines/llama.cpp/bin/llama-server` sha256_16 `c8be70d331ae7428`，chmod 0755，RUNPATH `$ORIGIN`（与 6 个 .so 同目录自包含，独立目录运行实测通过） |
| install.py / probe.py（沙箱部署副本） | `4c93527d88b0284…` / `a2ce9db92eff2fb7…`（与主仓一致；install.py 同 bi150 门记录指纹） |
| 正例 appspec（本目录 `appspec-bi100.json`） | sha256 `6eaf4168021ffbef41acb804c728db28edfaf79818aa8d82596c6308b7ed5ca9`（INSTALL_START 记 16 位） |
| 反例 appspec（`appspec-bi100-badeng.json`） | name=`qwen3-0.6b-q8_0-badeng`，engine.install.sha256 首字符 e→f（`fb78cff8…`），port 仍 18010 |
| 全程审计（44 行） | 本目录 `gate-audit-bi100.jsonl`（源：bi100 `/root/bicameral-sandbox/audit.jsonl`，远程保留原样） |

## 1. 步骤与输出摘要

### 步骤1 工具链 + 原生构建
- `mkdir -p /root/bicameral-sandbox && scp -P 46026 /tmp/llama-src.tgz …` → **1s**，sha256 双侧一致 `b983afe6…070a7`。
- `apt-get install -y build-essential cmake` → rc=0 **elapsed=34s**；gcc/g++ 11.4.0、cmake 3.22.1、make 4.3（apt 模拟 Inst 98 包）。
- `tar xzf llama-src.tgz` → `llama-src/`。
- `cmake -B build-cpu -DGGML_NATIVE=ON -DLLAMA_CURL=OFF -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON` → rc=0 2s。*注：多加 `CMAKE_BUILD_RPATH_USE_ORIGIN` 一项，使 RUNPATH=$ORIGIN、工件解压后自包含（原样钉旗时 rpath 为构建树绝对路径，工件仅在同机构建树存活时可运行）；其余按任务原文。*
- `cmake --build build-cpu --target llama-server -j 120` → rc=0 **elapsed=93s**；`bin/`：llama-server(17,856 B) + libllama/libllama-common/libllama-server-impl/libggml/libggml-base/libggml-cpu/libmtmd .so；`llama-server --version` → `0.7.0-dev (build 0, commit unknown)`。

### 步骤2 打包 + mirror
- 任务原文 `tar czf … -C build-cpu/bin .` 产出 `./llama-server` 成员，与任务钉死的 `binary_inside:"bin/llama-server"` 不匹配（解压落 eng_root 根，定位将 exit 3）——**按 bi150 先例与 appspec 钉死值，改 `tar czf artifacts/llama-jammy.tgz -C build-cpu bin`**（成员 `bin/llama-server`+6 .so），功能意图不变，如实注记。
- `python3 -m http.server 18099 --bind 127.0.0.1 --directory artifacts`（setsid 后台）→ 预检 `200 / 6956965`。

### 步骤3 部署 + selftest
- `scp install.py probe.py → /root/bicameral-sandbox/bicameral/`（同目录为 PROBE_REFRESH 子进程依赖）；指纹一致。
- `py_compile` OK；`install.py selftest` → **`selftest: 0 failure(s)`**。

### 步骤4 appspec
- 见本目录 `appspec-bi100.json`：engine.name=llama.cpp，install.mirror_urls=`["http://127.0.0.1:18099/llama-jammy.tgz"]`，sha256=`eb78cff8…e22dd`，format=tgz，strip_components=0，binary_inside=`bin/llama-server`；model=Qwen/Qwen3-0.6B-GGUF Qwen3-0.6B-Q8_0.gguf，sha256=`9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`（抄自 perf-bi150.json），mirror 首选 hf-mirror.com 次选 huggingface.co；service port 18010，`-c 2048 -t 32`。

### 步骤5 apply → READY（双证 + 真实推理）
- 门前快照：audit 不存在（新沙箱）、apps/engines/downloads 无、18010 空闲。
- **第一次 apply rc=3（125s）**：引擎段全绿（ENGINE_DOWNLOAD ok 6956965B → ENGINE_VERIFY ok 全串 → ENGINE_PLACE 21 成员 20,066,240B binary 0755 → ENGINE_FOUND c8be70d331ae7428）；**模型下载 hf-mirror `HTTP 429 Too Many Requests` ×2**（此前 30s 内手工预检 GET 同 URL 200——hf-mirror 按 IP 频次限流，预检 GET 自身占掉窗口），huggingface.co `Errno 99` ×2（出口仅放行 hf-mirror，预期内）→ INSTALL_FAIL step=download → ROLLBACK removed_dir=true（app 目录自动回滚，引擎树保留）。
- **等 90s 复跑 apply rc=0（38s）**：ENGINE_DOWNLOAD **skip**（出处标记 archive_sha256 全串相符，幂等）→ DOWNLOAD ok **639,446,688 B**（hf-mirror 302 → `cas-bridge.xethub.hf.co` 落点，https→https）→ VERIFY_OK sha256 全串 `9465e63a…bb031` 相符 → PLACE → START pid=3760 port 18010 → HEALTH 200（3 次内，2011ms）→ PROBE_REFRESH partial → **READY install_state=ready（fresh）**。
- **双证**：`GET /health` → **200 `{"status":"ok"}`**；`GET /v1/models` → **200**（Qwen3-0.6B GGUF，capabilities completion）。
- **真实推理** `POST /completion`（prompt "The capital of France is", n_predict=64, temperature=0）：wall 2.80s，输出连贯（"Paris. The capital of France is also…"），**timings.predicted_per_second = 23.01 tok/s**（prompt_per_second 81.42；-t 32）。
- `status` → `"state":"ready"`、`pid_alive:true`、`health_now:true`、`live_state:"ready"`、model_sha256_16 `9465e63a22add535`。
- **PROBE_REFRESH 如实记录**：`probe_state:"partial"`，probe_missing=["engine 'llama.cpp' (binary 'llama-server') not found","model file found outside appspec path"]，note=probe 扫描面只覆盖 PATH+安装根、自定义 engine.binary 由安装 marker 调和——**install.py 既有已知行为（与 stage3/bi150 门一致），非本轮引入**；install 侧 reconciled 终态 ready 与 probe 视角 partial 两视角并存入审计，不装假。

### 步骤6 反例（ENGINE_VERIFY_FAIL → 回滚无残留）
- 复制 appspec：name=`qwen3-0.6b-q8_0-badeng`、engine.install.sha256 首字符 e→f（`fb78cff8…`）、port 保持 18010（服务不会走到启动）。
- `apply appspec-bi100-badeng.json` → **rc=3（2s）**：出处门判 pin 不匹配 → 重装 → 2 次下载均 mismatch（`ENGINE_VERIFY final=false`，got eb78cff8…）→ **`ENGINE_VERIFY_FAIL`** → `INSTALL_FAIL step=engine exit_code=3` → **`ROLLBACK removed_dir=true state=absent`**。
- 无残留核查：apps/ 仅正例目录 + 2 个 mutex `.lock`（设计如此）；downloads/ 空且 0 个 `.part`；共享 `engines/llama.cpp` 连同旧树清空（出处不符不留半装树，bi150 同款已知行为）；**正例服务不受影响（/health 200）**。
- 可恢复性：正例 appspec 复跑 rc=0（2s）→ ENGINE_DOWNLOAD ok → PLACE → **DEDUP dedup_ready** → READY，服务未重启（health 200）。

### 步骤7 清理
- `rollback qwen3-0.6b-q8_0 --reason gate-2026-10-16-bi100-cleanup` → `killed_pid_outcome:"terminated" removed_dir:true state:"absent"`。
- 删 apps/ engines/ artifacts/ llama-src/ llama-src.tgz 与 /tmp 大文件（apt/cmake/apply 日志、源码包副本）。
- kill 18099（注：pgrep -f 误匹配到当前清理会话自身命令行导致 ssh 会话自杀 exit 255，kill 动作本身已生效；用 /proc 遍历复核无 http.server 进程）。
- 复核：监听集 **`[22]`**（18010/18099 已释放，sshd 未动）；沙箱 **328K**（README.md、2 appspec、audit.jsonl 44 行、bicameral/ 脚本、空 downloads/）；`status` → `apps: []`。

### 步骤8 证据取回
- `gate-audit-bi100.jsonl`（44 行全量）、`appspec-bi100.json`、`appspec-bi100-badeng.json` → 本目录；远程沙箱留 README.md 与审计原样。

## 2. 审计链摘录（≤500 字符）

```
audit.jsonl 44行: INSTALL_START 6eaf4168021ffbef → ENGINE_DOWNLOAD ok 6956965B eb78cff8… → ENGINE_VERIFY ok → ENGINE_PLACE 0755 → ENGINE_FOUND c8be70d3… → DOWNLOAD fail 429×2 → INSTALL_FAIL download → ROLLBACK；复跑 ENGINE_DOWNLOAD skip → DOWNLOAD ok 639446688B 9465e63a… → VERIFY_OK → START pid=3760 → HEALTH 200 → PROBE_REFRESH partial(调和) → READY ready；badeng ENGINE_VERIFY_FAIL → INSTALL_FAIL step=engine exit3 → ROLLBACK removed_dir=true → 复跑 DEDUP dedup_ready → ROLLBACK cleanup terminated
```

## 3. 结论

**门通过**：toolchain 34s / 原生构建 93s；selftest 0 失败；jammy 原生引擎（6.96MB，21 成员）经 mirror 走 engine.install 全链（DOWNLOAD→VERIFY→PLACE→FOUND）幂等可复跑；模型 639MB hf-mirror 下载 sha 全串相符；absent→ready（fresh）成立，/health+/v1/models 双证 200，真实推理 23.01 tok/s；反例 ENGINE_VERIFY_FAIL exit 3 回滚无残留且正例复跑恢复；清理后监听集回到 [22]、沙箱 328K。全程未触碰 22 端口与他人服务。

## 4. 如实注记

1. **hf-mirror 间歇性 429**：预检阶段与第一次 apply 各遇 `429 Too Many Requests`（前置事实"hf-mirror 通 313ms"在网络层成立，但该站按 IP 频次限流；等待 ~90s 后一次成功，639MB 流式全程无中断，~20MB/s）。生产建议：appspec 模型 mirror 已含双站回退，但 huggingface.co 在本环境出口被封（Errno 99），实际唯一可用为 hf-mirror——429 时依赖重试窗口。
2. **tar 成员布局与 binary_inside 的任务内矛盾**：任务原文 `-C build-cpu/bin .` 与 `binary_inside:"bin/llama-server"` 互斥，按后者（appspec 钉死值+bi150 先例）改 `-C build-cpu bin`，已在 §1 步骤2 记录。
3. **构建多加 `-DCMAKE_BUILD_RPATH_USE_ORIGIN=ON`**：使引擎工件解压后自包含（RUNPATH $ORIGIN），不依赖构建树存活；已实测独立目录运行。任务未禁额外旗，如实注记。
4. **PROBE_REFRESH partial**：probe 扫描面看不到沙箱 engines/ 自定义路径与安装目录内模型，由安装 marker 调和——install.py 既有行为（stage3/bi150 门均如此照记），READY 判定不受影响。
5. 反例失败清空共享 `engines/llama.cpp`（出处不符重装失败不留半装树）：bi150 同款已知行为；运行中正例服务不受影响，复跑即恢复（本轮实证）。
6. kill 18099 时 pgrep -f 自匹配致清理会话自杀（exit 255）：动作已生效，/proc 复核无残留进程；属操作小插曲非系统问题。
7. bi100 无 curl/ss/lsof：网络与端口检查全部改用 python3 stdlib（urllib、socket、/proc/net/tcp、/proc 遍历）。
