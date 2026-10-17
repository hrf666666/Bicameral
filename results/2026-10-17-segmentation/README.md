# 2026-10-17 分割能力探测（probe/1 `segmentation` 节双机实测）

> 目标：回答「天数智芯卡可否分割（vGPU/切片/实例分割）」，为算力细分提供客观依据。
> 探针：`bicameral/probe.py` 新增 `segmentation` 节（schema probe/1 兼容追加），
> 两机探针同一文件，sha256 `ab545930218054d4befb3e20a606af6ecc06ad8751c1d7165be8afa271023904`（前16 `ab545930218054d4`）。
> 只读红线：全程零分割创建；bi150 六个服务端口（22/8080/8181/18000/18001/8960）探测后逐一复核仍在监听。

## 归档物

| 文件 | 内容 |
|---|---|
| `device-seg-bi150.json` | bi150（8× BI-V150 32GB，pod `ai-exp-zb2557126-bi150-…`）probe/1 报告，machine_id `19978ab8db74…` |
| `device-seg-bi100.json` | bi100（2× BI-V150，pod `ai-exp-zb2557126-bi100-…`）probe/1 报告，machine_id `b0d995b9acec…` |

## 结论（由报告事实回答，不由人断言）

| 问题 | bi150 | bi100 |
|---|---|---|
| vGPU 工具面 | `ixsmi vgpu` 子命令存在（仅查询旗标 q/u/p/s/c/v/l，`--help` 无 create/destroy） | 同左（ixsmi 在 `/usr/local/iluvatar/bin`，非 corex 根） |
| `vgpu -s`（支持类型） | 8 卡全部 `No vGPUs found on this device`（0 个受支持类型） | `Not supported devices in vGPU mode` |
| `vgpu -c`（可创建类型） | 8 卡全部 0 | 同上（unsupported） |
| `vgpu -q`（活动 vGPU） | 8 卡全部 `Active vGPUs : 0` | （unsupported 口径） |
| **vgpu_capable** | **false**（查得明确否认） | **false**（驱动明示不支持） |
| /dev/itrctl 通道 | 存在（char 237），但**全盘无 itrctl 用户态工具**（deep find 仅得设备节点） | 内核注册 major 235，但节点未透入容器 |
| libixml C-API | 8/8 符号命中：`nvmlDeviceGet{Supported,Creatable,Active}Vgpus` + MIG 式 `nvmlDeviceCreateGpuInstance[WithPlacement]`/`nvmlGpuInstanceCreateComputeInstance` + 配对 `*Destroy` + `nvmlSetVgpuVersion` | 同左（`/usr/local/iluvatar/lib64/libixml.so`） |
| **slicing_method** | null | null |

## 受控实验判定：不执行

实验准门槛：某工具**自身文档**（--help）同时给出 create+destroy（`has_reversible_pair`，selftest 钉死）。实测：

1. 全盘不存在 `itrctl` 用户态二进制——无其 --help 可言；
2. `ixsmi vgpu` 仅查询旗标，无 create/destroy；
3. MIG 式创建仅以 **C API 符号**存在于 libixml——无 CLI 包装、无文档，裸 ioctl 属不可逆/不明确领域。

⇒ 只记 capabilities，不做创建实验（notes 内含此判定审计行）。bi150 的 0 受支持类型亦使「创建」无从谈起（类型表为空即无从 create）。

## 过程与工程事实

- 探测中的缺陷两则（当轮修复）：① `run_cmd` 默认 600 字符摘录截掉 help 尾部 `GRID vGPU` 节 → 改 `capture_full`（同 ss -tln 教训）；② `-q` 输出的 `Active vGPUs : 0` 落入 other_lines 致判 None → 解析进 `active_vgpus_total`。
- selftest：probe.py 新增 `--selftest`，33 项 segmentation 纯函数用例（真机输出钉为 fixture、absent 容错）0 失败；install/router/task/verify_result/fleet/nodeagent/pipeline/server 全部 selftest 0 失败。
- 复现：`python3 bicameral/probe.py -o device-seg-<dev>.json`（两机 /tmp 部署件 sha256 与本地一致，用后已清理；bi100 仅 /tmp 落盘探针与报告，属项目既有 scp-up 惯例）。

## 局限（如实）

- 两机均为 k8s 容器内视角：vGPU 供给通常是**宿主机层**操作（license/管理面），容器内 0 类型不能独断宿主机物理能力——报告 notes 已注明此口径。
- `virt.host_vgpu_mode` 查询返回 `[N/A]`（bi150 全部 8 卡），作为辅助证据记入探针原始输出而非结论。
