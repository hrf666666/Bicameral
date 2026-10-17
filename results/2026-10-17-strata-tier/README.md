# 2026-10-17 · Strata 层解锁实测（bi150 卡 3）

并行会话修复 decode NaN（根因=自适应层换入毒化 verify 窗口，CoreX 运行时围栏问题；修复=ivcore 构建默认 --adapt-every 0）后，本会话独立复测 Strata 层：

**门**：Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS（native+PLE 双分片 + strata-packs）--gpu 3，16 tokens 生成。

- **输出 16/16 全部有限，日志 0 个 NaN**（修复在第三方复跑中生效）
- 输出链尾部与 canonical 基准吻合（79299 314 95582 3971 13）；前段漂移为 PITFALLS 已记录的非阻塞「深位贪心漂移」
- decode 2.41 tok/s（无投机：drafts accepted 0/45）、TTFT 1395 ms、prefill 21.21 tok/s
- 显存：卡 3 上 28GB 设备缓冲捕获成功

**结论**：Bicameral 部署策略三层的中间层（爆显存上 Strata）在 bi150 实机解锁。对照：CPU 层 27B t56 = 5.21 tok/s（本卡 3 层 Flash-Next 2.41 tok/s 为无投机档；spec 4 需 --expert-profile profile.bin，已用 tools/make_profile.py 生成于 /root/strata/）。遗留：深位贪心漂移（非阻塞）、spec 草稿接受率 0（待查草稿对齐）。
