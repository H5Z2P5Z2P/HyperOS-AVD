# HyperOS 4.0.18.0 · v0.2.4 · Apple Silicon · r5

Release Tag：`v0.2.4-a17-hyperos4-hongkong-r5`。本版基于小米 18 Pro（代号 `hongkong`）官方 **OS4.0.18.0.XFRCNXM / Android 17** 移植。

## 相比 r4 的更新亮点

- **Core 4 / Apps 3 模块架构**：运行时兼容修复统一由两个 KernelSU 通用模块提供，手机和平板共享统一底座，并支持动态适配应用的新版安装路径。
- **离线状态 WebUI**：新增离线只读状态页面，可随时查看各适配项的生效情况与运行状态。
- **CPU 调度与编译策略**：ART 预编译按真实物理核心拓扑配置，大幅降低无效编译开销。
- **桌面与小组件修复**：修复了时钟小组件在缩放、长按拖拽或锁屏解锁后偶发的字形错位问题。
- **Vulkan 性能优化**：针对手机端 Vulkan 渲染组合优化了命令传输机制，桌面待机 CPU 占用大幅下降，流畅度显著提升。
- **原厂特性完整保留**：保留 Flutter 玻璃高斯模糊、桌面小组件、锁屏编辑、小爱同学边缘光效、天气动画、60 Hz 刷新率、macOS sRGB 色彩适配以及全天候息屏（AOD）与独立副屏（背屏）。

## 安装与升级

- **配套工具**：推荐使用 **Installer 1.2.2 或更高版本**。
- **推荐配置**：默认 **4 核 CPU / 6 GiB 内存 / 32 GiB 存储**（均可自由调大）。
- **升级须知**：升级前请先关闭运行中的 AVD。安装器会自动备份用户数据（userdata）、磁盘覆盖层（QCOW2）、加密密钥及实例配置，若遇异常可一键恢复。不支持跨手机 / 平板 / OS3 互相覆盖升级，同时不支持保留用户数据的降级操作。

---
[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [r5 验证记录](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r5-validation.md) · [补丁架构与维护](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/os4-patches.md)
