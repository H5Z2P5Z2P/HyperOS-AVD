# HyperOS Pad 4.0.15.0 · v0.1.1 · Apple Silicon · r2

Release Tag：`pad-v0.1.1-a17-hyperos4-yingtian-r2`。基于 Xiaomi Pad 9 Pro Max（代号 `yingtian`）官方 **OS4.0.15.0.XBMCNXM / Android 17** 移植。

## 相比 r1 的更新亮点

- **Core 4 / Apps 3 通用模块**：与手机版共享自适应 KernelSU 模块架构，支持动态跟随应用安装路径恢复挂载。
- **离线状态 WebUI**：新增离线只读状态页，方便查看模块运行情况与补丁生效状态。
- **CPU 与编译优化**：ART 预编译按真实物理核心拓扑配置，提升系统整体响应速度。
- **平板特性保留**：完整保留原厂横屏布局（**3408×2272 / 400 dpi**）、`yingtian.xml`、稳定机型标识、HWUI Skia-Vulkan 硬件加速、Flutter 玻璃模糊材质、官方天气渲染、相机预览、60 Hz 刷新率以及 macOS 色彩和音频输出适配（原机不支持的 AOD 保持关闭）。

推荐配置为 **4 核 CPU / 4 GiB 内存 / 32 GiB 存储**（内存可在安装器中自由调大，4 GiB 仅为初始推荐值）。

## 安装与升级

- **配套工具**：推荐使用 **Installer 1.2.2 或更高版本**。
- **升级须知**：升级前请先关闭运行中的平板 AVD。安装器会自动备份用户数据（userdata）、磁盘增量层（QCOW2）、加密密钥及实例配置，若遇异常可一键恢复。不支持跨平板 / 手机 / OS3 互相覆盖升级，同时不支持保留用户数据的降级操作。

---
[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [r2 验证记录](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-pad-r2-validation.md) · [补丁架构与维护](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/os4-patches.md)
