# HyperOS 4.0.24.0 · v0.2.5 · Apple Silicon · r6

Release Tag：`v0.2.5-a17-hyperos4-hongkong-r6`。本镜像基于小米 18 Pro（代号 `hongkong`）官方 **OS4.0.24.0.XFRCNXM / Android 17** 移植。

## 更新亮点

- **KernelSU 更新**：内核模块升级至 **v3.3.1 / 32680**，镜像内 ramdisk 与安装器自带离线载荷版本一致。
- **Core 18 / Apps 7 模块**：与平板端共用最新自适应兼容模块，支持根据运行时特征动态挂载补丁，并提供离线只读状态页面。
- **背屏唤醒与同步**：优化了独立背屏窗口的 AOD 状态同步与双击唤醒响应。
- **启动提速**：减少了系统初始化阶段不必要的重复哈希与命名空间挂载检查，启动更加迅速。
- **运行包协议**：采用 format 3 运行包格式（`verified-bundle-runtime-v1`），支持完全离线安装，要求 **Installer 1.2.3 或更高版本**（后续同协议镜像无需频繁更新安装器）。
- **设备配置独立**：手机与平板各自应用针对性的显示与 Vulkan 参数，手机参数不会影响平板端。

推荐硬件配置为 **4 核 CPU / 6 GiB 内存 / 32 GiB 存储**（均可在安装器菜单中自定义调大）。
**注意**：手机、平板与 OS3 分属不同产品线，不支持跨设备系列覆盖安装；同时不支持保留用户数据的降级操作。升级时安装器会自动对完整用户数据及配置进行安全快照备份。

## 适配状态与已知限制

- **验证情况**：新安装与冷启动已完成全面验证，KernelSU root、SELinux Enforcing、安全 ADB 调试、HWUI Vulkan 硬件加速及桌面/天气渲染均正常工作。
- **已知限制**：
  - 相机目前支持虚拟场景预览与基础拍照，夜景、人像算法及高质量录像仍有待完善；
  - 蓝牙、小米云服务与 Google 服务暂未适配；
  - 更多验证数据请参考 [双端验证报告](os4-r6-pad-r3-validation.md)。

---
[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [Installer 1.2.3](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/installer-v1.2.3.md) · [Pad r3 发版说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-pad-r3.md) · [双端验证报告](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6-pad-r3-validation.md)
