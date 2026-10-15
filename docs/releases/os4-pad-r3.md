# HyperOS Pad 4.0.15.0 · v0.1.2 · Apple Silicon · r3

Release Tag：`pad-v0.1.2-a17-hyperos4-yingtian-r3`。本镜像基于 Xiaomi Pad 9 Pro Max（代号 `yingtian`）官方 **OS4.0.15.0.XBMCNXM / Android 17** 移植，保持独立的 `pad-v*` 平板版本线。

## 更新亮点

- **KernelSU 更新**：内置 KernelSU 模块升级至 **v3.3.1 / 32680**。
- **Core 18 / Apps 7 通用模块**：与手机版共享自适应底层兼容模块，按运行时特征自动应用平板显示与硬件适配。
- **启动优化**：优化模块初始化与 framework 挂载流程，避免了开机阶段的重复校验，显著改善冷启动速度。
- **离线支持**：采用 format 3 运行包协议（`verified-bundle-runtime-v1`），完全支持离线安装，要求 **Installer 1.2.3 或更高版本**（后续同协议镜像无需频繁更新安装器）。
- **平板特性保留**：完整保留原厂横屏布局（**3408×2272 / 400 dpi**）、`yingtian.xml` 机型配置、HWUI Skia-Vulkan 硬件加速、Flutter 玻璃材质、天气动态渲染、相机预览、60 Hz 刷新率及 macOS 色彩校准。默认分配 **4 核 / 4 GiB 内存 / 32 GiB 存储**（可自由调大；原机不支持的 AOD 保持关闭）。

## 适配状态与已知限制

- **验证情况**：新安装与冷启动已完成测试，KernelSU root、全局 SELinux Enforcing、安全 ADB 调试、Vulkan 渲染及平板横屏显示均正常工作。
- **已知限制**：
  - 相机目前支持虚拟场景预览与基础拍照，夜景、人像算法及高质量录像仍有待完善；
  - 蓝牙、小米云服务与 Google 服务暂未适配；
  - 部分 macOS 环境下，虚拟机内关机后宿主模拟器窗口可能不会自动退出，手动关闭窗口即可；
  - 更多验证记录请参考 [双端验证报告](os4-r6-pad-r3-validation.md)。

---
[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [Installer 1.2.3](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/installer-v1.2.3.md) · [Phone r6 发版说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6.md) · [双端验证报告](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6-pad-r3-validation.md) · [Pad 系统说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/hyperos4-pad.md)
