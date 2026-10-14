# HyperOS Pad 4.0.15.0 · v0.1.2 · Apple Silicon · r3

Tag：`pad-v0.1.2-a17-hyperos4-yingtian-r3`。基于 Xiaomi Pad 9 Pro Max（yingtian）官方 **OS4.0.15.0.XBMCNXM / Android 17**，保持独立 `pad-v*` 版本线。

## 本版内容

- KernelSU 更新至 **v3.3.1 / 32680**，镜像内 ramdisk 与离线安装附件使用同一已校验版本。
- 与 Phone 共用 **Core 18 / Apps 7** 两个 KernelSU 模块。规则按内容、ABI 和硬件能力匹配，不按 AVD 名称、端口、宿主路径、OTA 文件名或 APK 版本号选择；未知内容与用户功能选择保留。
- 修复模块初始化与 framework 恢复时机，减少启动期间的重复认证和映射检查；缺少真实硬件的可选监控按能力处理。
- format 3 冻结运行包采用 `verified-bundle-runtime-v1` 校验协议，用户端不需要 NDK、原始 OTA 或生产者缓存。
- 保留 Pad 原厂横屏 **3408×2272 / 400 dpi**、`yingtian.xml`、HWUI Vulkan、Flutter 界面、天气、相机预览、60 Hz 与音频/色彩适配。默认 **4 核 / 4 GiB RAM / 32 GiB 存储**，资源均可调整；原机不支持的 AOD 不启用。
- 新 format 3 镜像要求 Installer **1.2.3 或更新版本**。最低版本绑定稳定的运行包协议；同一协议下的后续镜像不逐版提高安装器要求。

## 验证范围与限制

已用最终附件完成全新安装、模块激活与两次冷启动，核验 KernelSU root、SELinux Enforcing、安全 ADB、HWUI Vulkan、32 GiB 存储、完整模块资产与稳定序列号。天气首次启动成功；原厂首用权限确认后的完整内容与原生库映射，本轮未完成验证。

已知限制：一次观察中，来宾关机后宿主进程未自动退出；历史 warm-reboot / MoltenVK 问题仍未闭环。虚拟功耗模型、物理节点和厂商服务仍可能产生能力或 SELinux 诊断。最终新装实例的 framework ART DEX 和视觉验收、r2 → r3 实际保数据迁移、相机完整算法及长期稳定性未由本轮证明。详细证据与覆盖范围见[双端验证报告](os4-r6-pad-r3-validation.md)。

[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [Installer 1.2.3](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/installer-v1.2.3.md) · [Phone r6](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6.md) · [双端验证报告](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6-pad-r3-validation.md) · [Pad 系统说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/hyperos4-pad.md)
