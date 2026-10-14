# HyperOS 4.0.24.0 · v0.2.5 · Apple Silicon · r6

Tag：`v0.2.5-a17-hyperos4-hongkong-r6`。基于小米 18 Pro（hongkong）官方 **OS4.0.24.0.XFRCNXM / Android 17**。

## 本版内容

- KernelSU 更新至 **v3.3.1 / 32680**，镜像内 ramdisk 与离线安装附件使用同一已校验版本。
- OS4 共用的 KernelSU 运行模块更新为 **Core 18 / Apps 7**。规则按内容、ABI 和硬件能力匹配，不按 AVD 名称、端口、宿主路径、OTA 文件名或 APK 版本号选择；保留用户功能选择和未知内容，并提供离线只读状态页。
- 修复背屏 AOD 输入状态与双击唤醒同步；缺少真实硬件的凭据、温控与 Qualcomm 可选监控按能力处理，避免已识别的无效重试。
- 减少初始化时重复哈希、映射和命名空间检查；完整认证与未知内容保护继续保留。
- 镜像携带 format 3 冻结运行包，安装时按 `verified-bundle-runtime-v1` 校验协议、载荷与收据。用户端不需要 NDK、原始 OTA 或生产者缓存。
- Phone 和 Pad 使用相同的 Core / Apps 正式模块内容；系统平台上下文仍按设备系列绑定。Phone r6 继续使用已审计的手机显示与 Vulkan 配置，不把手机参数套用到 Pad。
- 新 format 3 镜像要求 Installer **1.2.3 或更新版本**。协议最低版本固定为 1.2.3；后续镜像继续使用该协议时，无需每个镜像版本单独提高安装器最低版本。

默认资源为 **4 核 / 6 GiB RAM / 32 GiB 存储**，均可调整。Phone OS4、Pad OS4 与 OS3 属于不同数据系列；只允许同系列向前升级，不支持跨系列覆盖或保数据降级。升级前由安装器备份 userdata、QCOW2、加密密钥及实例配置，并执行固件和模块兼容检查。

## 验证范围与限制

已用最终附件完成全新安装、模块激活与两次冷启动，核验 KernelSU root、SELinux Enforcing、安全 ADB、HWUI Vulkan、32 GiB 存储与稳定序列号；桌面引擎和天气原生库的实际加载内容匹配本版补丁。

已知限制：部分 FindDevice 包策略在多次冷启动后仍未稳定确认；虚拟功耗模型、物理节点和厂商服务仍可能产生能力或 SELinux 诊断。历史宿主 warm-reboot / MoltenVK 问题尚未闭环。最终新装实例的 framework ART DEX 和视觉验收、r5 → r6 实际保数据迁移、相机完整算法及长期稳定性未由本轮证明。详细证据与覆盖范围见[双端验证报告](os4-r6-pad-r3-validation.md)。

[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [Installer 1.2.3](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/installer-v1.2.3.md) · [Pad r3](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-pad-r3.md) · [双端验证报告](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6-pad-r3-validation.md) · [补丁与运行证据](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/os4-patches.md)
