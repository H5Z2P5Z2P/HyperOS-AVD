# HyperOS-AVD Installer v1.2.2

Release Tag：`installer-v1.2.2`。正式安装器版本 **1.2.2**。

## 相比 1.2.1 的更新亮点

- **证书校验优化**：修复了部分用户在 Python 环境下因本地 CA 证书缺失引起的 `CERTIFICATE_VERIFY_FAILED` 报错（[#123](https://github.com/NEORUAA/HyperOS-AVD/issues/123)）。当默认校验失败时，安装器会自动回退到 macOS 系统原生证书信任链，同时严格核验域名与下载文件的 SHA-256 哈希；若手动指定了自定义 CA，仍会优先遵循用户配置。
- **加密分区扩容**：支持对已启用元数据加密的用户分区进行安全扩容（例如由 **6 GiB 扩容至 32 GiB**）。扩容前会对底层磁盘进行离线备份，并在安全环境下同步扩展底层磁盘容器与解密后的 ext4 分区。
- **镜像生态配套**：配套手机 **v0.2.4 / r5** 与平板 **v0.1.1 / r2**，预编译包开箱即用，无需配置 NDK 或手机 OTA。

## 数据安全须知

升级或扩容操作前，请先关闭目标 AVD。安装器会自动备份用户数据（userdata）、QCOW2 覆盖层、加密密钥及实例配置，若遇异常可一键恢复。
注意：手机、平板与 OS3 分属不同产品线，不支持跨设备系列覆盖安装，同时不支持保留用户数据的降级操作。

---
[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [手机 r5 发版说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r5.md) · [Pad r2 发版说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-pad-r2.md)
