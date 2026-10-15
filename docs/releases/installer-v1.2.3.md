# HyperOS-AVD Installer v1.2.3

Release Tag：`installer-v1.2.3`。正式安装器版本 **1.2.3**，全面支持 Phone r6、Pad r3 以及后续采用 format 3 协议的运行包镜像。

## 更新亮点

- **Format 3 运行包协议支持**：通过 `verified-bundle-runtime-v1` 协议规范交接。安装器先验证镜像完整性与环境版本，再执行离线运行包；安装过程完全离线可用，无需额外安装 NDK 或下载手机 OTA。
- **协议基线统一**：将 Phone r6 与 Pad r3 的最低安装器要求设定为 **1.2.3**。该基线与协议版本绑定，只要后续镜像协议保持兼容，均可直接使用本安装器，无需每次发版都强制更新安装器。
- **状态验证修复**：修复了在新装实例中对 KernelSU 3.3.1 的状态检测逻辑。
- **继承特性**：完整保留 Installer 1.2.2 引入的特性，包括 Python CA 证书校验失败时自动回退 macOS 系统证书信任链，以及对已启用元数据加密的用户分区进行无损安全扩容。

## 数据安全与升级须知

- **备份保障**：升级或扩容操作前，请先关闭目标 AVD。安装器会自动对用户数据（userdata）、磁盘覆盖层（QCOW2）、加密密钥及实例配置进行安全快照备份，若遇异常可一键回滚。
- **产品线独立**：手机（`hongkong`）、平板（`yingtian`）与 OS3 属于不同设备体系，仅支持在各自系列内平滑升级，无法跨设备相互覆盖升级；同时不支持保留用户数据的降级操作。

## 附件清单

安装器发行包由以下文件组成：
- **`Installer ZIP`**：独立安装器压缩包（解压后双击 `Install.command` 运行）
- **`install.sh`**：一键安装脚本
- **`installer.json`** 与 **`SHA256SUMS`**：版本元数据与哈希校验和

---
[安装 / 升级 / 恢复指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [Phone r6 发版说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6.md) · [Pad r3 发版说明](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-pad-r3.md) · [版本发布流程](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releasing.md)
