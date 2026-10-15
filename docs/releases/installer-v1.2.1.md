# HyperOS-AVD Installer v1.2.1

Tag：`installer-v1.2.1`，**正式 Release**，可设为 Latest。镜像仍各自使用 Pre-release。

新增手机 OS4 **v0.2.3 / r4** 的安装和 **r1 / r2 / r3 → r4 保数据升级**，按同家族向前升级策略校验修复收据、固件身份与加密模板，后续修订无需逐版列出来源；继续支持 OS3、Pad、旧手机版本和 r2 → r3 升级。

升级前请先关闭目标 AVD。安装器会自动备份 userdata、QCOW2 覆盖层、加密密钥及实例配置，若遇异常可一键恢复；支持硬件资源调整与存储分区容量校验。注意：无法跨手机 / 平板 / OS3 互相覆盖升级，同时不支持保留用户数据的降级操作。

上传同目录安装器 ZIP、`install.sh`、`installer.json`、`SHA256SUMS`，共 4 件。用户可继续使用公开安装入口，或解压 ZIP 后运行 `Install.command`。

[安装指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [r4 镜像](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r4.md)
