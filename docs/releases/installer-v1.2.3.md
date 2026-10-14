# HyperOS-AVD Installer v1.2.3

Tag：`installer-v1.2.3`。正式安装器版本 **1.2.3**，用于 Phone r6、Pad r3 及后续采用同一 format 3 运行包协议的镜像。

## Format 3 运行包协议

- Installer 与镜像通过 `verified-bundle-runtime-v1` 协议交接。安装器先校验 manifest、文件清单、哈希和最低版本，再启动冻结的运行包入口；运行包在离线环境工作，不依赖 NDK、原始 OTA 或生产者缓存。
- 修复 KernelSU 3.3.1 新装状态验证，继续保留精确哈希、所有权及未知安装保护；离线打包可复用完整已认证的通用 Apps 包，并保留自定义文件。
- Phone r6 与 Pad r3 的 `minimum_installer` 均为 **1.2.3**。该最低版本是协议基线，不与单个镜像修订号绑定；后续镜像保持同一协议时仍可使用 Installer 1.2.3，无需为每个镜像版本单独升级安装器。
- Installer 1.2.2 已包含的 macOS 系统 HTTPS 证书校验回退和加密用户分区继续扩容能力继续保留。下载仍校验证书、域名、附件完整性与 SHA-256；扩容仍要求完整离线备份，并以解密 ext4 的实际容量、UUID 和文件探针确认结果。

## 升级与数据安全

升级或扩容前关闭目标 AVD。安装器先保存 userdata、QCOW2、加密密钥和实例配置，再检查固件身份、版本方向、用户模块所有权与兼容协议；未知内容或不完整备份会阻止切换。中断可恢复，不以旧备份覆盖激活后新增的数据。不支持跨 Phone / Pad / OS3 升级或保数据降级。

Phone r6 与 Pad r3 使用不同 userdata family。安装器只允许各自系列内向前升级，并保留原有实例名称、稳定身份、硬件配置与用户功能选择。预编译消费包可离线安装；发布端保留完整运行资产和校验收据。

Phone r5 → r6 与 Pad r2 → r3 的最终附件保数据迁移本轮均未执行；安装器支持路径与实际迁移验收分开记录，见[Phone r6 / Pad r3 验证报告](os4-r6-pad-r3-validation.md)。

## 附件

安装器发行包由同一目录的以下四项组成：**Installer ZIP、`install.sh`、`installer.json`、`SHA256SUMS`**。bootstrap 与 ZIP 使用同一 `install.sh` 内容及 SHA-256 收据。安装器走正式 Latest 渠道；OS 镜像分别使用普通正式 Release，并通过 `--latest=false` 保持 Latest 安装入口指向安装器。

[安装 / 升级 / 恢复指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md) · [Phone r6](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-r6.md) · [Pad r3](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releases/os4-pad-r3.md) · [发布流程](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/releasing.md)
