# HyperOS-AVD Installer v1.3.1

Release Tag：`installer-v1.3.1`。

- 支持同底包的全历史直达增量。Phone r6、r6.1 可分别一步升级到 r6.2，Pad r3、r3.1 可分别一步升级到 r3.2。
- 优先匹配当前实例的准确源版本与清单，复用其发行文件，只下载对应增量。r6.1 / r3.1 用户无需重新下载原始完整包。
- 新用户直接选择最新版，安装器自动下载原完整基包和到最新版的一条增量，直接完成安装，无需安装或启动中间版本。
- 附带预编译触控板适配，支持 Magic Trackpad 和 Mac 内置触控板的双指横竖滑动。方向遵循 macOS 设置，松手后由 Android 处理惯性，Phone、Pad 与 OS3 均可通过项目启动器使用。
- 继续支持 `delta-only-v1`、同底包文件与数据块差分、断点续传及离线安装，沿用升级前备份、配置保留与恢复流程。

Phone r6.2 / Pad r3.2 的 `delta-only-v2` 发行需要本安装器或更新版本。原有完整运行包继续使用 `verified-bundle-runtime-v1`，协议基线仍为 Installer 1.2.3。

安装器附件包含 `Installer ZIP`、`install.sh`、`installer.json` 与 `SHA256SUMS`。操作说明见[安装、升级与恢复指南](https://github.com/NEORUAA/HyperOS-AVD/blob/main/docs/installing.md)。
