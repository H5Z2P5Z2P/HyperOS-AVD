# Release 发布

本页记录 Phone OS4 r6、Pad OS4 r3 和 Installer 1.2.3 的命名、打包与发布约定。Phone / Pad 使用普通正式 Release；创建镜像 Release 时使用 `--latest=false`，让 GitHub Latest 安装入口继续指向正式 Installer。Installer 1.2.3 发布为 Latest。

| 内容 | Tag | Release 标题 | 类型 |
| --- | --- | --- | --- |
| Installer | `installer-v1.2.3` | `HyperOS-AVD Installer v1.2.3` | 正式 Release / Latest |
| Phone OS4 r6 | `v0.2.5-a17-hyperos4-hongkong-r6` | `HyperOS 4.0.24.0 · v0.2.5 · Apple Silicon · r6` | 普通正式 Release / `--latest=false` |
| Pad OS4 r3 | `pad-v0.1.2-a17-hyperos4-yingtian-r3` | `HyperOS Pad 4.0.15.0 · v0.1.2 · Apple Silicon · r3` | 普通正式 Release / `--latest=false` |

Phone 与 Pad 是独立的 firmware / userdata family。Phone 使用小米 18 Pro（hongkong）官方 **OS4.0.24.0.XFRCNXM / Android 17**；Pad 使用 Xiaomi Pad 9 Pro Max（yingtian）官方 **OS4.0.15.0.XBMCNXM / Android 17**。两端共享 **Core 18 / Apps 7** 通用模块内容，平台上下文仍按机型和硬件能力绑定。

## Format 3 冻结运行包

Phone 和 Pad 镜像使用 format 3，并通过 `verified-bundle-runtime-v1` 校验与运行。协议最低安装器版本集中定义为 **1.2.3**；该值由协议版本确定，不随每个镜像修订递增。同一协议下继续发布镜像时，不需为单个镜像版本重新提升 Installer 最低版本。用户消费包离线工作，不依赖 NDK、原始 OTA 或生产者缓存。

安装器源码、`install.sh` bootstrap 元数据和压缩包版本保持一致。Installer 1.2.3 的 `install.sh` 应与包内文件逐字节一致；Phone / Pad `manifest.json` 则分别记录对应固件身份、userdata family、运行包协议和 `minimum_installer=1.2.3`。

## 独立构建与打包

从各自已核验的 packed system 镜像派生独立工作区。`local/build.json` 必须与实际镜像一致；准备器重新读取分区、核验默认值和启动策略，不依赖过期 raw 缓存。只复制固件、工具和配置，不复制 `avd/`、账号、个人标识或密钥；打包器创建空白 userdata。已存在的输出或模板不得覆盖，重做时使用新目录。

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check

python3 scripts/prepare_release_image.py \
  --source /path/to/accepted-phone --output work/os4-r6-release-build \
  --variant os4-official
python3 scripts/prepare_release_image.py \
  --source /path/to/accepted-pad --output work/os4-pad-r3-release-build \
  --variant os4-pad

HYPEROS_AVD_WORKSPACE="$PWD/work/os4-r6-release-build" \
  python3 scripts/package_release.py --variant os4-official \
  --version v0.2.5-a17-hyperos4-hongkong-r6 \
  --compat-cache-root /path/to/accepted-phone \
  --compat-cache-root /path/to/accepted-pad
HYPEROS_AVD_WORKSPACE="$PWD/work/os4-pad-r3-release-build" \
  python3 scripts/package_release.py --variant os4-pad \
  --version pad-v0.1.2-a17-hyperos4-yingtian-r3 \
  --compat-cache-root /path/to/accepted-phone \
  --compat-cache-root /path/to/accepted-pad
python3 scripts/package_installer.py
```

Installer 打包前核对 `scripts/manage.py`、bootstrap 与 `installer.json` 版本均为 **1.2.3**。Phone / Pad 都携带完整 Core 18 / Apps 7 运行资产、WebUI、冻结规则和校验收据；生产者从已认证输入收集完整规则，缺少任一载荷时应失败，不能根据当前设备缩减通用包。

## 附件和清单

| Release | 输出目录 | 上传内容 |
| --- | --- | --- |
| Installer 1.2.3 | `releases/installer-v1.2.3/` | Installer ZIP、`install.sh`、`installer.json`、`SHA256SUMS` |
| Phone OS4 r6 | `releases/v0.2.5-a17-hyperos4-hongkong-r6/` | 全部镜像分卷、`manifest.json`、`SHA256SUMS` |
| Pad OS4 r3 | `releases/pad-v0.1.2-a17-hyperos4-yingtian-r3/` | 全部镜像分卷、`manifest.json`、`SHA256SUMS` |

```sh
(cd releases/installer-v1.2.3 && shasum -a 256 -c SHA256SUMS)
(cd releases/v0.2.5-a17-hyperos4-hongkong-r6 && shasum -a 256 -c SHA256SUMS)
(cd releases/pad-v0.1.2-a17-hyperos4-yingtian-r3 && shasum -a 256 -c SHA256SUMS)
```

核对分卷、解包文件、冻结运行源码、WebUI、安装器收据、权限和 SHA-256；核对空白 userdata、安全 ADB、原机配置与可启动基线。模块不能替代恢复出厂后的首次系统扫描、Java / SELinux / kernel 或宿主适配验收。

发行正文应与[Phone r6 / Pad r3 验证报告](releases/os4-r6-pad-r3-validation.md)保持一致，并分别陈述附件完整性、实际来宾启动、模块加载和迁移验收。短时日志窗口、旧运行实例的 DEX 映射或模块资产校验，均不能代替最终附件的独立新装证据。保留 PowerInsight 对虚拟 CPU 功耗模型及部分功耗 / 温度节点的采样失败、厂商能力探测及 SELinux 拒绝诊断；不放宽 SELinux。历史宿主 warm-reboot 图形卡顿、MoltenVK mutex 崩溃及 Pad 来宾关机后宿主未自行退出的问题继续作为未闭环事项；相机完整拍照、HDR、录像算法及长期稳定性不由有限采样证明。

## 发布顺序

发布前复核最终 tag、附件哈希、Release 标题与对应正文，确保没有私有原始日志、识别码、OTA、缓存或用户数据进入提交或附件。先创建 Installer 1.2.3 正式 Release 并标记为 Latest，再发布 Phone r6 和 Pad r3 普通正式 Release，两个镜像均使用 `--latest=false`，不设置 Pre-release。可按以下命令核对发布参数和正文路径：

```sh
gh release create installer-v1.2.3 releases/installer-v1.2.3/* \
  --title 'HyperOS-AVD Installer v1.2.3' \
  --notes-file docs/releases/installer-v1.2.3.md --latest
gh release create v0.2.5-a17-hyperos4-hongkong-r6 \
  releases/v0.2.5-a17-hyperos4-hongkong-r6/* \
  --title 'HyperOS 4.0.24.0 · v0.2.5 · Apple Silicon · r6' \
  --notes-file docs/releases/os4-r6.md --latest=false
gh release create pad-v0.1.2-a17-hyperos4-yingtian-r3 \
  releases/pad-v0.1.2-a17-hyperos4-yingtian-r3/* \
  --title 'HyperOS Pad 4.0.15.0 · v0.1.2 · Apple Silicon · r3' \
  --notes-file docs/releases/os4-pad-r3.md --latest=false
```

发布后读取三条 Release 元数据，确认 Installer 为 Latest、两个镜像不是 Latest 且均为普通 Release；再校验公共安装入口、附件哈希和安装器菜单中各镜像版本。

[Phone r6 正文](releases/os4-r6.md) · [Pad r3 正文](releases/os4-pad-r3.md) · [Installer 1.2.3 正文](releases/installer-v1.2.3.md) · [双端验证报告](releases/os4-r6-pad-r3-validation.md) · [安装 / 升级 / 恢复指南](installing.md)
