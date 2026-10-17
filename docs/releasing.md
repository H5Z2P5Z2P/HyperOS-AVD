# Release 发布

本页记录 Phone OS4 r6、Pad OS4 r3 和 Installer 1.2.3 的命名、打包与发布约定。Phone / Pad 使用普通正式 Release；创建镜像 Release 时使用 `--latest=false`，让 GitHub Latest 安装入口继续指向正式 Installer。Installer 1.2.3 发布为 Latest。

| 内容 | Tag | Release 标题 | 类型 |
| --- | --- | --- | --- |
| Installer | `installer-v1.2.3` | `HyperOS-AVD Installer v1.2.3` | 正式 Release / Latest |
| Phone OS4 r6 | `v0.2.5-a17-hyperos4-hongkong-r6` | `HyperOS 4.0.24.0 · v0.2.5 · Apple Silicon · r6` | 普通正式 Release / `--latest=false` |
| Pad OS4 r3 | `pad-v0.1.2-a17-hyperos4-yingtian-r3` | `HyperOS Pad 4.0.15.0 · v0.1.2 · Apple Silicon · r3` | 普通正式 Release / `--latest=false` |

Phone 与 Pad 是独立的 firmware / userdata family。Phone 使用小米 18 Pro（hongkong）官方 **OS4.0.24.0.XFRCNXM / Android 17**；Pad 使用 Xiaomi Pad 9 Pro Max（yingtian）官方 **OS4.0.15.0.XBMCNXM / Android 17**。两端共享 **Core 18 / Apps 7** 通用模块内容，平台上下文仍按机型和硬件能力绑定。

## Format 3 运行包协议

Phone 和 Pad 镜像均使用 format 3 运行包格式，并通过 `verified-bundle-runtime-v1` 协议验证与执行。该协议将最低安装器版本基线统一定义为 **1.2.3**；后续镜像只要保持同一协议，用户端均可直接使用 Installer 1.2.3 进行安装或升级，无需每次发布新镜像都单独提高安装器最低版本。发布的运行包完全支持离线使用，用户端无需配置 NDK、原始 OTA 或外部编译缓存。

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

Installer 打包前核对 `scripts/manage.py` 与生成的 `installer.json` 版本一致，bootstrap 应与包内文件逐字节一致。上面的发布示例对应 Installer 1.2.3，当前源码版本以 `scripts/manage.py` 为准。Phone / Pad 都携带完整 Core 18 / Apps 7 运行资产、WebUI、冻结规则和校验收据；生产者从已认证输入收集完整规则，缺少任一载荷时应失败，不能根据当前设备缩减通用包。

### 后续同底包更新的增量包

Phone 和 Pad 后续发布小修复时，如果官方底包没有变化，采用仅增量修复版，例如 Phone r6.1、Pad r3.1。保留它依赖的已发布完整包，新的 Release 只上传增量分卷、`manifest.json` 与 `SHA256SUMS`。安装器 1.3.1 会为新用户自动下载所需完整包，已有用户复用本地素材。

打包命令添加 `--delta-only --delta-from`，指向完整基包的发行文件清单。仅增量版只允许依赖一个完整包，不依赖另一个仅增量版本：

```sh
HYPEROS_AVD_WORKSPACE=/path/to/accepted-build \
  python3 scripts/package_release.py --variant os4-official \
  --version <new-tag> --output /path/to/new-release \
  --delta-only --delta-from /path/to/instance/versions/<full-base-tag>/local/installed-release.json
```

打包器核对官方 OTA 的 SHA-256、机型、固件版本及加密模板，只为同底包生成差分。完整基包必须已经解包，并保留清单列出的发行文件。仅增量模式直接生成差分，不会先创建数 GiB 的完整目标包。更换官方底包时不添加这两个参数，按完整包流程发布。

仅增量修复版的 `minimum_installer` 为 **1.3.1**，发行清单记录完整基包的原始清单和摘要。上传时保留基包 Release 的全部附件。若需要兼容旧安装器，仍可省略 `--delta-only`，同时分发完整目标包与增量包，这种模式保留 **1.2.3** 的安装基线。协议细节见 [安装器协议](installer-protocol.md#delta-only-repair-releases)。

## 附件和清单

仅增量修复批次使用以下命名。先发布 Installer 1.3.1 并设为 Latest，再发布两端修复版并设置 `--latest=false`。Phone r6、Pad r3 的完整包附件继续保留，供首次安装自动下载。

| 内容 | 输出目录 | 上传内容 |
| --- | --- | --- |
| Installer 1.3.1 | `releases/installer-v1.3.1/` | Installer ZIP、`install.sh`、`installer.json`、`SHA256SUMS` |
| Phone r6.1 | `releases/v0.2.5-a17-hyperos4-hongkong-r6.1/` | 全部增量分卷、`manifest.json`、`SHA256SUMS` |
| Pad r3.1 | `releases/pad-v0.1.2-a17-hyperos4-yingtian-r3.1/` | 全部增量分卷、`manifest.json`、`SHA256SUMS` |

发布说明分别使用 `docs/releases/installer-v1.3.1.md`、`docs/releases/os4-r6.1.md` 与 `docs/releases/os4-pad-r3.1.md`。以下保留原完整包批次的命名示例。

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

打包完成后，应核对分卷、文件清单、WebUI、安装器收据及 SHA-256 校验和，确保包含空白 userdata、安全 ADB 授权与正确的原机配置。

发布说明内容需与 [双端验证报告](releases/os4-r6-pad-r3-validation.md) 保持一致，客观呈现真实测试范围与已知问题（如相机高级夜景/录像算法待完善、部分虚拟功耗节点告警等），不作未经实测的过度承诺。

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
