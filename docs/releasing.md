# Release 发布

## 发行版本

开始迭代前，以 GitHub 上实际公开的 Release 为基准核对 Phone、Pad 和 Installer。源码版本、本地包与草稿不算已发布版本。

本次发行版本如下。Phone r6 与 Pad r3 的原始完整包继续保留，分别作为 r6.0 与 r3.0 使用，原标签及附件不改名。

| 内容 | Tag | Release 标题 | 发布说明 |
| --- | --- | --- | --- |
| Installer | `installer-v1.3.1` | `HyperOS-AVD Installer v1.3.1` | [Installer 1.3.1](releases/installer-v1.3.1.md) |
| Phone OS4 | `v0.2.5-a17-hyperos4-hongkong-r6.2` | `HyperOS 4.0.24.0 · v0.2.5 · Apple Silicon · r6.2` | [Phone r6.2](releases/os4-r6.2.md) |
| Pad OS4 | `pad-v0.1.2-a17-hyperos4-yingtian-r3.2` | `HyperOS Pad 4.0.15.0 · v0.1.2 · Apple Silicon · r3.2` | [Pad r3.2](releases/os4-pad-r3.2.md) |

本批次继续使用原官方底包：Phone 为小米 18 Pro（hongkong）**OS4.0.24.0.XFRCNXM / Android 17**，Pad 为 Xiaomi Pad 9 Pro Max（yingtian）**OS4.0.15.0.XBMCNXM / Android 17**。两端使用 **Core 20 / Apps 8**，补丁按实际内容、ARM64 架构与硬件能力选择。Phone 增加系统 Dolby 解码适配，Pad 镜像本次不包含该适配。

## 版本与增量规则

只有官方底包 OS 版本变化时，才递增 r 大版本并提供新的完整包。相同底包按 `rN.1`、`rN.2` 继续发布小修订，新的 Release 只提供增量包。Phone 与 Pad 独立维护版本序列。

每次小修订必须覆盖同一 r 大版本下全部已发布来源，直接还原目标版本。本批次必须包含以下四条路径：

| 系列 | 源版本 | 目标版本 |
| --- | --- | --- |
| Phone | r6（r6.0） | r6.2 |
| Phone | r6.1 | r6.2 |
| Pad | r3（r3.0） | r3.2 |
| Pad | r3.1 | r3.2 |

每条增量绑定源版本的准确清单及摘要，目标清单包含完整文件列表、大小与 SHA-256。生成后逐文件还原并校验目标。不得使用用户正在使用的 userdata、可变磁盘或未经校验的缓存作差分源。

已有用户优先使用当前版本的直达增量。新用户使用原完整基包，加上基包到最新版的一条增量，直接安装最新版。无需安装或启动中间版本。保留 r6、r3 的完整包与各历史修订附件，不能重新上传最新完整包代替历史来源覆盖。

## 运行包与安装器协议

Phone 和 Pad 继续使用 format 3 与 `verified-bundle-runtime-v1`，这个运行协议的固定安装基线仍为 **Installer 1.2.3**。`delta-only-v1` 由 Installer 1.3.0 支持，本批次多来源直达增量使用 `delta-only-v2`，最低要求为 **Installer 1.3.1**。

`delta-only-v2` 的目标没有完整分卷，`parts` 为空，`deltas` 覆盖全部历史来源，`base_release` 仍绑定原 rN.0 完整包。安装器先匹配当前实例的准确源清单与文件，直接应用对应补丁。只有首次安装或缺少可用源文件时才获取完整基包，之后一步还原到目标版本。旧版 `delta-only-v1` 和普通完整包继续兼容。协议字段详见[安装器协议](installer-protocol.md#delta-only-repair-releases)。

运行包必须携带离线所需的 Core / Apps 资产、WebUI、规则、收据及预编译宿主机适配。用户无需安装 NDK、编译触控板适配或下载 donor 镜像。

## 独立构建与打包

从已核验的 packed system 镜像派生独立工作区。`local/build.json` 必须与实际镜像一致。只复制固件、工具和配置，不复制运行实例的 `avd/`、账号、个人标识或密钥。打包器创建空白 userdata，已有输出或模板不得覆盖，重做时使用新目录。

先准备同一 r 大版本下每个已发布源版本的准确清单和完整发行文件。仅增量的历史修订先在独立目录还原，保留它原本的清单。以下 `/path/to/published/` 表示这些已解包且已校验的发行目录，不是用户正在使用的 AVD 镜像。

```sh
python3 scripts/prepare_release_image.py \
  --source /path/to/accepted-phone --output work/os4-r6.2-release-build \
  --variant os4-official
python3 scripts/prepare_release_image.py \
  --source /path/to/accepted-pad --output work/os4-pad-r3.2-release-build \
  --variant os4-pad

HYPEROS_AVD_WORKSPACE="$PWD/work/os4-r6.2-release-build" \
  python3 scripts/package_release.py --variant os4-official \
  --version v0.2.5-a17-hyperos4-hongkong-r6.2 \
  --output releases/v0.2.5-a17-hyperos4-hongkong-r6.2 \
  --compat-cache-root /path/to/accepted-phone \
  --compat-cache-root /path/to/accepted-pad \
  --delta-only \
  --delta-from /path/to/published/v0.2.5-a17-hyperos4-hongkong-r6/manifest.json \
  --delta-from /path/to/published/v0.2.5-a17-hyperos4-hongkong-r6.1/manifest.json

HYPEROS_AVD_WORKSPACE="$PWD/work/os4-pad-r3.2-release-build" \
  python3 scripts/package_release.py --variant os4-pad \
  --version pad-v0.1.2-a17-hyperos4-yingtian-r3.2 \
  --output releases/pad-v0.1.2-a17-hyperos4-yingtian-r3.2 \
  --compat-cache-root /path/to/accepted-phone \
  --compat-cache-root /path/to/accepted-pad \
  --delta-only \
  --delta-from /path/to/published/pad-v0.1.2-a17-hyperos4-yingtian-r3/manifest.json \
  --delta-from /path/to/published/pad-v0.1.2-a17-hyperos4-yingtian-r3.1/manifest.json

python3 scripts/package_installer.py
```

打包器核对官方 OTA 的 SHA-256、机型、固件版本及加密模板，仅为同底包生成差分。两次 `--delta-from` 缺一不可。也可指向解包目录内的 `local/installed-release.json`，清单旁的完整发行文件必须保留。仅增量模式直接生成差分，不会先创建数 GiB 的完整目标压缩包。

Installer 打包前核对源码版本、生成的 `installer.json` 与 ZIP 文件名均为 1.3.1，bootstrap 的 `install.sh` 与包内文件逐字节一致。Phone / Pad 的完整 Core 20 / Apps 8 通用资产必须齐全，不能按当前构建设备裁剪。

## 附件和清单

| 内容 | 输出目录 | 上传内容 |
| --- | --- | --- |
| Installer 1.3.1 | `releases/installer-v1.3.1/` | Installer ZIP、`install.sh`、`installer.json`、`SHA256SUMS` |
| Phone r6.2 | `releases/v0.2.5-a17-hyperos4-hongkong-r6.2/` | r6 → r6.2 与 r6.1 → r6.2 的全部增量分卷、`manifest.json`、`SHA256SUMS` |
| Pad r3.2 | `releases/pad-v0.1.2-a17-hyperos4-yingtian-r3.2/` | r3 → r3.2 与 r3.1 → r3.2 的全部增量分卷、`manifest.json`、`SHA256SUMS` |

每条增量的分卷名必须唯一，并记录各自大小与 SHA-256。下载目录、发行清单与发布说明使用同一版本号。打包完成后验证全部来源都能还原相同目标文件，再核对以下校验和：

```sh
(cd releases/installer-v1.3.1 && shasum -a 256 -c SHA256SUMS)
(cd releases/v0.2.5-a17-hyperos4-hongkong-r6.2 && shasum -a 256 -c SHA256SUMS)
(cd releases/pad-v0.1.2-a17-hyperos4-yingtian-r3.2 && shasum -a 256 -c SHA256SUMS)
```

检查提交与附件，不得包含私密原始日志、设备识别码、OTA 缓存、用户数据或临时构建文件。发布说明客观描述功能和已知限制，不写内部检查流水账。

## 发布顺序

发布时，先创建 Installer 1.3.1 正式 Release 并设为 Latest，再发布 Phone r6.2 与 Pad r3.2 普通正式 Release。两个镜像均使用 `--latest=false`，不设置 Pre-release，GitHub Latest 安装入口继续指向 Installer。原 r6、r3 完整包及历史修订附件全部保留。

发布后检查三条 Release 元数据与公共安装入口，确认 Installer 为 Latest，两个镜像为普通 Release，菜单能列出相应版本，附件与清单中的哈希一致。

[Phone r6.2 正文](releases/os4-r6.2.md) · [Pad r3.2 正文](releases/os4-pad-r3.2.md) · [Installer 1.3.1 正文](releases/installer-v1.3.1.md) · [安装 / 升级 / 恢复指南](installing.md)
