# 安装、升级与恢复指南

## 环境要求

- **硬件与系统**：Apple Silicon Mac（M 系列芯片）、macOS、Python 3
- **开发依赖**：Android Studio SDK 的 Emulator 与 Platform-Tools
- **分区工具**：新建或扩容用户数据分区需要 `e2fsprogs` 工具，安装器在修改磁盘前会自动检查该依赖：
  ```sh
  brew install e2fsprogs
  ```
- **磁盘空间**：建议预留 60 GiB 以上可用空间（用于解压镜像及升级备份）。预编译镜像开箱即用，无需配置 NDK 或下载官方手机 OTA。

## 启动安装器

在 macOS 终端中运行以下命令即可自动下载并启动安装器：

```sh
curl -fsSL https://github.com/NEORUAA/HyperOS-AVD/releases/latest/download/install.sh | bash
```

按提示选择语言（中文 / English）与工作目录即可。也可以前往 [Releases 页面](https://github.com/NEORUAA/HyperOS-AVD/releases) 下载 `Installer ZIP`，解压后双击运行 **`Install.command`**，或通过 Git 克隆本地运行：

```sh
git clone https://github.com/NEORUAA/HyperOS-AVD.git
cd HyperOS-AVD
chmod +x Install.command
./Install.command
```

### 版本要求与注意事项
- **安装器版本**：Phone r6 与 Pad r3 运行包采用 format 3 协议，需要 **Installer 1.2.3 或更高版本**。后续只要协议保持兼容，即可直接使用该安装器安装或升级，无需每次都单独更新安装器。
- **增量更新**：Installer 1.3.0 起支持同底包增量更新。发布版本提供匹配的增量包时，安装器只下载变更内容，并在本地还原完整目标版本。旧版安装器继续使用完整包。
- **仅增量修复版**：Phone r6.2、Pad r3.2 使用多来源直达增量，需要 **Installer 1.3.1 或更新版本**。首次安装自动下载所需完整基包，再应用到最新版的一条增量，无需先手动安装旧版。历史 r6.1 / r3.1 仍可使用 Installer 1.3.0。
- **证书错误排查**：若在下载阶段遇到 Python 环境引起的 `CERTIFICATE_VERIFY_FAILED` 证书报错，安装器已内置 macOS 系统原生证书信任链回退机制，同时严格核验域名与文件 SHA-256 哈希；若手动指定了自定义 CA，仍会优先遵循用户配置。

```text
+------------------------------------------------------------------+
| H Y P E R O S - A V D   /   INSTALLER 1.3.1                      |
+------------------------------------------------------------------+
| [1] Install a new AVD       [2] Upgrade / keep data              |
| [3] Start an instance       [4] RAM / storage / CPU              |
| [5] Browse images / updates [6] Recover / rollback               |
| [7] Installer updates      [0] Exit                              |
+------------------------------------------------------------------+
```

| 系统版本 | 推荐默认资源 | 数据系列 | 升级路径 |
| --- | --- | --- | --- |
| 手机 OS4 | 6 GiB RAM / 4 核 / 32 GiB 存储 | `hongkong` | 支持同系列平滑升级至 r6.2 |
| 平板 OS4 | 4 GiB RAM / 4 核 / 32 GiB 存储 | `yingtian` | 支持同系列平滑升级至 r3.2，与手机版独立 |
| 基础体验 OS3 | 2.5 GiB RAM / 2 核 / 32 GiB 存储 | `fuxi` | 基础 GSI 体验，与 OS4 系列独立 |

### 实例配置与启动
- **硬件资源**：内存、CPU 核心数与存储均可根据 Mac 实际配置自由调整（存储只支持扩容，不支持缩小；手机负一屏若需要完整的全局背景模糊，建议分配 8 GiB 内存）。
- **命名规范**：实例名称支持字母、数字、点、下划线及连字符。每个实例拥有完全独立的存储空间、镜像与 ADB 端口。
- **首次启动**：全新安装会初始化空白用户分区并进入官方开机引导。启动后若虚拟机屏幕弹出 ADB 调试授权请求，请勾选“始终允许”并确认，等待后台模块初始化完成。
- **启动方式**：日常使用推荐通过安装器的 **`[3] 启动已有实例`** 或实例目录下的 **`Start.command`** 启动，这样会自动加载 KernelSU root、传感器、60 Hz 刷新率及 macOS 色彩校准等配套适配（直接在 Android Studio 中点击启动会跳过这些配套初始化）。
- **功能特性**：手机版可选开启小米相机实验桥接；平板版会自动配置相机预览；手机 r3 及更新版本支持开启独立的副屏（背屏）窗口，支持双击息屏/唤醒与边缘返回手势。
- **重启生效**：首次启动会自动配置 Core 和 Apps 模块；若系统提示需要重启，请正常重启一次模拟器以完成全部模块激活。

### 触控板手势

Installer 1.3.1、Phone r6.2 和 Pad r3.2 均附带预编译触控板适配，OS3 也可通过更新后的 Installer 使用，无需自行编译。通过项目启动器启动 AVD，将指针放在模拟器屏幕内，即可通过 Magic Trackpad 或 Mac 内置触控板操作：

- 双指上下滑动：连续拖动列表、网页等内容。
- 双指左右滑动：连续拖动桌面页面，或操作应用内的横向内容。
- 松开双指：结束拖动，由 Android 处理惯性滚动。

滑动方向遵循 macOS 的滚动方向设置。手机、平板和独立背屏窗口均使用各自的屏幕位置与比例。普通鼠标滚轮继续使用模拟器原有的滚动方式。

更新启动器后，关闭并重新启动 AVD 即可生效。通过本源码目录启动时，可用 `./Start-HyperOS.command --no-host-trackpad` 临时关闭此适配。

---

## 升级现有实例

### 同底包增量更新

**r6.2 / r3.2**：使用 Installer 1.3.1 或更新版本。已有 r6.1 / r3.1 的实例优先下载对应的直达增量，直接还原最新版，无需重新下载原始完整包。r6 / r3 用户也有各自的直达增量。新用户直接选择最新版，安装器自动下载 r6 / r3 完整包和到最新版的一条增量，直接安装最新版，无需安装或启动中间版本。

| 当前版本 | 使用的增量 |
| --- | --- |
| Phone r6 | r6 → r6.2 |
| Phone r6.1 | r6.1 → r6.2 |
| Pad r3 | r3 → r3.2 |
| Pad r3.1 | r3.1 → r3.2 |

使用 Installer 1.3.1 或更新版本，照常选择 `[2] 保数据升级`。当目标版本提供与你当前版本匹配的增量包，而且官方底包没有变化时，安装器会自动显示增量包与完整包大小，只下载增量包。

安装器从实例中保存的旧版本文件还原新版本，逐文件校验完成后再备份数据、切换版本。应用、账号、设备标识和设置沿用原有升级流程。请保留实例目录中的 `versions` 文件夹，其中的旧版发行文件用于还原增量更新。

源版本文件缺失或被修改时，安装器会寻找可用的完整基包，必要时下载后再应用到目标版本的直达增量。提供完整目标包的版本也可回退到完整目标包。仅增量版本没有完整目标包，下载或还原失败时可保留缓存后重试。下载体积会减少，本地仍需预留完整版本和数据备份的磁盘空间。

### Phone r5 → r6 保数据升级
1. **先关闭当前运行中的手机 AVD**，然后运行 Installer 1.2.3 或更新版本。
2. 在主菜单选择 `[2] 保数据升级` → 选中你的 `hongkong` 手机实例 → 选择 `v0.2.5-a17-hyperos4-hongkong-r6`。
3. 安装器会自动校验固件与运行包兼容性，并在切换前对原始用户数据（userdata）、QCOW2 增量层、加密密钥及实例配置做完整备份。若检测到任何兼容性异常，安装器会主动中止以防数据受损。
4. 升级完成后，通过安装器或实例目录下的 `Start.command` 启动，原有应用、数据与设置将完整保留。

### Pad r2 → r3 保数据升级
1. **先关闭当前运行中的平板 AVD**，然后打开 Installer 1.2.3 或更新版本。
2. 选择 `[2] 保数据升级` → 选中你的 `yingtian` 平板实例 → 选择 `pad-v0.1.2-a17-hyperos4-yingtian-r3`。
3. 升级流程同手机版，安装器完成环境校验与数据备份后安全切换固件。
4. 升级完成后正常启动即可。**注意**：手机和平板属于不同硬件体系，无法互相跨设备覆盖升级；同时不支持保留用户数据的降级操作。

### 历史版本升级说明（Phone r1 / r2 / r3 → r4）
关闭目标 AVD，使用 **Installer 1.2.1** 选择升级至 `v0.2.3-a17-hyperos4-hongkong-r4`。安装器会自动备份用户分区及加密密钥，并平滑切换至 OS4.0.18.0 镜像，保留所有应用与设置。

- **旧版相机模块提示**：若升级时提示 `XiaomiCamera revision 1 cannot migrate`，说明固件尚未切换。请先选择“恢复 / 回滚”启动旧版 r2，将实验性相机桥接更新至 revision 2 并关闭 AVD，之后即可正常重试升级。
- **跨版本升级**：r1、r2、r3 实例均可直接平滑升级至 r4。

---

## 调整存储容量

1. 关闭目标 AVD，在安装器主菜单选择 **`[4] RAM / 存储 / CPU`**。
2. 输入新的存储容量（只能扩容，不支持缩小）。未加密的分区会在离线环境中安全扩容并校验文件系统。
3. **已加密分区的扩容**（Installer 1.2.2 起支持）：对于已开启元数据加密的实例（如由 6 GiB 扩容至 32 GiB），安装器会先对原始磁盘链建立完整备份，再在安全环境下同步扩展磁盘底层容器与解密后的 ext4 分区。
4. 若此前遇到过“配置已修改为 32 GiB 但系统内仍只识别 6 GiB”的情况，直接在该菜单中重新填入目标容量（例如 32 GiB），安装器会自动识别并完成在线分区扩展。

---

## 恢复与回滚

- **自动回滚**：若升级或配置切换过程中发生异常或意外中断，安装器会自动恢复到操作前的状态。
- **手动回滚**：如果升级后需要恢复旧版本，先关闭目标 AVD，进入安装器选择 **`[6] 恢复 / 回滚`**，即可选取升级前自动保存的快照备份进行还原。还原将精准恢复当时的固件版本、配置与用户数据。
- **安全机制**：安装器绝不会在后台擅自终止其他无关模拟器进程，也不会擅自清空用户数据。若遇到首次启动较慢的情况，请耐心等待系统完成首次 DEX 编译或安全关闭后执行冷启动。

## CLI / 离线安装

```sh
# Create a new Phone r6.2 instance.
python3 scripts/manage.py install --variant os4-official \
  --root "$HOME/HyperOS-AVD/instances/My_OS4" --name My_OS4 \
  --release v0.2.5-a17-hyperos4-hongkong-r6.2 --ram 6 --storage 32 --cores 4 --start

# Offline install or upgrade: keep the existing root, name and port.
python3 scripts/manage.py install --root /path/to/instance \
  --name My_OS4 --bundle /path/to/r6.2/manifest.json \
  --ram 6 --storage 32 --cores 4

python3 scripts/manage.py releases --variant os4-official
python3 scripts/manage.py releases --variant os4-pad
python3 scripts/manage.py installer-updates
python3 scripts/manage.py list
python3 scripts/manage.py start --root /path/to/instance

# Pad defaults to 4 GiB RAM / 32 GiB storage / 4 cores.
python3 scripts/manage.py install --variant os4-pad \
  --root "$HOME/HyperOS-AVD/instances/My_Pad" --name My_Pad \
  --release pad-v0.1.2-a17-hyperos4-yingtian-r3.2 --start
```

**离线安装说明**：如需离线安装，请将同一 Release 的所有分卷文件与 `manifest.json` 存放在同一目录下并保持原始文件名不变，安装器会自动校验 SHA-256 并完成解包安装。下载过程中若因网络波动或 GitHub API 限流中断，已下载的分卷缓存会自动保留，稍后重新运行即可断点续传。

**离线增量升级**：已有匹配旧版本的实例，只需保存目标 Release 的 `manifest.json` 与对应旧版本的全部增量分卷，再使用同一条 `--bundle` 命令升级。全新安装仍需完整包。旧文件校验失败时，离线升级需要补齐完整包，或联网重新运行升级。

**离线安装仅增量修复版**：将完整包和修复包放在相邻的两个目录，完整包目录名需与其 Release Tag 一致。例如 `v0.2.5-a17-hyperos4-hongkong-r6/` 与 `v0.2.5-a17-hyperos4-hongkong-r6.2/`。前者包含 r6 的完整分卷和 `manifest.json`，后者包含 r6 → r6.2 的增量分卷和 `manifest.json`。将 `--bundle` 指向 r6.2 的清单即可。已有 r6.1 且发行文件完整的实例只需 r6.1 → r6.2 增量。Pad 对应使用 r3 / r3.1 → r3.2。

**高级提示**：在 Android Studio 的 Device Manager 中修改 AVD 的显示名称（Display Name）是安全的；但请勿在文件管理器中直接重命名实例文件夹或底层 AVD ID，如需迁移路径请配合 `local/runtime.json` 保持配置同步。
