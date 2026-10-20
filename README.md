# HyperOS-AVD

在 Apple Silicon Mac 的 Android Studio ARM64 模拟器中运行小米 HyperOS，支持 **ADB、KernelSU root、GPU 加速和全局 SELinux Enforcing**。

**手机与平板 OS4 均由小米官方 OTA 原包移植**，保留原厂系统应用、桌面、首次开机引导及 Flutter 玻璃界面；OS3 使用 MysticGSI，适合体验基础功能。

## 版本选择

| | HyperOS 3 | HyperOS 4 手机 | HyperOS 4 Pad |
| --- | --- | --- | --- |
| 系统 | 3.0.2.0.WMCCNXM / Android 16 | 4.0.24.0.XFRCNXM / Android 17 | 4.0.15.0.XBMCNXM / Android 17 |
| 来源 | 小米 13（fuxi）MysticGSI | 小米 18 Pro（hongkong）官方 OTA | Xiaomi Pad 9 Pro Max（yingtian）官方 OTA |
| 显示 | 手机布局 | 主屏 1120×2436 / 480 dpi，背屏 912×596 / 450 dpi | 横屏 3408×2272 / 400 dpi |
| 默认资源 | 2 核 / 2.5 GiB | 4 核 / 6 GiB RAM / 32 GiB 存储（负一屏完整模糊建议 8 GiB RAM） | 4 核 / 4 GiB RAM / 32 GiB 存储 |
| 发布说明 | [兼容范围](docs/compatibility.md) | [r5](docs/releases/os4-r5.md) · [v0.2.5 / r6](docs/releases/os4-r6.md) | [r2](docs/releases/os4-pad-r2.md) · [v0.1.2 / r3](docs/releases/os4-pad-r3.md) |

Pad 采用独立的 `pad-v*` 版本号，手机与 OS3 沿用 `v*` 版本号。各版本镜像与用户数据完全独立，支持多实例共存。发布镜像均在 [GitHub Releases](https://github.com/NEORUAA/HyperOS-AVD/releases) 提供分卷下载，请不要混用不同 Release 的分卷文件。

Phone r6 与 Pad r3 均搭载 **Core 18 / Apps 7** 自适应 KernelSU 模块与离线状态页。运行包采用 format 3 协议，只需使用 [Installer 1.2.3](docs/releases/installer-v1.2.3.md) 或更高版本即可安装（后续镜像只要协议保持兼容，无需重复升级安装器）。虚拟机的 CPU、内存与存储空间均可自由调整（平板默认的 4 GiB 内存仅为推荐起步配置，并非上限）。

小修复采用仅增量版本：[Phone r6.1](docs/releases/os4-r6.1.md) / [Pad r3.1](docs/releases/os4-pad-r3.1.md) 更新至 **Core 19 / Apps 8**，需要 [Installer 1.3.0](docs/releases/installer-v1.3.0.md)。已有用户只需下载修复包，新用户直接选择修复版，安装器会自动下载它依赖的完整包并完成安装。

完整的发布附件校验与运行验证记录请参考 [Phone r6 / Pad r3 验证报告](docs/releases/os4-r6-pad-r3-validation.md)。

## Pad OS4 截图

<table>
  <tr>
    <td align="center" width="33.33%"><img src="screenshots/os4_pad/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-06%20%E4%B8%8A%E5%8D%883.13.44.png" width="360" alt="Pad OS4 横屏桌面与小组件" /><br />平板桌面与小组件</td>
    <td align="center" width="33.33%"><img src="screenshots/os4_pad/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-06%20%E4%B8%8A%E5%8D%883.13.53.png" width="360" alt="Pad OS4 设置中的系统版本与机型" /><br />系统版本与机型</td>
    <td align="center" width="33.33%"><img src="screenshots/os4_pad/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-06%20%E4%B8%8A%E5%8D%883.14.02.png" width="360" alt="Pad OS4 KernelSU 与 SELinux 强制执行" /><br />Root / 强制执行</td>
  </tr>
</table>

## 手机 OS4 截图

**r3：OS4.0.18.0 与独立背屏窗口。**

<img src="screenshots/os4/r3/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-06%20%E4%B8%8B%E5%8D%889.15.47.png" width="640" alt="OS4 r3 系统版本与独立妙享背屏窗口" />

以下 4×2 为 r2 的界面参考，后续手机版保留这些功能。

<table>
  <tr>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.21.27.png" width="220" alt="OS4 首次开机引导" /><br />首次开机引导</td>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.21.44.png" width="220" alt="OS4 语言设置" /><br />语言设置</td>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.23.03.png" width="220" alt="OS4 小米账号" /><br />小米账号</td>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.25.00.png" width="220" alt="OS4 设置完成" /><br />设置完成</td>
  </tr>
  <tr>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.26.08.png" width="220" alt="OS4 原生桌面与玻璃" /><br />原生桌面与玻璃</td>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.27.25.png" width="220" alt="OS4 KernelSU / Enforcing" /><br />Root / 强制执行</td>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.27.44.png" width="220" alt="OS4 系统版本" /><br />系统版本</td>
    <td align="center" width="25%"><img src="screenshots/os4/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-03%20%E4%B8%8A%E5%8D%883.28.03.png" width="220" alt="OS4 全天候息屏" /><br />全天候息屏</td>
  </tr>
</table>

<details>
<summary>OS3 截图</summary>

<table>
  <tr>
    <td align="center" width="25%"><img src="screenshots/os3/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-02%20%E4%B8%8A%E5%8D%886.46.18.png" width="200" alt="OS3 桌面" /><br />桌面</td>
    <td align="center" width="25%"><img src="screenshots/os3/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-02%20%E4%B8%8A%E5%8D%886.46.39.png" width="200" alt="OS3 KernelSU" /><br />Root</td>
    <td align="center" width="25%"><img src="screenshots/os3/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-02%20%E4%B8%8A%E5%8D%886.47.22.png" width="200" alt="OS3 设置" /><br />设置</td>
    <td align="center" width="25%"><img src="screenshots/os3/%E5%B7%B2%E7%B2%98%E8%B4%B4%202026-10-02%20%E4%B8%8A%E5%8D%886.49.35.png" width="200" alt="OS3 系统版本" /><br />系统版本</td>
  </tr>
</table>

</details>

## 安装与升级

### 前置要求
- **系统与硬件**：Apple Silicon Mac（M 系列芯片）、Python 3
- **开发工具**：Android Studio SDK 的 Emulator 与 Platform-Tools
- **磁盘工具**：新建或扩容用户分区需执行 `brew install e2fsprogs`
- **磁盘空间**：建议预留 60 GiB 以上可用空间（用于解压镜像与数据备份）。直接使用预构建镜像时，无需安装 NDK 或下载手机官方 OTA。

### 一键安装
在 macOS 终端中运行以下命令，按提示选择语言及安装目录，即可自动拉取并启动安装器：

```sh
curl -fsSL https://github.com/NEORUAA/HyperOS-AVD/releases/latest/download/install.sh | bash
```

也可前往 [Releases](https://github.com/NEORUAA/HyperOS-AVD/releases) 下载 `Installer ZIP`，解压后双击 **`Install.command`**；或克隆仓库直接运行：

```sh
git clone https://github.com/NEORUAA/HyperOS-AVD.git
cd HyperOS-AVD
chmod +x Install.command
./Install.command
```

安装器提供了交互式终端菜单，支持自动下载并校验 OS3、手机 OS4 与平板 OS4 镜像，支持自定义 **AVD 名称、内存大小、存储空间及 CPU 核心数**，并支持实例管理、硬件配置修改、备份升级与一键回滚。

### 升级现有实例
- **Phone r5 → r6**：先关闭当前手机 AVD，运行 Installer 1.2.3 或更高版本，选择“升级”并选中当前 `hongkong` 实例与 r6 镜像。
- **Pad r2 → r3**：流程同上，选择对应的 `yingtian` 平板实例与 r3 镜像。
- **安全保障**：升级前安装器会自动对完整用户数据（userdata）、磁盘覆盖层（QCOW2）、加密密钥及配置进行快照备份，验证兼容性后再行切换，发生异常可随时恢复。
- **注意**：手机和平板属于不同设备系列，不支持互相覆盖升级；同时不支持保留用户数据的降级操作。历史版本的升级说明请查阅 [安装与升级指南](docs/installing.md)。

[安装 / 升级 / 恢复指南](docs/installing.md) · [版本发布流程](docs/releasing.md)

## 兼容性与已知限制

- **触控板手势**：通过项目启动器打开 AVD 后，Magic Trackpad 和 Mac 内置触控板支持双指上下滚动、左右滑动切页。滑动从指针所在的屏幕位置开始，方向遵循 macOS 的滚动设置。
- **手机 OS4**：完整保留原厂开机引导、官方系统应用（天气、相册等）、全局 HWUI Vulkan 与 Flutter 玻璃模糊效果；已适配 60 Hz 刷新率、macOS 色彩与音频输出；支持小米 18 Pro 独特的副屏（妙享背屏）独立窗口、双击息屏/唤醒与侧滑手势，默认启用全天候息屏（AOD）与常亮支持。
- **平板 OS4**：保留原版横屏平板桌面布局与原厂设备特性，独立调校了显示与 Vulkan 渲染参数。内存推荐 4 GiB 起步且支持自由调大；原机硬件不支持的 AOD 功能保持关闭。
- **已知限制**：
  - 相机目前仅支持虚拟场景基础预览与普通拍照，高级夜景、人像、变焦算法及高质量录像尚未完整适配；
  - 蓝牙、小米云服务、Google 登录以及 Play 完整性认证（Play Integrity）暂未完成兼容；
  - 全局 SELinux 严格保持 Enforcing 状态，KernelSU root 运行域依官方规则保持 permissive；
  - 更多技术细节与测试边界请参考 [双端验证报告](docs/releases/os4-r6-pad-r3-validation.md)。

[OS3 兼容性说明](docs/compatibility.md) · [手机 OS4 适配文档](docs/hyperos4.md) · [平板 OS4 适配文档](docs/hyperos4-pad.md) · [补丁架构与维护](docs/os4-patches.md)

致谢：小米、MysticGSI、[Android Emulator / AOSP](https://developer.android.com/studio/run/emulator-commandline)、[KernelSU](https://github.com/tiann/KernelSU)。镜像保留 SDK 的 `NOTICE.txt`，第三方组件归各自权利人所有。
