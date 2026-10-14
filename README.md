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

Pad 使用独立的 `pad-v*` 版本线；手机与 OS3 的版本号继续沿用 `v*`。各版本独立保存镜像与用户数据，可同时安装。已发布镜像在 [GitHub Releases](https://github.com/NEORUAA/HyperOS-AVD/releases) 分卷提供，勿混用不同 Release 的文件；具体版本要求见对应发布说明。

Phone r6 与 Pad r3 共用 **Core 18 / Apps 7** 两个自适应 KernelSU 模块和离线状态页；规则按内容、ABI 与硬件能力匹配，保留用户选择和未知内容。format 3 冻结运行包使用 `verified-bundle-runtime-v1` 协议，最低要求为 [Installer 1.2.3](docs/releases/installer-v1.2.3.md)。该最低版本绑定稳定协议；沿用此协议的后续镜像无需逐版提高安装器版本。RAM、CPU 与存储均可调整，Pad 默认 4 GiB RAM 不构成上限。

发行附件校验与运行验证范围见[Phone r6 / Pad r3 验证报告](docs/releases/os4-r6-pad-r3-validation.md)。

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

需要 **Apple Silicon Mac、Python 3、Android Studio SDK 的 Emulator / Platform-Tools**。建议预留 60 GiB 加用户数据备份空间，无需 NDK 或手机 OTA；新建 / 扩容用户分区需 `brew install e2fsprogs`。

在终端运行，选择中文 / English 和安装目录即可自动拉取正式安装器：

```sh
curl -fsSL https://github.com/NEORUAA/HyperOS-AVD/releases/latest/download/install.sh | bash
```

ASCII 菜单自动下载并校验 OS3 / 手机 OS4 / Pad OS4 镜像，可自定义 **AVD 名称、RAM、存储和 CPU**，支持备份后升级与恢复。默认存储 32 GiB；Phone r6 与 Pad r3 需 **Installer 1.2.3 或以上**；历史版本要求见安装指南。也可下载 [Installer ZIP](https://github.com/NEORUAA/HyperOS-AVD/releases) 后双击 **`Install.command`**。

Installer 1.2.2 加入 macOS 系统 HTTPS 证书校验回退和完整备份后的加密用户分区继续扩容；Installer 1.2.3 在此基础上支持当前 format 3 运行包协议。

安装器与镜像独立发版：安装器使用 `installer-v*` 正式 Release 并占用 GitHub Latest；Phone / Pad 镜像使用各自的普通正式 Release，发布时加 `--latest=false`，让 Latest 下载入口继续指向安装器。也可直接从源码运行：

```sh
git clone https://github.com/NEORUAA/HyperOS-AVD.git
cd HyperOS-AVD
chmod +x Install.command
./Install.command
```

**Phone r5 → r6：关闭目标 AVD → 使用 Installer 1.2.3 或更新版本选择“升级” → 选择同一 `hongkong` 手机实例与 r6。Pad r2 → r3 使用同一流程，但选择 `yingtian` Pad 实例和 Pad r3。** 安装器先备份 userdata、QCOW2、加密密钥和配置，再检查固件与模块兼容性；失败可恢复。Phone 与 Pad 不能互相覆盖升级，保数据降级不支持。历史 r1 / r2 / r3 → r4 路径见[安装指南](docs/installing.md)。

[安装 / 升级 / 恢复指南](docs/installing.md) · [发布流程](docs/releasing.md)

## 兼容范围

**手机 OS4：** 保留全局 HWUI Vulkan、Flutter 玻璃、天气 / 相册、完整引导、60 Hz、Mac 色彩和声音适配，以及原版妙享背屏、独立窗口、双击息屏 / 唤醒和边缘返回；新用户默认常亮与 AOD。

**Pad OS4：** 保留平板布局与原厂 `yingtian.xml` 配置，使用平板独立的显示与 Vulkan 参数；默认 4 GiB RAM 可调整，原机不支持的 AOD 不启用。

**限制：** 相机完整算法、蓝牙、小米云服务、Google 登录与 Play Integrity 未完整验证；部分 APK、虚拟硬件日志、FindDevice 策略和宿主关机 / 重启仍有限制，见[双端验证报告](docs/releases/os4-r6-pad-r3-validation.md)。SELinux 保持 Enforcing，KernelSU root 域仍为 permissive。

[OS3 说明](docs/compatibility.md) · [手机 OS4 适配](docs/hyperos4.md) · [Pad OS4 适配](docs/hyperos4-pad.md) · [补丁与验证边界](docs/os4-patches.md)

致谢：小米、MysticGSI、[Android Emulator / AOSP](https://developer.android.com/studio/run/emulator-commandline)、[KernelSU](https://github.com/tiann/KernelSU)。镜像保留 SDK 的 `NOTICE.txt`，第三方组件归各自权利人所有。
