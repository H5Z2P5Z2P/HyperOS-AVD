# 官方 HyperOS 4 适配

将小米 18 Pro（`hongkong`）的 **OS4.0.17.0.XFRCNXM / Android 17（API 37）** 官方 OTA 转换为 AVD 镜像。硬件层使用 API 36 ARM64 revision 7 的 ranchu Vendor、4 KB 内核及 KernelSU 3.3.0。

## 构建与启动

使用发布的预构建镜像时，只需 Emulator、Platform-Tools 与 Python 3。v0.2.1 推荐双击 `Install.command` 自动下载、安装或升级；旧手动入口仍为 `./Setup.command --bundle /path/to/manifest.json` 和 `./Start-HyperOS4-Official.command`，使用 `work/os4-official/`。无需手机 OTA、NDK 或 Build-Tools。下述依赖仅用于重建镜像。

需要原始官方 OTA ZIP、下表中的原始签名 APK、Android Studio SDK、Python 3、JDK 17+，以及 `brew install erofs-utils e2fsprogs lz4`。天气兼容库还需 Android NDK 30。首次提取需要 `tools/payload-dumper-go`，建议预留至少 80 GiB 空间。

```sh
python3 scripts/build_os4_official.py --zip /path/to/hongkong-ota_full-OS4.0.17.0.XFRCNXM-user-17.0-9cf2afb0fc.zip
./Start-HyperOS4-Official.command
```

源分区默认保存到 `work/os4-official/input/hongkong-4.0.17/`，也可用 `--partitions` 指定已提取的 `system / system_ext / product / mi_ext / mi_product`。构建器将这些分区合并为 4 KB EROFS，保留文件权限、所有者、SELinux 与 capability 标签，并合入小米覆盖层和 OS4 软件版本属性。

OS4 默认分配 **6 GiB 内存**（`hw.ramSize=6144`）。原版负一屏会根据实际内存选择模式：≤4 GiB 时进入精简模式，将“添加小组件”替换为设置按钮；6 GiB 保留“＋”入口，但背景模糊按中档设备降级。需要完整背景模糊时，可在 `work/os4-official/config/avd.ini` 中设置 `hw.ramSize=8192`，关闭该 AVD 后通过项目启动器冷启动；8 GiB 已确认恢复 `BLUR_VIEW`、顶部玻璃和小组件选择页，保留应用原签名与用户卡片，此项无需修改 Flutter 引擎。

## 天气与相册预装

| 应用 | 固定版本 | 系统路径 |
| --- | --- | --- |
| 天气 | 18.0.0.27-R | `/product/app/MIUIWeather/MIUIWeather.apk` |
| 相册 | 5.4.2.10-0907-cn | `/product/app/MIUIGallery/MIUIGallery.apk` |

官方 OTA 原本将它们放在 `/product/data-app`，依赖真机首次开机时的安装解包流程。AVD 镜像将其调整为标准系统预装目录，采用官方原版签名 APK，并预装配套的 ARM64 原生渲染兼容库（包含天气的 Flutter / ANGLE 补丁与相册阴影兼容补丁）。新建实例时开箱即用，无需从应用商店重新下载；现有用户数据也会完整保留，后续仍可正常接收兼容签名的版本更新。

构建器默认读取 `work/os4-official/input/preinstalled-apps/MIUIWeather.apk` 与 `MIUIGallery.apk`，也可通过 `--preinstalled-apps /path/to/apks` 指定目录。在已安装这两个固定版本的官方 OS4 AVD 中，可导出原始签名 APK：

```sh
python3 scripts/preinstall_os4_apps.py --export
```

为已有适配镜像构建独立预装候选（不关闭 AVD、不覆盖当前镜像）：

```sh
python3 scripts/preinstall_os4_apps.py --prepare-image
```

候选位于 `work/os4-official/work/preinstalled-candidate/`。替换镜像前必须关闭**官方 OS4 AVD**，备份 `images/system.img` 与 `work/hyperos-system.img`，保留 `avd/` 用户数据。发布预构建系统镜像时已内置这两个应用，日常使用无需手动导入。

## 启动与系统配置

AVD 默认机型标识为 `HyperOS_4_Official_API_37`，ADB 端口为 `emulator-5574`，默认分配 4 核 CPU 与 6 GiB 内存。

- **音频输出**：默认开启，声音通过 macOS 当前默认音频输出设备播放。启动脚本不会传入 `-no-audio`；底层补丁为 tinyalsa 增加了错误重置与有限重试逻辑，避免持续播放时底层因偶发写入错误而丢失音频流。
- **屏幕分辨率与 AOD**：主屏采用小米 18 Pro 官方规格的 **1120×2436、480 dpi**。模拟器机型配置完整复用原厂 `hongkong.xml`，默认开启全天候息屏（AOD）并保持常亮；用户在系统设置中调整息屏选项后会被正常持久化。
- **色彩与 macOS 显示**：系统默认采用自然色彩模式（`display_color_mode=0`，饱和度 1.0）。同时，项目启动脚本会自动为 macOS 模拟器窗口与 Metal 渲染层配置 **sRGB 色彩空间标记**，消除了因色彩空间映射不当引起的画面过饱和与偏艳问题，色彩表现与真机保持一致。
- **主屏横屏**：主屏与背屏使用独立窗口时，旋转主屏会按主屏自身尺寸调整窗口，并恢复背屏的触摸区域，修复横屏画面被拉伸、点击位置偏移和旋转后背屏无法操作的问题。通过项目启动入口自动加载，按模拟器实际的 ARM64 多屏接口适配，无需按 Emulator 或 AVD 版本配置。接口不兼容时会在启动日志中说明原因。
- **60 Hz 刷新率锁定**：系统配置与启动服务将 SurfaceFlinger 实际渲染帧率与面板刷新率均锁定为稳定的 60 Hz，彻底解决了此前合成器以 20 Hz 低帧渲染引起的滑动卡顿与掉帧现象。
- **渐进式模糊**：通过 `persist.sys.gradient_blur_perf=false` 选用原生 HWUI 的通用 Skia 路径，解决了控制中心与搜索栏滑动时高斯模糊过渡丢失的问题。
- **传感器与模拟防误触**：启动器将虚拟距离与光线传感器初值设为 `5 cm / 200 lux`，避免模拟器默认的 `1 cm / 0 lux` 误触发相机防误触界面。
- **原厂机型身份与序列号**：内置小米 18 Pro（`hongkong` / `M610BB`）完整机型身份，并在首次启动时生成符合小米特征的模拟序列号，避免第三方应用将虚拟机识别为通用 Pixel。
- **首次开机引导（OOBE）**：镜像默认禁用了缺少硬件安全芯片支持的查找设备状态 Provider（`FindDeviceStatusManagerProvider`），确保首次开机向导可以顺畅通行进入桌面，不会在向导阶段黑屏。用户若确需跳过引导，可通过 `./Start-HyperOS4-Official.command --skip-oobe` 启动。
- **桌面启动**：系统启动前预设 `ro.miui.product.home=com.miui.home`，确保系统首次扫描时默认以小米桌面作为主 Launcher，避免误缓存为原生 Launcher3。


```sh
adb -s emulator-5574 shell "su -W -c 'id; getenforce'"
adb -s emulator-5574 emu kill
```

## 系统状态与兼容情况

| 功能模块 | 适配状态与说明 |
| --- | --- |
| 系统与桌面 | 正常启动，完整保留小米桌面、全局手势与多任务后台 |
| Root 与 SELinux | 内置 KernelSU root 支持，SELinux 保持全局 Enforcing 强制模式 |
| ADB 调试 | 正常连接，保留标准安全调试授权（`ro.adb.secure=1`） |
| Flutter 渲染 | 已修复深度范围、Float16 与缓冲区对齐；桌面快捷菜单文字、图标及玻璃模糊材质均正常显示；相册菜单与底部控件阴影正常 |
| 官方天气 / 相册 | 官方签名应用已固化至系统镜像，配套预装 ARM64 原生渲染兼容库 |
| 天气动态渲染 | 搭载专属 ANGLE Vulkan 桥接，温度、文字卡片及动态天空渲染正常 |
| 桌面导航与多任务 | 默认锁定为小米桌面（`RecentsActivity`），全面屏手势与多任务卡片滑动流畅 |
| 负一屏与高斯模糊 | 分配 6 GiB 内存时保留小组件添加入口；分配 8 GiB 内存时完整支持全屏背景高斯模糊与玻璃效果 |
| 首次开机向导 | 已禁用引起向导卡死的查找设备状态查询，全新安装可顺利完成开机向导进入桌面 |
| 屏幕常亮与 AOD | 默认启用息屏显示与常亮模式，支持在系统设置中自主调整 |
| 已知限制 | 蓝牙、小米云服务与 Google 服务暂未完成适配；相机目前支持基础预览与拍照；首次启动时着色器编译可能稍有延迟 |

启动器会自动维护 Flutter 渲染、桌面导航与天气 EGL 桥接等适配模块，在保留官方原版 APK 签名的同时完成运行时挂载，重启后持续生效。

### 相机实验性适配

模拟器默认后置摄像头为 `virtualscene`（三维虚拟场景），前置摄像头为 `emulated`（测试测试卡画面）。在模拟器右侧控制栏的 `… → Camera → Virtual scene images` 中可自由替换虚拟房间的墙面与桌面贴图。

- **基础拍照与预览**：已适配小米官方相机应用（`6.8.001960.0`），通过专属 JNI 桥接将模拟器 I420 图像帧转换为相机 NV21 编码，前后摄预览、前后摄切换及基础拍照均可正常工作。
- **算法限制**：由于模拟器环境缺少小米专用的硬件 ISP 处理器，拍照使用相机的 early JPEG 恢复路径，夜景模式、人像虚化、多倍变焦及真机计算摄影算法暂未完整支持。
- **视频录制状态**：修复了切换至录像模式时的报错问题，目前前置摄像头支持录制 720p MP4 视频；后置摄像头的视频录制仍存在掉帧与音画不同步现象，录像质量仍有待后续改进。

若需为现有实例安装或更新相机桥接模块，可运行以下命令：

```sh
HYPEROS_AVD_WORKSPACE="$PWD/work/os4-official" python3 scripts/apply_xiaomi_camera_fix.py
```

### 应用商店更新桌面后的补丁刷新

小米应用商店若更新了小米桌面，新版本可能会自带独立的 Flutter 引擎。如果更新后发现多任务界面或小组件文字缺失，无需重装系统，在模拟器运行状态下直接执行以下脚本即可刷新渲染与导航兼容补丁：

```sh
HYPEROS_AVD_WORKSPACE="$PWD/work/os4-official" python3 scripts/apply_flutter_fix.py
HYPEROS_AVD_WORKSPACE="$PWD/work/os4-official" python3 scripts/apply_navigation_fix.py
```

脚本会自动检测当前安装路径并重新挂载适配库，随后重启桌面进程，完整保留现有的桌面布局与数据。

### 细节体验与视觉修复

- **返回上一级动画渐隐**：原生模拟器硬件合成器在侧滑返回时可能出现黑色遮罩不渐隐的问题。项目补丁对合成器 alpha 指令进行了针对性修正，二级页面返回时窗口遮罩平滑渐隐退出，过渡自然连贯。
- **小爱同学边缘光效**：修复了长按电源键唤出小爱同学时因模拟器 OpenGL ES 驱动限制引起的黑屏与着色器错误，白色屏幕边缘光效正常渐现与淡出，桌面背景保持透明可见。
- **阴影与玻璃材质**：为系统共享 Flutter 引擎优化了阴影渲染指令，相册与系统控件中的弥散阴影和玻璃模糊材质均可正确呈现。

如需临时禁用某些运行时模块进行问题排查，可使用 `--disable` 参数（重新启用传入 `--enable`）：

```sh
HYPEROS_AVD_WORKSPACE="$PWD/work/os4-official" python3 scripts/apply_weather_fix.py --disable
```
