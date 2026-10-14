# OS4 Phone r6 / Pad r3 验证报告

本报告分别记录最终发行附件静态完整性、来宾运行观察及未覆盖范围。附件检查与来宾结果各自独立，不相互替代。

## 发布身份

| 镜像 | Tag | 运行包协议 | 最低安装器 | Manifest SHA-256 |
| --- | --- | --- | --- | --- |
| Phone OS4 r6 | `v0.2.5-a17-hyperos4-hongkong-r6` | format 3 / `verified-bundle-runtime-v1` | 1.2.3 | `4db6dd0d24a57feb7cc76a495b73da50f5e7f2d1f121b255fd1ef5896a99c320` |
| Pad OS4 r3 | `pad-v0.1.2-a17-hyperos4-yingtian-r3` | format 3 / `verified-bundle-runtime-v1` | 1.2.3 | `96a6769b0bee5d1444ce829e0ef7ae02390377ff1731089a213106cb52c68369` |

## 发行附件完整性

Phone 与 Pad 附件各含 166 个普通文件，分为 5 个镜像分卷。流式归档清单、分卷及文件 SHA-256 均通过；每个版本的 136 项冻结运行源码与仓库一致，另 29 项镜像、工具和配置与生产者输出一致。归档仅包含普通文件，私有宿主路径和密钥扫描通过。

| 镜像 | 压缩附件总字节数 | 默认 CPU / RAM / userdata |
| --- | ---: | --- |
| Phone r6 | 6,823,064,714 | 4 核 / 6 GiB / 32 GiB |
| Pad r3 | 7,683,620,504 | 4 核 / 4 GiB / 32 GiB |

两份附件均使用 6 GiB 空白 userdata 模板，根目录仅有 `lost+found`，且该目录为空。KernelSU 当前与兼容运行资产、ramdisk marker receipt 均与审核过的 SHA-256 对应；Core 保持平台上下文区分，Phone 与 Pad 的 Apps 归档逐字节相同，SHA-256 为 `7a1c0e63e262e2d29016a5227ae76fdbd4541aeb2f958e77815a32ec491d20be`。

这些检查证明附件完整性及其与冻结源码的对应关系；来宾运行和迁移结果见下文。

## Phone r6 来宾验证

最终附件首次启动、激活冷启动与随后一次稳定性冷启动通过；root、SELinux Enforcing、安全 ADB、skiavk、32 GiB userdata、稳定 serial3 和 Core 18 / Apps 7 完整模块完整性均通过。Home 一个引擎与 Weather 三个库的实际映射 device / inode / hash 均匹配已认证载荷。

最终附件本轮的 framework ART DEX 新映射证明未确认；此前运行实例中 system_server 的实际 DEX 映射匹配属于该实例的独立证据。多次冷启动中，FindDevice 的 Core 所有权收据存在，但 `currenthidden=false`；Core 安全跳过该项并保留用户状态。另一个时序样本未确认 package policy。该行为尚未在多次冷启动后稳定确认，因此不计为该项验收通过；未强制修改用户状态，也不推断该状态由宿主启动逻辑造成。Phone r5 → r6 保数据迁移未执行。Phone 截图的局域网模型识别请求超时，未直接检查图像，因此视觉验收未确认。

## Pad r3 来宾验证

最终附件首次启动、激活冷启动、随后一次稳定性冷启动与额外一次观察，均通过启动、模块完整性与稳定 serial3 检查。此前运行的 Pad 实例中，实际 framework DEX 映射与 Core 18 / Apps 7 对应产物匹配，属于该实例的独立证据；最终附件本轮的 ART DEX 新映射证明未确认。首次启动 Weather 时 `am start` 返回 Status ok 且进程存活；随后强制重启探测进入 OEM `SystemAppPermissionDialogActivity`，Weather 被 force-stop。该序列 crash buffer 为空，FATAL 与 Native fatal 计数为 0，因此不记作崩溃；但 Weather 原生映射以及用户确认首用权限后的完整天气内容本轮未确认。

三次来宾关机后宿主均自行退出；最后一次观察中，来宾关机后 ADB 离线，但宿主进程在 20 秒后仍未退出，Pad 宿主自退出问题仍存在。文本观察确认了首用权限页面，视觉验收未确认。Pad r2 → r3 保数据迁移未执行。

## 自动检查与边界

KernelSU、ramdisk、运行包与安装器相关检查共 91 项通过。发行准备回归 80 项中 79 项通过、1 项因缺少专有 Flutter 输入而跳过；该跳过不视为通过。

此前日用实例的约 180 秒 idle / active 采样中，指定 fatal、native crash、ANR 模式计数为零。此结果不代表所有日志告警、历史反馈或长期稳定性均已解决。PowerInsight 的虚拟功耗模型及物理节点采样失败、部分厂商能力查询和 SELinux 拒绝、历史 warm-reboot / MoltenVK 问题继续列为限制；相机完整算法和录像、逐页 OOBE、真实保数据升级及长期资源测试未由本轮覆盖。

原始日志、随机身份、用户数据与本机路径不随发行附件或本报告公开。本轮临时 AVD 和重建缓存已按归属清理，保留正式附件及必要校验收据。
