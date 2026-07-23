# 鸿鉴 HCheck

[English](README.en.md) · [文档](docs/00-文档导航.md) · [贡献](CONTRIBUTING.md) · [安全](SECURITY.md)

[![质量门禁](https://github.com/dososo/HarmonyOS-HCheck/actions/workflows/ci.yml/badge.svg)](https://github.com/dososo/HarmonyOS-HCheck/actions/workflows/ci.yml) [![Node.js 24.18.0](https://img.shields.io/badge/Node.js-24.18.0-339933?logo=nodedotjs&logoColor=white)](package.json) [![许可证：MIT](https://img.shields.io/badge/License-MIT-f7df1e)](LICENSE)

> 面向 HarmonyOS 应用的本地优先、证据驱动的发布前审查 CLI。

应用到了发布前，最容易漏掉的常常不是业务代码：权限没声明、版本没对齐、Debug 产物混入、测试地址遗留，或依赖与隐私说明对不上。鸿鉴 HCheck 把这些可确定的问题放到本地检查，给出位置、规则、修复方向和可复验的结果。

> 核心原则：能确认的问题才报出来；不能确认的，不伪装成「通过」。

## 当前能力边界

| 场景 | 当前状态 | 你得到的结果 |
|---|---|---|
| Stage 工程 `quick` 扫描 | 可用 | 配置、权限、版本、Debug 标记、测试地址与本地 SDK 披露检查 |
| 本地 APP/HAP/HSP/HAR 检查 | 可用 | 只读元数据、权限、Debug 标记与解析完整性 |
| Terminal、JSON、SARIF、JUnit、HTML、Agent JSON 报告 | 可用 | 可接入本地流程、CI 与后续审计 |
| 设备、外部工具、AGC | 受限边界 | 需要单独配置与人工授权，不能替代正式发布裁决 |

## 你会在什么时候用到它

- 提交或交付前，想先检查 HarmonyOS 工程的配置、权限、版本与依赖；
- 拿到 APP、HAP、HSP 或 HAR，想只读查看元数据、权限与 Debug 标记；
- 希望在终端和 CI 中得到同一份可追溯结果，而不是靠人肉截图和口头确认；
- 团队需要把「这个问题为什么出现、该怎么复验」留下来，方便后续修复和复盘。

## 三分钟上手

要求：Node.js `24.18.0`、pnpm `10.34.0`。

```bash
git clone https://github.com/dososo/HarmonyOS-HCheck.git
cd HarmonyOS-HCheck
corepack enable
pnpm install --frozen-lockfile
pnpm build

# 先运行仓库自带的干净样例，应显示 PASS
pnpm hcheck scan fixtures/clean-stage-app --format terminal
```

然后把目录换成你的 HarmonyOS 工程；检查本地软件包时换用第二条命令：

```bash
pnpm hcheck scan <你的工程目录> --format terminal
pnpm hcheck package inspect <本地-HAP-或-APP-路径> --format terminal
```

第一次请优先使用工程副本或非生产产物。不要把生产签名材料、真实用户数据或未脱敏日志提交到仓库、Issue 或报告中。

## 它会给你什么

1. **工程检查**：读取 Stage 工程、`app.json5`、`module.json5`、`build-profile.json5` 与 `oh-package` 依赖，检查占位元数据、测试地址、最小权限、Bundle/版本一致性、Debug 标记和本地 SDK 披露。
2. **软件包检查**：只读解析本地 APP、HAP、HSP、HAR，输出元数据、权限、Debug 标记与解析完整性。
3. **清楚的结论**：每条 Finding 同时说明严重性、置信度、适用性、规则 ID、位置与修复线索。
4. **可接入的结果**：支持 Terminal、JSON、SARIF、JUnit、HTML 和 Agent JSON，便于本地查看、CI 和后续审计。

## 可选：把门槛写进工程

在你的工程根目录创建 `.hcheck.yml`，下面这段最小覆盖配置会与内置安全默认值合并：

```yaml
scan:
  fail_on: high
  minimum_confidence: probable
```

也可以复制仓库中的 [.hcheck.example.yml](.hcheck.example.yml) 作为起点。默认不启用 AGC，且不会上传源码；完整字段与覆盖优先级见 [配置规范](docs/02-CLI与配置规范.md)。

## 真实输出示例

![HCheck 真实命令输出展示：左侧为预期的权限 BLOCKER，右侧为干净 fixture 通过门禁](docs/assets/cli-real-run.png)

上图来自仓库公开 fixture 的真实 CLI 输出：左侧的缺权限样例返回 `exit 1` 并报告 `HOS-PERM-001`；右侧的干净样例返回 `exit 0`。你可以用下面两条命令复现：

```bash
pnpm hcheck scan fixtures/missing-permission --format terminal --fail-on high --confidence probable
pnpm hcheck scan fixtures/clean-stage-app --format terminal
```

## 接入 CI（源码方式）

当前仓库发布的是源码，尚未发布 npm 安装包。完成 `pnpm install --frozen-lockfile` 与 `pnpm build` 后，在 CI 的检查步骤中运行同一条门禁命令即可：

```bash
pnpm hcheck scan "$TARGET_PROJECT" --format terminal --fail-on high --confidence probable
```

将 `TARGET_PROJECT` 指向待检查的 HarmonyOS 工程副本。命令返回 `0` 表示门禁通过，`1` 表示发现满足门槛的问题；其他退出码及机器可读报告格式见 [CLI 命令、配置与退出码](docs/02-CLI与配置规范.md)。

## 它不会做什么

- 不替代 HarmonyOS 或 AppGallery Connect 审核，也不保证应用一定通过审核或上架；
- 不上传源码，不默认执行设备写操作，不读取或分发生产签名材料；
- 不把网页抓取、逆向接口或隐式登录当成产品能力；
- 不把未实现、证据不完整或外部服务不可用写成「通过」。

## 常见问题

**会修改我的工程吗？** 不会。默认是本地、只读检查；修复能力只提供显式、可审计的 dry-run 计划。

**一定要连真机或登录 AGC 吗？** 不需要。工程扫描和本地软件包检查可离线完成。涉及设备或外部服务的流程需要单独配置与人工授权。

**这是华为官方工具吗？** 不是。它是独立的社区开源项目；任何结论都应结合目标 SDK、设备、官方文档和实际运行结果确认。

## 继续了解与参与

- [CLI 命令、配置与退出码](docs/02-CLI与配置规范.md)
- [规则体系与开发规范](docs/03-规则体系与开发规范.md)
- [运行时证据与设备边界](docs/04-运行时验证与证据.md)
- [安全与数据处理](docs/07-安全隐私与凭证.md)
- [变更记录](CHANGELOG.md) · [贡献指南](CONTRIBUTING.md) · [行为准则](CODE_OF_CONDUCT.md) · [安全政策](SECURITY.md) · [支持](SUPPORT.md)

<details>
<summary>贡献者：项目结构</summary>

```text
packages/  CLI、配置、规则引擎、报告与项目模型
adapters/  外部工具与服务的受限适配器
rules/     机器可读规则包
schemas/   配置、报告和证据契约
fixtures/  公开、非生产的正反例
examples/  可复制的流程与输入示例
```

</details>

## 关于作者

鸿鉴 HCheck 由爆裂队长NEXT（BLCaptain）独立创作与维护——一个独立、非官方的开源项目，专注把 HarmonyOS 应用工程的配置、依赖、软件包与验证证据，沉淀为面向 AI Agent 与工程团队的、可复现且可审计的发布前检查系统。

- GitHub：[@dososo](https://github.com/dososo)
- X / Twitter：[@thinkszyg](https://x.com/thinkszyg)
- 邮箱：blteam2026@outlook.com
- 开源中国传统纹样图录项目维护者：[wenyang.net](https://wenyang.net)

如果这个项目对你有帮助，欢迎 Star、分享，或在 X 上 @我交流。

## 许可证

本项目采用 [MIT License](LICENSE)。HarmonyOS、OpenHarmony、ArkUI、华为及相关名称和商标归各自权利人所有。
