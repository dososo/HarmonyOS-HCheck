# 首批规则样例

本目录中的大多数 YAML 仍是规则契约基线。当前 `rules/packs/p0.yml` 中的
`HOS-META-003`、`HOS-PKG-001`、`HOS-PKG-006`、`HOS-PKG-007`、`HOS-PERM-001` 和
`HOS-PRIV-002` 已实现检测器并通过结构 Fixture；其他规则不得视为可执行能力。

## 规则状态

- `experimental`：契约和样例阶段，不进入默认阻断；
- `active`：检测器、测试和 fixture 完成，可进入默认规则包；
- `deprecated`：保留历史解释，不用于新扫描。

## 当前样例

- 环境：`HOS-ENV-001`；
- 构建：`HOS-BUILD-001`；
- 软件包：`HOS-PKG-001`（`experimental`，P0 只具备工程侧 Bundle/版本身份框架，完整 APP/HAP/AGC 一致性仍未可执行）、`HOS-PKG-006`、`HOS-PKG-007`（`active`，仅识别 ArkTS、TypeScript、JSON5 字符串值中的本地环回 HTTP 测试地址）；
- 权限：`HOS-PERM-001`（`active`，首轮仅检测 `@kit.LocationKit` 的 `geoLocationManager.getCurrentLocation` 是否缺少 `ohos.permission.APPROXIMATELY_LOCATION`）；
- 隐私：`HOS-PRIV-001`、`HOS-PRIV-002`、`HOS-PRIV-004`；
- 账号：`HOS-ACCOUNT-001`；
- 元数据：`HOS-META-003`（`active`，仅识别 ArkTS、TypeScript、JSON5 字符串值中的精确 `HCHECK_PLACEHOLDER` 标记）。

## 当前默认规则包

`hcheck-p0@0.6.0` 包含 `HOS-META-003`、`HOS-PKG-001`、`HOS-PKG-006`、
`HOS-PKG-007`、`HOS-PERM-001` 和 `HOS-PRIV-002`。
`HOS-META-003`、`HOS-PKG-007`、`HOS-PRIV-002` 当前为 `HIGH + PROBABLE + APPLICABLE`；
`HOS-PKG-001`、`HOS-PKG-006` 当前为 `HIGH + CONFIRMED + APPLICABLE`；
`HOS-PERM-001` 当前为 `BLOCKER + PROBABLE + APPLICABLE`。是否退出 1 仍由
`fail_on` 与 `minimum_confidence` 共同决定。结构 Fixture 不代表 Release 构建、
APP/HAP 解析或产物规则已完成。

## P2 本地签名清单

P2-1 新增 `rules/packs/p0.signature.json` 作为本地规则包签名清单样本。该清单记录
`p0.yml` 和其引用规则文件的 SHA-256，并可通过 `loadRulePack({ signaturePolicy: { mode: "required" } })`
触发本地 verifier 合同校验。

边界：

- `local-test-key` 和 `local-test-ed25519` 是本地合同名称，不是生产密钥体系；
- 当前不托管真实私钥，不实现撤销列表，不声明发布签名已完成；
- 签名清单越界路径、重复路径、缺失文件哈希或文件被篡改时必须失败。

规则实现流程见 `docs/03-规则体系与开发规范.md`。
