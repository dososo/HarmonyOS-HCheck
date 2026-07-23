# Fixtures

本目录定义鸿鉴 HCheck 的首批故障样例工程。当前状态是**规格基线**，不代表这些目录已是可编译 HarmonyOS 项目。

真实工程必须在安装了合法 HarmonyOS SDK 和官方模板的环境中生成。Codex 不得凭空制造不可构建的项目结构并声称完成。

## 矩阵

| ID | 目录 | 主要规则 | 静态/产物/运行时 |
|---|---|---|---|
| F001 | clean-stage-app | 无 | 静态 + 构建 |
| F002 | missing-permission | HOS-PERM-001 | 静态、P0-B 结构规则 |
| F003 | privacy-before-consent | HOS-PRIV-004 | 静态 + 运行时 |
| F004 | undisclosed-sdk | HOS-PRIV-002 | 依赖 + 产物 |
| F005 | bundle-mismatch | HOS-PKG-001 | 工程 + 产物 + AGC 模拟 |
| F006 | debug-release-artifact | HOS-PKG-006 | 产物 |
| F007 | broken-account-delete | HOS-ACCOUNT-002/003 | 运行时 |
| F008 | agc-metadata-mismatch | HOS-META-001 | AGC 模拟 |
| F009 | placeholder-metadata | HOS-META-003 | 静态、首轮引擎闭环 |
| F010 | test-endpoint | HOS-PKG-007 | 静态、P0-B 结构规则 |

## 建设要求

- 一个 fixture 只有一个主要故障；
- 提供修复前、修复后对照；
- 不使用真实凭证和用户数据；
- 预期结果经过黄金测试；
- README 写清构建、复位和扫描；
- 真实构建环境不可用时保持 `status: specification`。

## P2/P3 运行时边界与合同证据

当前已为以下运行时 Fixture 增加本地边界或合同证据：

- `privacy-before-consent/.hcheck/runtime/privacy-refuse.boundary.json`：证明 `privacy-refuse` 流程合同和静态 `PROBABLE` 边界，不伪造真实设备 `CONFIRMED`；
- `broken-account-delete/.hcheck/runtime/account-delete.stub.json`：P3 记录账号注销本地测试桩合同，不访问真实账号、生产服务或 AGC。

这些 JSON 只用于 Schema/合同校验，不代表真机、模拟器、HarmonyOS PC、DevEco Testing 或云测已经执行。
