# F003：同意前数据行为

## 目的

EntryAbility 在隐私同意前初始化模拟分析 SDK 并产生本地可观察事件。

## 故障植入

使用本地测试 SDK 和本地服务，不发送真实个人信息。

## 当前状态

`specification` + P2 本地运行时边界证据。尚未声称为可编译 HarmonyOS 工程，
也未声称真机、模拟器、HarmonyOS PC 或云测已运行。

## 预期

HOS-PRIV-004

## 建设步骤

1. 在具备合法 HarmonyOS SDK 的环境中使用官方 Stage 模板创建最小工程；
2. 固定 SDK、工具和模板版本；
3. 只植入本规格描述的主故障；
4. 运行 Release 构建（如要求）；
5. 执行 HCheck 扫描和必要运行时流程；
6. 保存脱敏黄金结果；
7. 建立修复对照；
8. 更新 `fixture.yml` 状态为 `compilable`。

## 安全

不使用真实生产服务、真实用户、真实 AGC 凭证或可用于生产签名的材料。

## 备注

`.hcheck/runtime/privacy-refuse.boundary.json` 只记录本地流程合同、边界和升级条件。
当前静态为 PROBABLE；只有真实设备运行时证据齐全后才可升级 CONFIRMED。
