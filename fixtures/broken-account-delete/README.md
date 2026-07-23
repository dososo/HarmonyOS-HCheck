# F007：账号注销无效

## 目的

应用存在注销入口，但按钮仅退出登录或不清除本地 Token。

## 故障植入

使用本地模拟账号服务和可重置 Token。

## 当前状态

`specification` + P3 本地账号注销测试桩合同证据。尚未声称为可编译 HarmonyOS 工程，
也未声称真实账号注销、真机、模拟器、HarmonyOS PC 或云测已运行。

## 预期

HOS-ACCOUNT-002, HOS-ACCOUNT-003

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

`.hcheck/runtime/account-delete.stub.json` 记录本地录制账号服务、脱敏测试账号摘要、旧会话失效、
重新登录拒绝和本地数据清理的合同证据。该证据不访问真实账号、生产服务或 AGC，
也不能把 HOS-ACCOUNT-002/003 冒充为真实设备 `CONFIRMED`。
