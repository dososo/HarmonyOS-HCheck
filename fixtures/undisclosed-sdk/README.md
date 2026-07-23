# F004：未披露第三方 SDK

## 目的

依赖图或最终软件包包含模拟第三方 SDK，但披露清单缺失。

## 故障植入

引入本地测试 HAR/HSP，使用唯一 SDK 指纹。

## 当前状态

`structural`。当前目录包含最小工程结构、`oh-package.json5`、`oh-package-lock.json5`
和未披露模拟 SDK 的本地隐私政策，用于验证 `HOS-PRIV-002`。它不包含真实商业 SDK、
真实 SDK 构建、AGC、设备或可发布产物证明。

## 预期

HOS-PRIV-002

## 建设步骤

```bash
hcheck scan fixtures/undisclosed-sdk --rules HOS-PRIV-002 \
  --format json --fail-on high --confidence probable
```

预期只触发 1 个 `HOS-PRIV-002`。

## 安全

不使用真实生产服务、真实用户、真实 AGC 凭证或可用于生产签名的材料。

## 备注

当前只使用模拟依赖名和本地隐私政策文本。后续升级为 `compilable` 时，需在合法
HarmonyOS SDK 环境重新生成真实工程、Release 构建产物和脱敏黄金结果。
