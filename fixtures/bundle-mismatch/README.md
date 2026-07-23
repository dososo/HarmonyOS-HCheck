# F005：Bundle 标识不一致

## 目的

工程、模拟软件包清单或脱敏 AGC 快照中的 Bundle 标识不一致。

## 故障植入

只修改一个来源，其他来源保持一致。

## 当前状态

`structural`。当前目录包含最小工程结构和脱敏 `package-snapshot.json` 录制样本，
用于验证 `HOS-PKG-001`。它不包含真实 SDK、签名、AGC 或可发布产物证明。

## 预期

HOS-PKG-001

## 建设步骤

```bash
hcheck scan fixtures/bundle-mismatch --rules HOS-PKG-001 \
  --format json --fail-on high --confidence probable
```

预期只触发 1 个 `HOS-PKG-001`。

## 安全

不使用真实生产服务、真实用户、真实 AGC 凭证或可用于生产签名的材料。

## 备注

后续升级为 `compilable` 时，需在合法 HarmonyOS SDK 环境重新生成真实工程、Release
构建产物和脱敏黄金结果。
