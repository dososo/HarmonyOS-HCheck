# F006：正式产物包含调试资源

## 目的

Release 产物包含唯一测试入口或调试资源标识。

## 故障植入

通过受控构建资源植入，避免仅靠文件名。

## 当前状态

`structural`。当前目录包含最小工程结构和脱敏 `package-snapshot.json` 录制样本，
用于验证 `HOS-PKG-006`。它不包含真实 SDK、签名或可发布产物证明。

## 预期

HOS-PKG-006

## 建设步骤

```bash
hcheck scan fixtures/debug-release-artifact --rules HOS-PKG-006 \
  --format json --fail-on high --confidence probable
```

预期只触发 1 个 `HOS-PKG-006`。

## 安全

不使用真实生产服务、真实用户、真实 AGC 凭证或可用于生产签名的材料。

## 备注

后续升级为 `compilable` 时，需在合法 HarmonyOS SDK 环境重新生成真实工程、Release
构建产物和脱敏黄金结果。
