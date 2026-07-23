# F002：缺少权限声明

## 目的

源码调用官方已核验需要权限的 `geoLocationManager.getCurrentLocation`，但 `module.json5`
缺少 `ohos.permission.APPROXIMATELY_LOCATION`。

## 故障植入

在单一 ArkTS 调用点植入 `geoLocationManager.getCurrentLocation()`，并保持其他配置最小正确。

## 当前状态

`structural`。当前只用于 HCheck quick 结构扫描，不声称为可编译 HarmonyOS 工程。

## 预期

HOS-PERM-001

## 建设步骤

```bash
hcheck scan fixtures/missing-permission --rules HOS-PERM-001 \
  --format json --fail-on high --confidence probable
```

预期只触发 1 个 `HOS-PERM-001`。

## 安全

不使用真实生产服务、真实用户、真实 AGC 凭证或可用于生产签名的材料。

## 备注

API 与权限映射已按华为 `geoLocationManager.getCurrentLocation` 官方文档核验。后续若要升级为
`compilable`，仍需在合法 HarmonyOS SDK 和官方模板环境中重新生成真实工程并跑 Release 构建。
