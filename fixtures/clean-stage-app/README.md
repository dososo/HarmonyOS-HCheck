# F001：干净 Stage 应用

## 目的

无故障，用作规则误报和构建基线。

## 故障植入

提供 `AppScope/app.json5`、`build-profile.json5`、`entry/src/main/module.json5` 和声明源码目录。注释中保留精确标记，字符串中保留普通 `TODO`、`test`、`demo`，用于证明这些内容不会误报。

## 当前状态

`structural`。目录只满足工程发现、快照解析和源码扫描所需结构，不包含 SDK、签名、资源编译输入或构建产物，**不可作为 HarmonyOS 工程可编译证明**。

## 预期

无 HIGH/BLOCKER Finding

`build.required=false` 仅表示本轮验收不执行构建，不能解释为已经构建成功。

## 安全

不使用真实生产服务、真实用户、真实 AGC 凭证或可用于生产签名的材料。

## 备注

干净扫描不得出现 HIGH 或 BLOCKER。
