# F009：发布元数据占位内容

## 目的

为第一条端到端检测规则 `HOS-META-003` 提供最小、稳定、无歧义的故障样例，使 Codex 能先打通“配置/源文件收集—规则执行—Finding—Terminal/JSON 报告—退出码”的完整闭环。

## 故障注入

只放置一个精确占位标记：

```text
HCHECK_PLACEHOLDER
```

不要用 `test`、`demo`、`sample` 等高噪声词作为唯一触发条件。

## 预期结果

- 只命中一个 `HOS-META-003`；
- 默认置信度不高于 `PROBABLE`；
- Finding 使用相对路径；
- 重复扫描指纹稳定；
- 删除占位标记后 Finding 消失；
- 不产生任何无关 BLOCKER/HIGH。

## 当前状态

当前目录是与 `clean-stage-app` 同构的 `structural` Fixture，包含工程发现、快照解析和源码扫描所需的最小声明结构。`build.required=false`，且不包含 SDK、签名、资源编译输入或构建产物，**不可作为 HarmonyOS 工程可编译证明**。
