# F010：发布内容包含本地测试地址

## 目的

为 `HOS-PKG-007` 提供最小、稳定、无歧义的故障样例，验证结构扫描能发现可发布源码中的本地环回 HTTP 测试地址。

## 故障注入

只放置一个本地环回测试地址：

```text
http://localhost:8080/api
```

不使用普通 `test`、`demo`、`beta` 词作为触发条件，避免扩大误报范围。

## 预期结果

- 只命中一个 `HOS-PKG-007`；
- 默认置信度不高于 `PROBABLE`；
- Finding 使用相对路径；
- 报告不输出具体本地地址；
- 重复扫描指纹稳定；
- 替换为正式服务地址后 Finding 消失；
- 不产生 `HOS-META-003` 或其他无关 BLOCKER/HIGH。

## 当前状态

当前目录是与 `clean-stage-app` 同构的 `structural` Fixture，包含工程发现、快照解析和源码扫描所需的最小声明结构。`build.required=false`，且不包含 SDK、签名、资源编译输入或构建产物，**不可作为 HarmonyOS 工程可编译证明**。
