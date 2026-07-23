# 核心包

本目录包含 HCheck 的核心领域包、CLI、规则引擎、报告器与外部工具适配器。可用命令与公开边界以根目录 README 和 `docs/` 为准。

- `core`：三轴、Evidence/Finding、稳定指纹、错误、确定性规范化和 ProcessRunnerPort 合同；
- `config`：配置 Schema、YAML 加载、优先级合并与秘密引用摘要；
- `project-model`：工程根发现、AppScope/模块项目快照、权限声明清单和工程侧 Bundle/版本身份汇总；
- `rule-engine`：规则包加载、受限适用性、检测器调度和内置规则；
- `reporters`：完整性真值、多格式报告和运行时合同校验；
- `agent-protocol`：面向安全修复 dry-run 的结构化协议；
- `cli`：命令编排及 Node 文件系统、哈希、时钟、运行 ID 和安全进程适配器；
- `adapter-hvigor`：基于 `ProcessRunnerPort` 的 Hvigor 项目 wrapper 探测、受控构建编排和产物哈希清单。

结构 Fixture 只覆盖工程发现和源码结构扫描，不包含 SDK、签名、资源编译输入或 APP/HAP。
