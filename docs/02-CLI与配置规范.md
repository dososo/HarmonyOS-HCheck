# CLI 与配置规范

## 已实现命令

```text
hcheck doctor [目录] [--format terminal|json]
hcheck scan <目录> [--mode quick] [--format terminal|json|sarif|junit|html|agent-json]
hcheck package inspect <APP/HAP/HSP/HAR路径> [--format terminal|json]
hcheck explain <规则ID> [--format terminal|json]
hcheck baseline create <目录> [--format json] [--reference <名称>]
hcheck verify replay <manifest.json> [--format terminal|json]
hcheck fix --from-agent-json <文件> --dry-run
```

运行 `node packages/cli/dist/index.js --help` 获取当前构建版本的完整帮助。未实现的命令或参数必须被拒绝，不能静默降级。

## 常用示例

```bash
# 只读诊断一个 Stage 工程
hcheck doctor <工程目录> --format json

# 扫描并以高严重性作为失败门槛
hcheck scan <工程目录> --format sarif --fail-on high --confidence probable

# 检查本地 HAP 元数据；不会上传该文件
hcheck package inspect <产物.hap> --format json

# 读取规则解释
hcheck explain HOS-PERM-001 --format json
```

## 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 已完成且门禁通过 |
| `1` | 已发现满足门禁条件的问题 |
| `2` | 仅新增 Finding 的基线门禁失败 |
| `3` | 配置、参数或规则定义错误 |
| `4` | 工具、输入或证据不完整，不能得出通过结论 |

## 配置原则

根目录的 [.hcheck.example.yml](../.hcheck.example.yml) 是可复制到目标工程根目录并改名为 `.hcheck.yml` 的简化覆盖示例；它会与内置安全默认值合并。 [examples/hcheck.yml](../examples/hcheck.yml) 则是完整 Schema 样例。`--config <文件>` 的相对路径以目标工程根目录为准，跨目录使用时请传入绝对路径。配置中的凭据字段只能引用环境变量名，不能写入实际凭据。运行产物、缓存、报告与本地证据都应存放在 `.hcheck/`，该目录默认不会被 Git 跟踪。
