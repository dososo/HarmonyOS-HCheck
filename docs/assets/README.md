# 公开展示素材说明

本目录中的素材仅服务于公开 README 的阅读体验；不包含真实设备、账号、AGC、生产签名材料、用户数据或本机绝对路径。

| 文件 | 类型 | 来源与边界 |
|---|---|---|
| `cli-real-run.svg` / `cli-real-run.png` | 可复现运行展示 | 由公开 fixture 的实际 CLI 输出排版生成。命令、Finding、退出码和 Node.js 版本见 `real-run-output.html`，也可按 README 的命令重新执行。它不是终端、设备或 AGC 截图。 |
| `real-run-output.html` | 输出源文件 | 静态保存两次本地运行的原始文本输出，用于逐行核对展示图的内容。 |
| `external-verification/agc-cloudtest-preflight.png` | 非生产外部环境记录 | 用户提供的非生产 AGC 云测入口与连通性预检截图；源文件中前两张截图的 SHA-256 相同，公开 README 只保留一张。图中账号信息已打码，不作为 CLI 输出或平台背书。 |
| `external-verification/cloudtest-compatibility-summary.png` | 非生产外部环境记录 | 用户提供的非生产兼容性测试汇总截图；README 只陈述页面展示的本次测试数据，不外推为跨设备、跨版本或后续构建结论。 |

更新运行展示图时，必须先在 Node.js `24.18.0` 下执行对应命令，保留预期的失败与通过结果，再同步更新 HTML、SVG 和 PNG。
