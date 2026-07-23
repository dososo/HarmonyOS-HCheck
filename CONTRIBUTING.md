# 贡献指南 / Contributing

感谢你帮助改进鸿鉴 HCheck。提交贡献即表示你同意遵守 [行为准则](CODE_OF_CONDUCT.md)。

Thank you for improving HCheck. By contributing, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## 开始前 / Before you start

1. 搜索已有 Issue，避免重复讨论。
2. Bug、功能建议和规则建议请使用对应 Issue 模板；安全问题不要公开提交，见 [SECURITY.md](SECURITY.md)。
3. 一个 Pull Request 只解决一个清晰问题，说明范围外内容与取舍。
4. 不提交真实凭据、生产软件包、证书、设备序列号、用户数据、原始日志或受限文档。

## 本地验证 / Local validation

要求 Node.js `24.18.0` 与 pnpm `10.34.0`：

```bash
corepack enable
corepack install
pnpm install --frozen-lockfile
pnpm check
pnpm security:deps
```

## 变更标准 / Change standards

- 行为变化必须有正常、负向与边界测试；
- 公共 CLI、Schema、规则或报告变化必须同步更新文档与示例；
- 新规则必须说明来源、适用范围、置信度边界、正负样例和误报风险；
- 外部工具、设备或服务失败必须保持为失败或证据不完整，不能伪装成通过；
- 涉及架构、公开 Schema、许可证、数据外发或自动修复权限的变化，必须在 PR 中写明设计理由与迁移影响。

## Review expectations

维护者会优先审查正确性、可复现性、安全边界、测试覆盖和文档一致性。仓库公开后，项目所有者将通过 GitHub 设置维护者与合并权限；未被明确授权的贡献者不应合并自己的 PR。
