# HCheck

[中文](README.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [License](LICENSE) · [Docs](docs/00-文档导航.md)

> A local-first, evidence-driven CLI for pre-release inspection of HarmonyOS applications.

HCheck connects project configuration, dependencies, package metadata, rules, and verification evidence into reproducible checks. It helps teams find deterministic release risks earlier and keeps remediation evidence auditable.

## What it does

- Inspects Stage-model configuration, dependencies, and local APP/HAP/HSP/HAR packages.
- Runs implemented `quick` rules for metadata placeholders, local test endpoints, minimum permissions, Bundle/version consistency, Debug artifacts, and local SDK disclosure evidence.
- Produces stable findings with severity, confidence, and applicability; outputs Terminal, JSON, SARIF, JUnit, HTML, and Agent JSON.
- Uses local, read-only, and redacted defaults. Incomplete evidence and external failures are never reported as a pass.

## What it does not do

- It does not replace HarmonyOS or AppGallery Connect review and does not guarantee approval.
- It contains no production signing material, user data, production API credentials, real device logs, or real accounts.
- It does not rely on page scraping, private interfaces, or implicit login as a product contract.

## Quick start

Requirements: Node.js `24.18.0` and pnpm `10.34.0`.

```bash
corepack enable
corepack install
pnpm install --frozen-lockfile
pnpm check

pnpm build
node packages/cli/dist/index.js doctor fixtures/clean-stage-app --format json
node packages/cli/dist/index.js scan fixtures/missing-permission --format terminal
node packages/cli/dist/index.js package inspect <local-hap-or-app-path> --format json
```

All content in `fixtures/` is public, non-production test data. Read the [data-handling guide](docs/11-安全隐私与凭证.md) before inspecting your own project or package.

## Contributing and release

HCheck is licensed under the [MIT License](LICENSE). Please read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md) before participating. The repository is source-open; workspace packages remain `private: true` to prevent accidental npm publishing.
