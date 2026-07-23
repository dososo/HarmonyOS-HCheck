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

## Reproducible real output

![Actual HCheck command output: an expected permission blocker on the left and a clean fixture pass on the right](docs/assets/cli-real-run.png)

The image is a typeset rendering of actual CLI output from this repository's public fixtures: the left command returns `exit 1` with `HOS-PERM-001`, while the right command returns `exit 0` with no findings. It is not a terminal, device, or AGC screenshot. Inspect the [output source](docs/assets/real-run-output.html) or reproduce it locally:

```bash
pnpm build
node packages/cli/dist/index.js scan fixtures/missing-permission --format terminal --fail-on high --confidence probable
node packages/cli/dist/index.js scan fixtures/clean-stage-app --format terminal
```

## Non-production external verification record

To preserve evidence boundaries, the following screenshots record an environment action and result from the official Cloud Testing service in a non-production AppGallery Connect project. They are not HCheck CLI scan output and do not imply endorsement by Huawei or AppGallery Connect. Account information is redacted in the images.

### Cloud Testing entry and connectivity preflight

<p align="center">
  <img src="docs/assets/external-verification/agc-cloudtest-preflight.png" alt="Cloud Testing entry and connectivity preflight in a non-production AppGallery Connect project, with account information redacted" width="960" />
</p>

Before opening Cloud Testing in the non-production project, connectivity was checked and restored only for the specified Huawei Cloud CDN domain, then the official service entry was opened. This documents an explicit external-environment preflight; it includes no source upload, production account, production signing material, or device write action.

### Compatibility-test summary

<p align="center">
  <img src="docs/assets/external-verification/cloudtest-compatibility-summary.png" alt="Non-production compatibility-test summary: 39 test items, 100 percent pass rate, zero failures, and zero warnings" width="1200" />
</p>

This non-production compatibility-test record shows 39 total test items, a 100% pass rate, zero failed items, and zero warnings. It also records the target as Mate X5, system version 6.1.0.115, and 1080×2504 resolution. It describes this one test record only; it does not generalize to all devices, versions, or future builds.

## Contributing and release

HCheck is licensed under the [MIT License](LICENSE). Please read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md) before participating. The repository is source-open; workspace packages remain `private: true` to prevent accidental npm publishing.

## About the author

HCheck is independently created and maintained by 爆裂队长NEXT (BLCaptain). It is an independent, unofficial open-source project that turns HarmonyOS application configuration, dependencies, package metadata, and verification evidence into a reproducible, auditable pre-release inspection system for AI agents and engineering teams.

- GitHub: [@dososo](https://github.com/dososo)
- X / Twitter: [@thinkszyg](https://x.com/thinkszyg)
- Email: blteam2026@outlook.com
- Maintainer of an open-source catalogue of traditional Chinese patterns: [wenyang.net](https://wenyang.net)

If this project helps you, please star or share it, or reach out on X.

HarmonyOS, OpenHarmony, ArkUI, Huawei, and related names and trademarks belong to their respective owners. Validate inspection results against the target SDK, device, official documentation, and actual runtime results.
