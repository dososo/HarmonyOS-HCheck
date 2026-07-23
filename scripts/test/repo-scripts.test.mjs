import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { validateMarkdownLinks } from "../validate-docs.mjs";
import {
  validateExpectedFindingsContract,
  validateJsonAgainstSchema,
  validateRulePackSignatureManifests,
  validateRuntimeFixtureContracts,
} from "../validate-schemas.mjs";
import { generateSbom } from "../generate-sbom.mjs";
import { createCliPackageManifest, packageCli } from "../package-cli.mjs";

async function makeTempRepo() {
  return await mkdtemp(path.join(os.tmpdir(), "hcheck-repo-scripts-"));
}

test("validateMarkdownLinks 只检查本地 Markdown 链接且错误不泄露绝对路径", async () => {
  const root = await makeTempRepo();
  await mkdir(path.join(root, "docs"), { recursive: true });
  await writeFile(
    path.join(root, "README.md"),
    [
      "# 示例",
      "[有效文档](docs/valid.md)",
      "[外部链接](https://developer.huawei.com/)",
      "",
      "```md",
      "[代码块中的缺失链接](docs/missing-in-code.md)",
      "```",
      "",
    ].join("\n"),
  );
  await writeFile(path.join(root, "docs", "valid.md"), "# Valid\n");
  await writeFile(
    path.join(root, "docs", "broken.md"),
    "[缺失文档](missing.md)\n",
  );

  const result = await validateMarkdownLinks({ root });

  assert.equal(result.ok, false);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /docs\/broken\.md/u);
  assert.match(result.errors[0], /missing\.md/u);
  assert.ok(!result.errors[0].includes(root));
});

test("validateJsonAgainstSchema 校验 JSON Schema 且返回可读错误", () => {
  const schema = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    required: ["id"],
    additionalProperties: false,
    properties: {
      id: { type: "string" },
    },
  };

  assert.deepEqual(validateJsonAgainstSchema(schema, { id: "ok" }), {
    ok: true,
    errors: [],
  });

  const result = validateJsonAgainstSchema(schema, { id: 1, extra: true });

  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /id/u);
  assert.match(result.errors.join("\n"), /additionalProperties/u);
});

test("账号注销测试桩 Schema 只接受完整本地端点", async () => {
  const schema = JSON.parse(
    await readFile("schemas/account-deletion-stub.schema.json", "utf8"),
  );
  const valid = {
    schemaVersion: "1.0.0",
    fixtureId: "F007",
    flowId: "account-delete",
    evidenceKind: "account-deletion-stub-contract",
    status: "local_contract",
    runtimeConfirmed: false,
    redacted: true,
    service: {
      kind: "local-recorded-stub",
      endpoint: "http://127.0.0.1:18080/account-delete-stub",
      production: false,
    },
    account: { subject: "fixture-account-001", redacted: true },
    checks: [
      {
        id: "delete-request-accepted",
        status: "passed",
        summary: "本地测试桩接受注销请求。",
      },
      {
        id: "old-token-rejected",
        status: "passed",
        summary: "旧会话摘要被本地测试桩拒绝。",
      },
      {
        id: "relogin-rejected",
        status: "passed",
        summary: "注销后重新登录被本地测试桩拒绝。",
      },
      {
        id: "local-data-cleared",
        status: "passed",
        summary: "本地缓存摘要已清理。",
      },
    ],
    evidence: {
      collectedAt: "2026-07-11T00:00:00Z",
      commands: ["pnpm schema:check"],
    },
    boundaries: ["仅使用本地测试桩。"],
  };

  assert.equal(validateJsonAgainstSchema(schema, valid).ok, true);

  const invalid = {
    ...valid,
    service: {
      ...valid.service,
      endpoint: "http://127.0.0.1:18080/account-delete-stub https://evil.com",
    },
  };
  const result = validateJsonAgainstSchema(schema, invalid);

  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /endpoint/u);
});

test("generateSbom 从 pnpm-lock.yaml 生成稳定依赖清单且不含本机路径", async () => {
  const root = await makeTempRepo();
  await writeFile(
    path.join(root, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      left-pad:",
      "        specifier: 1.0.0",
      "        version: 1.0.0",
      "      '@scope/runtime':",
      "        specifier: 2.0.0",
      "        version: 2.0.0",
      "      '@internal/workspace':",
      "        specifier: workspace:*",
      "        version: link:../workspace",
      "    devDependencies:",
      "      tsx:",
      "        specifier: 4.0.0",
      "        version: 4.0.0",
      "packages:",
      "  left-pad@1.0.0:",
      "    resolution: {integrity: sha512-left}",
      "  tsx@4.0.0:",
      "    resolution: {integrity: sha512-tsx}",
      "",
    ].join("\n"),
  );

  const sbom = await generateSbom({ root });

  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.deepEqual(
    sbom.components.map(({ name, version, scope, purl }) => ({
      name,
      version,
      scope,
      purl,
    })),
    [
      {
        name: "@scope/runtime",
        version: "2.0.0",
        scope: "required",
        purl: "pkg:npm/%40scope%2Fruntime@2.0.0",
      },
      {
        name: "left-pad",
        version: "1.0.0",
        scope: "required",
        purl: "pkg:npm/left-pad@1.0.0",
      },
      {
        name: "tsx",
        version: "4.0.0",
        scope: "optional",
        purl: "pkg:npm/tsx@4.0.0",
      },
    ],
  );
  assert.ok(!JSON.stringify(sbom).includes(root));
});

test("validateExpectedFindingsContract 拒绝结构 Fixture 缺少稳定 count", async () => {
  const root = await makeTempRepo();
  const fixtureRoot = path.join(root, "fixtures", "demo");
  await mkdir(fixtureRoot, { recursive: true });
  await writeFile(
    path.join(fixtureRoot, "fixture.yml"),
    [
      "id: F999",
      "name: Demo",
      "status: structural",
      "expected_findings:",
      "  - rule_id: HOS-DEMO-001",
      "    minimum_confidence: PROBABLE",
      "forbidden_findings: []",
      "build: { required: false }",
      "runtime: { required: false, flows: [] }",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(fixtureRoot, "expected-findings.json"),
    JSON.stringify(
      {
        fixtureId: "F999",
        status: "structural",
        expected: [{ ruleId: "HOS-DEMO-001", minimumConfidence: "PROBABLE" }],
        forbidden: [],
      },
      null,
      2,
    ),
  );

  const result = await validateExpectedFindingsContract({ root });

  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /count/u);
  assert.ok(!result.errors.join("\n").includes(root));
});

test("validateRulePackSignatureManifests 拒绝越界路径且不泄露绝对路径", async () => {
  const root = await makeTempRepo();
  const packsRoot = path.join(root, "rules", "packs");
  await mkdir(packsRoot, { recursive: true });
  await writeFile(
    path.join(packsRoot, "demo.signature.json"),
    JSON.stringify(
      {
        version: 1,
        key_id: "local-test-key",
        algorithm: "local-test-ed25519",
        signed_at: "2026-07-11T00:00:00Z",
        files: [{ path: "../secret.yml", sha256: "0".repeat(64) }],
        signature: "local-test-signature",
      },
      null,
      2,
    ),
  );

  const result = await validateRulePackSignatureManifests({ root });

  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /越界|不安全/u);
  assert.ok(!result.errors.join("\n").includes(root));
});

test("validateRuntimeFixtureContracts 拒绝运行时 Fixture 缺少本地边界证据", async () => {
  const root = await makeTempRepo();
  const fixtureRoot = path.join(root, "fixtures", "runtime-demo");
  await mkdir(fixtureRoot, { recursive: true });
  await writeFile(
    path.join(fixtureRoot, "fixture.yml"),
    [
      "id: F998",
      "name: Runtime Demo",
      "status: specification",
      "expected_findings:",
      "  - rule_id: HOS-PRIV-004",
      "    minimum_confidence: PROBABLE",
      "forbidden_findings: []",
      "build: { required: false }",
      "runtime:",
      "  required: true",
      "  flows:",
      "    - privacy-refuse",
      "",
    ].join("\n"),
  );

  const result = await validateRuntimeFixtureContracts({ root });

  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /运行时边界证据/u);
  assert.ok(!result.errors.join("\n").includes(root));
});

test("validateRuntimeFixtureContracts 接受 F007 本地账号注销测试桩合同证据", async () => {
  const root = await makeTempRepo();
  const fixtureRoot = path.join(root, "fixtures", "broken-account-delete");
  const evidenceRoot = path.join(fixtureRoot, ".hcheck", "runtime");
  await mkdir(evidenceRoot, { recursive: true });
  await writeFile(
    path.join(fixtureRoot, "fixture.yml"),
    [
      "id: F007",
      "name: 账号注销无效",
      "status: specification",
      "target: { platform: harmonyos, model: stage }",
      "defect:",
      "  description: 应用存在注销入口，但旧会话仍可用。",
      "  injection: 使用本地录制账号服务和可重置会话摘要。",
      "expected_findings: []",
      "forbidden_findings: []",
      "build: { required: false }",
      "runtime:",
      "  required: true",
      "  flows:",
      "    - account-delete",
      "  evidence:",
      "    - .hcheck/runtime/account-delete.stub.json",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(evidenceRoot, "account-delete.stub.json"),
    JSON.stringify(
      {
        schemaVersion: "1.0.0",
        fixtureId: "F007",
        flowId: "account-delete",
        evidenceKind: "account-deletion-stub-contract",
        status: "local_contract",
        runtimeConfirmed: false,
        redacted: true,
        service: {
          kind: "local-recorded-stub",
          endpoint: "http://127.0.0.1:18080/account-delete-stub",
          production: false,
        },
        account: { subject: "fixture-account-001", redacted: true },
        checks: [
          {
            id: "delete-request-accepted",
            status: "passed",
            summary: "本地测试桩接受注销请求。",
          },
          {
            id: "old-token-rejected",
            status: "passed",
            summary: "旧会话摘要被本地测试桩拒绝。",
          },
          {
            id: "relogin-rejected",
            status: "passed",
            summary: "注销后重新登录被本地测试桩拒绝。",
          },
          {
            id: "local-data-cleared",
            status: "passed",
            summary: "本地缓存摘要已清理。",
          },
        ],
        evidence: {
          collectedAt: "2026-07-11T00:00:00Z",
          commands: [
            "pnpm schema:check",
            "pnpm --filter @hcheck/core test -- test/runtime-flow.test.ts",
          ],
        },
        boundaries: ["仅使用本地测试桩，不访问真实账号或生产服务。"],
      },
      null,
      2,
    ),
  );

  const result = await validateRuntimeFixtureContracts({ root });

  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
});

test("createCliPackageManifest 生成确定性 CLI 分发清单且不泄露绝对路径", async () => {
  const root = await makeTempRepo();
  await mkdir(path.join(root, "packages", "cli", "dist"), { recursive: true });
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      version: "0.6.0",
      packageManager: "pnpm@10.34.0",
      engines: { node: "24.18.0", pnpm: "10.34.0" },
    }),
  );
  await writeFile(
    path.join(root, "packages", "cli", "package.json"),
    JSON.stringify({ name: "@hcheck/cli", version: "0.6.0" }),
  );
  await writeFile(
    path.join(root, "packages", "cli", "dist", "index.js"),
    "console.log('0.6.0')\n",
  );

  const first = await createCliPackageManifest({
    root,
    platform: "darwin",
    arch: "arm64",
    observedVersion: "0.6.0",
  });
  const second = await createCliPackageManifest({
    root,
    platform: "darwin",
    arch: "arm64",
    observedVersion: "0.6.0",
  });

  assert.deepEqual(first, second);
  assert.equal(first.artifact.version, "0.6.0");
  assert.equal(first.artifact.entrypoint, "packages/cli/dist/index.js");
  assert.match(first.artifact.entrypointSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(first.runtime, {
    node: "24.18.0",
    pnpm: "10.34.0",
    packageManager: "pnpm@10.34.0",
  });
  assert.deepEqual(first.platform, {
    os: "darwin",
    arch: "arm64",
    verification: "current-platform-only",
  });
  assert.equal(first.smoke.status, "passed");
  assert.match(first.install.boundary, /不执行全局安装/u);
  assert.match(first.uninstall.boundary, /不删除用户文件/u);
  assert.deepEqual(first.externalValidation, {
    currentPlatform: "darwin",
    status: "local-workspace-only",
    note: "package:cli 只生成本地 Node CLI 清单，不写入全局 PATH，也不声明跨平台安装器验证。公开发布范围见 docs/06-验收与质量标准.md。",
  });
  assert.ok(!JSON.stringify(first).includes("threePlatformInstallUninstall"));
  assert.ok(!JSON.stringify(first).includes(root));
});

test("packageCli 写出 manifest 并执行当前平台 --version smoke", async () => {
  const root = await makeTempRepo();
  const outDir = path.join(root, "dist", "hcheck-cli-package");
  await mkdir(path.join(root, "packages", "cli", "dist"), { recursive: true });
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      version: "0.6.0",
      packageManager: "pnpm@10.34.0",
      engines: { node: "24.18.0", pnpm: "10.34.0" },
    }),
  );
  await writeFile(
    path.join(root, "packages", "cli", "package.json"),
    JSON.stringify({ name: "@hcheck/cli", version: "0.6.0" }),
  );
  await writeFile(
    path.join(root, "packages", "cli", "dist", "index.js"),
    "if (process.argv.includes('--version')) console.log('0.6.0')\n",
  );

  const result = await packageCli({ root, outDir });

  assert.equal(result.manifest.smoke.status, "passed");
  assert.equal(result.manifestPath, path.join(outDir, "manifest.json"));
  assert.ok(!JSON.stringify(result.manifest).includes(root));
});
