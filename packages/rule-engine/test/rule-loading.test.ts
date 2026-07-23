import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { HCheckError } from "@hcheck/core";
import type { ReadonlyFileSystemPort } from "@hcheck/project-model";
import {
  evaluateApplicability,
  loadRulePack,
  parseRuleDefinition,
  type ApplicabilityContext,
  type RuleDefinition,
  type RuleSchemas,
} from "../src/index.js";

const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const P0_PACK = path.join(REPOSITORY_ROOT, "rules/packs/p0.yml");
const schemas: RuleSchemas = {
  rule: JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/rule.schema.json"),
      "utf8",
    ),
  ) as object,
  pack: JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/rule-pack.schema.json"),
      "utf8",
    ),
  ) as object,
};

const fs: ReadonlyFileSystemPort = {
  readText: (file) => readFile(file, "utf8"),
  exists: async (candidate) =>
    stat(candidate).then(
      () => true,
      () => false,
    ),
  list: async () => [],
  kind: async (candidate) => {
    const value = await stat(candidate);
    if (value.isFile()) return "file";
    if (value.isDirectory()) return "directory";
    if (value.isSymbolicLink()) return "symlink";
    return "other";
  },
  size: async (file) => (await stat(file)).size,
  realpath,
  parent: path.dirname,
  resolve: path.resolve,
};

function loadPack(packPath: string, hcheckVersion = "0.6.0") {
  return loadRulePack({ packPath, hcheckVersion, fs, schemas });
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

interface SignedPackFixture {
  readonly packPath: string;
  readonly verifier: {
    verify(input: {
      readonly canonicalPayload: string;
      readonly signature: string;
      readonly keyId: string;
      readonly algorithm: "local-test-ed25519";
    }): Promise<boolean>;
  };
  readonly verifierCalls: { count: number };
}

async function createSignedPackFixture(
  variant: "valid" | "tampered-rule" | "unsafe-manifest-path",
): Promise<SignedPackFixture> {
  const root = await mkdtemp(path.join(tmpdir(), "hcheck-signed-pack-"));
  const packsDirectory = path.join(root, "packs");
  const metadataDirectory = path.join(root, "metadata");
  await mkdir(packsDirectory, { recursive: true });
  await mkdir(metadataDirectory, { recursive: true });

  const packPath = path.join(packsDirectory, "signed.yml");
  const rulePath = path.join(metadataDirectory, "HOS-META-003.yml");
  const packSource = [
    "id: signed-pack",
    "version: 0.6.0",
    'hcheck_compatibility: ">=0.6.0-0 <0.7.0"',
    "rules:",
    "  - metadata/HOS-META-003.yml",
    "",
  ].join("\n");
  const ruleSource = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  await writeFile(packPath, packSource);
  await writeFile(rulePath, ruleSource);

  const manifestFiles =
    variant === "unsafe-manifest-path"
      ? [
          {
            path: "../secret.yml",
            sha256: sha256Hex("tampered secret"),
          },
        ]
      : [
          {
            path: "packs/signed.yml",
            sha256: sha256Hex(packSource),
          },
          {
            path: "metadata/HOS-META-003.yml",
            sha256: sha256Hex(ruleSource),
          },
        ];
  const manifest = {
    version: 1,
    key_id: "local-test-key",
    algorithm: "local-test-ed25519",
    signed_at: "2026-07-11T00:00:00Z",
    files: manifestFiles,
    signature: "valid-local-test-signature",
  };
  await writeFile(
    path.join(packsDirectory, "signed.signature.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  if (variant === "tampered-rule") {
    await writeFile(rulePath, `${ruleSource}\n# tampered secret\n`);
  }

  const verifierCalls = { count: 0 };
  return {
    packPath,
    verifierCalls,
    verifier: {
      async verify(input) {
        verifierCalls.count += 1;
        assert.equal(input.keyId, "local-test-key");
        assert.equal(input.algorithm, "local-test-ed25519");
        assert.equal(input.signature, "valid-local-test-signature");
        assert.match(input.canonicalPayload, /"files"/u);
        return true;
      },
    },
  };
}

function context(
  mode: "quick" | null = "quick",
  platform: "harmonyos" | null = "harmonyos",
): ApplicabilityContext {
  return {
    ...(mode === null ? {} : { mode }),
    project: platform === null ? {} : { platform },
  };
}

function expectRuleError(secret?: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof HCheckError);
    assert.equal(error.code, "RULE_DEFINITION_ERROR");
    if (secret !== undefined) {
      assert.doesNotMatch(
        JSON.stringify({ message: error.message, details: error.details }),
        new RegExp(secret, "u"),
      );
    }
    return true;
  };
}

test("P0 规则包闭合且加载当前 active 结构规则，顺序稳定", async () => {
  const first = await loadPack(P0_PACK);
  const second = await loadPack(P0_PACK);

  assert.deepEqual(
    {
      id: first.id,
      version: first.version,
      compatibility: first.hcheckCompatibility,
      rules: first.rules.map((rule) => rule.id),
    },
    {
      id: "hcheck-p0",
      version: "0.6.0",
      compatibility: ">=0.6.0-0 <0.7.0",
      rules: [
        "HOS-META-003",
        "HOS-PKG-001",
        "HOS-PKG-006",
        "HOS-PKG-007",
        "HOS-PERM-001",
        "HOS-PRIV-002",
      ],
    },
  );
  assert.deepEqual(first, second);
  assert.equal(first.rules[0]?.status, "active");
  assert.equal(first.rules[1]?.status, "active");
  assert.equal(first.rules[2]?.status, "active");
  assert.equal(first.rules[3]?.status, "active");
  assert.equal(first.rules[4]?.status, "active");
  assert.equal(first.rules[5]?.status, "active");
});

test("规则包签名策略为 required 时缺少签名清单必须失败且不泄露绝对路径", async () => {
  const fixture = await createSignedPackFixture("valid");
  await assert.rejects(
    () =>
      loadRulePack({
        packPath: fixture.packPath,
        hcheckVersion: "0.6.0",
        fs,
        schemas,
        signaturePolicy: {
          mode: "required",
          manifestPath: "missing.signature.json",
          verifier: { verify: async () => true },
        },
      }),
    expectRuleError(REPOSITORY_ROOT),
  );
});

test("签名清单覆盖规则包和规则文件哈希时可加载", async () => {
  const fixture = await createSignedPackFixture("valid");
  const pack = await loadRulePack({
    packPath: fixture.packPath,
    hcheckVersion: "0.6.0",
    fs,
    schemas,
    signaturePolicy: {
      mode: "required",
      manifestPath: "signed.signature.json",
      verifier: fixture.verifier,
    },
  });

  assert.equal(pack.id, "signed-pack");
  assert.deepEqual(pack.signature, {
    status: "verified",
    keyId: "local-test-key",
    algorithm: "local-test-ed25519",
  });
  assert.equal(fixture.verifierCalls.count, 1);
});

test("规则文件被篡改时签名校验失败且不加载规则包", async () => {
  const fixture = await createSignedPackFixture("tampered-rule");
  await assert.rejects(
    () =>
      loadRulePack({
        packPath: fixture.packPath,
        hcheckVersion: "0.6.0",
        fs,
        schemas,
        signaturePolicy: {
          mode: "required",
          manifestPath: "signed.signature.json",
          verifier: fixture.verifier,
        },
      }),
    expectRuleError("tampered secret"),
  );
  assert.equal(fixture.verifierCalls.count, 0);
});

test("签名清单不得引用越界路径且失败时不访问 verifier", async () => {
  const fixture = await createSignedPackFixture("unsafe-manifest-path");
  await assert.rejects(
    () =>
      loadRulePack({
        packPath: fixture.packPath,
        hcheckVersion: "0.6.0",
        fs,
        schemas,
        signaturePolicy: {
          mode: "required",
          manifestPath: "signed.signature.json",
          verifier: fixture.verifier,
        },
      }),
    expectRuleError("secret"),
  );
  assert.equal(fixture.verifierCalls.count, 0);
});

test("RuleDefinition 完整映射规则 Schema 字段", async () => {
  const pack = await loadPack(P0_PACK);
  const rule = pack.rules[0];
  assert.ok(rule);

  assert.deepEqual(rule.category, {
    technical: "metadata",
    review: "app-information",
  });
  assert.deepEqual(rule.appliesWhen, {
    any: ["scan.mode == quick", "scan.mode == release", "scan.mode == submit"],
  });
  assert.deepEqual(rule.inputs, ["project_snapshot", "source_text"]);
  assert.equal(rule.detector.type, "structural");
  assert.equal(rule.detector.implementation, "metadata.placeholderContent");
  assert.equal(rule.detector.options?.marker, "HCHECK_PLACEHOLDER");
  assert.deepEqual(rule.detector.options?.extensions, [
    ".ets",
    ".ts",
    ".json5",
  ]);
  assert.deepEqual(rule.detector.options?.exclude_paths, [
    "node_modules/**",
    "**/node_modules/**",
    "oh_modules/**",
    "**/oh_modules/**",
    "build/**",
    "**/build/**",
  ]);
  assert.equal(rule.severity, "HIGH");
  assert.equal(rule.defaultConfidence, "PROBABLE");
  assert.equal(rule.policyRefs[0]?.verifiedAt, "2026-07-10");
  assert.equal(
    rule.remediation.verification,
    "hcheck scan . --rules HOS-META-003",
  );
  assert.equal(rule.autofix.level, "review_required");
  assert.deepEqual(rule.autofix.allowedPaths, [
    "**/*.ets",
    "**/*.ts",
    "**/*.json5",
  ]);
  assert.deepEqual(rule.knownFalsePositives, [
    "真实业务字符串若刻意包含 HCHECK_PLACEHOLDER，需要通过工程根相对路径精确豁免。",
  ]);
  assert.deepEqual(rule.tags, ["元数据", "占位"]);
  assert.equal(rule.introducedAt, "2026-07-10");
});

test("HOS-PKG-007 规则合同映射为保守测试地址检测器", async () => {
  const pack = await loadPack(P0_PACK);
  const rule = pack.rules.find((item) => item.id === "HOS-PKG-007");
  assert.ok(rule);

  assert.deepEqual(rule.category, {
    technical: "package",
    review: "app-information",
  });
  assert.deepEqual(rule.appliesWhen, {
    any: ["scan.mode == quick", "scan.mode == release", "scan.mode == submit"],
  });
  assert.deepEqual(rule.inputs, ["project_snapshot", "source_text"]);
  assert.equal(rule.detector.type, "structural");
  assert.equal(rule.detector.implementation, "package.testEndpoint");
  assert.deepEqual(rule.detector.options?.schemes, ["http", "https"]);
  assert.deepEqual(rule.detector.options?.blocked_hosts, [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
  ]);
  assert.deepEqual(rule.detector.options?.extensions, [
    ".ets",
    ".ts",
    ".json5",
  ]);
  assert.equal(rule.severity, "HIGH");
  assert.equal(rule.defaultConfidence, "PROBABLE");
  assert.deepEqual(
    rule.policyRefs.map((reference) => reference.verifiedAt),
    ["2026-07-11", "2026-07-11"],
  );
  assert.equal(
    rule.remediation.verification,
    "hcheck scan . --rules HOS-PKG-007",
  );
  assert.equal(rule.autofix.level, "review_required");
  assert.deepEqual(rule.autofix.allowedPaths, [
    "**/*.ets",
    "**/*.ts",
    "**/*.json5",
  ]);
  assert.deepEqual(rule.tags, ["测试地址", "本地环回", "发布内容"]);
  assert.equal(rule.introducedAt, "2026-07-11");
});

test("HOS-PKG-001 与 HOS-PKG-006 规则合同映射为本地软件包快照检测器", async () => {
  const pack = await loadPack(P0_PACK);
  const bundle = pack.rules.find((item) => item.id === "HOS-PKG-001");
  const debug = pack.rules.find((item) => item.id === "HOS-PKG-006");
  assert.ok(bundle);
  assert.ok(debug);

  assert.equal(bundle.status, "active");
  assert.equal(
    bundle.detector.implementation,
    "package.bundleIdentityConsistency",
  );
  assert.equal(
    bundle.detector.options?.snapshot_path,
    ".hcheck/package-snapshot.json",
  );
  assert.deepEqual(bundle.appliesWhen, {
    any: ["scan.mode == quick", "scan.mode == release", "scan.mode == submit"],
  });
  assert.deepEqual(bundle.inputs, ["project_snapshot", "package_manifest"]);
  assert.equal(bundle.severity, "BLOCKER");
  assert.equal(bundle.defaultConfidence, "CONFIRMED");
  assert.equal(bundle.autofix.level, "forbidden");

  assert.equal(debug.status, "active");
  assert.equal(debug.detector.implementation, "package.debugMaterial");
  assert.equal(
    debug.detector.options?.snapshot_path,
    ".hcheck/package-snapshot.json",
  );
  assert.deepEqual(debug.appliesWhen, {
    any: ["scan.mode == quick", "scan.mode == release", "scan.mode == submit"],
  });
  assert.deepEqual(debug.inputs, ["package_manifest"]);
  assert.equal(debug.severity, "BLOCKER");
  assert.equal(debug.defaultConfidence, "CONFIRMED");
  assert.equal(debug.autofix.level, "review_required");
});

test("HOS-PERM-001 规则合同映射为官方最小 API 权限检测器", async () => {
  const pack = await loadPack(P0_PACK);
  const rule = pack.rules.find((item) => item.id === "HOS-PERM-001");
  assert.ok(rule);

  assert.deepEqual(rule.category, {
    technical: "permission",
    review: "user-privacy",
  });
  assert.deepEqual(rule.appliesWhen, {
    any: ["scan.mode == quick", "scan.mode == release", "scan.mode == submit"],
  });
  assert.deepEqual(rule.inputs, ["project_snapshot", "source_ast"]);
  assert.equal(rule.detector.type, "semantic");
  assert.equal(
    rule.detector.implementation,
    "permission.apiDeclarationConsistency",
  );
  assert.equal(
    rule.detector.options?.mapping_source,
    "official-minimal-2026-07-11",
  );
  assert.deepEqual(rule.detector.options?.extensions, [".ets", ".ts"]);
  assert.deepEqual(rule.detector.options?.mappings, [
    {
      import_module: "@kit.LocationKit",
      import_name: "geoLocationManager",
      member: "getCurrentLocation",
      permission: "ohos.permission.APPROXIMATELY_LOCATION",
      source:
        "https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/js-apis-geolocationmanager-V5",
      verified_at: "2026-07-11",
    },
  ]);
  assert.equal(rule.severity, "BLOCKER");
  assert.equal(rule.defaultConfidence, "PROBABLE");
  assert.deepEqual(
    rule.policyRefs.map((reference) => reference.verifiedAt),
    ["2026-07-11", "2026-07-11"],
  );
  assert.equal(
    rule.remediation.verification,
    "hcheck scan . --rules HOS-PERM-001",
  );
  assert.equal(rule.autofix.level, "review_required");
  assert.deepEqual(rule.autofix.allowedPaths, ["**/module.json5"]);
  assert.deepEqual(rule.tags, ["权限", "API", "位置服务"]);
  assert.equal(rule.introducedAt, "2026-07-11");
});

test("HOS-PRIV-002 规则合同映射为本地 SDK 披露检测器", async () => {
  const pack = await loadPack(P0_PACK);
  const rule = pack.rules.find((candidate) => candidate.id === "HOS-PRIV-002");
  assert.ok(rule);

  assert.equal(rule.status, "active");
  assert.deepEqual(rule.appliesWhen, {
    any: ["scan.mode == quick", "scan.mode == release", "scan.mode == submit"],
  });
  assert.deepEqual(rule.inputs, ["dependency_graph", "privacy_policy"]);
  assert.equal(rule.detector.type, "composite");
  assert.equal(
    rule.detector.implementation,
    "privacy.sdkDisclosureConsistency",
  );
  assert.deepEqual(rule.detector.options, {
    minimum_fingerprint_confidence: "possible",
    policy_files: ["docs/privacy-policy.md"],
  });
  assert.equal(rule.defaultConfidence, "PROBABLE");
});

test("缺失 status、非法 date/uri 和规则原文均转换为脱敏规则定义错误", async () => {
  const secret = "SECRET-RULE-TEXT";
  const badRule = `id: ${secret}\npolicy_refs:\n  - url: not-a-uri\n    verified_at: 2026-99-99`;

  assert.throws(
    () => parseRuleDefinition(badRule, schemas),
    expectRuleError(secret),
  );

  const validRule = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  for (const invalidRule of [
    validRule.replace("status: active\n", ""),
    validRule.replace(
      "https://developer.huawei.com/consumer/cn/doc/app/50170",
      "不是 URI",
    ),
    validRule.replace('verified_at: "2026-07-10"', 'verified_at: "2026-99-99"'),
  ]) {
    assert.throws(
      () => parseRuleDefinition(invalidRule, schemas),
      expectRuleError(),
    );
  }
});

test("缺文件、损坏 YAML 和规则包未知字段均分类为规则定义错误且不泄密", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hcheck-rule-pack-"));
  const cases = [
    ["missing.yml", ""],
    ["broken.yml", "id: SECRET-BROKEN: ["],
    [
      "unknown.yml",
      "id: test\nversion: 0.6.0\nhcheck_compatibility: '>=0.6.0 <0.7.0'\nrules: []\nsecret_unknown: SECRET-UNKNOWN",
    ],
  ] as const;

  for (const [name, content] of cases) {
    const file = path.join(directory, name);
    if (content !== "") await writeFile(file, content, "utf8");
    await assert.rejects(
      loadPack(file),
      expectRuleError(
        content.includes("UNKNOWN") ? "SECRET-UNKNOWN" : "SECRET-BROKEN",
      ),
    );
  }
});

test("重复 ID 和同 ID 版本冲突明确失败", async () => {
  const sourceRule = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  const directory = await mkdtemp(path.join(tmpdir(), "hcheck-duplicate-"));
  const packsDirectory = path.join(directory, "packs");
  await mkdir(packsDirectory);
  await writeFile(path.join(directory, "one.yml"), sourceRule, "utf8");
  await writeFile(path.join(directory, "same.yml"), sourceRule, "utf8");
  await writeFile(
    path.join(directory, "other.yml"),
    sourceRule.replace("version: 1.0.0", "version: 2.0.0"),
    "utf8",
  );

  const pack = (rules: readonly string[]) =>
    `id: test-pack\nversion: 0.6.0\nhcheck_compatibility: ">=0.6.0 <0.7.0"\nrules:\n${rules.map((rule) => `  - ${rule}`).join("\n")}\n`;
  await writeFile(
    path.join(packsDirectory, "duplicate.yml"),
    pack(["one.yml", "same.yml"]),
    "utf8",
  );
  await writeFile(
    path.join(packsDirectory, "conflict.yml"),
    pack(["one.yml", "other.yml"]),
    "utf8",
  );

  await assert.rejects(
    loadPack(path.join(packsDirectory, "duplicate.yml")),
    /重复/u,
  );
  await assert.rejects(
    loadPack(path.join(packsDirectory, "conflict.yml")),
    /版本冲突/u,
  );
});

test("不兼容 HCheck 版本明确失败", async () => {
  await assert.rejects(loadPack(P0_PACK, "0.7.0"), /不兼容/u);
});

test("YAML alias 与危险对象键被拒绝且不泄露原文", () => {
  const sourceRule = readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  return sourceRule.then((validRule) => {
    const aliasSecret = validRule.replace(
      "  options:\n",
      "  options:\n    alias_seed: &secret [SECRET-ALIAS]\n    alias_use: *secret\n",
    );
    const dangerousSecret = validRule.replace(
      "  options:\n",
      "  options:\n    __proto__: SECRET-PROTO\n",
    );
    assert.throws(
      () => parseRuleDefinition(aliasSecret, schemas),
      expectRuleError("SECRET-ALIAS"),
    );
    assert.throws(
      () => parseRuleDefinition(dangerousSecret, schemas),
      expectRuleError("SECRET-PROTO"),
    );
  });
});

test("受限表达式返回真、假和登记字段缺值 UNKNOWN", () => {
  assert.equal(
    evaluateApplicability("project.platform == harmonyos", context()).value,
    "APPLICABLE",
  );
  assert.equal(
    evaluateApplicability("scan.mode != quick", context()).value,
    "NOT_APPLICABLE",
  );
  assert.equal(
    evaluateApplicability(
      "project.platform == harmonyos",
      context("quick", null),
    ).value,
    "UNKNOWN",
  );
  assert.equal(
    evaluateApplicability('scan.mode == "quick"', context()).value,
    "APPLICABLE",
  );
});

test("all/any 使用三值逻辑，且组合对象必须恰好一个运算符", () => {
  assert.equal(
    evaluateApplicability(
      { all: ["scan.mode == quick", "project.platform == harmonyos"] },
      context("quick", null),
    ).value,
    "UNKNOWN",
  );
  assert.equal(
    evaluateApplicability(
      { all: ["scan.mode != quick", "project.platform == harmonyos"] },
      context("quick", null),
    ).value,
    "NOT_APPLICABLE",
  );
  assert.equal(
    evaluateApplicability(
      { any: ["scan.mode == quick", "project.platform == harmonyos"] },
      context("quick", undefined),
    ).value,
    "APPLICABLE",
  );
  assert.throws(
    () =>
      evaluateApplicability(
        {
          all: ["scan.mode == quick"],
          any: ["scan.mode == quick"],
        } as unknown as RuleDefinition["appliesWhen"],
        context(),
      ),
    expectRuleError(),
  );
});

test("未登记路径、非法语法和代码文本均被拒绝且绝不执行", () => {
  const marker = { executed: false };
  Object.defineProperty(globalThis, "hcheckAttack", {
    configurable: true,
    set: () => {
      marker.executed = true;
    },
  });

  for (const expression of [
    "project.secret == token",
    "scan.mode === quick",
    "globalThis.hcheckAttack = true",
    "scan.mode == quick || globalThis.hcheckAttack = true",
  ]) {
    assert.throws(
      () => evaluateApplicability(expression, context()),
      expectRuleError(),
    );
  }
  assert.equal(marker.executed, false);
  delete (globalThis as Record<string, unknown>).hcheckAttack;
});

test("未登记路径和非法语法在规则解析与规则包加载边界即被脱敏拒绝", async () => {
  const validRule = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  const invalidRules = [
    validRule.replace("scan.mode == quick", "project.secret == SECRET-PATH"),
    validRule.replace("scan.mode == quick", "scan.mode === SECRET-SYNTAX"),
  ];
  const directory = await mkdtemp(path.join(tmpdir(), "hcheck-applicability-"));
  const packsDirectory = path.join(directory, "packs");
  await mkdir(packsDirectory);

  for (const [index, invalidRule] of invalidRules.entries()) {
    const secret = index === 0 ? "SECRET-PATH" : "SECRET-SYNTAX";
    assert.throws(
      () => parseRuleDefinition(invalidRule, schemas),
      expectRuleError(secret),
    );
    const ruleName = `invalid-${index}.yml`;
    await writeFile(path.join(directory, ruleName), invalidRule, "utf8");
    const packPath = path.join(packsDirectory, `invalid-${index}.yml`);
    await writeFile(
      packPath,
      `id: invalid-pack\nversion: 0.6.0\nhcheck_compatibility: ">=0.6.0 <0.7.0"\nrules:\n  - ${ruleName}\n`,
      "utf8",
    );
    await assert.rejects(loadPack(packPath), expectRuleError(secret));
  }
});

test("P0 兼容实际 CLI 预发布版本，SemVer 正确比较 beta.2 与 beta.10", async () => {
  const cliSource = await readFile(
    path.join(REPOSITORY_ROOT, "packages/cli/src/version.ts"),
    "utf8",
  );
  const cliVersion = /HCHECK_VERSION = "([^"]+)"/u.exec(cliSource)?.[1];
  assert.ok(cliVersion);
  assert.equal((await loadPack(P0_PACK, cliVersion)).id, "hcheck-p0");
  const directory = await mkdtemp(path.join(tmpdir(), "hcheck-semver-"));
  const packsDirectory = path.join(directory, "packs");
  await mkdir(packsDirectory);
  await writeFile(
    path.join(directory, "rule.yml"),
    await readFile(
      path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
      "utf8",
    ),
    "utf8",
  );
  const packPath = path.join(packsDirectory, "beta.yml");
  await writeFile(
    packPath,
    'id: beta-pack\nversion: 0.1.0\nhcheck_compatibility: ">=0.1.0-beta.10 <0.2.0"\nrules:\n  - rule.yml\n',
    "utf8",
  );
  await assert.rejects(loadPack(packPath, "0.1.0-beta.2"), /不兼容/u);
  assert.equal((await loadPack(packPath, "0.1.0-beta.10")).id, "beta-pack");
});

test("规则包和规则读取前执行字节上限，规则数也有上限", async () => {
  const oversizedFs: ReadonlyFileSystemPort = {
    ...fs,
    size: async () => Number.MAX_SAFE_INTEGER,
  };
  await assert.rejects(
    loadRulePack({
      packPath: P0_PACK,
      hcheckVersion: "0.6.0",
      fs: oversizedFs,
      schemas,
    }),
    expectRuleError(),
  );
  const oversizedRuleFs: ReadonlyFileSystemPort = {
    ...fs,
    size: async (file) =>
      file.endsWith("p0.yml") ? fs.size(file) : Number.MAX_SAFE_INTEGER,
  };
  await assert.rejects(
    loadRulePack({
      packPath: P0_PACK,
      hcheckVersion: "0.6.0",
      fs: oversizedRuleFs,
      schemas,
    }),
    expectRuleError(),
  );
  const directory = await mkdtemp(path.join(tmpdir(), "hcheck-many-rules-"));
  const packPath = path.join(directory, "many.yml");
  await writeFile(
    packPath,
    `id: too-many\nversion: 0.6.0\nhcheck_compatibility: ">=0.6.0-0 <0.7.0"\nrules:\n${Array.from({ length: 257 }, (_, index) => `  - r${index}.yml`).join("\n")}\n`,
    "utf8",
  );
  await assert.rejects(loadPack(packPath), expectRuleError());
});

test("拒绝异步 Schema，适用性字段只接受登记值", async () => {
  const validRule = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  for (const invalidRule of [
    validRule.replace("scan.mode == quick", "scan.mode == quik"),
    validRule.replace("scan.mode == quick", "project.platform == harmony"),
  ]) {
    assert.throws(
      () => parseRuleDefinition(invalidRule, schemas),
      expectRuleError(),
    );
  }
  assert.throws(
    () =>
      parseRuleDefinition(validRule, {
        ...schemas,
        rule: { ...schemas.rule, $async: true },
      }),
    expectRuleError(),
  );
  await assert.rejects(
    loadRulePack({
      packPath: P0_PACK,
      hcheckVersion: "0.6.0",
      fs,
      schemas: { ...schemas, pack: { ...schemas.pack, $async: true } },
    }),
    expectRuleError(),
  );
});

test("加载结果深拷贝并深冻结所有嵌套对象和数组", async () => {
  const pack = await loadPack(P0_PACK);
  const rule = pack.rules[0];
  assert.ok(rule);
  for (const value of [
    pack,
    pack.rules,
    rule,
    rule.detector,
    rule.detector.options,
    rule.inputs,
    rule.policyRefs,
  ]) {
    assert.equal(Object.isFrozen(value), true);
  }
  assert.throws(() => {
    (rule.detector.options as { extensions: string[] }).extensions.push("篡改");
  }, TypeError);
});

test("Windows realpath containment 对盘符和 UNC 大小写不敏感，POSIX 保持区分", async () => {
  const ruleSource = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  const packSource =
    'id: win-pack\nversion: 0.6.0\nhcheck_compatibility: ">=0.6.0-0 <0.7.0"\nrules:\n  - metadata/HOS-META-003.yml\n';
  const windowsFs = (
    root: string,
    canonicalRoot: string,
    canonicalRuleRoot: string,
  ): ReadonlyFileSystemPort => ({
    readText: async (file) =>
      file.toLowerCase().endsWith("p0.yml") ? packSource : ruleSource,
    exists: async () => true,
    list: async () => [],
    kind: async () => "file",
    size: async (file) =>
      file.toLowerCase().endsWith("p0.yml")
        ? packSource.length
        : ruleSource.length,
    realpath: async (file) =>
      file.toLowerCase().endsWith("rules")
        ? canonicalRoot
        : `${canonicalRuleRoot}\\metadata\\HOS-META-003.yml`,
    parent: path.win32.dirname,
    resolve: path.win32.resolve,
  });
  for (const [root, canonical, canonicalRule] of [
    ["C:\\Repo\\Rules", "c:\\repo\\rules", "C:\\REPO\\RULES"],
    [
      "\\\\Server\\Share\\Rules",
      "\\\\server\\share\\rules",
      "\\\\SERVER\\SHARE\\RULES",
    ],
  ]) {
    const port = windowsFs(root, canonical, canonicalRule);
    assert.equal(
      (
        await loadRulePack({
          packPath: `${root}\\packs\\p0.yml`,
          hcheckVersion: "0.6.0",
          fs: port,
          schemas,
        })
      ).id,
      "win-pack",
    );
  }
  const posixFs: ReadonlyFileSystemPort = {
    readText: async (file) =>
      file.endsWith("p0.yml") ? packSource : ruleSource,
    exists: async () => true,
    list: async () => [],
    kind: async () => "file",
    size: async (file) =>
      file.endsWith("p0.yml") ? packSource.length : ruleSource.length,
    realpath: async (file) =>
      file.endsWith("Rules")
        ? "/Repo/Rules"
        : "/repo/rules/metadata/HOS-META-003.yml",
    parent: path.posix.dirname,
    resolve: path.posix.resolve,
  };
  await assert.rejects(
    loadRulePack({
      packPath: "/Repo/Rules/packs/p0.yml",
      hcheckVersion: "0.6.0",
      fs: posixFs,
      schemas,
    }),
    expectRuleError(),
  );
});

test("Windows 盘符根保留根分隔符并允许根内规则", async () => {
  const ruleSource = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  const packSource =
    'id: root-pack\nversion: 0.6.0\nhcheck_compatibility: ">=0.6.0-0 <0.7.0"\nrules:\n  - HOS-META-003.yml\n';
  const rootFs: ReadonlyFileSystemPort = {
    readText: async (file) =>
      file.toLowerCase().endsWith("p0.yml") ? packSource : ruleSource,
    exists: async () => true,
    list: async () => [],
    kind: async () => "file",
    size: async (file) =>
      file.toLowerCase().endsWith("p0.yml")
        ? packSource.length
        : ruleSource.length,
    realpath: async (file) =>
      file === "C:\\" ? "C:\\" : "C:\\HOS-META-003.yml",
    parent: path.win32.dirname,
    resolve: path.win32.resolve,
  };
  assert.equal(
    (
      await loadRulePack({
        packPath: "C:\\packs\\p0.yml",
        hcheckVersion: "0.6.0",
        fs: rootFs,
        schemas,
      })
    ).id,
    "root-pack",
  );
});

test("非法 Rule/Pack/HCheck SemVer 分别以脱敏领域错误拒绝", async () => {
  const validRule = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  assert.throws(
    () =>
      parseRuleDefinition(
        validRule.replace("version: 1.0.0", "version: 1.0.0-01"),
        schemas,
      ),
    expectRuleError(),
  );
  await assert.rejects(loadPack(P0_PACK, "0.6.0-01"), (error: unknown) => {
    assert.ok(error instanceof HCheckError);
    assert.equal(error.code, "RULE_DEFINITION_ERROR");
    assert.equal(error.details.kind, "hcheck_version");
    return true;
  });
  const directory = await mkdtemp(
    path.join(tmpdir(), "hcheck-invalid-semver-"),
  );
  const packPath = path.join(directory, "pack.yml");
  await writeFile(
    packPath,
    'id: invalid-version\nversion: 0.1.0-01\nhcheck_compatibility: ">=0.1.0-0 <0.2.0"\nrules:\n  - x.yml\n',
    "utf8",
  );
  await assert.rejects(loadPack(packPath), expectRuleError());
});

test("缺失 Schema id 和 Schema 编译异常均转为脱敏规则定义错误", async () => {
  const validRule = await readFile(
    path.join(REPOSITORY_ROOT, "rules/metadata/HOS-META-003.yml"),
    "utf8",
  );
  const ruleWithoutId = { ...schemas.rule } as Record<string, unknown>;
  Reflect.deleteProperty(ruleWithoutId, "$id");
  assert.throws(
    () => parseRuleDefinition(validRule, { ...schemas, rule: ruleWithoutId }),
    expectRuleError(),
  );
  assert.throws(
    () =>
      parseRuleDefinition(validRule, {
        ...schemas,
        rule: { ...schemas.rule, type: "SECRET-BAD-SCHEMA" },
      }),
    expectRuleError("SECRET-BAD-SCHEMA"),
  );
});

test("端口 size 偏小但 readText 实际 UTF-8 超限时在解析前拒绝", async () => {
  const raceFs: ReadonlyFileSystemPort = {
    ...fs,
    size: async () => 1,
    readText: async () => "密".repeat(70_000),
  };
  await assert.rejects(
    loadRulePack({
      packPath: P0_PACK,
      hcheckVersion: "0.6.0",
      fs: raceFs,
      schemas,
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "RULE_DEFINITION_ERROR");
      assert.equal(error.details.kind, "pack_size");
      return true;
    },
  );
});
