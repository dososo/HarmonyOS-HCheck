import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { HCheckError, type HashPort } from "@hcheck/core";
import type {
  ProjectSnapshot,
  ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import type { RuleDefinition } from "../src/index.js";
import { detectSdkDisclosureConsistency } from "../src/detectors/privacy-sdk.js";

const workspaceRoot = "/workspace";
const hash: HashPort = {
  async sha256(content) {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  },
};

function project(): ProjectSnapshot {
  return {
    schemaVersion: "1.0.0",
    root: ".",
    platform: "harmonyos",
    appScope: "AppScope/app.json5",
    bundleName: "com.example.project",
    products: [],
    modules: [],
    metadata: {},
    configSources: {
      appScope: "AppScope/app.json5",
      buildProfile: "build-profile.json5",
      modules: [],
    },
  };
}

function rule(): RuleDefinition {
  return {
    id: "HOS-PRIV-002",
    version: "1.0.0",
    status: "active",
    title: "最终应用包含未披露的第三方 SDK",
    summary: "依赖图中发现第三方 SDK 候选，但隐私政策未披露。",
    category: { technical: "privacy", review: "user-privacy" },
    appliesWhen: "project.platform == harmonyos",
    inputs: ["dependency_graph", "privacy_policy"],
    detector: {
      type: "composite",
      implementation: "privacy.sdkDisclosureConsistency",
      options: {
        policy_files: ["docs/privacy-policy.md"],
        minimum_fingerprint_confidence: "possible",
      },
    },
    severity: "BLOCKER",
    defaultConfidence: "PROBABLE",
    policyRefs: [
      {
        source: "Huawei AppGallery Connect",
        section: "管理隐私声明",
        url: "https://developer.huawei.com/consumer/cn/doc/app/agc-help-privacy-policy-overview-0000002316881805",
        verifiedAt: "2026-07-10",
      },
    ],
    remediation: { summary: "补充 SDK 披露。", verification: "重新扫描。" },
    autofix: { level: "forbidden" },
  };
}

test("SDK 披露规则在依赖候选未出现在隐私政策时输出 PROBABLE Finding", async () => {
  const result = await detectSdkDisclosureConsistency({
    project: project(),
    rule: rule(),
    fs: fsWithFiles({
      "oh-package.json5": `{
        dependencies: { '@mock/analytics-sdk': '1.0.0' },
      }`,
      "oh-package-lock.json5": `{
        packages: {
          '@mock/analytics-sdk@1.0.0': { version: '1.0.0' },
        },
      }`,
      "docs/privacy-policy.md": "本应用不包含任何第三方 SDK。",
    }),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.findings[0]?.ruleId, "HOS-PRIV-002");
  assert.equal(result.findings[0]?.confidence, "PROBABLE");
  assert.notEqual(result.findings[0]?.confidence, "CONFIRMED");
  assert.deepEqual(result.findings[0]?.locations, [
    {
      uri: "oh-package-lock.json5",
      logicalPath: "packages.@mock/analytics-sdk@1.0.0",
    },
  ]);
  assert.ok(!JSON.stringify(result).includes(workspaceRoot));
});

test("SDK 披露规则在隐私政策已有披露时不输出 Finding", async () => {
  const result = await detectSdkDisclosureConsistency({
    project: project(),
    rule: rule(),
    fs: fsWithFiles({
      "oh-package.json5": `{
        dependencies: { '@mock/analytics-sdk': '1.0.0' },
      }`,
      "oh-package-lock.json5": `{
        packages: {
          '@mock/analytics-sdk@1.0.0': { version: '1.0.0' },
        },
      }`,
      "docs/privacy-policy.md":
        "本应用使用 @mock/analytics-sdk 进行匿名稳定性分析。",
    }),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });

  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.evidence, []);
});

test("SDK 披露规则在隐私政策缺失时不假 PASS", async () => {
  const result = await detectSdkDisclosureConsistency({
    project: project(),
    rule: rule(),
    fs: fsWithFiles({
      "oh-package.json5": `{
        dependencies: { '@mock/analytics-sdk': '1.0.0' },
      }`,
      "oh-package-lock.json5": `{
        packages: {
          '@mock/analytics-sdk@1.0.0': { version: '1.0.0' },
        },
      }`,
    }),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });

  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0]?.message ?? "", /隐私政策/u);
  assert.ok(!JSON.stringify(result).includes(workspaceRoot));
});

test("SDK 披露规则在依赖证据损坏时返回证据不完整且不泄露路径", async () => {
  await assert.rejects(
    detectSdkDisclosureConsistency({
      project: project(),
      rule: rule(),
      fs: fsWithFiles({
        "oh-package.json5": "{",
      }),
      hash,
      workspaceRoot,
      globalExcludePaths: [],
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "EVIDENCE_INCOMPLETE");
      assert.ok(!JSON.stringify(error).includes(workspaceRoot));
      return true;
    },
  );
});

function fsWithFiles(
  files: Readonly<Record<string, string>>,
): ReadonlyFileSystemPort {
  const entries = new Map(
    Object.entries(files).map(([file, content]) => [
      `${workspaceRoot}/${file}`,
      content,
    ]),
  );
  return {
    readText: async (file) => {
      const content = entries.get(file);
      if (content === undefined) throw new Error("missing");
      return content;
    },
    exists: async (file) => entries.has(file),
    list: async () => [],
    kind: async (file) => (entries.has(file) ? "file" : "other"),
    size: async (file) => {
      const content = entries.get(file);
      if (content === undefined) throw new Error("missing");
      return Buffer.byteLength(content);
    },
    realpath: async (file) => file,
    parent: (file) => file.slice(0, file.lastIndexOf("/")),
    resolve: (...parts) => parts.join("/").replace(/\/{2,}/gu, "/"),
  };
}
