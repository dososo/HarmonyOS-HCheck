import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { HCheckError, type HashPort } from "@hcheck/core";
import type {
  ProjectSnapshot,
  ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import type { RuleDefinition } from "../src/index.js";
import {
  detectPackageBundleIdentity,
  detectPackageDebugMaterial,
} from "../src/detectors/package-artifact.js";

const hash: HashPort = {
  async sha256(content) {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  },
};

const workspaceRoot = "/workspace";
const snapshotPath = ".hcheck/package-snapshot.json";

function project(bundleName = "com.example.project"): ProjectSnapshot {
  return {
    schemaVersion: "1.0.0",
    root: ".",
    platform: "harmonyos",
    appScope: "AppScope/app.json5",
    bundleName,
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

function bundleRule(): RuleDefinition {
  return {
    id: "HOS-PKG-001",
    version: "1.0.0",
    status: "active",
    title: "工程与软件包 Bundle 标识不一致",
    summary: "工程与录制软件包快照中的 Bundle 标识不一致。",
    category: { technical: "package", review: "app-information" },
    appliesWhen: "project.platform == harmonyos",
    inputs: ["project_snapshot", "package_manifest"],
    detector: {
      type: "composite",
      implementation: "package.bundleIdentityConsistency",
      options: { snapshot_path: snapshotPath },
    },
    severity: "BLOCKER",
    defaultConfidence: "CONFIRMED",
    policyRefs: [
      {
        source: "Huawei AppGallery Connect Help",
        section: "发布应用与软件包",
        url: "https://developer.huawei.com/consumer/en/doc/app/agc-help-release-app-prepare-0000002306311921",
        verifiedAt: "2026-07-11",
      },
    ],
    remediation: { summary: "统一 Bundle。", verification: "重新扫描。" },
    autofix: { level: "forbidden" },
  };
}

function debugRule(): RuleDefinition {
  return {
    id: "HOS-PKG-006",
    version: "1.0.0",
    status: "active",
    title: "正式软件包包含调试或测试资源",
    summary: "录制软件包快照中发现调试模块或测试资源标记。",
    category: { technical: "package", review: "app-security" },
    appliesWhen: "project.platform == harmonyos",
    inputs: ["package_manifest"],
    detector: {
      type: "artifact",
      implementation: "package.debugMaterial",
      options: { snapshot_path: snapshotPath },
    },
    severity: "BLOCKER",
    defaultConfidence: "CONFIRMED",
    policyRefs: [
      {
        source: "Huawei AppGallery Connect Help",
        section: "应用软件包检查",
        url: "https://developer.huawei.com/consumer/en/doc/app/agc-help-release-app-prepare-0000002306311921",
        verifiedAt: "2026-07-11",
      },
    ],
    remediation: { summary: "移除调试资源。", verification: "重新扫描。" },
    autofix: { level: "review_required" },
  };
}

test("软件包 Bundle 规则只在录制快照与工程 Bundle 不一致时输出 CONFIRMED Finding", async () => {
  const result = await detectPackageBundleIdentity({
    project: project(),
    rule: bundleRule(),
    fs: fsWithSnapshot(snapshot({ bundleName: "com.example.package" })),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.findings[0]?.ruleId, "HOS-PKG-001");
  assert.equal(result.findings[0]?.confidence, "CONFIRMED");
  assert.equal(result.findings[0]?.evidenceIds[0], result.evidence[0]?.id);
  assert.ok(!JSON.stringify(result).includes(workspaceRoot));

  const clean = await detectPackageBundleIdentity({
    project: project("com.example.package"),
    rule: bundleRule(),
    fs: fsWithSnapshot(snapshot({ bundleName: "com.example.package" })),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });
  assert.deepEqual(clean.findings, []);
  assert.deepEqual(clean.evidence, []);
});

test("调试资源规则基于录制快照中的 debug 标记输出 CONFIRMED Finding", async () => {
  const result = await detectPackageDebugMaterial({
    project: project(),
    rule: debugRule(),
    fs: fsWithSnapshot(
      snapshot({
        bundleName: "com.example.project",
        markerFiles: ["resources/rawfile/hcheck-debug-marker.txt"],
      }),
    ),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.evidence.length, 1);
  assert.equal(result.findings[0]?.ruleId, "HOS-PKG-006");
  assert.equal(result.findings[0]?.confidence, "CONFIRMED");
  assert.deepEqual(result.findings[0]?.locations, [
    {
      uri: ".hcheck/package-snapshot.json",
      logicalPath: "debug.markerFiles",
    },
  ]);
  assert.ok(!JSON.stringify(result).includes(workspaceRoot));

  const clean = await detectPackageDebugMaterial({
    project: project(),
    rule: debugRule(),
    fs: fsWithSnapshot(snapshot({ bundleName: "com.example.project" })),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });
  assert.deepEqual(clean.findings, []);
  assert.deepEqual(clean.evidence, []);
});

test("录制软件包快照缺失时不伪造 Finding，损坏时返回证据不完整", async () => {
  const missing = await detectPackageBundleIdentity({
    project: project(),
    rule: bundleRule(),
    fs: fsWithSnapshot(undefined),
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });
  assert.deepEqual(missing, { evidence: [], findings: [] });

  await assert.rejects(
    detectPackageDebugMaterial({
      project: project(),
      rule: debugRule(),
      fs: fsWithRawSnapshot("{"),
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

function snapshot({
  bundleName,
  markerFiles = [],
}: {
  readonly bundleName: string;
  readonly markerFiles?: readonly string[];
}): string {
  return JSON.stringify({
    schemaVersion: "1.0.0",
    artifact: { type: "hap", sizeBytes: 1024 },
    entries: [],
    modules: [
      {
        name: "entry",
        type: "entry",
        packageName: bundleName,
        deviceTypes: ["phone"],
        requestPermissions: [],
        source: "module.json",
      },
    ],
    bundleName,
    permissions: [],
    debug: {
      enabledModules: [],
      markerFiles,
    },
    completeness: "COMPLETE",
    issues: [],
  });
}

function fsWithSnapshot(content: string | undefined): ReadonlyFileSystemPort {
  return fsWithRawSnapshot(content);
}

function fsWithRawSnapshot(
  content: string | undefined,
): ReadonlyFileSystemPort {
  const absolute = `${workspaceRoot}/${snapshotPath}`;
  return {
    readText: async (file) => {
      if (file !== absolute || content === undefined)
        throw new Error("missing");
      return content;
    },
    exists: async (file) => file === absolute && content !== undefined,
    list: async () => [],
    kind: async (file) =>
      file === absolute && content !== undefined ? "file" : "other",
    size: async (file) => {
      if (file !== absolute || content === undefined)
        throw new Error("missing");
      return Buffer.byteLength(content);
    },
    realpath: async (file) => file,
    parent: (file) => file.slice(0, file.lastIndexOf("/")),
    resolve: (...parts) => parts.join("/").replace(/\/{2,}/gu, "/"),
  };
}
