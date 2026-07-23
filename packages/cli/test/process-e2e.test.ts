import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const entry = path.join(repositoryRoot, "packages/cli/dist/index.js");

function execute(args: readonly string[]) {
  return spawnSync(process.execPath, [entry, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "" },
  });
}

test("真实 dist 进程保持正向1、干净0和配置错误3的标准流合同", () => {
  const defaultPositive = execute([
    "scan",
    "fixtures/placeholder-metadata",
    "--format",
    "json",
  ]);
  assert.equal(defaultPositive.status, 0);
  const defaultReport = JSON.parse(defaultPositive.stdout) as {
    findings: unknown[];
    summary: { gate: string };
  };
  assert.equal(defaultReport.findings.length, 1);
  assert.equal(defaultReport.summary.gate, "PASS");

  const positive = execute([
    "scan",
    "fixtures/placeholder-metadata",
    "--format",
    "json",
    "--fail-on",
    "high",
    "--confidence",
    "probable",
  ]);
  assert.equal(positive.status, 1);
  assert.equal(positive.stderr, "");
  const positiveReport = JSON.parse(positive.stdout) as {
    run: { hcheckVersion: string };
    summary: { gate: string };
  };
  assert.equal(positiveReport.run.hcheckVersion, "0.6.0");
  assert.equal(positiveReport.summary.gate, "FAIL");

  const clean = execute([
    "scan",
    "fixtures/clean-stage-app",
    "--format",
    "json",
    "--fail-on",
    "high",
    "--confidence",
    "probable",
  ]);
  assert.equal(clean.status, 0);
  assert.equal(clean.stderr, "");
  assert.equal(JSON.parse(clean.stdout).summary.gate, "PASS");

  const invalid = execute([
    "scan",
    "fixtures/clean-stage-app",
    "--api-token=HCHECK_SUPER_SECRET",
  ]);
  assert.equal(invalid.status, 3);
  assert.equal(invalid.stdout, "");
  assert.equal(invalid.stderr, "存在未知扫描参数。\n");
  assert.ok(!invalid.stderr.includes("HCHECK_SUPER_SECRET"));
});

test("真实 dist 将外部模块保守报告为 PARTIAL 并退出4", () => {
  const base = mkdtempSync(path.join(tmpdir(), "hcheck-external-"));
  const project = path.join(base, "project");
  const external = path.join(base, "external");
  const appScope = path.join(project, "AppScope");
  const externalMain = path.join(external, "src", "main");
  const files = [
    path.join(project, "build-profile.json5"),
    path.join(appScope, "app.json5"),
    path.join(externalMain, "module.json5"),
  ];
  const directories = [
    externalMain,
    path.join(external, "src"),
    external,
    appScope,
    project,
    base,
  ];
  try {
    mkdirSync(appScope, { recursive: true });
    mkdirSync(externalMain, { recursive: true });
    writeFileSync(
      files[0],
      `{ modules: [{ name: "entry", srcPath: ${JSON.stringify(external)} }] }`,
    );
    writeFileSync(
      files[1],
      `{ app: { bundleName: "com.hcheck.fixture.external" } }`,
    );
    writeFileSync(
      files[2],
      `{ module: { name: "entry", type: "entry", deviceTypes: ["phone"] } }`,
    );

    const result = execute(["scan", project, "--format", "json"]);
    assert.equal(result.status, 4);
    assert.equal(result.stderr, "");
    assert.ok(!result.stdout.includes(base));
    const report = JSON.parse(result.stdout) as {
      completeness: string;
      summary: { gate: string; total: number };
      findings: unknown[];
      errors: { kind: string }[];
    };
    assert.equal(report.completeness, "PARTIAL");
    assert.equal(report.summary.gate, "INCOMPLETE");
    assert.equal(report.summary.total, 0);
    assert.deepEqual(report.findings, []);
    assert.deepEqual(
      report.errors.map(({ kind }) => kind),
      ["EVIDENCE_INCOMPLETE"],
    );
  } finally {
    for (const file of files) unlinkSync(file);
    for (const directory of directories) rmdirSync(directory);
  }
});

test("真实 dist 支持 baseline create，并让空基线新增问题返回2", () => {
  const base = mkdtempSync(path.join(tmpdir(), "hcheck-baseline-e2e-"));
  const baseline = path.join(base, "baseline.json");
  try {
    const created = execute([
      "baseline",
      "create",
      "fixtures/missing-permission",
      "--reference",
      "baseline/main",
      "--rules",
      "HOS-PERM-001",
    ]);
    assert.equal(created.status, 0);
    assert.equal(created.stderr, "");
    const createdBaseline = JSON.parse(created.stdout) as {
      reference: string;
      findings: readonly { ruleId: string }[];
    };
    assert.equal(createdBaseline.reference, "baseline/main");
    assert.deepEqual(
      createdBaseline.findings.map(({ ruleId }) => ruleId),
      ["HOS-PERM-001"],
    );
    assert.ok(!created.stdout.includes(repositoryRoot));

    writeFileSync(
      baseline,
      `${JSON.stringify(
        {
          schemaVersion: "1.0.0",
          hcheckVersion: "0.6.0",
          createdAt: "2026-07-11T00:00:00Z",
          reference: "baseline/main",
          findings: [],
        },
        null,
        2,
      )}\n`,
    );
    const scan = execute([
      "scan",
      "fixtures/missing-permission",
      "--format",
      "json",
      "--fail-on",
      "high",
      "--confidence",
      "probable",
      "--rules",
      "HOS-PERM-001",
      "--baseline",
      baseline,
    ]);
    assert.equal(scan.status, 2);
    assert.equal(scan.stderr, "");
    const report = JSON.parse(scan.stdout) as {
      summary: { gate: string };
      findings: readonly {
        status: string;
        baseline?: { present?: boolean; reference?: string };
      }[];
    };
    assert.equal(report.summary.gate, "FAIL");
    assert.equal(report.findings[0]?.status, "new");
    assert.deepEqual(report.findings[0]?.baseline, {
      present: false,
      reference: "baseline/main",
    });
    assert.ok(!scan.stdout.includes(base));
  } finally {
    try {
      unlinkSync(baseline);
    } catch {
      // 基线文件可能尚未创建；不影响清理目录。
    }
    rmdirSync(base);
  }
});
