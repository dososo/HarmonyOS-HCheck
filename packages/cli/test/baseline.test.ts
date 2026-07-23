import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";
import { NodeHash } from "../src/infrastructure/node-hash.js";
import { parseBaselineArguments, runBaseline } from "../src/baseline.js";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

test("baseline create 参数只接受显式 create、目录、JSON 输出和可选引用", () => {
  assert.deepEqual(parseBaselineArguments(["baseline", "create", "."]), {
    path: ".",
    format: "json",
    reference: "baseline/local",
    rules: [],
  });
  assert.deepEqual(
    parseBaselineArguments([
      "baseline",
      "create",
      ".",
      "--reference",
      "baseline/main",
      "--rules",
      "HOS-PERM-001,HOS-PKG-007",
    ]),
    {
      path: ".",
      format: "json",
      reference: "baseline/main",
      rules: ["HOS-PERM-001", "HOS-PKG-007"],
    },
  );
  assert.throws(
    () => parseBaselineArguments(["baseline", "diff", "."]),
    /baseline create/u,
  );
  assert.throws(
    () =>
      parseBaselineArguments(["baseline", "create", ".", "--format", "sarif"]),
    /仅支持 json/u,
  );
});

test("baseline create 从真实扫描结果生成稳定基线且不触发门禁", async () => {
  let stdout = "",
    stderr = "";
  const code = await runBaseline(
    [
      "baseline",
      "create",
      path.join(repositoryRoot, "fixtures", "missing-permission"),
      "--reference",
      "baseline/main",
      "--rules",
      "HOS-PERM-001",
    ],
    {
      fs: new NodeFileSystem(),
      hash: new NodeHash(),
      clock: { now: () => new Date("2026-07-11T00:00:00Z") },
      runId: { next: () => "baseline-test-run" },
      repositoryRoot,
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
      environment: {},
    },
  );

  const baseline = JSON.parse(stdout) as {
    schemaVersion: string;
    hcheckVersion: string;
    createdAt: string;
    reference: string;
    findings: readonly { fingerprint: string; ruleId: string }[];
  };
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(baseline.schemaVersion, "1.0.0");
  assert.equal(baseline.hcheckVersion, "0.6.0");
  assert.equal(baseline.createdAt, "2026-07-11T00:00:00.000Z");
  assert.equal(baseline.reference, "baseline/main");
  assert.deepEqual(
    baseline.findings.map(({ ruleId }) => ruleId),
    ["HOS-PERM-001"],
  );
  assert.match(
    baseline.findings[0]?.fingerprint ?? "",
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.ok(!stdout.includes(repositoryRoot));
});
