import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";
import { runExplain } from "../src/explain.js";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

test("explain 输出规则来源、证据类型、适用性和复验建议且不泄露本地路径", async () => {
  let stdout = "",
    stderr = "";
  const code = await runExplain(
    ["explain", "HOS-PRIV-002", "--format", "json"],
    {
      fs: new NodeFileSystem(),
      repositoryRoot,
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    },
  );

  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.ok(!stdout.includes(repositoryRoot));
  const payload = JSON.parse(stdout) as {
    ruleId: string;
    title: string;
    inputs: readonly string[];
    detector: string;
    appliesWhen: unknown;
    policyRefs: readonly { source: string; verifiedAt: string }[];
    remediation: { verification: string };
  };
  assert.equal(payload.ruleId, "HOS-PRIV-002");
  assert.match(payload.title, /第三方 SDK/u);
  assert.deepEqual(payload.inputs, ["dependency_graph", "privacy_policy"]);
  assert.equal(payload.detector, "privacy.sdkDisclosureConsistency");
  assert.equal(payload.policyRefs[0]?.source, "Huawei AppGallery Connect");
  assert.match(payload.remediation.verification, /HOS-PRIV-002/u);
});
