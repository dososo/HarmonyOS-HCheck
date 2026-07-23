import assert from "node:assert/strict";
import test from "node:test";
import {
  compareFindings,
  normalizeRelativeUri,
  type Finding,
} from "../src/index.js";

const base: Finding = {
  schemaVersion: "1.0.0",
  id: "finding-0001",
  ruleId: "HOS-META-003",
  ruleVersion: "1.0.0",
  title: "占位内容",
  severity: "HIGH",
  confidence: "PROBABLE",
  applicability: "APPLICABLE",
  fingerprint: `sha256:${"1".repeat(64)}`,
  message: "发现占位内容。",
  locations: [{ uri: "entry/a.ets" }],
  evidenceIds: ["evidence-0001"],
  remediation: { summary: "移除占位内容。", verification: "hcheck scan ." },
  autofix: "review_required",
  status: "new",
};

test("路径规范化不保留平台分隔符", () => {
  assert.equal(
    normalizeRelativeUri("./entry\\pages\\Index.ets"),
    "entry/pages/Index.ets",
  );
});

test("Finding 按严重性稳定排序", () => {
  const blocker: Finding = { ...base, severity: "BLOCKER", id: "finding-0002" };
  assert.ok(compareFindings(blocker, base) < 0);
});
