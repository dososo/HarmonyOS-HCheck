import assert from "node:assert/strict";
import test from "node:test";
import type { Finding } from "@hcheck/core";
import {
  buildAgentJsonReport,
  buildSafeFixPlan,
  evaluatePostFixRescan,
  renderAgentJsonReport,
} from "../src/index.js";

const A = "a".repeat(64);
const finding = (overrides: Partial<Finding> = {}): Finding => ({
  schemaVersion: "1.0.0",
  id: `finding:${A}`,
  ruleId: "HOS-PERM-001",
  ruleVersion: "1.0.0",
  title: "缺少权限声明",
  severity: "HIGH",
  confidence: "PROBABLE",
  applicability: "APPLICABLE",
  fingerprint: `sha256:${A}`,
  message: "API 调用缺少对应权限声明。",
  locations: [{ uri: "entry/src/main/ets/Index.ets", line: 8 }],
  evidenceIds: [`evidence:${A}`],
  remediation: {
    summary: "补充 requestPermissions 声明",
    verification: "重新执行扫描",
  },
  autofix: "review_required",
  status: "new",
  ...overrides,
});

test("buildAgentJsonReport 输出修改范围、风险、修复建议、复验命令和安全边界", () => {
  const report = buildAgentJsonReport({
    run: {
      id: "run-agent",
      hcheckVersion: "0.6.0",
      completeness: "COMPLETE",
      gate: "FAIL",
    },
    findings: [finding()],
    allowedPaths: ["entry/src/main/module.json5"],
    forbiddenPaths: ["oh_modules", "build"],
    verificationCommands: ["pnpm check"],
  });

  assert.equal(report.schemaVersion, "1.0.0");
  assert.deepEqual(report.safety, {
    allowedPaths: ["entry/src/main/module.json5"],
    forbiddenPaths: ["build", "oh_modules"],
    boundaries: [
      "只允许修改 allowedPaths 中声明的仓库相对路径。",
      "禁止读取或写入凭证、私钥、Token、真实用户数据和生产数据。",
      "修复后必须执行 verificationCommands 并回填结果。",
    ],
  });
  assert.deepEqual(report.actions, [
    {
      findingId: `finding:${A}`,
      ruleId: "HOS-PERM-001",
      title: "缺少权限声明",
      risk: "high",
      autofix: "review_required",
      locations: ["entry/src/main/ets/Index.ets:8"],
      suggestedFix: "补充 requestPermissions 声明",
      verificationCommands: ["pnpm check"],
    },
  ]);
  assert.doesNotMatch(renderAgentJsonReport(report), /\/Users\/|SECRET/u);
});

test("buildSafeFixPlan 只允许 allowed 级别且受规则和路径白名单限制", () => {
  const report = buildAgentJsonReport({
    run: {
      id: "run-agent",
      hcheckVersion: "0.6.0",
      completeness: "COMPLETE",
      gate: "FAIL",
    },
    findings: [
      finding({
        id: `finding:${"b".repeat(64)}`,
        fingerprint: `sha256:${"b".repeat(64)}`,
        evidenceIds: [`evidence:${"b".repeat(64)}`],
        autofix: "allowed",
        locations: [{ uri: "entry/src/main/module.json5", line: 4 }],
      }),
      finding({
        id: `finding:${"c".repeat(64)}`,
        fingerprint: `sha256:${"c".repeat(64)}`,
        evidenceIds: [`evidence:${"c".repeat(64)}`],
        ruleId: "HOS-PKG-006",
        autofix: "forbidden",
        locations: [{ uri: "entry/src/main/module.json5", line: 9 }],
      }),
      finding({
        id: `finding:${"d".repeat(64)}`,
        fingerprint: `sha256:${"d".repeat(64)}`,
        evidenceIds: [`evidence:${"d".repeat(64)}`],
        autofix: "allowed",
        locations: [{ uri: "entry/src/main/ets/Index.ets", line: 12 }],
      }),
    ],
    allowedPaths: ["entry/src/main/module.json5"],
    forbiddenPaths: ["build", "oh_modules"],
    verificationCommands: ["pnpm check"],
  });

  const plan = buildSafeFixPlan({
    report,
    mode: "dry-run",
    allowedRules: ["HOS-PERM-001"],
  });

  assert.deepEqual(
    plan.actions.map((action) => ({
      findingId: action.findingId,
      ruleId: action.ruleId,
      targetPath: action.targetPath,
      status: action.status,
    })),
    [
      {
        findingId: `finding:${"b".repeat(64)}`,
        ruleId: "HOS-PERM-001",
        targetPath: "entry/src/main/module.json5",
        status: "executable",
      },
    ],
  );
  assert.deepEqual(
    plan.blockedActions.map((action) => ({
      findingId: action.findingId,
      ruleId: action.ruleId,
      targetPath: action.targetPath,
      reason: action.reason,
    })),
    [
      {
        findingId: `finding:${"c".repeat(64)}`,
        ruleId: "HOS-PKG-006",
        targetPath: "entry/src/main/module.json5",
        reason: "AUTOFIX_FORBIDDEN",
      },
      {
        findingId: `finding:${"d".repeat(64)}`,
        ruleId: "HOS-PERM-001",
        targetPath: "entry/src/main/ets/Index.ets",
        reason: "PATH_NOT_ALLOWED",
      },
    ],
  );
  assert.equal(plan.audit.rescanRequired, true);
  assert.equal(plan.audit.canMarkFixedWithoutRescan, false);
  assert.deepEqual(plan.verificationCommands, ["pnpm check"]);
});

test("evaluatePostFixRescan 在重扫不完整或问题仍存在时不能标记 fixed", () => {
  const before = `finding:${"e".repeat(64)}`;
  const after = finding({
    id: before,
    fingerprint: `sha256:${"e".repeat(64)}`,
    evidenceIds: [`evidence:${"e".repeat(64)}`],
    autofix: "allowed",
  });

  assert.deepEqual(
    evaluatePostFixRescan({
      beforeFindingIds: [before],
      afterFindings: [],
      completeness: "PARTIAL",
      verification: [
        { command: "pnpm check", status: "passed", summary: "ok" },
      ],
    }),
    {
      schemaVersion: "1.0.0",
      status: "blocked",
      unresolvedFindingIds: [before],
      reason: "RESCAN_INCOMPLETE",
    },
  );

  assert.deepEqual(
    evaluatePostFixRescan({
      beforeFindingIds: [before],
      afterFindings: [after],
      completeness: "COMPLETE",
      verification: [
        { command: "pnpm check", status: "passed", summary: "ok" },
      ],
    }),
    {
      schemaVersion: "1.0.0",
      status: "not-fixed",
      unresolvedFindingIds: [before],
      reason: "FINDINGS_STILL_PRESENT",
    },
  );

  assert.deepEqual(
    evaluatePostFixRescan({
      beforeFindingIds: [before],
      afterFindings: [],
      completeness: "COMPLETE",
      verification: [
        { command: "pnpm check", status: "passed", summary: "ok" },
      ],
    }),
    {
      schemaVersion: "1.0.0",
      status: "fixed",
      unresolvedFindingIds: [],
      reason: "VERIFIED_BY_RESCAN",
    },
  );
});

test("buildAgentJsonReport 拒绝绝对路径和越界路径", () => {
  assert.throws(
    () =>
      buildAgentJsonReport({
        run: {
          id: "run-agent",
          hcheckVersion: "0.6.0",
          completeness: "COMPLETE",
          gate: "FAIL",
        },
        findings: [finding()],
        allowedPaths: ["/Users/me/project"],
        forbiddenPaths: ["build"],
        verificationCommands: ["pnpm check"],
      }),
    /仓库相对路径/u,
  );

  assert.throws(
    () =>
      buildAgentJsonReport({
        run: {
          id: "run-agent",
          hcheckVersion: "0.6.0",
          completeness: "COMPLETE",
          gate: "FAIL",
        },
        findings: [finding()],
        allowedPaths: ["../outside"],
        forbiddenPaths: ["build"],
        verificationCommands: ["pnpm check"],
      }),
    /仓库相对路径/u,
  );
});
