import assert from "node:assert/strict";
import test from "node:test";
import { parseDevecoTestingReport } from "../src/index.js";

test("parseDevecoTestingReport 导入正式导出报告并记录版本、哈希和脱敏状态", () => {
  const report = parseDevecoTestingReport(
    JSON.stringify({
      tool: "DevEco Testing",
      reportVersion: "2026.1",
      testingVersion: "6.0.0",
      generatedAt: "2026-07-10T00:00:00Z",
      redacted: true,
      cases: [
        {
          id: "compatibility-startup",
          status: "failed",
          category: "compatibility",
          device: "REDACTED_DEVICE",
          message: "启动兼容性测试失败。",
        },
      ],
    }),
  );

  assert.equal(report.parserVersion, "hcheck-deveco-testing-v1");
  assert.equal(report.reportVersion, "2026.1");
  assert.equal(report.testingVersion, "6.0.0");
  assert.equal(report.redacted, true);
  assert.match(report.rawReportHash, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(report.cases, [
    {
      id: "compatibility-startup",
      status: "failed",
      category: "compatibility",
      device: "REDACTED_DEVICE",
      message: "启动兼容性测试失败。",
    },
  ]);
});

test("parseDevecoTestingReport 导入脱敏的官方云测汇总而不伪造逐用例结果", () => {
  const report = parseDevecoTestingReport(
    JSON.stringify({
      tool: "AGC Cloud Testing",
      reportVersion: "official-ui-summary-v1",
      redacted: true,
      cases: [],
      summary: {
        sourceKind: "official_ui_summary",
        total: 39,
        passed: 39,
        failed: 0,
        warnings: 0,
        deviceCount: 1,
      },
      source: {
        sourceKind: "official_ui_transcription",
        reportReferenceHash:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        testedAt: "2026-07-23T14:14:03+08:00",
        testDimension: "compatibility",
        deviceFormFactor: "foldable",
      },
    }),
  );

  assert.deepEqual(report.cases, []);
  assert.deepEqual(report.summary, {
    sourceKind: "official_ui_summary",
    total: 39,
    passed: 39,
    failed: 0,
    warnings: 0,
    deviceCount: 1,
  });
  assert.deepEqual(report.source, {
    sourceKind: "official_ui_transcription",
    reportReferenceHash:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    testedAt: "2026-07-23T14:14:03+08:00",
    testDimension: "compatibility",
    deviceFormFactor: "foldable",
  });
});

test("parseDevecoTestingReport 拒绝超过总数的官方云测汇总", () => {
  assert.throws(
    () =>
      parseDevecoTestingReport(
        JSON.stringify({
          redacted: true,
          cases: [],
          summary: {
            sourceKind: "official_ui_summary",
            total: 39,
            passed: 39,
            failed: 1,
            warnings: 0,
            deviceCount: 1,
          },
          source: {
            sourceKind: "official_ui_transcription",
            reportReferenceHash:
              "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            testedAt: "2026-07-23T14:14:03+08:00",
            testDimension: "compatibility",
            deviceFormFactor: "foldable",
          },
        }),
      ),
    /汇总计数不能超过 total/u,
  );
});

test("parseDevecoTestingReport 拒绝官方汇总夹带逐用例结果或缺失来源绑定", () => {
  const summary = {
    sourceKind: "official_ui_summary",
    total: 1,
    passed: 1,
    failed: 0,
    warnings: 0,
    deviceCount: 1,
  };
  assert.throws(
    () =>
      parseDevecoTestingReport(
        JSON.stringify({
          redacted: true,
          cases: [
            {
              id: "invented-case",
              status: "passed",
              category: "compatibility",
              device: "REDACTED_DEVICE",
              message: "不应存在。",
            },
          ],
          summary,
          source: {
            sourceKind: "official_ui_transcription",
            reportReferenceHash:
              "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            testedAt: "2026-07-23T14:14:03+08:00",
            testDimension: "compatibility",
            deviceFormFactor: "foldable",
          },
        }),
      ),
    /不能包含逐用例/u,
  );
  assert.throws(
    () =>
      parseDevecoTestingReport(
        JSON.stringify({ redacted: true, cases: [], summary }),
      ),
    /必须提供来源绑定/u,
  );
  assert.throws(
    () =>
      parseDevecoTestingReport(
        JSON.stringify({
          redacted: true,
          cases: [],
          summary: { ...summary, token: "not-allowed" },
          source: {
            sourceKind: "official_ui_transcription",
            reportReferenceHash:
              "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            testedAt: "2026-07-23T14:14:03+08:00",
            testDimension: "compatibility",
            deviceFormFactor: "foldable",
          },
        }),
      ),
    /summary 包含未支持字段/u,
  );
});

test("parseDevecoTestingReport 拒绝未脱敏路径或内部数据库字段", () => {
  assert.throws(
    () =>
      parseDevecoTestingReport(
        JSON.stringify({
          tool: "DevEco Testing",
          reportVersion: "2026.1",
          redacted: true,
          internalDatabasePath: "/Users/me/.deveco/testing/internal.db",
          cases: [],
        }),
      ),
    /不支持内部数据库/u,
  );

  assert.throws(
    () =>
      parseDevecoTestingReport(
        JSON.stringify({
          tool: "DevEco Testing",
          reportVersion: "2026.1",
          redacted: false,
          cases: [
            {
              id: "case",
              status: "passed",
              category: "compatibility",
              device: "SERIAL",
              message: "/Users/me/project/report.json",
            },
          ],
        }),
      ),
    /录制样本必须先脱敏/u,
  );
});
