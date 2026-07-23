import assert from "node:assert/strict";
import test from "node:test";
import { parseAppAnalyzerReport } from "../src/index.js";

test("parseAppAnalyzerReport 导入正式导出报告并保留解析版本和原始哈希", () => {
  const report = parseAppAnalyzerReport(
    JSON.stringify({
      tool: "AppAnalyzer",
      reportVersion: "2026.1",
      analyzerVersion: "6.0.0",
      generatedAt: "2026-07-10T00:00:00Z",
      issues: [
        {
          id: "APPANALYZER-PKG-001",
          severity: "BLOCKER",
          artifact: "build/default/app-release.app",
          message: "上架包 Bundle 与工程声明不一致。",
        },
      ],
    }),
  );

  assert.equal(report.parserVersion, "hcheck-appanalyzer-v1");
  assert.equal(report.reportVersion, "2026.1");
  assert.equal(report.analyzerVersion, "6.0.0");
  assert.match(report.rawReportHash, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(report.issues, [
    {
      id: "APPANALYZER-PKG-001",
      severity: "BLOCKER",
      artifactUri: "build/default/app-release.app",
      message: "上架包 Bundle 与工程声明不一致。",
    },
  ]);
});

test("parseAppAnalyzerReport 拒绝依赖内部数据库路径或绝对路径的样本", () => {
  assert.throws(
    () =>
      parseAppAnalyzerReport(
        JSON.stringify({
          tool: "AppAnalyzer",
          reportVersion: "2026.1",
          internalDatabasePath: "/Users/me/.deveco/appanalyzer/internal.db",
          issues: [],
        }),
      ),
    /不支持内部数据库/u,
  );
});
