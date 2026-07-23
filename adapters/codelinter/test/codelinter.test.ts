import assert from "node:assert/strict";
import test from "node:test";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import { parseCodelinterReport, probeCodelinter } from "../src/index.js";

const completed = (
  fields: Partial<ProcessRunResult> = {},
): ProcessRunResult => ({
  status: "completed",
  exitCode: 0,
  timedOut: false,
  stdout: "",
  stderr: "",
  stdoutTruncated: false,
  stderrTruncated: false,
  ...fields,
});

class FakeRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];

  public constructor(private readonly result: ProcessRunResult) {}

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    this.requests.push(request);
    return this.result;
  }
}

test("probeCodelinter 工具缺失返回 unavailable 且不伪造成功", async () => {
  const runner = new FakeRunner(
    completed({ status: "start_failed", errorMessage: "ENOENT /Users/me/bin" }),
  );

  const capability = await probeCodelinter({ runner });

  assert.equal(capability.status, "unavailable");
  assert.equal(capability.available, false);
  assert.equal(capability.version, undefined);
  assert.equal(runner.requests[0]?.executable, "codelinter");
  assert.deepEqual(runner.requests[0]?.args, ["--version"]);
  assert.ok(!JSON.stringify(capability).includes("/Users/me"));
});

test("parseCodelinterReport 解析脱敏录制样本并记录解析版本和原始哈希", () => {
  const report = parseCodelinterReport(
    JSON.stringify({
      tool: "codelinter",
      toolVersion: "1.2.3",
      generatedAt: "2026-07-10T00:00:00Z",
      findings: [
        {
          ruleId: "ARKTS-STYLE-001",
          severity: "HIGH",
          file: "entry/src/main/ets/Index.ets",
          message: "禁止在发布代码中保留调试入口。",
        },
      ],
    }),
  );

  assert.equal(report.parserVersion, "hcheck-codelinter-v1");
  assert.equal(report.toolVersion, "1.2.3");
  assert.match(report.rawReportHash, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(report.findings, [
    {
      ruleId: "ARKTS-STYLE-001",
      severity: "HIGH",
      uri: "entry/src/main/ets/Index.ets",
      message: "禁止在发布代码中保留调试入口。",
    },
  ]);
});

test("parseCodelinterReport 拒绝含本机绝对路径的未脱敏样本", () => {
  assert.throws(
    () =>
      parseCodelinterReport(
        JSON.stringify({
          tool: "codelinter",
          findings: [
            {
              ruleId: "ARKTS-STYLE-001",
              severity: "HIGH",
              file: "/Users/me/project/entry/src/main/ets/Index.ets",
              message: "bad",
            },
          ],
        }),
      ),
    /录制样本必须先脱敏/u,
  );
});
