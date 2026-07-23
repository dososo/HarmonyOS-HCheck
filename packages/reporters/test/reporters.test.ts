import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { HCheckError, type Evidence, type Finding } from "@hcheck/core";
import {
  buildScanReport,
  renderHtml,
  renderJunit,
  renderJson,
  renderSarif,
  renderTerminal,
  type ClockPort,
  type RunIdPort,
} from "../src/index.js";

const A = "a".repeat(64);
const B = "b".repeat(64);
const evidence = (hex = A): Evidence => ({
  id: `evidence:${hex}`,
  type: "source",
  source: "entry/src/main/ets/Index.ets",
  summary: "发现占位内容",
  contentHash: `sha256:${hex}`,
  redacted: true,
  location: { uri: "entry/src/main/ets/Index.ets", line: 8 },
});
const finding = (hex = A, severity: Finding["severity"] = "HIGH"): Finding => ({
  schemaVersion: "1.0.0",
  id: `finding:${hex}`,
  ruleId: hex === A ? "HOS-META-003" : "HOS-META-004",
  ruleVersion: "1.0.0",
  title: "存在占位内容",
  severity,
  confidence: "PROBABLE",
  applicability: "APPLICABLE",
  fingerprint: `sha256:${hex}`,
  message: "正式源码仍含占位内容。",
  locations: [{ uri: "entry/src/main/ets/Index.ets", line: 8 }],
  evidenceIds: [`evidence:${hex}`],
  remediation: { summary: "替换占位内容", verification: "重新执行扫描" },
  autofix: "review_required",
  status: "new",
});

class SequenceClock implements ClockPort {
  public constructor(private readonly values: readonly Date[]) {}
  public now(): Date {
    const value = this.values.shift();
    if (value === undefined) throw new Error("时钟调用次数超出预期");
    return value;
  }
}
class SequenceRunId implements RunIdPort {
  public constructor(private readonly values: string[]) {}
  public next(): string {
    const value = this.values.shift();
    if (value === undefined) throw new Error("运行 ID 调用次数超出预期");
    return value;
  }
}

const baseInput = () => ({
  hcheckVersion: "0.6.0",
  mode: "quick" as const,
  project: {
    bundleName: "com.example.safe",
    modules: [
      { name: "entry", type: "entry" as const },
      { name: "shared", type: "shared" as const, isExternal: true },
    ],
    hasExternalModules: true,
  },
  rulePacks: [{ id: "hcheck-p0", version: "0.6.0" }],
  findings: [finding()],
  evidence: [evidence()],
  errors: [] as readonly unknown[],
  incompleteReasons: [] as readonly string[],
  gate: "FAIL" as const,
});
const ports = (runIds = ["run-fixed"]) => ({
  clock: new SequenceClock([
    new Date("2026-07-11T01:02:03.000Z"),
    new Date("2026-07-11T01:02:04.000Z"),
  ]),
  runId: new SequenceRunId(runIds),
});

test("构造完整、排序稳定且深冻结的报告信封", () => {
  const input = baseInput();
  input.findings = [finding(B, "LOW"), finding(A, "HIGH")];
  input.evidence = [evidence(B), evidence(A)];
  input.rulePacks = [
    { id: "z-pack", version: "1.0.0" },
    { id: "hcheck-p0", version: "0.6.0" },
  ];
  const report = buildScanReport(input, ports());
  assert.deepEqual(report.run, {
    id: "run-fixed",
    hcheckVersion: "0.6.0",
    mode: "quick",
    startedAt: "2026-07-11T01:02:03.000Z",
    finishedAt: "2026-07-11T01:02:04.000Z",
    rulePacks: [
      { id: "hcheck-p0", version: "0.6.0" },
      { id: "z-pack", version: "1.0.0" },
    ],
  });
  assert.deepEqual(report.summary.bySeverity, {
    BLOCKER: 0,
    HIGH: 1,
    MEDIUM: 0,
    LOW: 1,
    INFO: 0,
  });
  assert.deepEqual(
    report.findings.map(({ severity }) => severity),
    ["HIGH", "LOW"],
  );
  assert.deepEqual(
    report.evidence.map(({ id }) => id),
    [`evidence:${A}`, `evidence:${B}`],
  );
  assert.equal(report.completeness, "COMPLETE");
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.project.modules), true);
});

test("接受零 Finding 并生成 PASS", () => {
  const input = baseInput();
  input.findings = [];
  input.evidence = [];
  input.gate = "PASS";
  const report = buildScanReport(input, ports());
  assert.equal(report.summary.total, 0);
  assert.equal(report.summary.gate, "PASS");
});

test("拒绝悬空 Evidence、未脱敏对象、额外字段和危险项目摘要", () => {
  const dangling = baseInput();
  dangling.evidence = [];
  assert.throws(
    () => buildScanReport(dangling, ports()),
    /Evidence.*无法解析/u,
  );

  const unredacted = baseInput();
  unredacted.evidence = [{ ...evidence(), redacted: false }];
  assert.throws(() => buildScanReport(unredacted, ports()), /脱敏/u);

  const extra = baseInput() as ReturnType<typeof baseInput> & {
    password?: string;
  };
  extra.password = "secret-value";
  assert.throws(() => buildScanReport(extra, ports()), /字段合同/u);

  const absolute = baseInput();
  absolute.project.bundleName = "/Users/alice/workspace/token";
  assert.throws(() => buildScanReport(absolute, ports()), /项目摘要/u);
});

test("拒绝藏在 Finding 或 Evidence 自由文本中的秘密和绝对路径", () => {
  const secretFinding = baseInput();
  secretFinding.findings = [
    { ...finding(), message: "password=do-not-report" },
  ];
  assert.throws(() => buildScanReport(secretFinding, ports()), /不安全内容/u);

  const absoluteEvidence = baseInput();
  absoluteEvidence.evidence = [
    { ...evidence(), summary: "/Users/alice/private/work" },
  ];
  assert.throws(
    () => buildScanReport(absoluteEvidence, ports()),
    /不安全内容/u,
  );
});

test("完整报告统一拒绝常见绝对路径、文件 URI 与凭证字段", () => {
  const unsafeTexts = [
    "/home/alice/private",
    "/Users/alice/private",
    "C:\\workspace\\private",
    "\\\\server\\share\\private",
    "file:///home/alice/private",
    "apiKey=abc123",
    "credential: abc123",
    "accessKey=abc123",
    "password=abc123",
    "token: abc123",
    "secret: abc123",
  ];
  for (const unsafeText of unsafeTexts) {
    const input = baseInput();
    input.incompleteReasons = [unsafeText];
    assert.throws(
      () => buildScanReport(input, ports()),
      /不安全内容/u,
      unsafeText,
    );
  }

  const ordinaryChinese = baseInput();
  ordinaryChinese.incompleteReasons = ["外部模块尚未纳入本次扫描范围。"];
  const report = buildScanReport(ordinaryChinese, ports());
  assert.equal(report.redaction.applied, true);
  assert.deepEqual(report.incompleteReasons, [
    "外部模块尚未纳入本次扫描范围。",
  ]);
});

test("拒绝中文冒号后的 Linux 绝对路径", () => {
  const unsafe = baseInput();
  unsafe.incompleteReasons = ["无法读取：/home/alice/private，已跳过。"];
  assert.throws(() => buildScanReport(unsafe, ports()), /不安全内容/u);
});

test("拒绝括号 path 标签后的 Linux 绝对路径", () => {
  const unsafe = baseInput();
  unsafe.incompleteReasons = ["无法读取(path:/home/alice/private)，已跳过。"];
  assert.throws(() => buildScanReport(unsafe, ports()), /不安全内容/u);
});

test("普通 HTTP 和 API 术语允许进入报告", () => {
  const safe = baseInput();
  safe.incompleteReasons = ["请检查 HTTP / API 的兼容性。"];
  assert.deepEqual(buildScanReport(safe, ports()).incompleteReasons, [
    "请检查 HTTP / API 的兼容性。",
  ]);
});

test("不携带实际值的 access token 术语允许进入报告", () => {
  const safe = baseInput();
  safe.incompleteReasons = ["规则用于识别 access token 的错误配置。"];
  assert.deepEqual(buildScanReport(safe, ports()).incompleteReasons, [
    "规则用于识别 access token 的错误配置。",
  ]);
});

test("拒绝只有两个组件的 macOS 绝对路径", () => {
  const unsafe = baseInput();
  unsafe.incompleteReasons = ["无法读取 /Users/alice"];
  assert.throws(() => buildScanReport(unsafe, ports()), /不安全内容/u);
});

test("拒绝只有两个组件的 POSIX 临时文件路径", () => {
  const unsafe = baseInput();
  unsafe.incompleteReasons = ["结果位于 /tmp/result.json"];
  assert.throws(() => buildScanReport(unsafe, ports()), /不安全内容/u);
});

test("拒绝盘符后只有一个组件的 Windows 绝对路径", () => {
  const unsafe = baseInput();
  unsafe.incompleteReasons = ["结果位于 C:\\secret.txt"];
  assert.throws(() => buildScanReport(unsafe, ports()), /不安全内容/u);
});

test("英文 token 配置术语与 HTTP URL 允许进入报告", () => {
  const safe = baseInput();
  safe.incompleteReasons = [
    "This rule detects token configuration mistakes.",
    "详情见 https://example.com/docs/api/token/configuration。",
  ];
  assert.deepEqual(buildScanReport(safe, ports()).incompleteReasons, [
    "This rule detects token configuration mistakes.",
    "详情见 https://example.com/docs/api/token/configuration。",
  ]);
});

test("拒绝凭证显式赋值后的中文敏感值", () => {
  for (const reason of [
    "password=秘密口令",
    "token：中文敏感值",
    "credential=密钥内容",
  ]) {
    const unsafe = baseInput();
    unsafe.incompleteReasons = [reason];
    assert.throws(
      () => buildScanReport(unsafe, ports()),
      /不安全内容/u,
      reason,
    );
  }
});

test("允许凭证字段使用明确的已脱敏占位值", () => {
  const safe = baseInput();
  safe.incompleteReasons = ["password=[REDACTED]", "token：***"];
  assert.deepEqual(buildScanReport(safe, ports()).incompleteReasons, [
    "password=[REDACTED]",
    "token：***",
  ]);
});

test("严格校验 UTC 时间且结束不得早于开始", () => {
  assert.throws(
    () =>
      buildScanReport(baseInput(), {
        clock: new SequenceClock([new Date("invalid"), new Date()]),
        runId: new SequenceRunId(["run-x"]),
      }),
    /UTC/u,
  );
  assert.throws(
    () =>
      buildScanReport(baseInput(), {
        clock: new SequenceClock([
          new Date("2026-07-11T01:02:04Z"),
          new Date("2026-07-11T01:02:03Z"),
        ]),
        runId: new SequenceRunId(["run-x"]),
      }),
    /早于/u,
  );
});

test("RunIdPort 连续提供不同 ID 且不改变 Finding 指纹", () => {
  const runId = new SequenceRunId(["run-one", "run-two"]);
  const first = buildScanReport(baseInput(), { ...ports(), runId });
  const second = buildScanReport(baseInput(), { ...ports(), runId });
  assert.notEqual(first.run.id, second.run.id);
  assert.equal(first.findings[0]?.fingerprint, second.findings[0]?.fingerprint);
});

test("EvidenceIncomplete 映射 PARTIAL，其他错误映射 FAILED，且不透传秘密", () => {
  const partialInput = baseInput();
  partialInput.findings = [];
  partialInput.evidence = [];
  partialInput.errors = [
    new HCheckError("EVIDENCE_INCOMPLETE", "password=raw", { token: "raw" }),
  ];
  const partial = buildScanReport(partialInput, ports());
  assert.equal(partial.completeness, "PARTIAL");
  assert.equal(partial.summary.gate, "INCOMPLETE");
  assert.deepEqual(partial.errors, [
    { kind: "EVIDENCE_INCOMPLETE", message: "证据收集不完整。" },
  ]);
  assert.doesNotMatch(JSON.stringify(partial), /password|token|raw/u);

  const failedInput = baseInput();
  failedInput.findings = [];
  failedInput.evidence = [];
  failedInput.errors = [new HCheckError("INTERNAL_ERROR", "secret")];
  const failed = buildScanReport(failedInput, ports());
  assert.equal(failed.completeness, "FAILED");
  assert.equal(failed.summary.gate, "INCOMPLETE");
});

test("Terminal 无颜色展示完整上下文，错误时不声称通过", () => {
  const terminal = renderTerminal(buildScanReport(baseInput(), ports()));
  assert.match(terminal, /运行 ID：run-fixed/u);
  assert.match(terminal, /模式：quick/u);
  assert.match(terminal, /项目：com\.example\.safe/u);
  assert.match(terminal, /规则包：hcheck-p0@0\.6\.0/u);
  assert.match(terminal, /HIGH：1/u);
  assert.match(terminal, /entry\/src\/main\/ets\/Index\.ets:8/u);
  assert.match(terminal, /修复：替换占位内容/u);
  assert.equal(terminal.includes("\u001b["), false);

  const failedInput = baseInput();
  failedInput.findings = [];
  failedInput.evidence = [];
  failedInput.errors = [new HCheckError("BUILD_FAILED", "secret")];
  const failed = renderTerminal(buildScanReport(failedInput, ports()));
  assert.doesNotMatch(failed, /未发现问题|通过/u);
  assert.match(failed, /不完整|失败/u);
});

test("JSON 输出完整信封、尾随换行且同报告确定", () => {
  const report = buildScanReport(baseInput(), ports());
  const first = renderJson(report);
  assert.equal(first.endsWith("\n"), true);
  assert.equal(first, renderJson(report));
  assert.deepEqual(JSON.parse(first), report);
  assert.doesNotMatch(first, /\/Users\/|password|token|secret/u);
});

test("JSON 与 Terminal 渲染前拒绝伪造的不安全内容和不一致汇总", () => {
  const report = buildScanReport(baseInput(), ports());
  const forgedReports = [
    {
      ...structuredClone(report),
      incompleteReasons: ["读取失败：/home/alice/private"],
    },
    {
      ...structuredClone(report),
      findings: [
        { ...structuredClone(report.findings[0]), message: "token=中文敏感值" },
      ],
    },
    {
      ...structuredClone(report),
      completeness: "FAILED",
      summary: { ...structuredClone(report.summary), gate: "PASS" },
    },
    {
      ...structuredClone(report),
      summary: { ...structuredClone(report.summary), total: 99 },
    },
  ];
  for (const forged of forgedReports) {
    assert.throws(() => renderJson(forged as never), TypeError);
    assert.throws(() => renderTerminal(forged as never), TypeError);
  }
});

test("SARIF Reporter 输出稳定规则、结果和逻辑位置", () => {
  const report = buildScanReport(baseInput(), ports());
  const sarif = JSON.parse(renderSarif(report)) as {
    version: string;
    runs: readonly {
      tool: { driver: { name: string; rules: readonly { id: string }[] } };
      results: readonly {
        ruleId: string;
        level: string;
        properties: {
          severity: string;
          confidence: string;
          applicability: string;
          status: string;
        };
        locations: readonly {
          physicalLocation: { artifactLocation: { uri: string } };
        }[];
      }[];
    }[];
  };

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0]?.tool.driver.name, "鸿鉴 HCheck");
  assert.deepEqual(
    sarif.runs[0]?.tool.driver.rules.map(({ id }) => id),
    ["HOS-META-003"],
  );
  assert.deepEqual(
    sarif.runs[0]?.results.map(({ ruleId, level, locations, properties }) => ({
      ruleId,
      level,
      uri: locations[0]?.physicalLocation.artifactLocation.uri,
      properties,
    })),
    [
      {
        ruleId: "HOS-META-003",
        level: "error",
        uri: "entry/src/main/ets/Index.ets",
        properties: {
          severity: "HIGH",
          confidence: "PROBABLE",
          applicability: "APPLICABLE",
          status: "new",
        },
      },
    ],
  );
  assert.ok(!renderSarif(report).includes(process.cwd()));
});

test("JUnit Reporter 输出可被 CI 展示的稳定失败用例", () => {
  const report = buildScanReport(baseInput(), ports());
  const junit = renderJunit(report);

  assert.match(junit, /<testsuite name="hcheck" tests="1" failures="1"/u);
  assert.match(
    junit,
    /<testcase classname="HOS-META-003" name="存在占位内容">/u,
  );
  assert.match(junit, /<failure message="正式源码仍含占位内容。"/u);
  assert.ok(!junit.includes(process.cwd()));

  const clean = baseInput();
  clean.findings = [];
  clean.evidence = [];
  clean.gate = "PASS";
  assert.match(
    renderJunit(buildScanReport(clean, ports())),
    /<testsuite name="hcheck" tests="0" failures="0"/u,
  );
});

test("HTML Reporter 输出离线安全页面且不包含脚本、外链或本地路径", () => {
  const report = buildScanReport(baseInput(), ports());
  const html = renderHtml(report);

  assert.match(html, /^<!doctype html>/iu);
  assert.match(html, /鸿鉴 HCheck 扫描报告/u);
  assert.match(html, /HOS-META-003/u);
  assert.match(html, /entry\/src\/main\/ets\/Index\.ets:8/u);
  assert.ok(!html.includes("<script"));
  assert.ok(!html.includes("http://"));
  assert.ok(!html.includes("https://"));
  assert.ok(!html.includes(process.cwd()));
});

test("JSON 与 Terminal 拒绝 metadata/properties 中的不安全键名", () => {
  const report = buildScanReport(baseInput(), ports());
  const forgedReports = [
    {
      ...structuredClone(report),
      evidence: [
        {
          ...structuredClone(report.evidence[0]),
          metadata: { "password=真实密钥": "已隐藏" },
        },
      ],
    },
    {
      ...structuredClone(report),
      findings: [
        {
          ...structuredClone(report.findings[0]),
          properties: { "/Users/alice/private": "已隐藏" },
        },
      ],
    },
  ];
  for (const forged of forgedReports) {
    assert.throws(() => renderJson(forged as never), /不安全内容/u);
    assert.throws(() => renderTerminal(forged as never), /不安全内容/u);
  }

  const safe = structuredClone(report);
  safe.evidence = [
    { ...safe.evidence[0]!, metadata: { detectorName: "metadata-check" } },
  ];
  assert.doesNotThrow(() => renderJson(safe));
  assert.doesNotThrow(() => renderTerminal(safe));
});

test("JSON 与 Terminal 拒绝报告文本和键名中的换行及控制字符", () => {
  const report = buildScanReport(baseInput(), ports());
  const forgedReports = [
    {
      ...structuredClone(report),
      findings: [
        {
          ...structuredClone(report.findings[0]),
          message: "恶意内容\n门禁：PASS",
        },
      ],
    },
    {
      ...structuredClone(report),
      findings: [
        {
          ...structuredClone(report.findings[0]),
          title: "恶意内容\r门禁：PASS",
        },
      ],
    },
    {
      ...structuredClone(report),
      findings: [
        {
          ...structuredClone(report.findings[0]),
          remediation: {
            ...structuredClone(report.findings[0]!.remediation),
            summary: "恶意内容\u001b门禁：PASS",
          },
        },
      ],
    },
    {
      ...structuredClone(report),
      evidence: [
        {
          ...structuredClone(report.evidence[0]),
          metadata: { "恶意内容\u2028门禁：PASS": "已隐藏" },
        },
      ],
    },
    {
      ...structuredClone(report),
      findings: [
        {
          ...structuredClone(report.findings[0]),
          properties: { "恶意内容\u2029门禁：PASS": "已隐藏" },
        },
      ],
    },
  ];
  for (const forged of forgedReports) {
    assert.throws(() => renderJson(forged as never), /不安全内容/u);
    assert.throws(() => renderTerminal(forged as never), /不安全内容/u);
  }

  const safe = structuredClone(report);
  safe.findings = [
    {
      ...safe.findings[0]!,
      message: "普通中文标点，允许：检查（项目）；然后继续。",
    },
  ];
  assert.doesNotThrow(() => renderJson(safe));
  assert.doesNotThrow(() => renderTerminal(safe));
});

test("JSON 与 Terminal 拒绝 C1 NEL 和 CSI，保留 TAB 中文与 URL", () => {
  const report = buildScanReport(baseInput(), ports());
  const forgedReports = [
    {
      ...structuredClone(report),
      findings: [
        {
          ...structuredClone(report.findings[0]),
          message: "恶意内容\u0085门禁：PASS",
        },
      ],
    },
    {
      ...structuredClone(report),
      evidence: [
        {
          ...structuredClone(report.evidence[0]),
          metadata: { "恶意内容\u009b门禁：PASS": "已隐藏" },
        },
      ],
    },
  ];
  for (const forged of forgedReports) {
    assert.throws(() => renderJson(forged as never), /不安全内容/u);
    assert.throws(() => renderTerminal(forged as never), /不安全内容/u);
  }

  const safe = structuredClone(report);
  safe.findings = [
    {
      ...safe.findings[0]!,
      message: "普通中文\t详情见 https://example.com/docs/api。",
    },
  ];
  assert.doesNotThrow(() => renderJson(safe));
  assert.doesNotThrow(() => renderTerminal(safe));
});

test("实际报告通过显式注册相对引用的 Draft 2020-12 Schema，反例失败", async () => {
  const schemaDir = new URL("../../../schemas/", import.meta.url);
  const [reportSchema, findingSchema, evidenceSchema] = await Promise.all(
    ["report.schema.json", "finding.schema.json", "evidence.schema.json"].map(
      async (name) =>
        JSON.parse(await readFile(new URL(name, schemaDir), "utf8")),
    ),
  );
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  ajv.addSchema(findingSchema, "finding.schema.json");
  ajv.addSchema(evidenceSchema, "evidence.schema.json");
  const validate = ajv.compile(reportSchema);
  const report = buildScanReport(baseInput(), ports());
  assert.equal(validate(report), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...report, evidence: undefined }), false);
  assert.equal(
    validate({ ...report, project: { ...report.project, root: "/tmp/work" } }),
    false,
  );
  assert.equal(
    validate({
      ...report,
      completeness: "FAILED",
      summary: { ...report.summary, gate: "PASS" },
    }),
    false,
  );
  assert.equal(
    validate({
      ...report,
      completeness: "PARTIAL",
      summary: { ...report.summary, gate: "PASS" },
    }),
    false,
  );
  assert.equal(
    validate({
      ...report,
      completeness: "COMPLETE",
      summary: { ...report.summary, gate: "INCOMPLETE" },
    }),
    false,
  );
});
