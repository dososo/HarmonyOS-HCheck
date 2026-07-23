import assert from "node:assert/strict";
import test from "node:test";
import { HCheckError, type Evidence, type Finding } from "@hcheck/core";
import type { ProjectSnapshot } from "@hcheck/project-model";
import {
  DetectorRegistry,
  executeRules,
  normalizeDetectionResult,
  type DetectionResult,
  type Detector,
  type RuleDefinition,
} from "../src/index.js";

const EVIDENCE_ID = `evidence:${"1".repeat(64)}`;
const OTHER_EVIDENCE_ID = `evidence:${"2".repeat(64)}`;
const FINGERPRINT = `sha256:${"3".repeat(64)}` as const;
const FINDING_ID = `finding:${"3".repeat(64)}`;
const runtime = {
  fs: {
    readText: async () => "",
    exists: async () => false,
    list: async () => [],
    kind: async () => "other" as const,
    size: async () => 0,
    realpath: async (candidate: string) => candidate,
    parent: (candidate: string) => candidate,
    resolve: (...parts: readonly string[]) => parts.join("/"),
  },
  hash: {
    async sha256() {
      return `sha256:${"0".repeat(64)}` as const;
    },
  },
  workspaceRoot: "/workspace",
  globalExcludePaths: [] as readonly string[],
};

const project: ProjectSnapshot = {
  schemaVersion: "1.0.0",
  root: ".",
  platform: "harmonyos",
  appScope: "AppScope/app.json5",
  bundleName: "com.example.test",
  products: [],
  modules: [],
  metadata: {},
  configSources: {
    appScope: "AppScope/app.json5",
    buildProfile: "build-profile.json5",
    modules: [],
  },
};

function rule(
  id: string,
  implementation: string,
  appliesWhen: RuleDefinition["appliesWhen"] = "project.platform == harmonyos",
): RuleDefinition {
  return {
    id,
    version: "1.0.0",
    status: "active",
    title: "测试规则",
    summary: "测试规则摘要",
    category: { technical: "test", review: "test" },
    appliesWhen,
    inputs: ["project_snapshot"],
    detector: { type: "structural", implementation },
    severity: "HIGH",
    defaultConfidence: "PROBABLE",
    policyRefs: [],
    remediation: { summary: "修复。", verification: "复验。" },
    autofix: { level: "forbidden" },
  };
}

function evidence(id = EVIDENCE_ID, summary = "脱敏证据"): Evidence {
  return {
    id,
    type: "source",
    source: "entry/src/main/Index.ets",
    summary,
    contentHash: `sha256:${"4".repeat(64)}`,
    redacted: true,
  };
}

function finding(
  evidenceIds: readonly string[] = [EVIDENCE_ID],
  locations: Finding["locations"] = [
    { uri: "entry/src/main/Index.ets", line: 12 },
  ],
): Finding {
  return {
    schemaVersion: "1.0.0",
    id: FINDING_ID,
    ruleId: "HOS-META-003",
    ruleVersion: "1.0.0",
    title: "发现占位信息",
    severity: "HIGH",
    confidence: "PROBABLE",
    applicability: "APPLICABLE",
    fingerprint: FINGERPRINT,
    message: "正式源码中发现占位信息。",
    locations,
    evidenceIds,
    remediation: { summary: "删除占位信息。", verification: "重新扫描。" },
    autofix: "review_required",
    status: "new",
  };
}

class StaticDetector implements Detector {
  public constructor(
    public readonly implementation: string,
    private readonly result: DetectionResult,
  ) {}

  public async detect(): Promise<DetectionResult> {
    return this.result;
  }
}

function expectInternalError(kind: string, secret?: string) {
  return (error: unknown): boolean => {
    assert.ok(error instanceof HCheckError);
    assert.equal(error.code, "INTERNAL_ERROR");
    assert.equal(error.details.kind, kind);
    if (secret !== undefined) {
      assert.doesNotMatch(
        JSON.stringify({ message: error.message, details: error.details }),
        new RegExp(secret, "u"),
      );
    }
    return true;
  };
}

test("调度器只执行 APPLICABLE，跳过 NOT_APPLICABLE，并记录 UNKNOWN", async () => {
  const registry = new DetectorRegistry();
  let calls = 0;
  registry.register({
    implementation: "applicable",
    async detect() {
      calls += 1;
      return { evidence: [evidence()], findings: [finding()] };
    },
  });
  const result = await executeRules({
    rules: [
      rule("HOS-META-003", "applicable"),
      rule(
        "HOS-META-004",
        "missing-not-applicable",
        "project.platform != harmonyos",
      ),
      rule("HOS-META-005", "missing-unknown", "scan.mode == quick"),
    ],
    context: { ...runtime, project },
    registry,
  });

  assert.equal(calls, 1);
  assert.deepEqual(
    result.evaluations.map(({ ruleId, applicability, executed }) => ({
      ruleId,
      applicability,
      executed,
    })),
    [
      { ruleId: "HOS-META-003", applicability: "APPLICABLE", executed: true },
      {
        ruleId: "HOS-META-004",
        applicability: "NOT_APPLICABLE",
        executed: false,
      },
      { ruleId: "HOS-META-005", applicability: "UNKNOWN", executed: false },
    ],
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.evidence.length, 1);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.evaluations));
});

test("适用规则缺少 detector 明确映射 INTERNAL_ERROR 且不泄露实现名", async () => {
  await assert.rejects(
    executeRules({
      rules: [rule("HOS-META-003", "SECRET-DETECTOR")],
      context: { ...runtime, mode: "quick", project },
      registry: new DetectorRegistry(),
    }),
    expectInternalError("missing_detector", "SECRET-DETECTOR"),
  );
});

test("detector 普通错误转为 detector_failure，证据不完整保留 code 并脱敏", async () => {
  for (const [thrown, code, kind] of [
    [new Error("SECRET-PLAIN"), "INTERNAL_ERROR", "detector_failure"],
    [
      new HCheckError("EVIDENCE_INCOMPLETE", "SECRET-DOMAIN", {
        secret: "SECRET-DETAIL",
      }),
      "EVIDENCE_INCOMPLETE",
      "detector_evidence_incomplete",
    ],
  ] as const) {
    const registry = new DetectorRegistry();
    registry.register({
      implementation: "failing",
      async detect() {
        throw thrown;
      },
    });
    await assert.rejects(
      executeRules({
        rules: [rule("HOS-META-003", "failing")],
        context: { ...runtime, mode: "quick", project },
        registry,
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError);
        assert.equal(error.code, code);
        assert.equal(error.details.kind, kind);
        assert.doesNotMatch(JSON.stringify(error), /SECRET/u);
        return true;
      },
    );
  }
});

test("null 与畸形 DetectionResult 转为 invalid_detection_result", async () => {
  for (const raw of [
    null,
    {},
    { evidence: null, findings: [] },
    { evidence: [], findings: [], extra: "SECRET" },
  ]) {
    const registry = new DetectorRegistry();
    registry.register({
      implementation: "malformed",
      async detect() {
        return raw as unknown as DetectionResult;
      },
    });
    await assert.rejects(
      executeRules({
        rules: [rule("HOS-META-003", "malformed")],
        context: { ...runtime, mode: "quick", project },
        registry,
      }),
      expectInternalError("invalid_detection_result"),
    );
  }
});

test("executeRules 保留正常化产生的脱敏领域错误", async () => {
  const registry = new DetectorRegistry();
  registry.register(
    new StaticDetector("dangling", { evidence: [], findings: [finding()] }),
  );
  await assert.rejects(
    executeRules({
      rules: [rule("HOS-META-003", "dangling")],
      context: { ...runtime, mode: "quick", project },
      registry,
    }),
    expectInternalError("dangling_evidence"),
  );
});

test("跨规则相同 Evidence 完整一致时去重，内容冲突时拒绝", async () => {
  const registry = new DetectorRegistry();
  registry.register(
    new StaticDetector("one", { evidence: [evidence()], findings: [] }),
  );
  registry.register(
    new StaticDetector("two", { evidence: [evidence()], findings: [] }),
  );
  const deduplicated = await executeRules({
    rules: [rule("HOS-META-003", "one"), rule("HOS-META-004", "two")],
    context: { ...runtime, mode: "quick", project },
    registry,
  });
  assert.equal(deduplicated.evidence.length, 1);

  const conflicting = new DetectorRegistry();
  conflicting.register(
    new StaticDetector("one", { evidence: [evidence()], findings: [] }),
  );
  conflicting.register(
    new StaticDetector("two", {
      evidence: [evidence(EVIDENCE_ID, "SECRET-CONFLICT")],
      findings: [],
    }),
  );
  await assert.rejects(
    executeRules({
      rules: [rule("HOS-META-003", "one"), rule("HOS-META-004", "two")],
      context: { ...runtime, mode: "quick", project },
      registry: conflicting,
    }),
    expectInternalError("conflicting_evidence", "SECRET-CONFLICT"),
  );
});

test("悬空 Evidence、未脱敏 Evidence 和重复 Evidence ID 均明确内部错误", async () => {
  const cases: readonly [string, DetectionResult][] = [
    ["dangling_evidence", { evidence: [], findings: [finding()] }],
    [
      "invalid_evidence",
      {
        evidence: [
          { ...evidence(), redacted: false, summary: "SECRET-EVIDENCE" },
        ],
        findings: [finding()],
      },
    ],
    [
      "duplicate_evidence_id",
      {
        evidence: [evidence(), evidence(EVIDENCE_ID, "SECRET-CONFLICT")],
        findings: [finding()],
      },
    ],
  ];

  for (const [kind, result] of cases) {
    assert.throws(
      () => normalizeDetectionResult(result),
      expectInternalError(kind, "SECRET"),
    );
  }
});

test("损坏的 Finding 哈希、ID 和重复证据引用均明确内部错误", () => {
  const cases: readonly Finding[] = [
    { ...finding(), fingerprint: "sha256:BAD" },
    { ...finding(), id: `finding:${"9".repeat(64)}` },
    { ...finding(), evidenceIds: [EVIDENCE_ID, EVIDENCE_ID] },
  ];

  for (const damaged of cases) {
    assert.throws(
      () =>
        normalizeDetectionResult({
          evidence: [evidence()],
          findings: [damaged],
        }),
      expectInternalError("invalid_finding"),
    );
  }
});

test("归一化入口调用完整 Validator 并将合同错误脱敏包装", () => {
  const cases: readonly DetectionResult[] = [
    {
      evidence: [{ ...evidence(), source: "/SECRET/evidence.ets" }],
      findings: [],
    },
    {
      evidence: [evidence()],
      findings: [{ ...finding(), schemaVersion: "SECRET" as "1.0.0" }],
    },
    {
      evidence: [evidence()],
      findings: [
        { ...finding(), locations: [{ uri: "entry/file.ets", line: -1 }] },
      ],
    },
    {
      evidence: [evidence()],
      findings: [{ ...finding(), extra: "SECRET" } as Finding],
    },
    {
      evidence: [
        {
          ...evidence(),
          metadata: { value: "x".repeat(16 * 1024 + 1) },
        },
      ],
      findings: [],
    },
  ];
  const expectedKinds = [
    "invalid_evidence",
    "invalid_finding",
    "invalid_finding",
    "invalid_finding",
    "invalid_evidence",
  ];
  for (const [index, result] of cases.entries()) {
    assert.throws(
      () => normalizeDetectionResult(result),
      expectInternalError(expectedKinds[index]!, "SECRET"),
    );
  }
});

test("归一化稳定排序并按 fingerprint 确定性合并位置与 Evidence 引用", () => {
  const secondEvidence = evidence(OTHER_EVIDENCE_ID, "第二证据");
  const input: DetectionResult = {
    evidence: [secondEvidence, evidence()],
    findings: [
      finding(
        [OTHER_EVIDENCE_ID],
        [
          { uri: "entry/src/main/Z.ets", line: 1 },
          { uri: "entry/src/main/Index.ets", line: 12 },
        ],
      ),
      finding(
        [EVIDENCE_ID, OTHER_EVIDENCE_ID],
        [
          { uri: "entry/src/main/Index.ets", line: 12 },
          { uri: "entry/src/main/A.ets", line: 99 },
        ],
      ),
    ],
  };
  const before = structuredClone(input);
  const normalized = normalizeDetectionResult(input);

  assert.deepEqual(input, before);
  assert.deepEqual(
    normalized.evidence.map((item) => item.id),
    [EVIDENCE_ID, OTHER_EVIDENCE_ID],
  );
  assert.equal(normalized.findings.length, 1);
  assert.deepEqual(normalized.findings[0]?.evidenceIds, [
    EVIDENCE_ID,
    OTHER_EVIDENCE_ID,
  ]);
  assert.deepEqual(normalized.findings[0]?.locations, [
    { uri: "entry/src/main/A.ets", line: 99 },
    { uri: "entry/src/main/Index.ets", line: 12 },
    { uri: "entry/src/main/Z.ets", line: 1 },
  ]);
  assert.ok(Object.isFrozen(normalized.findings[0]));
  assert.ok(Object.isFrozen(normalized.findings[0]?.locations));
});

test("同 fingerprint 语义冲突被拒绝，不静默覆盖", () => {
  assert.throws(
    () =>
      normalizeDetectionResult({
        evidence: [evidence()],
        findings: [
          finding(),
          { ...finding(), message: "SECRET-CONFLICT-MESSAGE" },
        ],
      }),
    expectInternalError("conflicting_finding", "SECRET-CONFLICT-MESSAGE"),
  );
});

test("DetectorRegistry 重复注册使用领域错误且不泄露实现名", () => {
  const registry = new DetectorRegistry();
  registry.register(
    new StaticDetector("SECRET-DETECTOR", { evidence: [], findings: [] }),
  );

  assert.throws(
    () =>
      registry.register(
        new StaticDetector("SECRET-DETECTOR", { evidence: [], findings: [] }),
      ),
    expectInternalError("duplicate_detector", "SECRET-DETECTOR"),
  );
});
