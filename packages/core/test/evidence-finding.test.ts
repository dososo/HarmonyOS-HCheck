import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import addFormats from "ajv-formats";
import { Ajv2020 } from "ajv/dist/2020.js";
import {
  applySuppressions,
  canonicalStringify,
  createEvidence,
  createBaselineSnapshot,
  createFinding,
  diffFindingsWithBaseline,
  HCheckError,
  SAFE_JSON_BUDGET,
  validateEvidence,
  validateFinding,
  type Evidence,
  type Finding,
  type FindingInput,
  type HashPort,
} from "../src/index.js";

const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

const hash: HashPort = {
  async sha256(content) {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  },
};

const findingInput: FindingInput = {
  ruleId: "HOS-META-003",
  ruleVersion: "1.7.2",
  moduleId: "entry",
  semanticKey: "placeholder:HCHECK_PLACEHOLDER",
  primaryLocationUri: "entry/src/main/Index.ets",
  title: "发布内容包含占位信息",
  severity: "HIGH",
  confidence: "PROBABLE",
  applicability: "APPLICABLE",
  message: "正式源码中发现占位内容。",
  locations: [{ uri: "entry\\src/main/Index.ets", line: 12, column: 5 }],
  evidenceIds: [`evidence:${"2".repeat(64)}`],
  policyRefs: [
    {
      source: "Huawei 应用审核 Checklist",
      section: "应用信息与应用功能",
      url: "https://example.com/policy",
      verifiedAt: "2026-07-10",
    },
  ],
  remediation: { summary: "移除占位内容。", verification: "hcheck scan ." },
  autofix: "review_required",
  status: "new",
  baseline: { present: false },
  properties: { nested: { detector: "metadata.placeholderContent" } },
};

function expectContractError(secret?: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TypeError);
    if (secret !== undefined)
      assert.doesNotMatch(error.message, new RegExp(secret, "u"));
    return true;
  };
}

test("canonicalStringify 按代码点稳定排序且不依赖输入键顺序", () => {
  const left = { z: 1, a: { y: 2, x: 3 }, array: [{ b: 1, a: 2 }] };
  const right = { array: [{ a: 2, b: 1 }], a: { x: 3, y: 2 }, z: 1 };

  assert.equal(canonicalStringify(left), canonicalStringify(right));
  assert.equal(
    canonicalStringify({ "\u{10000}": 1, "\ue000": 2 }),
    '{"":2,"𐀀":1}',
  );
});

test("Evidence 计算内容哈希与稳定 ID，丢弃原始内容并深冻结输出", async () => {
  const input = {
    type: "source" as const,
    source: ".\\entry\\src/main/Index.ets",
    summary: "发现占位标记。",
    content: "token=SECRET-RAW-CONTENT",
    redacted: true,
    collectedAt: "2026-07-10T12:00:00Z",
    location: {
      uri: "./entry/src/main/Index.ets",
      line: 12,
      column: 5,
      logicalPath: "entry\\src/main/Index.ets",
    },
    metadata: { nested: { matchedPattern: "HCHECK_PLACEHOLDER" } },
    archiveRef: ".hcheck/evidence/source.json",
  };
  const first = await createEvidence(input, hash);
  const second = await createEvidence(
    { ...input, collectedAt: "2026-07-11T00:00:00Z" },
    hash,
  );

  assert.match(first.id, /^evidence:[a-f0-9]{64}$/u);
  assert.match(first.contentHash, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(first.id, second.id);
  assert.equal(first.source, "entry/src/main/Index.ets");
  assert.equal(first.location?.uri, "entry/src/main/Index.ets");
  assert.equal(first.location?.logicalPath, "entry/src/main/Index.ets");
  assert.doesNotMatch(JSON.stringify(first), /SECRET-RAW-CONTENT/u);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.location));
  assert.ok(Object.isFrozen(first.metadata));
  assert.ok(Object.isFrozen(first.metadata?.nested));

  const otherSource = await createEvidence(
    { ...input, source: "feature/src/main/Index.ets" },
    hash,
  );
  assert.notEqual(first.id, otherSource.id);
});

test("Evidence 拒绝绝对、越界路径和非法 HashPort 输出且错误不泄露路径", async () => {
  for (const source of [
    "/Users/alice/SECRET/project/file.ets",
    "C:\\SECRET\\file.ets",
    "\\\\server\\SECRET\\file.ets",
    "../SECRET/file.ets",
  ]) {
    await assert.rejects(
      createEvidence(
        {
          type: "source",
          source,
          summary: "摘要",
          content: "安全内容",
          redacted: true,
        },
        hash,
      ),
      (error: unknown) => {
        assert.ok(error instanceof TypeError);
        assert.doesNotMatch(error.message, /SECRET/u);
        return true;
      },
    );
  }

  await assert.rejects(
    createEvidence(
      {
        type: "source",
        source: "entry/file.ets",
        summary: "摘要",
        content: "内容",
        redacted: true,
      },
      { sha256: async () => "sha256:BAD" },
    ),
    /SHA-256/u,
  );
  await assert.rejects(
    createEvidence(
      {
        type: "unknown" as "source",
        source: "entry/file.ets",
        summary: "摘要",
        content: "内容",
        redacted: true,
      },
      hash,
    ),
    /证据类型/u,
  );
  await assert.rejects(
    createEvidence(
      {
        type: "source",
        source: "entry/file.ets",
        summary: "摘要",
        content: "内容",
        redacted: true,
        collectedAt: "2026-99-99T12:00:00Z",
      },
      hash,
    ),
    /采集时间/u,
  );
});

test("Finding 指纹跨行列稳定、规范化 Windows 分隔符且 semanticKey 参与身份", async () => {
  const first = await createFinding(findingInput, hash);
  const moved = await createFinding(
    {
      ...findingInput,
      locations: [{ uri: "./entry/src/main/Index.ets", line: 99, column: 31 }],
    },
    hash,
  );
  const differentSemanticKey = await createFinding(
    { ...findingInput, semanticKey: "placeholder:OTHER" },
    hash,
  );
  const differentVolatileProperties = await createFinding(
    {
      ...findingInput,
      properties: {
        observedAt: "2099-12-31T23:59:59Z",
        runId: "another-run",
      },
    },
    hash,
  );

  assert.equal(first.fingerprint, moved.fingerprint);
  assert.equal(first.id, moved.id);
  assert.notEqual(first.fingerprint, differentSemanticKey.fingerprint);
  assert.equal(first.fingerprint, differentVolatileProperties.fingerprint);
  assert.match(first.id, /^finding:[a-f0-9]{64}$/u);
  assert.equal(first.locations[0]?.uri, "entry/src/main/Index.ets");
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.locations));
  assert.ok(Object.isFrozen(first.properties?.nested));
});

test("Finding 使用显式主位置，新增字典序靠前位置不改变指纹", async () => {
  const base = await createFinding(findingInput, hash);
  const supplemented = await createFinding(
    {
      ...findingInput,
      locations: [
        { uri: "entry/src/main/A.ets", line: 1 },
        ...findingInput.locations,
      ],
    },
    hash,
  );
  assert.equal(base.fingerprint, supplemented.fingerprint);
  await assert.rejects(
    createFinding(
      { ...findingInput, primaryLocationUri: "entry/src/main/Missing.ets" },
      hash,
    ),
    /主位置/u,
  );
});

test("基线 diff 只标记新增、既有和已消失问题", async () => {
  const current = await createFinding(findingInput, hash);
  const resolved = await createFinding(
    { ...findingInput, semanticKey: "placeholder:RESOLVED" },
    hash,
  );
  const baseline = createBaselineSnapshot([current, resolved], {
    hcheckVersion: "0.6.0",
    createdAt: "2026-07-11T00:00:00Z",
    reference: "baseline/main",
  });

  const diff = diffFindingsWithBaseline([current], baseline);

  assert.equal(diff.findings[0]?.status, "existing");
  assert.deepEqual(diff.findings[0]?.baseline, {
    present: true,
    reference: "baseline/main",
  });
  assert.deepEqual(diff.resolved, [
    {
      fingerprint: resolved.fingerprint,
      ruleId: "HOS-META-003",
      title: "发布内容包含占位信息",
      severity: "HIGH",
      reference: "baseline/main",
    },
  ]);

  const other = await createFinding(
    { ...findingInput, semanticKey: "placeholder:NEW" },
    hash,
  );
  const newDiff = diffFindingsWithBaseline([other], baseline);
  assert.equal(newDiff.findings[0]?.status, "new");
  assert.deepEqual(newDiff.findings[0]?.baseline, {
    present: false,
    reference: "baseline/main",
  });
});

test("抑制必须有理由和未来过期时间，且只匹配同规则同指纹", async () => {
  const current = await createFinding(findingInput, hash);
  const now = new Date("2026-07-11T00:00:00Z");

  assert.equal(
    applySuppressions(
      [current],
      {
        schemaVersion: "1.0.0",
        suppressions: [
          {
            fingerprint: current.fingerprint,
            ruleId: current.ruleId,
            reason: "已由发布负责人确认。",
            expiresAt: "2026-08-01T00:00:00Z",
          },
        ],
      },
      now,
    )[0]?.status,
    "suppressed",
  );

  for (const bad of [
    {
      fingerprint: current.fingerprint,
      ruleId: current.ruleId,
      reason: "",
      expiresAt: "2026-08-01T00:00:00Z",
    },
    {
      fingerprint: current.fingerprint,
      ruleId: current.ruleId,
      reason: "已确认。",
      expiresAt: "2026-01-01T00:00:00Z",
    },
    {
      fingerprint: current.fingerprint,
      ruleId: "HOS-PKG-007",
      reason: "规则不匹配。",
      expiresAt: "2026-08-01T00:00:00Z",
    },
    {
      fingerprint:
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      ruleId: current.ruleId,
      reason: "指纹不匹配。",
      expiresAt: "2026-08-01T00:00:00Z",
    },
  ] as const) {
    assert.throws(
      () =>
        applySuppressions(
          [current],
          { schemaVersion: "1.0.0", suppressions: [bad] },
          now,
        ),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError);
        assert.equal(error.code, "CONFIGURATION_ERROR");
        return true;
      },
    );
  }
});

test("Finding 规则主版本参与身份且拒绝绝对位置、空位置和非法哈希", async () => {
  const nextMajor = await createFinding(
    { ...findingInput, ruleVersion: "2.0.0" },
    hash,
  );
  const current = await createFinding(findingInput, hash);
  assert.notEqual(current.fingerprint, nextMajor.fingerprint);

  await assert.rejects(
    createFinding(
      { ...findingInput, locations: [{ uri: "/tmp/SECRET/file.ets" }] },
      hash,
    ),
    (error: unknown) => {
      assert.ok(error instanceof TypeError);
      assert.doesNotMatch(error.message, /SECRET/u);
      return true;
    },
  );
  await assert.rejects(
    createFinding(
      { ...findingInput, moduleId: "/tmp/SECRET/project/entry" },
      hash,
    ),
    (error: unknown) => {
      assert.ok(error instanceof TypeError);
      assert.doesNotMatch(error.message, /SECRET/u);
      return true;
    },
  );
  await assert.rejects(
    createFinding({ ...findingInput, locations: [] }, hash),
    /位置/u,
  );
  await assert.rejects(
    createFinding(findingInput, { sha256: async () => "sha256:BAD" }),
    /SHA-256/u,
  );
  await assert.rejects(
    createFinding({ ...findingInput, evidenceIds: ["bad-evidence-id"] }, hash),
    /Evidence ID/u,
  );
  await assert.rejects(
    createFinding(
      {
        ...findingInput,
        evidenceIds: [
          findingInput.evidenceIds[0]!,
          findingInput.evidenceIds[0]!,
        ],
      },
      hash,
    ),
    /重复/u,
  );
});

test("Evidence/Finding TypeScript 合同与 Schema 必需字段一致", async () => {
  const evidenceSchema = JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/evidence.schema.json"),
      "utf8",
    ),
  ) as { required: string[]; properties: Record<string, unknown> };
  const findingSchema = JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/finding.schema.json"),
      "utf8",
    ),
  ) as { required: string[]; properties: Record<string, unknown> };

  assert.deepEqual(evidenceSchema.required, [
    "id",
    "type",
    "source",
    "summary",
    "contentHash",
    "redacted",
  ]);
  assert.deepEqual(Object.keys(evidenceSchema.properties).sort(), [
    "archiveRef",
    "collectedAt",
    "contentHash",
    "id",
    "location",
    "metadata",
    "redacted",
    "source",
    "summary",
    "type",
  ]);
  assert.ok(findingSchema.required.includes("locations"));
  assert.ok("policyRefs" in findingSchema.properties);
  assert.ok("baseline" in findingSchema.properties);
});

test("运行时 Validator 拒绝 Evidence 合同绕过且不泄露原值", async () => {
  const valid = await createEvidence(
    {
      type: "source",
      source: "entry/src/main/Index.ets",
      summary: "有效证据",
      content: "内容",
      redacted: true,
      collectedAt: "2026-02-28T12:00:00Z",
    },
    hash,
  );
  validateEvidence(valid);

  const invalidValues: unknown[] = [
    { ...valid, redacted: false },
    { ...valid, source: "/SECRET/absolute.ets" },
    { ...valid, source: " " },
    { ...valid, summary: " " },
    { ...valid, collectedAt: "2026-02-30T12:00:00Z" },
    { ...valid, contentHash: "sha256:BAD" },
    { ...valid, extra: "SECRET-EXTRA" },
    { ...valid, location: { uri: "entry/file.ets", line: -1 } },
    { ...valid, metadata: { nested: undefined } },
  ];
  for (const value of invalidValues) {
    assert.throws(() => validateEvidence(value), expectContractError("SECRET"));
  }
  for (const source of [
    "file:SECRET",
    "http:SECRET",
    "mailto:SECRET",
    "data:SECRET",
  ]) {
    assert.throws(
      () => validateEvidence({ ...valid, source }),
      expectContractError("SECRET"),
    );
  }

  await assert.rejects(
    createEvidence(
      {
        type: "source",
        source: "entry/file.ets",
        summary: "摘要",
        content: "内容",
        redacted: false,
      },
      hash,
    ),
    /脱敏/u,
  );
});

test("Evidence date-time 仅接受大写 T/Z 且拒绝闰秒和偏移", async () => {
  const valid = await createEvidence(
    {
      type: "source",
      source: "entry/file.ets",
      summary: "摘要",
      content: "内容",
      redacted: true,
      collectedAt: "2026-02-28T12:00:00Z",
    },
    hash,
  );
  for (const collectedAt of [
    "2026-02-28t12:00:00z",
    "2026-02-28T12:00:60Z",
    "2026-02-28T12:00:00+08:00",
  ]) {
    assert.throws(() => validateEvidence({ ...valid, collectedAt }), TypeError);
  }
});

test("安全 JSON 预算稳定拒绝深度、节点、容器、字符串和总字节越限", () => {
  assert.deepEqual(SAFE_JSON_BUDGET, {
    maxDepth: 64,
    maxNodes: 10_000,
    maxArrayItems: 1_000,
    maxObjectKeys: 256,
    maxStringLength: 16 * 1024,
    maxCanonicalBytes: 1024 * 1024,
  });

  const tooDeep: Record<string, unknown> = {};
  let cursor = tooDeep;
  for (let index = 0; index < SAFE_JSON_BUDGET.maxDepth + 1; index += 1) {
    const next: Record<string, unknown> = {};
    cursor.next = next;
    cursor = next;
  }
  const tooManyNodes = Object.fromEntries(
    Array.from({ length: 40 }, (_, group) => [
      `group${group}`,
      Object.fromEntries(
        Array.from({ length: 256 }, (_, item) => [`item${item}`, item]),
      ),
    ]),
  );
  const tooLargeCanonical = Object.fromEntries(
    Array.from({ length: 65 }, (_, index) => [
      `key${index}`,
      "x".repeat(SAFE_JSON_BUDGET.maxStringLength),
    ]),
  );
  const values = [
    tooDeep,
    tooManyNodes,
    Array.from({ length: SAFE_JSON_BUDGET.maxArrayItems + 1 }, () => 0),
    Object.fromEntries(
      Array.from({ length: SAFE_JSON_BUDGET.maxObjectKeys + 1 }, (_, index) => [
        `key${index}`,
        index,
      ]),
    ),
    "x".repeat(SAFE_JSON_BUDGET.maxStringLength + 1),
    tooLargeCanonical,
  ];
  for (const value of values) {
    assert.throws(() => canonicalStringify(value), TypeError);
  }
});

test("许多单串合规但聚合超过 1MiB 时在预算遍历阶段稳定拒绝", () => {
  const aggregate = Object.fromEntries(
    Array.from({ length: 65 }, (_, index) => [
      `key${index}`,
      "汉".repeat(SAFE_JSON_BUDGET.maxStringLength),
    ]),
  );
  assert.throws(
    () => canonicalStringify(aggregate),
    (error: unknown) => {
      assert.ok(error instanceof TypeError);
      assert.ok(!(error instanceof RangeError));
      assert.match(error.message, /JSON UTF-8 总量预算/u);
      return true;
    },
  );
});

test("安全 JSON 最大深度内可构造且 Evidence 输出逐层深冻结", async () => {
  const metadata: Record<string, unknown> = {};
  let cursor = metadata;
  for (let index = 0; index < SAFE_JSON_BUDGET.maxDepth; index += 1) {
    const next: Record<string, unknown> = {};
    cursor.next = next;
    cursor = next;
  }
  const result = await createEvidence(
    {
      type: "source",
      source: "entry/file.ets",
      summary: "摘要",
      content: "内容",
      redacted: true,
      metadata,
    },
    hash,
  );
  let frozen: unknown = result.metadata;
  for (let index = 0; index <= SAFE_JSON_BUDGET.maxDepth; index += 1) {
    assert.ok(Object.isFrozen(frozen));
    frozen = (frozen as Record<string, unknown>).next;
  }
});

test("运行时 Validator 完整拒绝 Finding 损坏字段", async () => {
  const valid = await createFinding(findingInput, hash);
  validateFinding(valid);
  const invalidValues: unknown[] = [
    { ...valid, schemaVersion: "2.0.0" },
    { ...valid, id: `finding:${"9".repeat(64)}` },
    { ...valid, ruleId: "SECRET-RULE" },
    { ...valid, ruleVersion: "1.0" },
    { ...valid, severity: "SECRET-SEVERITY" },
    { ...valid, confidence: "SECRET-CONFIDENCE" },
    { ...valid, applicability: "SECRET-APPLICABILITY" },
    { ...valid, status: "SECRET-STATUS" },
    { ...valid, autofix: "SECRET-AUTOFIX" },
    { ...valid, title: " " },
    { ...valid, locations: [{ uri: "/SECRET/file.ets" }] },
    { ...valid, locations: [{ uri: "entry/file.ets", column: -1 }] },
    { ...valid, evidenceIds: [valid.evidenceIds[0], valid.evidenceIds[0]] },
    { ...valid, remediation: { summary: "", verification: "复验" } },
    {
      ...valid,
      policyRefs: [
        { source: "来源", section: "章节", verifiedAt: "2026-02-30" },
      ],
    },
    { ...valid, baseline: { present: false, extra: "SECRET-EXTRA" } },
    { ...valid, properties: { unsafe: Number.NaN } },
    { ...valid, extra: "SECRET-EXTRA" },
  ];
  for (const value of invalidValues) {
    assert.throws(() => validateFinding(value), expectContractError("SECRET"));
  }
});

test("构造结果实际通过 Ajv 2020 Evidence/Finding Schema", async () => {
  const evidenceSchema = JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/evidence.schema.json"),
      "utf8",
    ),
  ) as object;
  const findingSchema = JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/finding.schema.json"),
      "utf8",
    ),
  ) as object;
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const checkEvidence = ajv.compile<Evidence>(evidenceSchema);
  const checkFinding = ajv.compile<Finding>(findingSchema);
  const evidenceValue = await createEvidence(
    {
      type: "source",
      source: "entry/src/main/Index.ets",
      summary: "有效证据",
      content: "内容",
      redacted: true,
      collectedAt: "2026-02-28T12:00:00Z",
    },
    hash,
  );
  const findingValue = await createFinding(
    { ...findingInput, evidenceIds: [evidenceValue.id] },
    hash,
  );

  assert.equal(
    checkEvidence(evidenceValue),
    true,
    JSON.stringify(checkEvidence.errors),
  );
  assert.equal(
    checkFinding(findingValue),
    true,
    JSON.stringify(checkFinding.errors),
  );
  assert.equal(
    checkEvidence({ ...evidenceValue, source: "/absolute/file.ets" }),
    false,
  );
  assert.equal(
    checkEvidence({ ...evidenceValue, collectedAt: "2026-02-30T12:00:00Z" }),
    false,
  );
  assert.equal(
    checkEvidence({ ...evidenceValue, collectedAt: "2026-02-28t12:00:00z" }),
    false,
  );
  assert.equal(
    checkEvidence({ ...evidenceValue, collectedAt: "2026-02-28T12:00:60Z" }),
    false,
  );
  for (const source of ["file:path", "http:path", "mailto:path", "data:path"]) {
    assert.equal(checkEvidence({ ...evidenceValue, source }), false);
    assert.equal(
      checkFinding({
        ...findingValue,
        locations: [{ uri: source }],
      }),
      false,
    );
  }
  assert.equal(checkFinding({ ...findingValue, ruleVersion: "1.0" }), false);
  assert.equal(
    checkFinding({
      ...findingValue,
      locations: [{ uri: "/absolute/file.ets" }],
    }),
    false,
  );

  for (const dangerousKey of ["__proto__", "constructor", "prototype"]) {
    const dangerous = JSON.parse(`{"${dangerousKey}":1}`) as Record<
      string,
      unknown
    >;
    for (const metadata of [dangerous, { nested: dangerous }]) {
      assert.throws(
        () => validateEvidence({ ...evidenceValue, metadata }),
        TypeError,
      );
      assert.equal(checkEvidence({ ...evidenceValue, metadata }), false);
      assert.throws(
        () => validateFinding({ ...findingValue, properties: metadata }),
        TypeError,
      );
      assert.equal(
        checkFinding({ ...findingValue, properties: metadata }),
        false,
      );
    }
  }

  const unicodeWithinLimit = "汉".repeat(6_000);
  const overStringLimit = "字".repeat(SAFE_JSON_BUDGET.maxStringLength + 1);
  validateEvidence({
    ...evidenceValue,
    metadata: { value: unicodeWithinLimit },
  });
  assert.equal(
    checkEvidence({
      ...evidenceValue,
      metadata: { value: unicodeWithinLimit },
    }),
    true,
  );
  assert.throws(
    () =>
      validateEvidence({
        ...evidenceValue,
        metadata: { value: overStringLimit },
      }),
    TypeError,
  );
  assert.equal(
    checkEvidence({
      ...evidenceValue,
      metadata: { value: overStringLimit },
    }),
    false,
  );

  const depth65: Record<string, unknown> = {};
  let depthCursor = depth65;
  for (let index = 0; index < SAFE_JSON_BUDGET.maxDepth + 1; index += 1) {
    const next: Record<string, unknown> = {};
    depthCursor.next = next;
    depthCursor = next;
  }
  assert.equal(checkEvidence({ ...evidenceValue, metadata: depth65 }), true);
  assert.throws(
    () => validateEvidence({ ...evidenceValue, metadata: depth65 }),
    TypeError,
  );

  for (const schema of [evidenceSchema, findingSchema]) {
    assert.match(
      String(Reflect.get(schema, "$comment")),
      /Schema之外.*core validator.*附加资源门禁/u,
    );
  }
});
