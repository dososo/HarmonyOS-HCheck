import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  APPLICABILITIES,
  CONFIDENCES,
  SEVERITIES,
  parseApplicability,
  parseConfidence,
  parseSeverity,
} from "../src/index.js";

interface FindingSchema {
  readonly properties: {
    readonly severity: { readonly enum: readonly unknown[] };
    readonly confidence: { readonly enum: readonly unknown[] };
    readonly applicability: { readonly enum: readonly unknown[] };
  };
}

function assertRejectsInvalidValues(
  label: string,
  allowedValues: readonly string[],
  parse: (value: unknown) => string,
  invalidValues: readonly unknown[],
): void {
  const expectedMessage = `${label}必须是以下值之一：${allowedValues.join("、")}`;

  for (const value of invalidValues) {
    assert.throws(
      () => parse(value),
      (error: unknown) => {
        assert.ok(error instanceof TypeError);
        assert.equal(error.message, expectedMessage);
        assert.ok(!error.message.includes(String(value)));
        return true;
      },
    );
  }
}

test("严重性解析原样返回所有合法值", () => {
  for (const value of SEVERITIES) {
    assert.equal(parseSeverity(value), value);
  }
});

test("严重性解析拒绝非精确匹配且不泄露非法输入", () => {
  assertRejectsInvalidValues("严重性（severity）", SEVERITIES, parseSeverity, [
    "SECRET_CRITICAL",
    "high",
    " HIGH ",
    null,
  ]);
});

test("置信度解析原样返回所有合法值", () => {
  for (const value of CONFIDENCES) {
    assert.equal(parseConfidence(value), value);
  }
});

test("置信度解析拒绝非精确匹配且不泄露非法输入", () => {
  assertRejectsInvalidValues(
    "置信度（confidence）",
    CONFIDENCES,
    parseConfidence,
    ["CERTAIN", "probable", 1],
  );
});

test("适用性解析原样返回所有合法值", () => {
  for (const value of APPLICABILITIES) {
    assert.equal(parseApplicability(value), value);
  }
});

test("适用性解析拒绝非精确匹配且不泄露非法输入", () => {
  assertRejectsInvalidValues(
    "适用性（applicability）",
    APPLICABILITIES,
    parseApplicability,
    ["YES", "unknown", {}],
  );
});

test("三轴允许值在运行时不可修改", () => {
  assert.equal(Object.isFrozen(SEVERITIES), true);
  assert.equal(Object.isFrozen(CONFIDENCES), true);
  assert.equal(Object.isFrozen(APPLICABILITIES), true);

  assert.equal(Reflect.set(SEVERITIES, 0, "SECRET_CRITICAL"), false);
  assert.equal(Reflect.set(CONFIDENCES, 0, "CERTAIN"), false);
  assert.equal(Reflect.set(APPLICABILITIES, 0, "YES"), false);

  assert.equal(SEVERITIES[0], "BLOCKER");
  assert.equal(CONFIDENCES[0], "CONFIRMED");
  assert.equal(APPLICABILITIES[0], "APPLICABLE");
});

test("三轴常量与 Finding Schema 枚举保持一致", () => {
  const schema = JSON.parse(
    readFileSync(
      new URL("../../../schemas/finding.schema.json", import.meta.url),
      "utf8",
    ),
  ) as FindingSchema;

  assert.deepEqual(schema.properties.severity.enum, SEVERITIES);
  assert.deepEqual(schema.properties.confidence.enum, CONFIDENCES);
  assert.deepEqual(schema.properties.applicability.enum, APPLICABILITIES);
});
