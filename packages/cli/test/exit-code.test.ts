import assert from "node:assert/strict";
import test from "node:test";
import { HCheckError, type HCheckErrorCode } from "@hcheck/core";
import {
  exitCodeForError,
  type HCheckErrorExitCode,
} from "../src/exit-code.js";

const cases: readonly [HCheckErrorCode, HCheckErrorExitCode][] = [
  ["CONFIGURATION_ERROR", 3],
  ["UNSUPPORTED_PROJECT", 8],
  ["TOOL_UNAVAILABLE", 3],
  ["TOOL_EXECUTION_ERROR", 3],
  ["BUILD_FAILED", 3],
  ["ARTIFACT_PARSE_ERROR", 8],
  ["EXTERNAL_SERVICE_UNAVAILABLE", 5],
  ["CREDENTIAL_ERROR", 7],
  ["DEVICE_UNAVAILABLE", 4],
  ["RULE_DEFINITION_ERROR", 6],
  ["EVIDENCE_INCOMPLETE", 4],
  ["INTERNAL_ERROR", 10],
];

test("全部领域错误映射到基础退出码", () => {
  for (const [code, expectedExitCode] of cases) {
    assert.equal(
      exitCodeForError(new HCheckError(code, "测试错误。")),
      expectedExitCode,
    );
  }
});

test("基础错误映射不占用门禁退出码", () => {
  const gateExitCodes: readonly number[] = [0, 1, 2];

  for (const [code] of cases) {
    assert.ok(
      !gateExitCodes.includes(
        exitCodeForError(new HCheckError(code, "测试错误。")),
      ),
    );
  }
});

test("未知异常保守映射到内部错误退出码", () => {
  const unknownValues: readonly unknown[] = [
    new Error("普通异常"),
    undefined,
    null,
    "非错误值",
    { code: "CONFIGURATION_ERROR" },
  ];

  for (const value of unknownValues) {
    assert.equal(exitCodeForError(value), 10);
  }
});

test("运行时未知领域错误码保守映射到内部错误退出码", () => {
  const error = new HCheckError(
    "RUNTIME_UNKNOWN" as HCheckErrorCode,
    "未知领域错误。",
  );

  assert.equal(exitCodeForError(error), 10);
});

test("映射敏感错误时不写控制台或标准流", () => {
  const originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn,
    info: console.info,
    debug: console.debug,
  };
  const originalStdoutWrite = process.stdout.write;
  const originalStderrWrite = process.stderr.write;
  const calls = {
    log: 0,
    error: 0,
    warn: 0,
    info: 0,
    debug: 0,
    stdoutWrite: 0,
    stderrWrite: 0,
  };
  console.log = () => {
    calls.log += 1;
  };
  console.error = () => {
    calls.error += 1;
  };
  console.warn = () => {
    calls.warn += 1;
  };
  console.info = () => {
    calls.info += 1;
  };
  console.debug = () => {
    calls.debug += 1;
  };
  process.stdout.write = (() => {
    calls.stdoutWrite += 1;
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = (() => {
    calls.stderrWrite += 1;
    return true;
  }) as typeof process.stderr.write;

  try {
    const error = new HCheckError(
      "CREDENTIAL_ERROR",
      "令牌 secret-token 不可用。",
      { token: "secret-token" },
    );

    assert.equal(exitCodeForError(error), 7);
    assert.deepEqual(calls, {
      log: 0,
      error: 0,
      warn: 0,
      info: 0,
      debug: 0,
      stdoutWrite: 0,
      stderrWrite: 0,
    });
  } finally {
    console.log = originalConsole.log;
    console.error = originalConsole.error;
    console.warn = originalConsole.warn;
    console.info = originalConsole.info;
    console.debug = originalConsole.debug;
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }
});
