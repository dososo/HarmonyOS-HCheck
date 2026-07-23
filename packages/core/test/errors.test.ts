import assert from "node:assert/strict";
import test from "node:test";
import { HCheckError } from "../src/index.js";

test("HCheckError 保存领域错误上下文", () => {
  const cause = new Error("底层解析失败");
  const details = { configPath: ".hcheck.yml", field: "version" };
  const error = new HCheckError(
    "CONFIGURATION_ERROR",
    "配置文件缺少 version 字段。",
    details,
    { cause },
  );

  assert.equal(error.code, "CONFIGURATION_ERROR");
  assert.equal(error.message, "配置文件缺少 version 字段。");
  assert.deepEqual(error.details, details);
  assert.equal(error.cause, cause);
  assert.equal(error.name, "HCheckError");
});

test("HCheckError 默认使用空 details", () => {
  const error = new HCheckError("INTERNAL_ERROR", "发生内部错误。");

  assert.deepEqual(error.details, {});
});
