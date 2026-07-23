import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import addFormats from "ajv-formats";
import { Ajv2020 } from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";

const EXAMPLE_MAPPINGS = [
  [
    "examples/account-deletion-stub.json",
    "account-deletion-stub.schema.json",
    "json",
  ],
  ["examples/evidence.json", "evidence.schema.json", "json"],
  ["examples/finding.json", "finding.schema.json", "json"],
  ["examples/report.json", "report.schema.json", "json"],
  ["examples/hcheck.yml", "hcheck-config.schema.json", "yaml"],
  ["examples/account-delete.yml", "runtime-flow.schema.json", "yaml"],
  ["examples/privacy-refuse.yml", "runtime-flow.schema.json", "yaml"],
  ["examples/permission-deny.yml", "runtime-flow.schema.json", "yaml"],
];

export function validateJsonAgainstSchema(schema, data) {
  const ajv = createAjv();
  const validate = ajv.compile(schema);
  const ok = validate(data);
  return {
    ok,
    errors: ok ? [] : formatAjvErrors(validate.errors),
  };
}

export async function validateRepositorySchemas({ root = process.cwd() } = {}) {
  const absoluteRoot = path.resolve(root);
  const schemas = await loadSchemas(absoluteRoot);
  const ajv = createAjv();
  for (const { name, schema } of schemas) {
    ajv.addSchema(schema, name);
  }

  const errors = [];
  for (const { name, schema } of schemas) {
    try {
      ajv.compile(schema);
    } catch (error) {
      errors.push(`${name} 编译失败：${safeMessage(error)}`);
    }
  }

  for (const [file, schemaName, format] of EXAMPLE_MAPPINGS) {
    await validateFile(absoluteRoot, ajv, file, schemaName, format, errors);
  }

  for (const file of await collectBySuffix(
    path.join(absoluteRoot, "fixtures"),
    "fixture.yml",
  )) {
    await validateFile(
      absoluteRoot,
      ajv,
      relative(absoluteRoot, file),
      "fixture.schema.json",
      "yaml",
      errors,
    );
  }
  errors.push(
    ...(await validateExpectedFindingsContract({ root: absoluteRoot })).errors,
  );
  errors.push(
    ...(await validateRuntimeFixtureContracts({ root: absoluteRoot })).errors,
  );
  for (const file of await collectYamlFiles(path.join(absoluteRoot, "rules"))) {
    const relativeFile = relative(absoluteRoot, file);
    if (relativeFile.startsWith("rules/packs/")) {
      await validateFile(
        absoluteRoot,
        ajv,
        relativeFile,
        "rule-pack.schema.json",
        "yaml",
        errors,
      );
    } else if (relativeFile !== "rules/manifest.yml") {
      await validateFile(
        absoluteRoot,
        ajv,
        relativeFile,
        "rule.schema.json",
        "yaml",
        errors,
      );
    }
  }
  for (const file of await collectBySuffix(
    path.join(absoluteRoot, "rules", "packs"),
    ".signature.json",
  )) {
    await validateFile(
      absoluteRoot,
      ajv,
      relative(absoluteRoot, file),
      "rule-pack-signature.schema.json",
      "json",
      errors,
    );
  }
  errors.push(
    ...(
      await validateRulePackSignatureManifests({
        root: absoluteRoot,
      })
    ).errors,
  );

  errors.sort();
  return { ok: errors.length === 0, errors };
}

export async function validateRulePackSignatureManifests({
  root = process.cwd(),
} = {}) {
  const absoluteRoot = path.resolve(root);
  const errors = [];
  const packsRoot = path.join(absoluteRoot, "rules", "packs");
  const files = await collectBySuffix(packsRoot, ".signature.json");

  for (const file of files) {
    const relativeFile = relative(absoluteRoot, file);
    let manifest;
    try {
      manifest = JSON.parse(await readFile(file, "utf8"));
    } catch (error) {
      errors.push(`${relativeFile} 解析失败：${safeMessage(error)}`);
      continue;
    }
    if (!isRecord(manifest) || !Array.isArray(manifest.files)) {
      errors.push(`${relativeFile} 签名清单结构无效。`);
      continue;
    }
    const seen = new Set();
    for (const [index, item] of manifest.files.entries()) {
      if (!isRecord(item) || typeof item.path !== "string") {
        errors.push(`${relativeFile} files[${index}] 缺少 path。`);
        continue;
      }
      if (!isSafeRepositoryRelativePath(item.path)) {
        errors.push(`${relativeFile} files[${index}] 包含不安全或越界路径。`);
        continue;
      }
      if (seen.has(item.path)) {
        errors.push(`${relativeFile} files[${index}] 路径重复。`);
        continue;
      }
      seen.add(item.path);
    }
  }

  errors.sort();
  return { ok: errors.length === 0, errors };
}

export async function validateExpectedFindingsContract({
  root = process.cwd(),
} = {}) {
  const absoluteRoot = path.resolve(root);
  const errors = [];
  const fixtureFiles = await collectBySuffix(
    path.join(absoluteRoot, "fixtures"),
    "fixture.yml",
  );

  for (const fixtureFile of fixtureFiles) {
    const fixtureRelative = relative(absoluteRoot, fixtureFile);
    let fixture;
    try {
      fixture = parseYaml(await readFile(fixtureFile, "utf8"), {
        maxAliasCount: 0,
        uniqueKeys: true,
      });
    } catch (error) {
      errors.push(`${fixtureRelative} 解析失败：${safeMessage(error)}`);
      continue;
    }
    if (!isRecord(fixture)) {
      errors.push(`${fixtureRelative} 必须是对象。`);
      continue;
    }

    const expectedFile = path.join(
      path.dirname(fixtureFile),
      "expected-findings.json",
    );
    const expectedRelative = relative(absoluteRoot, expectedFile);
    let expected;
    try {
      expected = JSON.parse(await readFile(expectedFile, "utf8"));
    } catch (error) {
      errors.push(`${expectedRelative} 解析失败：${safeMessage(error)}`);
      continue;
    }
    if (!isRecord(expected)) {
      errors.push(`${expectedRelative} 必须是对象。`);
      continue;
    }

    validateExpectedFindingsFile({
      fixture,
      expected,
      fixtureRelative,
      expectedRelative,
      errors,
    });
  }

  errors.sort();
  return { ok: errors.length === 0, errors };
}

export async function validateRuntimeFixtureContracts({
  root = process.cwd(),
} = {}) {
  const absoluteRoot = path.resolve(root);
  const errors = [];
  const fixtureFiles = await collectBySuffix(
    path.join(absoluteRoot, "fixtures"),
    "fixture.yml",
  );

  for (const fixtureFile of fixtureFiles) {
    const fixtureRelative = relative(absoluteRoot, fixtureFile);
    let fixture;
    try {
      fixture = parseYaml(await readFile(fixtureFile, "utf8"), {
        maxAliasCount: 0,
        uniqueKeys: true,
      });
    } catch (error) {
      errors.push(`${fixtureRelative} 解析失败：${safeMessage(error)}`);
      continue;
    }
    if (!isRecord(fixture)) continue;
    const runtime = fixture.runtime;
    if (!isRecord(runtime) || runtime.required !== true) continue;

    const flows = Array.isArray(runtime.flows)
      ? runtime.flows.filter(isString)
      : [];
    if (flows.length === 0) {
      errors.push(`${fixtureRelative} 运行时 Fixture 必须声明 flows。`);
      continue;
    }
    if (!Array.isArray(runtime.evidence) || runtime.evidence.length === 0) {
      errors.push(`${fixtureRelative} 运行时 Fixture 必须声明运行时边界证据。`);
      continue;
    }

    for (const [index, evidencePath] of runtime.evidence.entries()) {
      if (typeof evidencePath !== "string") {
        errors.push(
          `${fixtureRelative} runtime.evidence[${index}] 必须是路径。`,
        );
        continue;
      }
      if (!isSafeRepositoryRelativePath(evidencePath)) {
        errors.push(
          `${fixtureRelative} runtime.evidence[${index}] 包含不安全或越界路径。`,
        );
        continue;
      }
      await validateRuntimeFixtureEvidence({
        absoluteRoot,
        fixtureFile,
        fixture,
        fixtureRelative,
        evidencePath,
        flows,
        errors,
      });
    }
  }

  errors.sort();
  return { ok: errors.length === 0, errors };
}

async function validateRuntimeFixtureEvidence({
  absoluteRoot,
  fixtureFile,
  fixture,
  fixtureRelative,
  evidencePath,
  flows,
  errors,
}) {
  const evidenceFile = path.join(path.dirname(fixtureFile), evidencePath);
  const evidenceRelative = relative(absoluteRoot, evidenceFile);
  let evidence;
  try {
    evidence = JSON.parse(await readFile(evidenceFile, "utf8"));
  } catch (error) {
    errors.push(`${evidenceRelative} 解析失败：${safeMessage(error)}`);
    return;
  }
  if (!isRecord(evidence)) {
    errors.push(`${evidenceRelative} 必须是对象。`);
    return;
  }
  if (evidence.schemaVersion !== "1.0.0") {
    errors.push(`${evidenceRelative} schemaVersion 必须是 1.0.0。`);
  }
  if (
    !["runtime-flow-boundary", "account-deletion-stub-contract"].includes(
      evidence.evidenceKind,
    )
  ) {
    errors.push(
      `${evidenceRelative} evidenceKind 必须是 runtime-flow-boundary 或 account-deletion-stub-contract。`,
    );
  }
  if (evidence.fixtureId !== fixture.id) {
    errors.push(`${evidenceRelative} fixtureId 必须匹配 ${fixtureRelative}。`);
  }
  if (typeof evidence.flowId !== "string" || !flows.includes(evidence.flowId)) {
    errors.push(
      `${evidenceRelative} flowId 必须匹配 fixture.yml runtime.flows。`,
    );
  }
  if (!["local_contract", "p3_blocked"].includes(evidence.status)) {
    errors.push(
      `${evidenceRelative} status 必须是 local_contract 或 p3_blocked。`,
    );
  }
  if (evidence.runtimeConfirmed !== false) {
    errors.push(
      `${evidenceRelative} runtimeConfirmed 必须为 false，不能伪造真实运行。`,
    );
  }
  if (evidence.redacted !== true) {
    errors.push(`${evidenceRelative} 必须标记 redacted=true。`);
  }
  if (!Array.isArray(evidence.boundaries) || evidence.boundaries.length === 0) {
    errors.push(`${evidenceRelative} 必须写明边界。`);
  }
  if (evidence.evidenceKind === "account-deletion-stub-contract") {
    validateAccountDeletionStubEvidence(evidence, evidenceRelative, errors);
  }
  if (
    fixture.id === "F007" &&
    evidence.evidenceKind === "runtime-flow-boundary" &&
    (!Array.isArray(evidence.p3BlockedBy) ||
      !evidence.p3BlockedBy.includes("TASK-8007"))
  ) {
    errors.push(
      `${evidenceRelative} F007 边界证据必须标记 P3 TASK-8007 阻塞。`,
    );
  }
}

function validateAccountDeletionStubEvidence(
  evidence,
  evidenceRelative,
  errors,
) {
  if (evidence.flowId !== "account-delete") {
    errors.push(
      `${evidenceRelative} 账号注销测试桩 flowId 必须是 account-delete。`,
    );
  }
  if (evidence.status !== "local_contract") {
    errors.push(
      `${evidenceRelative} 账号注销测试桩 status 必须是 local_contract。`,
    );
  }
  const service = evidence.service;
  if (!isRecord(service)) {
    errors.push(`${evidenceRelative} 账号注销测试桩必须声明 service。`);
  } else {
    if (service.kind !== "local-recorded-stub") {
      errors.push(
        `${evidenceRelative} service.kind 必须是 local-recorded-stub。`,
      );
    }
    if (service.production !== false) {
      errors.push(`${evidenceRelative} service.production 必须是 false。`);
    }
    if (
      typeof service.endpoint !== "string" ||
      !isLocalStubEndpoint(service.endpoint)
    ) {
      errors.push(
        `${evidenceRelative} service.endpoint 必须是本地测试桩地址。`,
      );
    }
  }
  const account = evidence.account;
  if (!isRecord(account)) {
    errors.push(`${evidenceRelative} 账号注销测试桩必须声明 account。`);
  } else {
    if (account.redacted !== true) {
      errors.push(`${evidenceRelative} account.redacted 必须是 true。`);
    }
    if (
      typeof account.subject !== "string" ||
      !/^[a-z0-9][a-z0-9_.:-]*$/u.test(account.subject)
    ) {
      errors.push(`${evidenceRelative} account.subject 必须是脱敏稳定 ID。`);
    }
  }
  const requiredChecks = new Set([
    "delete-request-accepted",
    "old-token-rejected",
    "relogin-rejected",
    "local-data-cleared",
  ]);
  if (!Array.isArray(evidence.checks)) {
    errors.push(`${evidenceRelative} 账号注销测试桩 checks 必须是数组。`);
  } else {
    const seen = new Set();
    for (const [index, check] of evidence.checks.entries()) {
      if (!isRecord(check)) {
        errors.push(`${evidenceRelative} checks[${index}] 必须是对象。`);
        continue;
      }
      if (!requiredChecks.has(check.id)) {
        errors.push(`${evidenceRelative} checks[${index}] id 无效。`);
      } else if (seen.has(check.id)) {
        errors.push(`${evidenceRelative} checks[${index}] id 重复。`);
      } else {
        seen.add(check.id);
      }
      if (!["passed", "failed", "evidence_incomplete"].includes(check.status)) {
        errors.push(`${evidenceRelative} checks[${index}] status 无效。`);
      }
      if (typeof check.summary !== "string" || !isSafeText(check.summary)) {
        errors.push(
          `${evidenceRelative} checks[${index}] summary 必须已脱敏。`,
        );
      }
    }
    for (const id of requiredChecks) {
      if (!seen.has(id)) errors.push(`${evidenceRelative} checks 缺少 ${id}。`);
    }
  }
  if (!isRecord(evidence.evidence)) {
    errors.push(`${evidenceRelative} 账号注销测试桩必须声明 evidence。`);
  } else {
    if (typeof evidence.evidence.collectedAt !== "string") {
      errors.push(`${evidenceRelative} evidence.collectedAt 必须是字符串。`);
    }
    if (
      !Array.isArray(evidence.evidence.commands) ||
      evidence.evidence.commands.length === 0 ||
      !evidence.evidence.commands.every(
        (command) => typeof command === "string" && isSafeText(command),
      )
    ) {
      errors.push(`${evidenceRelative} evidence.commands 必须是脱敏命令数组。`);
    }
  }
  if (!Array.isArray(evidence.boundaries) || evidence.boundaries.length === 0) {
    errors.push(`${evidenceRelative} 账号注销测试桩必须写明 boundaries。`);
  } else if (
    !evidence.boundaries.every(
      (item) => typeof item === "string" && isSafeText(item),
    )
  ) {
    errors.push(`${evidenceRelative} boundaries 必须已脱敏。`);
  }
  if (!isSafeText(JSON.stringify(evidence))) {
    errors.push(`${evidenceRelative} 账号注销测试桩证据包含未脱敏内容。`);
  }
}

function validateExpectedFindingsFile({
  fixture,
  expected,
  fixtureRelative,
  expectedRelative,
  errors,
}) {
  if (typeof fixture.id === "string" && expected.fixtureId !== fixture.id) {
    errors.push(
      `${expectedRelative} fixtureId 必须匹配 ${fixtureRelative} 的 id。`,
    );
  }
  if (
    typeof expected.status === "string" &&
    typeof fixture.status === "string" &&
    expected.status !== fixture.status
  ) {
    errors.push(
      `${expectedRelative} status 必须匹配 ${fixtureRelative} 的 status。`,
    );
  }
  if (!Array.isArray(fixture.expected_findings)) {
    errors.push(`${fixtureRelative} expected_findings 必须是数组。`);
    return;
  }
  if (!Array.isArray(expected.expected)) {
    errors.push(`${expectedRelative} expected 必须是数组。`);
    return;
  }

  const fixtureRules = fixture.expected_findings.map((item, index) => {
    if (!isRecord(item) || typeof item.rule_id !== "string") {
      errors.push(
        `${fixtureRelative} expected_findings[${index}] 缺少 rule_id。`,
      );
      return undefined;
    }
    return item.rule_id;
  });
  const expectedRules = expected.expected.map((item, index) => {
    if (!isRecord(item) || typeof item.ruleId !== "string") {
      errors.push(`${expectedRelative} expected[${index}] 缺少 ruleId。`);
      return undefined;
    }
    if (
      fixture.status === "structural" &&
      (!Number.isSafeInteger(item.count) || item.count < 0)
    ) {
      errors.push(
        `${expectedRelative} expected[${index}] 必须为结构 Fixture 提供非负整数 count。`,
      );
    }
    return item.ruleId;
  });

  const fixtureRuleSet = new Set(fixtureRules.filter(isString));
  const expectedRuleSet = new Set(expectedRules.filter(isString));
  for (const ruleId of fixtureRuleSet) {
    if (!expectedRuleSet.has(ruleId)) {
      errors.push(`${expectedRelative} 缺少 ${ruleId} 的黄金期望。`);
    }
  }
  for (const ruleId of expectedRuleSet) {
    if (!fixtureRuleSet.has(ruleId)) {
      errors.push(
        `${expectedRelative} 包含未在 fixture.yml 声明的 ${ruleId}。`,
      );
    }
  }
}

async function loadSchemas(root) {
  const schemaRoot = path.join(root, "schemas");
  const entries = await readdir(schemaRoot, { withFileTypes: true });
  const schemas = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".schema.json")) continue;
    const text = await readFile(path.join(schemaRoot, entry.name), "utf8");
    schemas.push({ name: entry.name, schema: JSON.parse(text) });
  }
  return schemas.sort((left, right) =>
    compareCodePoints(left.name, right.name),
  );
}

async function validateFile(
  root,
  ajv,
  relativeFile,
  schemaName,
  format,
  errors,
) {
  const absoluteFile = path.join(root, relativeFile);
  let data;
  try {
    const text = await readFile(absoluteFile, "utf8");
    data =
      format === "json"
        ? JSON.parse(text)
        : parseYaml(text, { maxAliasCount: 0, uniqueKeys: true });
  } catch (error) {
    errors.push(`${relativeFile} 解析失败：${safeMessage(error)}`);
    return;
  }

  const validate = ajv.getSchema(schemaName);
  if (validate === undefined) {
    errors.push(`${relativeFile} 缺少 Schema：${schemaName}`);
    return;
  }

  if (!validate(data)) {
    for (const error of formatAjvErrors(validate.errors)) {
      errors.push(`${relativeFile} 不符合 ${schemaName}：${error}`);
    }
  }
}

async function collectBySuffix(root, suffix) {
  const files = [];
  await visit(root, files, (file) => file.endsWith(suffix));
  return files.sort(compareCodePoints);
}

async function collectYamlFiles(root) {
  const files = [];
  await visit(
    root,
    files,
    (file) => file.endsWith(".yml") || file.endsWith(".yaml"),
  );
  return files.sort(compareCodePoints);
}

async function visit(directory, files, accepts) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await visit(absolute, files, accepts);
    } else if (entry.isFile() && accepts(absolute)) {
      files.push(absolute);
    }
  }
}

function formatAjvErrors(errors) {
  return (errors ?? []).map((error) => {
    const pathText = error.instancePath.length === 0 ? "/" : error.instancePath;
    return `${pathText} ${error.keyword} ${error.message ?? "校验失败"}`;
  });
}

function createAjv() {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    allowUnionTypes: true,
  });
  addFormats(ajv);
  return ajv;
}

function safeMessage(error) {
  return error instanceof Error
    ? error.message.replaceAll(process.cwd(), "[REDACTED_PATH]")
    : "未知错误";
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value) {
  return typeof value === "string";
}

function isSafeRepositoryRelativePath(value) {
  const normalized = value.replaceAll("\\", "/");
  return (
    normalized.length > 0 &&
    normalized.length <= 512 &&
    !normalized.startsWith("/") &&
    !/^[A-Za-z]:\//u.test(normalized) &&
    !normalized.startsWith("//") &&
    !normalized.split("/").includes("..") &&
    !normalized.split("/").includes("")
  );
}

function isLocalStubEndpoint(value) {
  return (
    value.startsWith("stub://") ||
    /^http:\/\/(?:127\.0\.0\.1|localhost)(?::[0-9]{2,5})?(?:\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]*)?$/u.test(
      value,
    )
  );
}

function isSafeText(value) {
  return !(
    /\b(token|password|secret|authorization|cookie)\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+/iu.test(
      value,
    ) ||
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu.test(value) ||
    /[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+/u.test(value) ||
    /(?:\/Users|\/home|\/tmp|\/var|\/private\/tmp|\/Volumes)\/[^\s,;]+/u.test(
      value,
    )
  );
}

function relative(root, file) {
  return path.relative(root, file).replaceAll(path.sep, "/");
}

function compareCodePoints(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function main() {
  try {
    const result = await validateRepositorySchemas({ root: process.cwd() });
    for (const error of result.errors) console.error(error);
    process.exitCode = result.ok ? 0 : 1;
  } catch (error) {
    console.error(`Schema 校验失败：${safeMessage(error)}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
