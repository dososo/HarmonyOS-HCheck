import assert from "node:assert/strict";
import test from "node:test";
import {
  buildArkTsSymbolIndex,
  buildCallGraph,
  findConsentGateCandidates,
} from "../src/arkts-symbol-index.js";

test("ArkTS 符号索引记录 import/export、函数声明和别名 API 调用", () => {
  const index = buildArkTsSymbolIndex([
    {
      uri: "entry/src/main/ets/Index.ets",
      source: [
        "import { geoLocationManager as geo } from '@kit.LocationKit';",
        "export async function locate() {",
        "  return geo.getCurrentLocation();",
        "}",
        "export const label = 'ok';",
      ].join("\n"),
    },
  ]);

  assert.deepEqual(index.imports, [
    {
      uri: "entry/src/main/ets/Index.ets",
      module: "@kit.LocationKit",
      imported: "geoLocationManager",
      local: "geo",
      location: { uri: "entry/src/main/ets/Index.ets", line: 1, column: 10 },
    },
  ]);
  assert.deepEqual(
    index.declarations.map(({ name, kind, exported }) => ({
      name,
      kind,
      exported,
    })),
    [
      { name: "locate", kind: "function", exported: true },
      { name: "label", kind: "variable", exported: true },
    ],
  );
  assert.deepEqual(
    index.callSites.map((call) => ({
      callee: call.callee,
      receiver: call.receiver,
      member: call.member,
      importModule: call.importModule,
      importName: call.importName,
      enclosingFunction: call.enclosingFunction,
      line: call.location.line,
    })),
    [
      {
        callee: "geo.getCurrentLocation",
        receiver: "geo",
        member: "getCurrentLocation",
        importModule: "@kit.LocationKit",
        importName: "geoLocationManager",
        enclosingFunction: "locate",
        line: 3,
      },
    ],
  );
});

test("调用图输出函数到敏感 API 的可追溯边", () => {
  const index = buildArkTsSymbolIndex([
    {
      uri: "entry/src/main/ets/Index.ets",
      source: [
        "import { geoLocationManager } from '@kit.LocationKit';",
        "function helper() {",
        "  return geoLocationManager.getCurrentLocation();",
        "}",
        "export function locate() {",
        "  return helper();",
        "}",
      ].join("\n"),
    },
  ]);

  const graph = buildCallGraph(index);

  assert.deepEqual(
    graph.edges.map((edge) => ({
      from: edge.from,
      to: edge.to,
      kind: edge.kind,
    })),
    [
      {
        from: "entry/src/main/ets/Index.ets#helper",
        to: "@kit.LocationKit#geoLocationManager.getCurrentLocation",
        kind: "imported-api",
      },
      {
        from: "entry/src/main/ets/Index.ets#locate",
        to: "entry/src/main/ets/Index.ets#helper",
        kind: "local-call",
      },
    ],
  );
});

test("调用图预算超限时输出 INCOMPLETE，不把截断结果当完整调用图", () => {
  const index = buildArkTsSymbolIndex([
    {
      uri: "entry/src/main/ets/Index.ets",
      source: [
        "import { geoLocationManager } from '@kit.LocationKit';",
        "function helper() {",
        "  return geoLocationManager.getCurrentLocation();",
        "}",
        "export function locate() {",
        "  helper();",
        "  return helper();",
        "}",
      ].join("\n"),
    },
  ]);

  const graph = buildCallGraph(index, { budget: { maxEdges: 1 } });

  assert.equal(graph.completeness, "INCOMPLETE");
  assert.deepEqual(graph.incompleteReason, {
    code: "resource_budget",
    limit: 1,
    observedAtLeast: 2,
  });
  assert.equal(graph.edges.length, 1);
});

test("同意门控候选只输出 PROBABLE 静态证据，不冒充运行时确认", () => {
  const index = buildArkTsSymbolIndex([
    {
      uri: "entry/src/main/ets/Index.ets",
      source: [
        "import { geoLocationManager } from '@kit.LocationKit';",
        "import { abilityAccessCtrl } from '@kit.AbilityKit';",
        "export async function locate() {",
        "  await abilityAccessCtrl.requestPermissionsFromUser(context, ['ohos.permission.APPROXIMATELY_LOCATION']);",
        "  return geoLocationManager.getCurrentLocation();",
        "}",
      ].join("\n"),
    },
  ]);

  const candidates = findConsentGateCandidates(index, [
    {
      importModule: "@kit.LocationKit",
      importName: "geoLocationManager",
      member: "getCurrentLocation",
      permission: "ohos.permission.APPROXIMATELY_LOCATION",
    },
  ]);

  assert.deepEqual(
    candidates.map((candidate) => ({
      api: candidate.api,
      permission: candidate.permission,
      confidence: candidate.confidence,
      runtimeConfirmed: candidate.runtimeConfirmed,
      hasPriorConsentCandidate: candidate.hasPriorConsentCandidate,
    })),
    [
      {
        api: "@kit.LocationKit#geoLocationManager.getCurrentLocation",
        permission: "ohos.permission.APPROXIMATELY_LOCATION",
        confidence: "PROBABLE",
        runtimeConfirmed: false,
        hasPriorConsentCandidate: true,
      },
    ],
  );
});
