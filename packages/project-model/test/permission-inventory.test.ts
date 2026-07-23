import assert from "node:assert/strict";
import test from "node:test";
import { HCheckError } from "@hcheck/core";
import {
  collectPermissionDeclarations,
  hasDeclaredPermission,
  type ProjectSnapshot,
} from "../src/index.js";

function project(modules: ProjectSnapshot["modules"]): ProjectSnapshot {
  return {
    schemaVersion: "1.0.0",
    root: ".",
    platform: "harmonyos",
    appScope: "AppScope/app.json5",
    bundleName: "com.example.permission",
    products: [],
    modules,
    metadata: {},
    configSources: {
      appScope: "AppScope/app.json5",
      buildProfile: "build-profile.json5",
      modules: modules.map((module) => module.configSource),
    },
  };
}

function moduleSnapshot(
  name: string,
  requestPermissions: ProjectSnapshot["modules"][number]["requestPermissions"],
  extra: Partial<ProjectSnapshot["modules"][number]> = {},
): ProjectSnapshot["modules"][number] {
  return {
    name,
    type: "entry",
    root: name,
    relativePath: name,
    isExternal: false,
    moduleConfig: `${name}/src/main/module.json5`,
    sourceRoots: [`${name}/src/main`],
    deviceTypes: ["phone"],
    abilities: [],
    extensionAbilities: [],
    requestPermissions,
    metadata: [],
    profileRefs: [],
    configSource: `${name}/src/main/module.json5`,
    ...extra,
  };
}

test("权限声明清单稳定合并多模块 requestPermissions 且忽略组件访问权限", () => {
  const inventory = collectPermissionDeclarations(
    project([
      moduleSnapshot(
        "entry",
        [
          {
            name: "ohos.permission.INTERNET",
            reason: "$string:internet_reason",
          },
          {
            name: "ohos.permission.CAMERA",
            reason: "$string:camera_reason",
            usedScene: {
              abilities: ["EntryAbility"],
              when: "inuse",
            },
          },
        ],
        {
          abilities: [
            {
              name: "EntryAbility",
              permissions: ["ohos.permission.NOT_REQUESTED"],
            },
          ],
        },
      ),
      moduleSnapshot(
        "feature",
        [
          {
            name: "ohos.permission.CAMERA",
            reason: "$string:feature_camera_reason",
            usedScene: {
              abilities: ["FeatureAbility"],
              when: "always",
            },
          },
        ],
        { type: "feature" },
      ),
    ]),
  );

  assert.deepEqual(inventory.permissionNames, [
    "ohos.permission.CAMERA",
    "ohos.permission.INTERNET",
  ]);
  assert.deepEqual(
    inventory.modules.map((module) => ({
      name: module.name,
      configSource: module.configSource,
      permissionNames: module.permissionNames,
    })),
    [
      {
        name: "entry",
        configSource: "entry/src/main/module.json5",
        permissionNames: ["ohos.permission.CAMERA", "ohos.permission.INTERNET"],
      },
      {
        name: "feature",
        configSource: "feature/src/main/module.json5",
        permissionNames: ["ohos.permission.CAMERA"],
      },
    ],
  );
  assert.deepEqual(
    inventory.declarations.map((item) => ({
      moduleName: item.moduleName,
      name: item.name,
      reason: item.reason,
      usedScene: item.usedScene,
      source: item.source,
    })),
    [
      {
        moduleName: "entry",
        name: "ohos.permission.INTERNET",
        reason: "$string:internet_reason",
        usedScene: undefined,
        source: {
          uri: "entry/src/main/module.json5",
          logicalPath: "module.requestPermissions[0]",
        },
      },
      {
        moduleName: "entry",
        name: "ohos.permission.CAMERA",
        reason: "$string:camera_reason",
        usedScene: {
          abilities: ["EntryAbility"],
          when: "inuse",
        },
        source: {
          uri: "entry/src/main/module.json5",
          logicalPath: "module.requestPermissions[1]",
        },
      },
      {
        moduleName: "feature",
        name: "ohos.permission.CAMERA",
        reason: "$string:feature_camera_reason",
        usedScene: {
          abilities: ["FeatureAbility"],
          when: "always",
        },
        source: {
          uri: "feature/src/main/module.json5",
          logicalPath: "module.requestPermissions[0]",
        },
      },
    ],
  );
  assert.equal(
    hasDeclaredPermission(inventory, "entry", "ohos.permission.CAMERA"),
    true,
  );
  assert.equal(
    hasDeclaredPermission(inventory, "entry", "ohos.permission.NOT_REQUESTED"),
    false,
  );
  assert.ok(Object.isFrozen(inventory));
  assert.ok(Object.isFrozen(inventory.declarations[0]?.usedScene?.abilities));
});

test("非法权限声明返回脱敏领域错误而不是伪装成未声明权限", () => {
  assert.throws(
    () =>
      collectPermissionDeclarations(
        project([
          moduleSnapshot("entry", [
            {
              name: "SECRET-PERMISSION",
              usedScene: {
                abilities: ["EntryAbility"],
                when: "sometimes",
              },
            },
          ]),
        ]),
      ),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      assert.equal(error.details.path, "entry/src/main/module.json5");
      assert.equal(
        error.details.field,
        "module.requestPermissions[0].usedScene.when",
      );
      assert.doesNotMatch(
        JSON.stringify({ message: error.message, details: error.details }),
        /SECRET-PERMISSION|sometimes/u,
      );
      return true;
    },
  );
});
