import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { HCheckError } from "@hcheck/core";
import {
  collectDependencyManifest,
  collectPrivacyPolicyEvidence,
  collectProjectIdentity,
  createDependencyGraph,
  createBuildTargetModel,
  createProjectSnapshot,
  findProjectRoot,
  type ReadonlyFileSystemPort,
} from "../src/index.js";

type Entry =
  | { readonly kind: "file"; readonly content: string }
  | { readonly kind: "directory" };
type FailingOperation = "exists" | "kind" | "readText" | "realpath";

class MemoryFileSystem implements ReadonlyFileSystemPort {
  readonly #entries = new Map<string, Entry>();

  public constructor(
    files: Readonly<Record<string, string>>,
    private readonly flavor: typeof path.posix | typeof path.win32 = path.posix,
    private readonly failures: Readonly<
      Partial<Record<FailingOperation, readonly string[]>>
    > = {},
  ) {
    for (const [file, content] of Object.entries(files)) {
      const normalized = this.resolve(file);
      this.#entries.set(normalized, { kind: "file", content });
      let directory = this.parent(normalized);
      while (directory !== this.parent(directory)) {
        this.#entries.set(directory, { kind: "directory" });
        directory = this.parent(directory);
      }
      this.#entries.set(directory, { kind: "directory" });
    }
  }

  public async readText(file: string): Promise<string> {
    this.failIfConfigured("readText", file);
    const entry = this.#entries.get(this.resolve(file));
    if (entry?.kind !== "file") throw new Error("文件不存在");
    return entry.content;
  }

  public async exists(candidate: string): Promise<boolean> {
    this.failIfConfigured("exists", candidate);
    return this.#entries.has(this.resolve(candidate));
  }

  public async list(directory: string): Promise<readonly string[]> {
    const prefix = `${this.resolve(directory)}${this.flavor.sep}`;
    return [...this.#entries.keys()]
      .filter((entry) => entry.startsWith(prefix))
      .map((entry) => entry.slice(prefix.length).split(this.flavor.sep)[0])
      .filter(
        (entry, index, entries) =>
          entry !== undefined && entries.indexOf(entry) === index,
      ) as string[];
  }

  public async kind(
    candidate: string,
  ): Promise<"file" | "directory" | "symlink" | "other"> {
    this.failIfConfigured("kind", candidate);
    return this.#entries.get(this.resolve(candidate))?.kind ?? "other";
  }

  public async size(file: string): Promise<number> {
    return (await this.readText(file)).length;
  }

  public async realpath(candidate: string): Promise<string> {
    this.failIfConfigured("realpath", candidate);
    return this.resolve(candidate);
  }

  public parent(candidate: string): string {
    return this.flavor.dirname(this.resolve(candidate));
  }

  public resolve(...parts: readonly string[]): string {
    return this.flavor.resolve(...parts);
  }

  private failIfConfigured(
    operation: FailingOperation,
    candidate: string,
  ): void {
    const absolutePath = this.resolve(candidate);
    if (
      this.failures[operation]
        ?.map((value) => this.resolve(value))
        .includes(absolutePath)
    ) {
      if (operation === "realpath") {
        throw new HCheckError(
          "INTERNAL_ERROR",
          `EACCES secret-token ${absolutePath}`,
          { path: absolutePath },
        );
      }
      throw new Error(`EACCES secret-token ${absolutePath}`);
    }
  }
}

const APP = `\ufeff{
  app: {
    bundleName: 'com.example.鸿鉴',
    bundleType: 'app',
    versionCode: 1000000,
    versionName: '1.0.0',
    apiReleaseType: 'Release1',
    minCompatibleVersionCode: 900000,
    apiKey: '不应进入快照',
  },
}`;

const BUILD = `{
  // JSON5 注释、尾逗号与未引号键必须被成熟解析器接受。
  app: {
    products: [{
      name: 'default',
      signingConfig: 'release',
      compatibleSdkVersion: '5.0.0(12)',
      targetSdkVersion: 12,
      compileSdkVersion: '5.0.0(12)',
      runtimeOS: 'HarmonyOS',
      bundleType: 'app',
      versionCode: 1000001,
      versionName: '1.0.1-stage',
    }],
    signingConfigs: [{ name: 'release', storePassword: '绝密口令' }],
  },
  modules: [{ name: 'entry', srcPath: './entry', },],
}`;

const MODULE = `{
  module: {
    name: 'first',
    name: 'entry',
    type: 'entry',
    deviceTypes: ['phone', '2in1'],
    pages: '$profile:main_pages',
    abilities: [{ name: 'EntryAbility', srcEntry: './ets/entryability/EntryAbility.ets' }],
    extensionAbilities: [{ name: 'ShareExtAbility', type: 'share' }],
    requestPermissions: [{ name: 'ohos.permission.INTERNET', reason: '$string:reason' }],
    metadata: [{ name: 'client_id', value: '公开元数据' }, { name: 'route', resource: '$profile:route_map' }],
  },
}`;

function projectFiles(root = "/工作区/中文 项目"): Record<string, string> {
  return {
    [`${root}/AppScope/app.json5`]: APP,
    [`${root}/build-profile.json5`]: BUILD,
    [`${root}/entry/src/main/module.json5`]: MODULE,
  };
}

function expectHCheckError(
  code: HCheckError["code"],
  forbidden?: string,
): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof HCheckError);
    assert.equal(error.code, code);
    if (forbidden !== undefined)
      assert.doesNotMatch(error.message, new RegExp(forbidden, "u"));
    return true;
  };
}

test("从工程子目录向上找到最近的合法根", async () => {
  const files = {
    ...projectFiles("/repo"),
    ...projectFiles("/repo/examples/nested"),
  };
  const fs = new MemoryFileSystem(files);

  assert.equal(
    await findProjectRoot("/repo/examples/nested/entry/src/main", fs),
    "/repo/examples/nested",
  );
});

test("跳过损坏的内层候选并返回最近的合法外层根", async () => {
  const files = projectFiles("/repo");
  files["/repo/examples/nested/AppScope/app.json5"] = APP;
  files["/repo/examples/nested/build-profile.json5"] = "{ modules: [] }";

  assert.equal(
    await findProjectRoot(
      "/repo/examples/nested/src",
      new MemoryFileSystem(files),
    ),
    "/repo",
  );
});

test("缺失必需文件、空 modules 和损坏 modules 均不构成合法工程根", async () => {
  const invalidRoots = [
    new MemoryFileSystem({ "/repo/AppScope/app.json5": APP }),
    new MemoryFileSystem({
      "/repo/AppScope/app.json5": APP,
      "/repo/build-profile.json5": "{ modules: [] }",
    }),
    new MemoryFileSystem({
      "/repo/AppScope/app.json5": APP,
      "/repo/build-profile.json5": "{ modules: [ } 原始秘密",
    }),
  ];

  for (const fs of invalidRoots) {
    await assert.rejects(
      findProjectRoot("/repo/entry", fs),
      expectHCheckError("UNSUPPORTED_PROJECT", "原始秘密"),
    );
  }
});

test("未找到工程根时不在错误中泄露起始绝对路径", async () => {
  const startPath = "/Users/secret-user/private-project/src";

  await assert.rejects(
    findProjectRoot(startPath, new MemoryFileSystem({})),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      const visibleError = JSON.stringify({
        message: error.message,
        details: error.details,
      });
      assert.doesNotMatch(
        visibleError,
        /Users|secret-user|private-project|\/src/u,
      );
      return true;
    },
  );
});

test("根发现期间的端口异常转换为不泄露起始绝对路径的领域错误", async () => {
  const root = "/用户/根发现秘密";
  const fs = new MemoryFileSystem(projectFiles(root), path.posix, {
    exists: [`${root}/entry`],
  });

  await assert.rejects(
    findProjectRoot(`${root}/entry`, fs),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      const visibleError = JSON.stringify({
        message: error.message,
        details: error.details,
      });
      assert.doesNotMatch(
        visibleError,
        /EACCES|secret-token|\/用户\/根发现秘密/u,
      );
      return true;
    },
  );
});

test("快照按固定配置链读取 JSON5，并保留扫描需要的字段", async () => {
  const root = "/工作区/中文 项目";
  const snapshot = await createProjectSnapshot(
    root,
    new MemoryFileSystem(projectFiles(root)),
  );

  assert.deepEqual(snapshot, {
    schemaVersion: "1.0.0",
    root: ".",
    platform: "harmonyos",
    appScope: "AppScope/app.json5",
    bundleName: "com.example.鸿鉴",
    bundleType: "app",
    versionCode: 1000000,
    versionName: "1.0.0",
    apiReleaseType: "Release1",
    minCompatibleVersionCode: 900000,
    products: [
      {
        name: "default",
        signingConfig: "release",
        compatibleSdkVersion: "5.0.0(12)",
        targetSdkVersion: 12,
        compileSdkVersion: "5.0.0(12)",
        runtimeOS: "HarmonyOS",
        bundleType: "app",
        versionCode: 1000001,
        versionName: "1.0.1-stage",
      },
    ],
    modules: [
      {
        name: "entry",
        type: "entry",
        root: "entry",
        relativePath: "entry",
        isExternal: false,
        moduleConfig: "entry/src/main/module.json5",
        sourceRoots: ["entry/src/main"],
        deviceTypes: ["phone", "2in1"],
        abilities: [
          {
            name: "EntryAbility",
            srcEntry: "./ets/entryability/EntryAbility.ets",
          },
        ],
        extensionAbilities: [{ name: "ShareExtAbility", type: "share" }],
        requestPermissions: [
          { name: "ohos.permission.INTERNET", reason: "$string:reason" },
        ],
        metadata: [
          { name: "client_id", value: "公开元数据" },
          { name: "route", resource: "$profile:route_map" },
        ],
        profileRefs: ["$profile:main_pages", "$profile:route_map"],
        configSource: "entry/src/main/module.json5",
      },
    ],
    minimumApi: "5.0.0(12)",
    metadata: {},
    configSources: {
      appScope: "AppScope/app.json5",
      buildProfile: "build-profile.json5",
      modules: ["entry/src/main/module.json5"],
    },
  });

  assert.doesNotMatch(
    JSON.stringify(snapshot),
    /绝密口令|storePassword|apiKey/u,
  );
});

test("工程身份汇总稳定表达 app、product 和 module 的 Bundle/版本边界", async () => {
  const root = "/workspace/identity";
  const snapshot = await createProjectSnapshot(
    root,
    new MemoryFileSystem(projectFiles(root)),
  );

  assert.deepEqual(collectProjectIdentity(snapshot), {
    bundleName: "com.example.鸿鉴",
    bundleType: "app",
    versionCode: 1000000,
    versionName: "1.0.0",
    apiReleaseType: "Release1",
    minCompatibleVersionCode: 900000,
    source: {
      appScope: "AppScope/app.json5",
      buildProfile: "build-profile.json5",
    },
    products: [
      {
        name: "default",
        signingConfig: "release",
        runtimeOS: "HarmonyOS",
        bundleType: "app",
        versionCode: 1000001,
        versionName: "1.0.1-stage",
        effectiveBundleType: "app",
        effectiveVersionCode: 1000001,
        effectiveVersionName: "1.0.1-stage",
        compatibleSdkVersion: "5.0.0(12)",
        targetSdkVersion: 12,
        compileSdkVersion: "5.0.0(12)",
      },
    ],
    modules: [
      {
        name: "entry",
        type: "entry",
        root: "entry",
        configSource: "entry/src/main/module.json5",
        isExternal: false,
      },
    ],
  });
});

test("构建目标模型汇总 build profile、API 和设备目标且拒绝缺失 API 配置", async () => {
  const snapshot = await createProjectSnapshot(
    "/repo",
    new MemoryFileSystem(projectFiles("/repo")),
  );

  assert.deepEqual(
    createBuildTargetModel(snapshot, {
      build: {
        profile: "release",
        clean: true,
        command: "./hvigorw assembleApp",
        artifact: {
          include: ["**/*.app", "**/*.hap"],
          exclude: ["**/debug/**"],
        },
      },
      minimumApi: 12,
      runtimeDevice: "local",
    }),
    {
      schemaVersion: "1.0.0",
      profile: "release",
      clean: true,
      command: "./hvigorw assembleApp",
      artifact: {
        include: ["**/*.app", "**/*.hap"],
        exclude: ["**/debug/**"],
      },
      api: {
        minimum: 12,
        source: "config",
        products: [
          {
            name: "default",
            compatibleSdkVersion: "5.0.0(12)",
            targetSdkVersion: 12,
            compileSdkVersion: "5.0.0(12)",
          },
        ],
      },
      devices: ["2in1", "phone"],
      runtimeDevice: "local",
      modules: [
        {
          name: "entry",
          type: "entry",
          deviceTypes: ["2in1", "phone"],
        },
      ],
      completeness: "COMPLETE",
      issues: [],
    },
  );

  assert.throws(
    () =>
      createBuildTargetModel(snapshot, {
        build: {
          profile: "release",
          clean: true,
          command: "./hvigorw assembleApp",
          artifact: { include: ["**/*.app"], exclude: [] },
        },
        runtimeDevice: "local",
      }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "CONFIGURATION_ERROR");
      assert.match(error.message, /project.minimum_api/u);
      return true;
    },
  );
});

test("依赖清单从 oh-package 与 lockfile 表达直接和间接依赖且不泄露本机路径", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem({
    ...projectFiles(root),
    [`${root}/oh-package.json5`]: `{
      dependencies: {
        '@vendor/analytics': '1.2.3',
        '@local/private': 'file:../private-sdk',
      },
      devDependencies: {
        '@tool/linter': '2.0.0',
      },
    }`,
    [`${root}/oh-package-lock.json5`]: `{
      packages: {
        '@vendor/analytics@1.2.3': {
          version: '1.2.3',
          dependencies: { '@vendor/core': '3.0.0' },
        },
        '@vendor/core@3.0.0': { version: '3.0.0' },
      },
    }`,
  });

  const manifest = await collectDependencyManifest(root, fs);

  assert.equal(manifest.completeness, "COMPLETE");
  assert.deepEqual(manifest.directDependencies, [
    {
      name: "@local/private",
      specifier: "file:[REDACTED_LOCAL_PATH]",
      scope: "runtime",
      source: "oh-package.json5",
      local: true,
    },
    {
      name: "@tool/linter",
      specifier: "2.0.0",
      scope: "development",
      source: "oh-package.json5",
      local: false,
    },
    {
      name: "@vendor/analytics",
      specifier: "1.2.3",
      scope: "runtime",
      source: "oh-package.json5",
      local: false,
    },
  ]);
  assert.deepEqual(manifest.lockfilePackages, [
    {
      name: "@vendor/analytics",
      version: "1.2.3",
      direct: true,
      dependencies: ["@vendor/core@3.0.0"],
    },
    {
      name: "@vendor/core",
      version: "3.0.0",
      direct: false,
      dependencies: [],
    },
  ]);
  assert.ok(!JSON.stringify(manifest).includes(root));
  assert.ok(!JSON.stringify(manifest).includes("../private-sdk"));
});

test("依赖图输出 SDK 候选、依赖路径、稳定指纹并处理循环依赖", async () => {
  const manifest = await collectDependencyManifest(
    "/repo",
    new MemoryFileSystem({
      ...projectFiles("/repo"),
      ["/repo/oh-package.json5"]: `{
        dependencies: {
          '@mock/analytics-sdk': '1.0.0',
        },
      }`,
      ["/repo/oh-package-lock.json5"]: `{
        packages: {
          '@mock/analytics-sdk@1.0.0': {
            version: '1.0.0',
            dependencies: { '@mock/sdk-core': '2.0.0' },
          },
          '@mock/sdk-core@2.0.0': {
            version: '2.0.0',
            dependencies: { '@mock/analytics-sdk': '1.0.0' },
          },
        },
      }`,
    }),
  );

  const graph = createDependencyGraph(manifest);

  assert.equal(graph.completeness, "COMPLETE");
  assert.deepEqual(
    graph.nodes.map(({ id, direct, dependencies, paths }) => ({
      id,
      direct,
      dependencies,
      paths,
    })),
    [
      {
        id: "@mock/analytics-sdk@1.0.0",
        direct: true,
        dependencies: ["@mock/sdk-core@2.0.0"],
        paths: [["@mock/analytics-sdk@1.0.0"]],
      },
      {
        id: "@mock/sdk-core@2.0.0",
        direct: false,
        dependencies: ["@mock/analytics-sdk@1.0.0"],
        paths: [["@mock/analytics-sdk@1.0.0", "@mock/sdk-core@2.0.0"]],
      },
    ],
  );
  assert.deepEqual(graph.sdkCandidates, [
    {
      id: "@mock/analytics-sdk@1.0.0",
      name: "@mock/analytics-sdk",
      version: "1.0.0",
      confidence: "PROBABLE",
      source: "oh-package-lock.json5",
      dependencyPath: ["@mock/analytics-sdk@1.0.0"],
      fingerprint: "sdk:@mock/analytics-sdk@1.0.0",
      disclosureNames: ["@mock/analytics-sdk", "analytics sdk"],
    },
    {
      id: "@mock/sdk-core@2.0.0",
      name: "@mock/sdk-core",
      version: "2.0.0",
      confidence: "POSSIBLE",
      source: "oh-package-lock.json5",
      dependencyPath: ["@mock/analytics-sdk@1.0.0", "@mock/sdk-core@2.0.0"],
      fingerprint: "sdk:@mock/sdk-core@2.0.0",
      disclosureNames: ["@mock/sdk-core", "sdk core"],
    },
  ]);
  assert.ok(!JSON.stringify(graph).includes("/repo"));
});

test("缺失 lockfile 时依赖图保留直接 SDK 候选但标记证据不完整", async () => {
  const manifest = await collectDependencyManifest(
    "/repo",
    new MemoryFileSystem({
      ...projectFiles("/repo"),
      ["/repo/oh-package.json5"]: `{
        dependencies: { '@mock/analytics-sdk': '1.0.0' },
      }`,
    }),
  );

  const graph = createDependencyGraph(manifest);

  assert.equal(graph.completeness, "INCOMPLETE");
  assert.match(graph.issues.join("\n"), /oh-package-lock\.json5/u);
  assert.deepEqual(graph.sdkCandidates, [
    {
      id: "@mock/analytics-sdk@1.0.0",
      name: "@mock/analytics-sdk",
      version: "1.0.0",
      confidence: "PROBABLE",
      source: "oh-package.json5",
      dependencyPath: ["@mock/analytics-sdk@1.0.0"],
      fingerprint: "sdk:@mock/analytics-sdk@1.0.0",
      disclosureNames: ["@mock/analytics-sdk", "analytics sdk"],
    },
  ]);
});

test("隐私政策证据收集区分本地披露、缺失、离线链接和超大文件且不泄露绝对路径", async () => {
  const root = "/secret/repo";
  const fs = new MemoryFileSystem({
    ...projectFiles(root),
    [`${root}/docs/privacy-policy.md`]:
      "本应用使用 @mock/analytics-sdk 用于匿名崩溃分析。",
    [`${root}/docs/large-privacy.md`]: "x".repeat(33),
  });

  const evidence = await collectPrivacyPolicyEvidence(root, fs, {
    policyFiles: ["docs/privacy-policy.md"],
    policyUrls: ["https://example.invalid/privacy"],
    offline: true,
    maxBytes: 128,
    expectedDisclosures: ["@mock/analytics-sdk", "@mock/missing-sdk"],
  });

  assert.equal(evidence.completeness, "INCOMPLETE");
  assert.deepEqual(evidence.files, [
    {
      path: "docs/privacy-policy.md",
      sizeBytes: 63,
      disclosedSdkNames: ["@mock/analytics-sdk"],
    },
  ]);
  assert.match(evidence.issues.join("\n"), /离线|链接/u);
  assert.ok(!JSON.stringify(evidence).includes(root));

  const missingAndLarge = await collectPrivacyPolicyEvidence(root, fs, {
    policyFiles: ["docs/missing.md", "docs/large-privacy.md"],
    maxBytes: 32,
    expectedDisclosures: ["@mock/analytics-sdk"],
  });
  assert.equal(missingAndLarge.completeness, "INCOMPLETE");
  assert.match(missingAndLarge.issues.join("\n"), /缺少|超过大小限制/u);
  assert.deepEqual(missingAndLarge.files, []);
  assert.ok(!JSON.stringify(missingAndLarge).includes(root));
});

test("支持所有 P0 模块类型", async () => {
  for (const moduleType of [
    "entry",
    "feature",
    "har",
    "shared",
    "skill",
  ] as const) {
    const files = projectFiles("/repo");
    files["/repo/entry/src/main/module.json5"] = MODULE.replace(
      "type: 'entry'",
      `type: '${moduleType}'`,
    );
    const snapshot = await createProjectSnapshot(
      "/repo",
      new MemoryFileSystem(files),
    );
    assert.equal(snapshot.modules[0]?.type, moduleType);
  }
});

test("工程声明名和 module.name 不一致时拒绝快照", async () => {
  const files = projectFiles("/repo");
  files["/repo/build-profile.json5"] = BUILD.replace(
    "name: 'entry'",
    "name: '声明秘密'",
  );
  files["/repo/entry/src/main/module.json5"] = MODULE.replace(
    "name: 'entry'",
    "name: '模块秘密'",
  );

  await assert.rejects(
    createProjectSnapshot("/repo", new MemoryFileSystem(files)),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      assert.doesNotMatch(error.message, /声明秘密|模块秘密/u);
      assert.match(
        error.message,
        /module\.name|entry\/src\/main\/module\.json5/u,
      );
      return true;
    },
  );
});

test("非法 module.type 不回显不可信原值", async () => {
  const files = projectFiles("/repo");
  files["/repo/entry/src/main/module.json5"] = MODULE.replace(
    "type: 'entry'",
    "type: '恶意类型秘密'",
  );

  await assert.rejects(
    createProjectSnapshot("/repo", new MemoryFileSystem(files)),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      assert.doesNotMatch(error.message, /恶意类型秘密/u);
      assert.match(
        error.message,
        /module\.type|entry\/src\/main\/module\.json5/u,
      );
      return true;
    },
  );
});

test("模块文件系统端口异常统一转为不泄露绝对路径的领域错误", async () => {
  const root = "/用户/绝密项目";
  const files = projectFiles(root);
  const targets: Readonly<Record<FailingOperation, string>> = {
    exists: `${root}/entry/src/main/module.json5`,
    kind: `${root}/entry/src/main/module.json5`,
    readText: `${root}/entry/src/main/module.json5`,
    realpath: `${root}/entry`,
  };

  for (const operation of Object.keys(targets) as FailingOperation[]) {
    const fs = new MemoryFileSystem(files, path.posix, {
      [operation]: [targets[operation]],
    });
    await assert.rejects(createProjectSnapshot(root, fs), (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      const visibleError = JSON.stringify({
        message: error.message,
        details: error.details,
      });
      assert.doesNotMatch(
        visibleError,
        /EACCES|secret-token|\/用户\/绝密项目/u,
      );
      assert.match(visibleError, /entry\/src\/main\/module\.json5/u);
      return true;
    });
  }
});

test("缺失模块配置返回仅含相对配置路径的领域错误", async () => {
  const root = "/用户/绝密项目";
  const files = projectFiles(root);
  delete files[`${root}/entry/src/main/module.json5`];

  await assert.rejects(
    createProjectSnapshot(root, new MemoryFileSystem(files)),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "UNSUPPORTED_PROJECT");
      const visibleError = JSON.stringify({
        message: error.message,
        details: error.details,
      });
      assert.doesNotMatch(visibleError, /\/用户\/绝密项目/u);
      assert.match(visibleError, /entry\/src\/main\/module\.json5/u);
      return true;
    },
  );
});

test("外部模块被明确标记而不伪装为已完整扫描", async () => {
  const files = projectFiles("/repo/app");
  files["/repo/app/build-profile.json5"] = BUILD.replace(
    "./entry",
    "../shared feature",
  ).replace("name: 'entry'", "name: 'shared'");
  delete files["/repo/app/entry/src/main/module.json5"];
  files["/repo/shared feature/src/main/module.json5"] = MODULE.replace(
    "name: 'entry'",
    "name: 'shared'",
  ).replace("type: 'entry'", "type: 'shared'");

  const snapshot = await createProjectSnapshot(
    "/repo/app",
    new MemoryFileSystem(files),
  );
  assert.equal(snapshot.modules[0]?.isExternal, true);
  assert.equal(snapshot.modules[0]?.relativePath, "../shared feature");
  assert.equal(snapshot.modules[0]?.root, "../shared feature");
});

test("POSIX 绝对外部模块使用稳定占位路径且快照不泄露绝对路径", async () => {
  const root = "/Users/secret-user/private-app";
  const externalRoot = "/Users/secret-user/private-modules/shared";
  const files = projectFiles(root);
  files[`${root}/build-profile.json5`] = BUILD.replace(
    "./entry",
    externalRoot,
  ).replace("name: 'entry'", "name: 'shared'");
  delete files[`${root}/entry/src/main/module.json5`];
  files[`${externalRoot}/src/main/module.json5`] = MODULE.replace(
    "name: 'entry'",
    "name: 'shared'",
  ).replace("type: 'entry'", "type: 'shared'");

  const snapshot = await createProjectSnapshot(
    root,
    new MemoryFileSystem(files),
  );

  assert.equal(snapshot.root, ".");
  assert.deepEqual(
    {
      root: snapshot.modules[0]?.root,
      relativePath: snapshot.modules[0]?.relativePath,
      moduleConfig: snapshot.modules[0]?.moduleConfig,
      sourceRoots: snapshot.modules[0]?.sourceRoots,
      configSource: snapshot.modules[0]?.configSource,
      configSources: snapshot.configSources.modules,
    },
    {
      root: "@external/module-1",
      relativePath: "@external/module-1",
      moduleConfig: "@external/module-1/src/main/module.json5",
      sourceRoots: ["@external/module-1/src/main"],
      configSource: "@external/module-1/src/main/module.json5",
      configSources: ["@external/module-1/src/main/module.json5"],
    },
  );
  assert.doesNotMatch(
    JSON.stringify(snapshot),
    /Users|secret-user|private-app|private-modules/u,
  );
});

test("双模块按声明顺序生成稳定的内部与外部模块快照", async () => {
  const root = "/repo/app";
  const files = projectFiles(root);
  files[`${root}/build-profile.json5`] = BUILD.replace(
    "modules: [{ name: 'entry', srcPath: './entry', },]",
    "modules: [{ name: 'entry', srcPath: './entry' }, { name: 'shared', srcPath: '../shared' }]",
  );
  files["/repo/shared/src/main/module.json5"] = MODULE.replace(
    "name: 'entry'",
    "name: 'shared'",
  ).replace("type: 'entry'", "type: 'shared'");
  const fs = new MemoryFileSystem(files);

  const first = await createProjectSnapshot(root, fs);
  const second = await createProjectSnapshot(root, fs);

  assert.deepEqual(first, second);
  assert.deepEqual(
    first.modules.map((module) => ({
      name: module.name,
      relativePath: module.relativePath,
      isExternal: module.isExternal,
    })),
    [
      { name: "entry", relativePath: "entry", isExternal: false },
      { name: "shared", relativePath: "../shared", isExternal: true },
    ],
  );
  assert.deepEqual(first.configSources.modules, [
    "entry/src/main/module.json5",
    "../shared/src/main/module.json5",
  ]);
});

test("损坏 JSON5 返回脱敏的解析错误并保留行列", async () => {
  const files = projectFiles("/repo");
  files["/repo/entry/src/main/module.json5"] =
    "{\n module: { password: '不应泄露', name: ]\n}";

  await assert.rejects(
    createProjectSnapshot("/repo", new MemoryFileSystem(files)),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.doesNotMatch(error.message, /不应泄露|password/u);
      assert.equal(error.details.path, "entry/src/main/module.json5");
      assert.equal(error.details.line, 2);
      assert.equal(typeof error.details.column, "number");
      return true;
    },
  );
});

test("AppScope 和 build-profile 的解析错误同样不回显原文", async () => {
  for (const relativePath of [
    "AppScope/app.json5",
    "build-profile.json5",
  ] as const) {
    const files = projectFiles("/repo");
    files[`/repo/${relativePath}`] = "{\n password: '不应泄露', broken: ]\n}";
    await assert.rejects(
      createProjectSnapshot("/repo", new MemoryFileSystem(files)),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.equal(error.details.path, relativePath);
        assert.doesNotMatch(error.message, /不应泄露|password/u);
        return true;
      },
    );
  }
});

test("Windows 分隔符按路径段判断边界，不把同前缀目录误判为内部模块", async () => {
  const root = "C:\\repo\\app";
  const files = projectFiles(root);
  files[`${root}\\build-profile.json5`] = BUILD.replace(
    "./entry",
    "../application-shared",
  ).replace("name: 'entry'", "name: 'shared'");
  delete files[`${root}/entry/src/main/module.json5`];
  files["C:\\repo\\application-shared\\src\\main\\module.json5"] =
    MODULE.replace("name: 'entry'", "name: 'shared'").replace(
      "type: 'entry'",
      "type: 'shared'",
    );
  const fs = new MemoryFileSystem(files, path.win32);

  assert.equal(await findProjectRoot("C:\\repo\\app\\entry\\src", fs), root);
  const snapshot = await createProjectSnapshot(root, fs);
  assert.equal(snapshot.modules[0]?.isExternal, true);
  assert.equal(
    snapshot.modules[0]?.moduleConfig,
    "../application-shared/src/main/module.json5",
  );
});

test("Windows UNC 绝对外部模块按真实路径读取但快照只输出稳定占位路径", async () => {
  const root = "C:\\repo\\app";
  const externalRoot = "\\\\server\\share\\私密用户\\shared";
  const files = projectFiles(root);
  files[`${root}\\build-profile.json5`] = BUILD.replace(
    "./entry",
    externalRoot.replaceAll("\\", "\\\\"),
  ).replace("name: 'entry'", "name: 'shared'");
  delete files[`${root}/entry/src/main/module.json5`];
  files[`${externalRoot}\\src\\main\\module.json5`] = MODULE.replace(
    "name: 'entry'",
    "name: 'shared'",
  ).replace("type: 'entry'", "type: 'shared'");

  const snapshot = await createProjectSnapshot(
    root,
    new MemoryFileSystem(files, path.win32),
  );

  assert.equal(snapshot.modules[0]?.isExternal, true);
  assert.equal(snapshot.modules[0]?.relativePath, "@external/module-1");
  assert.equal(
    snapshot.modules[0]?.moduleConfig,
    "@external/module-1/src/main/module.json5",
  );
  assert.equal(snapshot.root, ".");
  assert.doesNotMatch(
    JSON.stringify(snapshot),
    /server|私密用户|C:|\\\\server/u,
  );
});

test("Windows 当前盘根外部模块可读取且快照不泄露根路径", async () => {
  const root = "C:\\repo\\app";
  const rootRelativePath = "\\private-user\\shared";
  const files = projectFiles(root);
  files[`${root}\\build-profile.json5`] = BUILD.replace(
    "./entry",
    rootRelativePath.replaceAll("\\", "\\\\"),
  );
  files["C:\\private-user\\shared\\src\\main\\module.json5"] = MODULE;

  const snapshot = await createProjectSnapshot(
    root,
    new MemoryFileSystem(files, path.win32),
  );

  assert.equal(snapshot.modules[0]?.isExternal, true);
  assert.equal(snapshot.modules[0]?.relativePath, "@external/module-1");
  assert.equal(
    snapshot.modules[0]?.moduleConfig,
    "@external/module-1/src/main/module.json5",
  );
  assert.deepEqual(snapshot.modules[0]?.sourceRoots, [
    "@external/module-1/src/main",
  ]);
  assert.deepEqual(snapshot.configSources.modules, [
    "@external/module-1/src/main/module.json5",
  ]);
  assert.doesNotMatch(JSON.stringify(snapshot), /private-user|shared/u);
});

test("Windows 普通反斜杠相对模块仍输出工程相对路径", async () => {
  const root = "C:\\repo\\app";
  const relativePath = "feature\\module";
  const files = projectFiles(root);
  files[`${root}\\build-profile.json5`] = BUILD.replace(
    "./entry",
    relativePath.replaceAll("\\", "\\\\"),
  );
  files[`${root}\\feature\\module\\src\\main\\module.json5`] = MODULE;

  const snapshot = await createProjectSnapshot(
    root,
    new MemoryFileSystem(files, path.win32),
  );

  assert.equal(snapshot.modules[0]?.isExternal, false);
  assert.equal(snapshot.modules[0]?.relativePath, "feature/module");
  assert.equal(
    snapshot.modules[0]?.moduleConfig,
    "feature/module/src/main/module.json5",
  );
});
