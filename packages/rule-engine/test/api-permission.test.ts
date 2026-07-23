import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { type HashPort } from "@hcheck/core";
import type {
  ProjectSnapshot,
  ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import {
  apiPermissionDetector,
  detectApiPermissionConsistency,
  type RuleDefinition,
} from "../src/index.js";

const hash: HashPort = {
  async sha256(input: string | Uint8Array) {
    const { createHash } = await import("node:crypto");
    return `sha256:${createHash("sha256").update(input).digest("hex")}`;
  },
};

const rule: RuleDefinition = {
  id: "HOS-PERM-001",
  version: "1.0.0",
  status: "active",
  title: "使用受限 API 但未声明对应权限",
  summary: "源码中存在受权限保护的 API 调用，但应用模块配置未声明对应权限。",
  category: { technical: "permission", review: "user-privacy" },
  appliesWhen: "project.platform == harmonyos",
  inputs: ["project_snapshot", "source_ast"],
  detector: {
    type: "semantic",
    implementation: "permission.apiDeclarationConsistency",
    options: {
      mapping_source: "official-minimal-2026-07-11",
      extensions: [".ets", ".ts"],
      exclude_paths: [
        "node_modules/**",
        "**/node_modules/**",
        "oh_modules/**",
        "**/oh_modules/**",
        "build/**",
        "**/build/**",
      ],
      mappings: [
        {
          import_module: "@kit.LocationKit",
          import_name: "geoLocationManager",
          member: "getCurrentLocation",
          permission: "ohos.permission.APPROXIMATELY_LOCATION",
          source:
            "https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/js-apis-geolocationmanager-V5",
          verified_at: "2026-07-11",
        },
      ],
    },
  },
  severity: "BLOCKER",
  defaultConfidence: "PROBABLE",
  policyRefs: [
    {
      source: "Huawei geoLocationManager API",
      section: "geoLocationManager.getCurrentLocation",
      url: "https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/js-apis-geolocationmanager-V5",
      verifiedAt: "2026-07-11",
    },
    {
      source: "Huawei HarmonyOS 权限开发指南",
      section: "在配置文件中声明权限",
      url: "https://developer.huawei.com/consumer/cn/doc/HarmonyOS-Guides/declare-permissions",
      verifiedAt: "2026-07-11",
    },
  ],
  remediation: {
    summary:
      "根据实际业务需要在对应模块配置中声明权限；若业务不需要该能力，应移除调用。",
    verification: "hcheck scan . --rules HOS-PERM-001",
  },
  autofix: { level: "review_required" },
};

type Entry =
  | { readonly kind: "file"; readonly content: string; readonly size?: number }
  | { readonly kind: "directory" }
  | { readonly kind: "symlink"; readonly target?: string };

class MemoryFileSystem implements ReadonlyFileSystemPort {
  readonly #entries = new Map<string, Entry>();

  public constructor(
    files: Readonly<Record<string, string>>,
    private readonly flavor: typeof path.posix | typeof path.win32 = path.posix,
  ) {
    for (const [file, content] of Object.entries(files)) {
      const absolute = this.resolve(file);
      this.#entries.set(absolute, { kind: "file", content });
      this.addParents(absolute);
    }
  }

  public async readText(file: string): Promise<string> {
    const entry = this.#entries.get(this.resolve(file));
    if (entry?.kind !== "file") throw new Error(`SECRET:${file}`);
    return entry.content;
  }

  public async exists(candidate: string): Promise<boolean> {
    return this.#entries.has(this.resolve(candidate));
  }

  public async list(directory: string): Promise<readonly string[]> {
    const prefix = `${this.resolve(directory)}${this.flavor.sep}`;
    return [
      ...new Set(
        [...this.#entries.keys()]
          .filter((entry) => entry.startsWith(prefix))
          .map((entry) => entry.slice(prefix.length).split(this.flavor.sep)[0])
          .filter(
            (entry): entry is string => entry !== undefined && entry !== "",
          ),
      ),
    ];
  }

  public async kind(candidate: string): Promise<Entry["kind"] | "other"> {
    return this.#entries.get(this.resolve(candidate))?.kind ?? "other";
  }

  public async size(file: string): Promise<number> {
    const entry = this.#entries.get(this.resolve(file));
    if (entry?.kind !== "file") throw new Error(`SECRET:${file}`);
    return entry.size ?? new TextEncoder().encode(entry.content).byteLength;
  }

  public async realpath(candidate: string): Promise<string> {
    const absolute = this.resolve(candidate);
    const entry = this.#entries.get(absolute);
    if (entry?.kind === "symlink") {
      if (entry.target === undefined) throw new Error(`SECRET:${candidate}`);
      return this.resolve(entry.target);
    }
    if (entry === undefined) throw new Error(`SECRET:${candidate}`);
    return absolute;
  }

  public parent(candidate: string): string {
    return this.flavor.dirname(this.resolve(candidate));
  }

  public resolve(...parts: readonly string[]): string {
    return this.flavor.resolve(...parts);
  }

  private addParents(file: string): void {
    let directory = this.parent(file);
    while (true) {
      if (!this.#entries.has(directory))
        this.#entries.set(directory, { kind: "directory" });
      const parent = this.parent(directory);
      if (parent === directory) return;
      directory = parent;
    }
  }
}

function project(
  requestPermissions: ProjectSnapshot["modules"][number]["requestPermissions"],
): ProjectSnapshot {
  return {
    schemaVersion: "1.0.0",
    root: ".",
    platform: "harmonyos",
    appScope: "AppScope/app.json5",
    bundleName: "com.example.fixture",
    products: [],
    modules: [
      {
        name: "entry",
        type: "entry",
        root: "entry",
        relativePath: "entry",
        isExternal: false,
        moduleConfig: "entry/src/main/module.json5",
        sourceRoots: ["entry/src/main"],
        deviceTypes: ["phone"],
        abilities: [],
        extensionAbilities: [],
        requestPermissions,
        metadata: [],
        profileRefs: [],
        configSource: "entry/src/main/module.json5",
      },
    ],
    metadata: {},
    configSources: {
      appScope: "AppScope/app.json5",
      buildProfile: "build-profile.json5",
      modules: ["entry/src/main/module.json5"],
    },
  };
}

function files(root: string, source: string): Record<string, string> {
  return {
    [`${root}/entry/src/main/module.json5`]:
      "{ module: { name: 'entry', type: 'entry', deviceTypes: ['phone'] } }",
    [`${root}/entry/src/main/ets/Index.ets`]: source,
  };
}

async function detect(
  fs: ReadonlyFileSystemPort,
  workspaceRoot: string,
  snapshot = project([]),
) {
  return detectApiPermissionConsistency({
    project: snapshot,
    rule,
    fs,
    hash,
    workspaceRoot,
    globalExcludePaths: [],
  });
}

test("API 权限检测器发现已核验 API 调用但模块未声明权限", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(
    files(
      root,
      [
        "import { geoLocationManager } from '@kit.LocationKit';",
        "export async function locate() {",
        "  return geoLocationManager.getCurrentLocation();",
        "}",
      ].join("\n"),
    ),
  );

  const result = await detect(fs, root);

  assert.equal(
    apiPermissionDetector.implementation,
    rule.detector.implementation,
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.evidence.length, 1);
  assert.deepEqual(
    result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      applicability: finding.applicability,
      uri: finding.locations[0]?.uri,
      permission: finding.properties?.missingPermission,
    })),
    [
      {
        ruleId: "HOS-PERM-001",
        severity: "BLOCKER",
        confidence: "PROBABLE",
        applicability: "APPLICABLE",
        uri: "entry/src/main/ets/Index.ets",
        permission: "ohos.permission.APPROXIMATELY_LOCATION",
      },
    ],
  );
  assert.ok(result.evidence.every((item) => item.redacted));
  assert.doesNotMatch(
    JSON.stringify(result),
    /return geoLocationManager\.getCurrentLocation/u,
  );
});

test("API 权限检测器在模块已声明所需权限时不产生 Finding", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(
    files(
      root,
      [
        "import { geoLocationManager } from '@kit.LocationKit';",
        "geoLocationManager.getCurrentLocation();",
      ].join("\n"),
    ),
  );

  assert.deepEqual(
    await detect(
      fs,
      root,
      project([{ name: "ohos.permission.APPROXIMATELY_LOCATION" }]),
    ),
    { evidence: [], findings: [] },
  );
});

test("API 权限检测器忽略注释、字符串和非官方导入对象", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(
    files(
      root,
      [
        "// geoLocationManager.getCurrentLocation();",
        "const sample = 'geoLocationManager.getCurrentLocation()';",
        "const geoLocationManager = { getCurrentLocation() {} };",
        "geoLocationManager.getCurrentLocation();",
      ].join("\n"),
    ),
  );

  assert.deepEqual(await detect(fs, root), { evidence: [], findings: [] });
});
