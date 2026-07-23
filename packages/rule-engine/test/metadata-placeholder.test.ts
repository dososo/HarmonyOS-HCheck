import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { HCheckError, type HashPort } from "@hcheck/core";
import {
  createProjectSnapshot,
  type ProjectSnapshot,
  type ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import {
  DetectorRegistry,
  executeRules,
  metadataPlaceholderDetector,
  testEndpointDetector,
  type RuleDefinition,
} from "../src/index.js";
import {
  detectMetadataPlaceholder,
  METADATA_PLACEHOLDER_LIMITS,
  type MetadataPlaceholderLimits,
} from "../src/detectors/metadata-placeholder.js";
import { detectTestEndpoint } from "../src/detectors/test-endpoint.js";

const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const MARKER = "HCHECK_PLACEHOLDER";
const hash: HashPort = {
  async sha256(content) {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  },
};

const nodeFs: ReadonlyFileSystemPort = {
  readText: (file) => readFile(file, "utf8"),
  exists: async (candidate) =>
    lstat(candidate).then(
      () => true,
      () => false,
    ),
  list: (directory) => readdir(directory),
  kind: async (candidate) => {
    const value = await lstat(candidate);
    if (value.isSymbolicLink()) return "symlink";
    if (value.isFile()) return "file";
    if (value.isDirectory()) return "directory";
    return "other";
  },
  size: async (file) => (await stat(file)).size,
  realpath,
  parent: path.dirname,
  resolve: path.resolve,
};

const rule: RuleDefinition = {
  id: "HOS-META-003",
  version: "1.0.0",
  status: "active",
  title: "发布内容包含占位标记",
  summary: "可发布源码或配置中发现精确占位标记。",
  category: { technical: "metadata", review: "app-information" },
  appliesWhen: "project.platform == harmonyos",
  inputs: ["project_snapshot", "source_text"],
  detector: {
    type: "structural",
    implementation: "metadata.placeholderContent",
    options: {
      marker: MARKER,
      extensions: [".ets", ".ts", ".json5"],
      exclude_paths: [
        "node_modules/**",
        "**/node_modules/**",
        "oh_modules/**",
        "**/oh_modules/**",
        "build/**",
        "**/build/**",
      ],
    },
  },
  severity: "HIGH",
  defaultConfidence: "PROBABLE",
  policyRefs: [
    {
      source: "Huawei 应用审核 Checklist",
      section: "应用信息与应用功能",
      url: "https://example.invalid/checklist",
      verifiedAt: "2026-07-10",
    },
  ],
  remediation: { summary: "删除占位标记。", verification: "重新扫描。" },
  autofix: { level: "review_required" },
};

const testEndpointRule: RuleDefinition = {
  id: "HOS-PKG-007",
  version: "1.0.0",
  status: "active",
  title: "可发布内容包含本地测试地址",
  summary: "源码或配置字符串中发现本地环回测试地址。",
  category: { technical: "package", review: "app-information" },
  appliesWhen: "project.platform == harmonyos",
  inputs: ["project_snapshot", "source_text"],
  detector: {
    type: "structural",
    implementation: "package.testEndpoint",
    options: {
      schemes: ["http", "https"],
      blocked_hosts: ["localhost", "127.0.0.1", "0.0.0.0", "[::1]"],
      extensions: [".ets", ".ts", ".json5"],
      exclude_paths: [
        "node_modules/**",
        "**/node_modules/**",
        "oh_modules/**",
        "**/oh_modules/**",
        "build/**",
        "**/build/**",
      ],
    },
  },
  severity: "HIGH",
  defaultConfidence: "PROBABLE",
  policyRefs: [
    {
      source: "Huawei 应用审核指南",
      section: "常见审核不通过原因",
      url: "https://developer.huawei.com/consumer/cn/doc/App/50104",
      verifiedAt: "2026-07-11",
    },
  ],
  remediation: {
    summary: "将可发布源码和配置中的本地测试地址替换为正式服务地址。",
    verification: "hcheck scan . --rules HOS-PKG-007",
  },
  autofix: { level: "review_required" },
};

function project(sourceRoot = "entry/src/main"): ProjectSnapshot {
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
        sourceRoots: [sourceRoot],
        deviceTypes: ["phone"],
        abilities: [],
        extensionAbilities: [],
        requestPermissions: [],
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

  public set(candidate: string, entry: Entry): void {
    const absolute = this.resolve(candidate);
    this.#entries.set(absolute, entry);
    this.addParents(absolute);
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
  snapshot = project(),
  selectedRule = rule,
  globalExcludePaths: readonly string[] = [],
  limits: MetadataPlaceholderLimits = METADATA_PLACEHOLDER_LIMITS,
) {
  return detectMetadataPlaceholder(
    {
      project: snapshot,
      rule: selectedRule,
      fs,
      hash,
      workspaceRoot,
      globalExcludePaths,
    },
    limits,
  );
}

function expectIncomplete(error: unknown): boolean {
  assert.ok(error instanceof HCheckError);
  assert.equal(error.code, "EVIDENCE_INCOMPLETE");
  assert.equal(error.message, "源码证据采集不完整。");
  assert.doesNotMatch(JSON.stringify(error), /SECRET|Users|中文 工程/u);
  return true;
}

function expectBudgetExceeded(error: unknown): boolean {
  assert.ok(error instanceof HCheckError);
  assert.equal(error.code, "EVIDENCE_INCOMPLETE");
  assert.equal(error.message, "源码证据采集不完整。");
  assert.equal(error.details.reason, "resource_budget");
  assert.doesNotMatch(JSON.stringify(error), /SECRET|Users|中文 工程/u);
  return true;
}

async function detectEndpoint(
  fs: ReadonlyFileSystemPort,
  workspaceRoot: string,
  snapshot = project(),
  selectedRule = testEndpointRule,
  globalExcludePaths: readonly string[] = [],
) {
  return detectTestEndpoint({
    project: snapshot,
    rule: selectedRule,
    fs,
    hash,
    workspaceRoot,
    globalExcludePaths,
  });
}

test("同构结构 Fixture：正向仅命中一个，干净样例零命中", async () => {
  const positiveRoot = path.join(
    REPOSITORY_ROOT,
    "fixtures/placeholder-metadata",
  );
  const cleanRoot = path.join(REPOSITORY_ROOT, "fixtures/clean-stage-app");
  const positive = await detect(
    nodeFs,
    positiveRoot,
    await createProjectSnapshot(positiveRoot, nodeFs),
  );
  const clean = await detect(
    nodeFs,
    cleanRoot,
    await createProjectSnapshot(cleanRoot, nodeFs),
  );

  assert.equal(positive.findings.length, 1);
  assert.equal(positive.evidence.length, 1);
  assert.equal(clean.findings.length, 0);
  assert.equal(clean.evidence.length, 0);
  const finding = positive.findings[0];
  const evidence = positive.evidence[0];
  assert.ok(finding && evidence);
  assert.deepEqual(
    {
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      applicability: finding.applicability,
      uri: finding.locations[0]?.uri,
      line: finding.locations[0]?.line,
      column: finding.locations[0]?.column,
      evidenceIds: finding.evidenceIds,
      source: evidence.source,
      redacted: evidence.redacted,
    },
    {
      ruleId: "HOS-META-003",
      severity: "HIGH",
      confidence: "PROBABLE",
      applicability: "APPLICABLE",
      uri: "entry/src/main/module.json5",
      line: 6,
      column: 19,
      evidenceIds: [evidence.id],
      source: "entry/src/main/module.json5",
      redacted: true,
    },
  );
  assert.ok(evidence.summary.length <= 128);
  assert.doesNotMatch(evidence.summary, /bundleName|deviceTypes/u);
  assert.ok(Object.isFrozen(positive));
  assert.ok(Object.isFrozen(positive.findings));
  assert.ok(Object.isFrozen(finding.locations));
  assert.ok(Object.isFrozen(evidence));
});

test("测试地址检测器仅识别字符串值中的环回 HTTP 地址", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(
    files(root, "const api = 'http://localhost:8080/v1';"),
  );
  fs.set(`${root}/entry/src/main/metadata.json5`, {
    kind: "file",
    content:
      "{ api: 'https://example.com', callback: 'https://127.0.0.1:8443/oauth' }",
  });

  const result = await detectEndpoint(fs, root);

  assert.equal(result.findings.length, 2);
  assert.equal(result.evidence.length, 2);
  assert.deepEqual(
    result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      applicability: finding.applicability,
      uri: finding.locations[0]?.uri,
    })),
    [
      {
        ruleId: "HOS-PKG-007",
        severity: "HIGH",
        confidence: "PROBABLE",
        applicability: "APPLICABLE",
        uri: "entry/src/main/ets/Index.ets",
      },
      {
        ruleId: "HOS-PKG-007",
        severity: "HIGH",
        confidence: "PROBABLE",
        applicability: "APPLICABLE",
        uri: "entry/src/main/metadata.json5",
      },
    ],
  );
  assert.ok(result.evidence.every((item) => item.redacted));
  assert.doesNotMatch(JSON.stringify(result), /localhost|127\.0\.0\.1/u);
});

test("测试地址检测器忽略注释、普通词、私网地址和非最终 JSON5 值", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(
    files(
      root,
      [
        "// http://localhost:8080",
        "const label = 'TODO test demo beta localhost';",
        "const privateApi = 'http://192.168.1.10:8080';",
        "const docs = 'https://example.com/localhost/path';",
      ].join("\n"),
    ),
  );
  fs.set(`${root}/entry/src/main/metadata.json5`, {
    kind: "file",
    content: "{ api: 'http://localhost:8080', api: 'https://example.com' }",
  });

  assert.deepEqual(await detectEndpoint(fs, root), {
    evidence: [],
    findings: [],
  });
});

test("源码 lexer 仅识别字符串 token，忽略注释、标识符和转义", async () => {
  const root = "/repo";
  const source = [
    `// '${MARKER}'`,
    `/* "${MARKER}" */`,
    `const ${MARKER} = '普通 TODO test demo';`,
    "const escaped = 'HCHECK\\_PLACEHOLDER';",
    "const unicode = '\\u0048CHECK_PLACEHOLDER';",
    `const templateComment = \`\${/* ${MARKER} */ 'clean'}\`;`,
  ].join("\n");
  assert.deepEqual(
    await detect(new MemoryFileSystem(files(root, source)), root),
    { evidence: [], findings: [] },
  );
});

test("JSON5 只检查最终生效字符串值，旧重复键和注释中的标记不命中", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(files(root, "export const clean = true;"));
  fs.set(`${root}/entry/src/main/metadata.json5`, {
    kind: "file",
    content: `{
      // '${MARKER}'
      label: '${MARKER}',
      label: '普通 TODO test demo',
      identifier_${MARKER}: 'clean',
    }`,
  });
  assert.deepEqual(await detect(fs, root), { evidence: [], findings: [] });
});

test("JSON5 quoted property key 即使注释后接冒号也不冒充最终字符串值", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(files(root, "export const clean = true;"));
  fs.set(`${root}/entry/src/main/metadata.json5`, {
    kind: "file",
    content: `{ value: "${MARKER}", "${MARKER}" /* key */ : "clean" }`,
  });

  const result = await detect(fs, root);
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0]?.locations, [
    { uri: "entry/src/main/metadata.json5", line: 1, column: 11 },
  ]);
});

test("JSON5 AST 精确保留最终属性、嵌套、数组及重复同值的位置", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(files(root, "export const clean = true;"));
  fs.set(`${root}/entry/src/main/metadata.json5`, {
    kind: "file",
    content: `{b:'${MARKER}',a:'${MARKER}',a:'clean',nested:{v:'${MARKER}'},items:['${MARKER}','${MARKER}'],"${MARKER}":'clean'}`,
  });

  const result = await detect(fs, root);
  assert.deepEqual(
    result.findings.map((finding) => finding.locations[0]?.column),
    [5, 69, 98, 119],
  );
});

test("JSON5 BOM 不改变 AST range 对应的原始位置", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem(files(root, "export const clean = true;"));
  fs.set(`${root}/entry/src/main/metadata.json5`, {
    kind: "file",
    content: `\uFEFF{value:'${MARKER}'}`,
  });

  const result = await detect(fs, root);
  assert.deepEqual(result.findings[0]?.locations, [
    { uri: "entry/src/main/metadata.json5", line: 1, column: 10 },
  ]);
});

test("JSON5 和 TypeScript AST 超出深度或节点预算时不假 PASS", async () => {
  const root = "/repo";
  const tooDeep = new MemoryFileSystem(files(root, "clean"));
  tooDeep.set(`${root}/entry/src/main/deep.json5`, {
    kind: "file",
    content: `${"[".repeat(65)}'clean'${"]".repeat(65)}`,
  });
  const tooManyNodes = new MemoryFileSystem(
    files(
      root,
      Array.from({ length: 5_001 }, (_, index) => `x${index};`).join(""),
    ),
  );

  await assert.rejects(detect(tooDeep, root), expectIncomplete);
  await assert.rejects(detect(tooManyNodes, root), expectIncomplete);
});

test("源码遍历目录、条目、候选文件、总字节和总命中预算超限均不假 PASS", async () => {
  const root = "/repo";
  const source = `const first = '${MARKER}'; const second = '${MARKER}';`;
  const cases: MetadataPlaceholderLimits[] = [
    { ...METADATA_PLACEHOLDER_LIMITS, directories: 1 },
    { ...METADATA_PLACEHOLDER_LIMITS, directoryEntries: 1 },
    { ...METADATA_PLACEHOLDER_LIMITS, candidateFiles: 1 },
    { ...METADATA_PLACEHOLDER_LIMITS, totalReadBytes: 1 },
    { ...METADATA_PLACEHOLDER_LIMITS, matches: 1 },
  ];

  for (const limits of cases) {
    await assert.rejects(
      detect(
        new MemoryFileSystem(files(root, source)),
        root,
        project(),
        rule,
        [],
        limits,
      ),
      expectBudgetExceeded,
    );
  }
});

test("大量命中只建立一次行索引且首中尾位置正确", async () => {
  const root = "/repo";
  const source = Array.from(
    { length: 500 },
    (_, index) => `const value${index} = '${MARKER}';`,
  ).join("\n");
  const result = await detect(new MemoryFileSystem(files(root, source)), root);

  assert.equal(result.findings.length, 500);
  assert.deepEqual(
    [result.findings[0], result.findings[249], result.findings[499]].map(
      (finding) => finding?.locations[0],
    ),
    [
      { uri: "entry/src/main/ets/Index.ets", line: 1, column: 17 },
      { uri: "entry/src/main/ets/Index.ets", line: 250, column: 19 },
      { uri: "entry/src/main/ets/Index.ets", line: 500, column: 19 },
    ],
  );
});

test("TypeScript AST 忽略正则和注释并继续识别模板片段与后续字符串", async () => {
  const root = "/repo";
  const source = [
    `const regex = /['${MARKER}']\\/\\/\\* }/;`,
    "const quotient = 12 / 3;",
    `const template = \`head ${MARKER} \${/\\/\\* }/.test('clean')} tail ${MARKER}\`;`,
    `const actual = '${MARKER}';`,
  ].join("\n");

  const result = await detect(new MemoryFileSystem(files(root, source)), root);
  assert.deepEqual(
    result.findings.map((finding) => finding.locations[0]?.line),
    [3, 3, 4],
  );
});

test("内置 detector options 损坏固定映射 INTERNAL_ERROR 而非证据不完整", async () => {
  const root = "/Users/SECRET/中文 工程";
  const invalidOptions = [
    { ...rule.detector.options, marker: "SECRET-WRONG" },
    { ...rule.detector.options, extensions: [".ets", ".js"] },
    { ...rule.detector.options, exclude_paths: ["build/**", 42] },
    { ...rule.detector.options, extensions: [".ets", ".ts", ".ts"] },
    {
      ...rule.detector.options,
      exclude_paths: Array.from({ length: 65 }, (_, index) => `x${index}`),
    },
    { ...rule.detector.options, exclude_paths: [""] },
    { ...rule.detector.options, exclude_paths: ["bad\0pattern"] },
    { ...rule.detector.options, unexpected: true },
  ];

  for (const options of invalidOptions) {
    await assert.rejects(
      detect(new MemoryFileSystem(files(root, "clean")), root, project(), {
        ...rule,
        detector: { ...rule.detector, options },
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError);
        assert.equal(error.code, "INTERNAL_ERROR");
        assert.equal(error.message, "内置检测器配置无效。");
        assert.equal(error.details.kind, "invalid_detector_options");
        assert.doesNotMatch(JSON.stringify(error), /SECRET|Users|中文 工程/u);
        return true;
      },
    );
  }

  await assert.rejects(
    detect(
      new MemoryFileSystem(files(root, "clean")),
      root,
      project(),
      rule,
      Array.from({ length: 65 }, (_, index) => `x${index}`),
    ),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "INTERNAL_ERROR");
      return true;
    },
  );
});

test("canonical 目录重复出现时证据固定为不完整", async () => {
  const root = "/repo";
  const base = new MemoryFileSystem({
    ...files(root, "clean"),
    [`${root}/entry/src/main/alias/Other.ts`]: "clean",
  });
  const fs: ReadonlyFileSystemPort = {
    ...base,
    readText: base.readText.bind(base),
    exists: base.exists.bind(base),
    list: base.list.bind(base),
    kind: base.kind.bind(base),
    size: base.size.bind(base),
    parent: base.parent.bind(base),
    resolve: base.resolve.bind(base),
    realpath: async (candidate) => {
      const resolved = base.resolve(candidate);
      return resolved.endsWith("/alias")
        ? base.resolve(`${root}/entry/src/main/ets`)
        : base.realpath(candidate);
    },
  };

  await assert.rejects(detect(fs, root), expectIncomplete);
});

test("同一位置只产出一次，指纹不受行列变化影响且删除标记后归零", async () => {
  const root = "/repo";
  const first = await detect(
    new MemoryFileSystem(files(root, `const value = '${MARKER}';`)),
    root,
  );
  const shifted = await detect(
    new MemoryFileSystem(files(root, `\n\nconst value = '${MARKER}';`)),
    root,
  );
  const removed = await detect(
    new MemoryFileSystem(files(root, "const value = 'ready';")),
    root,
  );
  assert.equal(first.findings.length, 1);
  assert.equal(first.evidence.length, 1);
  assert.equal(
    first.findings[0]?.fingerprint,
    shifted.findings[0]?.fingerprint,
  );
  assert.notEqual(
    first.findings[0]?.locations[0]?.line,
    shifted.findings[0]?.locations[0]?.line,
  );
  assert.deepEqual(removed, { evidence: [], findings: [] });
});

test("全局排除先于规则排除，模式均相对工程根且 Windows 路径归一化", async () => {
  const root = "C:\\中文 工程";
  const fs = new MemoryFileSystem(
    {
      ...files(root, "const clean = true;"),
      [`${root}\\entry\\src\\main\\global\\One.ets`]: `const x='${MARKER}';`,
      [`${root}\\entry\\src\\main\\rule\\Two.ts`]: `const x='${MARKER}';`,
      [`${root}\\entry\\src\\main\\kept\\A.ts`]: `const x='${MARKER}';`,
      [`${root}\\entry\\src\\main\\kept\\三.ts`]: `const x='${MARKER}';`,
    },
    path.win32,
  );
  const selectedRule: RuleDefinition = {
    ...rule,
    detector: {
      ...rule.detector,
      options: {
        ...rule.detector.options,
        exclude_paths: ["entry/src/main/rule/**"],
      },
    },
  };
  const result = await detect(fs, root, project(), selectedRule, [
    "entry/src/main/global/**",
  ]);
  assert.deepEqual(
    result.findings.map((finding) => finding.locations[0]?.uri),
    ["entry/src/main/kept/A.ts", "entry/src/main/kept/三.ts"],
  );
});

test("POSIX 根、Windows 盘根和 UNC 根均正确执行 containment", async () => {
  const cases: Array<readonly [string, typeof path.posix | typeof path.win32]> =
    [
      ["/", path.posix],
      ["C:\\", path.win32],
      ["\\\\Server\\Share", path.win32],
    ];

  for (const [root, flavor] of cases) {
    const result = await detect(
      new MemoryFileSystem(files(root, `const value = '${MARKER}';`), flavor),
      root,
    );
    assert.equal(result.findings.length, 1);
  }
});

test("依赖、build 和非白名单文件被忽略", async () => {
  const root = "/repo";
  const fs = new MemoryFileSystem({
    ...files(root, "const clean = true;"),
    [`${root}/entry/src/main/oh_modules/pkg/index.ets`]: `'${MARKER}'`,
    [`${root}/entry/src/main/node_modules/pkg/index.ts`]: `'${MARKER}'`,
    [`${root}/entry/src/main/build/generated.ts`]: `'${MARKER}'`,
    [`${root}/entry/src/main/assets/image.png`]: MARKER,
  });
  assert.deepEqual(await detect(fs, root), { evidence: [], findings: [] });
});

test("外部模块、symlink、越界 realpath、超限、替换字符和损坏 JSON5 均不假 PASS", async () => {
  const root = "/Users/SECRET/中文 工程";
  const external = {
    ...project(),
    modules: [{ ...project().modules[0]!, isExternal: true }],
  };
  const cases: Array<readonly [ReadonlyFileSystemPort, ProjectSnapshot]> = [];

  cases.push([new MemoryFileSystem(files(root, "clean")), external]);

  const symlink = new MemoryFileSystem(files(root, "clean"));
  symlink.set(`${root}/entry/src/main/link.ets`, {
    kind: "symlink",
    target: `${root}/entry/src/main/ets/Index.ets`,
  });
  cases.push([symlink, project()]);

  const brokenSymlink = new MemoryFileSystem(files(root, "clean"));
  brokenSymlink.set(`${root}/entry/src/main/broken-link.ets`, {
    kind: "symlink",
  });
  cases.push([brokenSymlink, project()]);

  const escaped = new MemoryFileSystem(files(root, "clean"));
  escaped.set(`${root}/entry/src/main/escape.ets`, {
    kind: "symlink",
    target: "/outside/secret.ets",
  });
  cases.push([escaped, project()]);

  const reportedOversized = new MemoryFileSystem(files(root, "clean"));
  reportedOversized.set(`${root}/entry/src/main/large.ts`, {
    kind: "file",
    content: "small",
    size: 1024 * 1024 + 1,
  });
  cases.push([reportedOversized, project()]);

  const readOversized = new MemoryFileSystem(files(root, "clean"));
  readOversized.set(`${root}/entry/src/main/race.ts`, {
    kind: "file",
    content: "密".repeat(400_000),
    size: 1,
  });
  cases.push([readOversized, project()]);

  const replacement = new MemoryFileSystem(files(root, "clean"));
  replacement.set(`${root}/entry/src/main/broken.ts`, {
    kind: "file",
    content: "const broken = '\uFFFD';",
  });
  cases.push([replacement, project()]);

  const invalidJson5 = new MemoryFileSystem(files(root, "clean"));
  invalidJson5.set(`${root}/entry/src/main/broken.json5`, {
    kind: "file",
    content: `{ value: '${MARKER}',`,
  });
  cases.push([invalidJson5, project()]);

  const unterminatedSource = new MemoryFileSystem(
    files(root, `const value = '${MARKER}`),
  );
  cases.push([unterminatedSource, project()]);

  for (const [fs, snapshot] of cases) {
    await assert.rejects(detect(fs, root, snapshot), expectIncomplete);
  }
});

test("executeRules 透传运行时端口并保留脱敏 EVIDENCE_INCOMPLETE code", async () => {
  const root = "/Users/SECRET/中文 工程";
  const registry = new DetectorRegistry();
  registry.register(metadataPlaceholderDetector);
  registry.register(testEndpointDetector);
  await assert.rejects(
    executeRules({
      rules: [rule],
      context: {
        mode: "quick",
        project: {
          ...project(),
          modules: [{ ...project().modules[0]!, isExternal: true }],
        },
        fs: new MemoryFileSystem(files(root, "clean")),
        hash,
        workspaceRoot: root,
        globalExcludePaths: [],
      },
      registry,
    }),
    expectIncomplete,
  );
});
