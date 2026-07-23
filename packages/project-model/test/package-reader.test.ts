import assert from "node:assert/strict";
import test from "node:test";
import { deflateRawSync, gzipSync } from "node:zlib";
import {
  HCheckError,
  readHarmonyPackage,
  type PackageFileSystemPort,
} from "../src/package-reader.js";

class MemoryPackageFileSystem implements PackageFileSystemPort {
  public constructor(
    private readonly files: Readonly<
      Record<
        string,
        | Uint8Array
        | {
            readonly kind: "file" | "directory" | "symlink" | "other";
            readonly content?: Uint8Array;
          }
      >
    >,
  ) {}

  public async kind(
    file: string,
  ): Promise<"file" | "directory" | "symlink" | "other"> {
    const entry = this.files[file];
    if (entry === undefined) return "other";
    return entry instanceof Uint8Array ? "file" : entry.kind;
  }

  public async size(file: string): Promise<number> {
    const entry = this.files[file];
    if (entry === undefined) throw new Error("missing");
    if (entry instanceof Uint8Array) return entry.byteLength;
    return entry.content?.byteLength ?? 0;
  }

  public async readFile(file: string): Promise<Uint8Array> {
    const entry = this.files[file];
    if (entry === undefined) throw new Error("missing");
    if (entry instanceof Uint8Array) return entry;
    return entry.content ?? new Uint8Array();
  }
}

const DEV_ECO_TAR_7_5_11_GOLDEN_HAR = Buffer.from(
  "H4sIAAAAAAAAE+2TzW6EIBCAPfcpyJy3OKBo4qlP0HdgkSx2BYyuTTcb371xsY3pob8mbRq+y8yECTCEr5PqKA86HXqVWtm41Pp6bDV9GLxLNgIRizwncywLcY3IQz3DeEYSJjgXORMZyxPkWGQlSXCrC7zHOJxknyBa6Z4a6ZUZv7dPmIW8xj/A+k3X+ZoLyK6D6gL70dWtvpdWQwXKW2qU0epID76ttYNpB+FnzL0udC1LOzidu7k2sodpuvm1eSNfp1v89+Z2Sa/qiy3P+MB/FOKN/6wsefT/x3zKfzLLXBG4C76nL1KTR90PjXcVAUaRIpBodiQSifwjngGgMMvyAAwAAA==",
  "base64",
);

test("读取 HAP 基础元数据、权限和调试标记且不泄露本机路径", async () => {
  const artifact = "/private/tmp/fixture/release.hap";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "module.json",
          content: JSON.stringify({
            module: {
              name: "entry",
              type: "entry",
              packageName: "com.example.release",
              deviceTypes: ["phone"],
              debug: true,
              requestPermissions: [
                { name: "ohos.permission.APPROXIMATELY_LOCATION" },
              ],
            },
          }),
        },
        {
          name: "resources/rawfile/hcheck-debug-marker.txt",
          content: "debug marker",
        },
      ]),
    }),
  });

  assert.equal(snapshot.artifact.type, "hap");
  assert.equal(snapshot.completeness, "COMPLETE");
  assert.equal(snapshot.bundleName, "com.example.release");
  assert.deepEqual(snapshot.permissions, [
    "ohos.permission.APPROXIMATELY_LOCATION",
  ]);
  assert.deepEqual(snapshot.modules, [
    {
      name: "entry",
      type: "entry",
      packageName: "com.example.release",
      deviceTypes: ["phone"],
      requestPermissions: ["ohos.permission.APPROXIMATELY_LOCATION"],
      debug: true,
      source: "module.json",
    },
  ]);
  assert.deepEqual(snapshot.debug.enabledModules, ["entry"]);
  assert.deepEqual(snapshot.debug.markerFiles, [
    "resources/rawfile/hcheck-debug-marker.txt",
  ]);
  assert.ok(!JSON.stringify(snapshot).includes("/private/tmp"));
});

test("真实 HAP manifest 优先使用 app.bundleName 而不是模块 packageName", async () => {
  const artifact = "/private/tmp/fixture/real-release.hap";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "module.json",
          content: JSON.stringify({
            app: {
              bundleName: "com.hcheck.p4buildsample",
              debug: false,
              versionCode: 1000000,
              versionName: "1.0.0",
            },
            module: {
              name: "entry",
              type: "entry",
              packageName: "entry",
              deviceTypes: ["phone", "tablet", "2in1"],
            },
          }),
        },
      ]),
    }),
  });

  assert.equal(snapshot.bundleName, "com.hcheck.p4buildsample");
  assert.deepEqual(snapshot.version, { code: 1000000, name: "1.0.0" });
  assert.equal(snapshot.modules[0]?.packageName, "entry");
  assert.equal(snapshot.modules[0]?.debug, false);
});

test("module.debug=false 优先覆盖 app.debug=true", async () => {
  const artifact = "/private/tmp/fixture/debug-priority.hap";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "module.json",
          content: JSON.stringify({
            app: { bundleName: "com.hcheck.debug", debug: true },
            module: { name: "entry", type: "entry", debug: false },
          }),
        },
      ]),
    }),
  });

  assert.equal(snapshot.modules[0]?.debug, false);
  assert.deepEqual(snapshot.debug.enabledModules, []);
});

test("versionCode 只保留安全整数且不额外限制正数", async () => {
  const cases = [
    {
      name: "最大安全整数",
      code: Number.MAX_SAFE_INTEGER,
      expected: { code: Number.MAX_SAFE_INTEGER },
    },
    { name: "零", code: 0, expected: { code: 0 } },
    {
      name: "超过安全整数",
      code: Number.MAX_SAFE_INTEGER + 1,
      expected: undefined,
    },
    { name: "小数", code: 1.5, expected: undefined },
  ];

  for (const [index, item] of cases.entries()) {
    const artifact = `/private/tmp/fixture/version-code-${index}.hap`;
    const snapshot = await readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "module.json",
            content: JSON.stringify({
              app: {
                bundleName: "com.hcheck.version-boundary",
                versionCode: item.code,
              },
              module: { name: "entry", type: "entry" },
            }),
          },
        ]),
      }),
    });
    assert.deepEqual(snapshot.version, item.expected, item.name);
  }
});

test("读取 HSP 根 manifest 的 shared 模块和权限，缺失 manifest 时证据不完整", async () => {
  const sharedArtifact = "/private/tmp/fixture/shared.hsp";
  const missingArtifact = "/private/tmp/fixture/missing.hsp";
  const packageOnlyArtifact = "/private/tmp/fixture/package-only.hsp";
  const fs = new MemoryPackageFileSystem({
    [sharedArtifact]: zip([
      {
        name: "module.json",
        content: JSON.stringify({
          app: {
            bundleName: "com.hcheck.p4packagematrix",
            versionCode: 2000000,
            versionName: "2.0.0",
          },
          module: {
            name: "shared",
            type: "shared",
            packageName: "shared",
            requestPermissions: [{ name: "ohos.permission.INTERNET" }],
          },
        }),
      },
    ]),
    [missingArtifact]: zip([{ name: "oh-package.json5", content: "{}" }]),
    [packageOnlyArtifact]: zip([
      {
        name: "module.json",
        content: JSON.stringify({
          module: {
            name: "shared-only",
            type: "shared",
            packageName: "com.hcheck.shared-only",
          },
        }),
      },
    ]),
  });

  const shared = await readHarmonyPackage(sharedArtifact, { fs });
  const missing = await readHarmonyPackage(missingArtifact, { fs });
  const packageOnly = await readHarmonyPackage(packageOnlyArtifact, { fs });

  assert.equal(shared.artifact.type, "hsp");
  assert.equal(shared.bundleName, "com.hcheck.p4packagematrix");
  assert.equal(shared.modules[0]?.type, "shared");
  assert.deepEqual(shared.version, { code: 2000000, name: "2.0.0" });
  assert.deepEqual(shared.permissions, ["ohos.permission.INTERNET"]);
  assert.equal(shared.completeness, "COMPLETE");
  assert.equal(missing.completeness, "INCOMPLETE");
  assert.match(missing.issues.join("\n"), /module\.json/u);
  assert.equal(packageOnly.completeness, "COMPLETE");
  assert.equal(packageOnly.bundleName, undefined);
});

test("HAP/HSP 只接受唯一的根目录 module.json 或 module.json5", async () => {
  const cases = [
    {
      name: "HAP 双根 manifest",
      artifact: "/private/tmp/fixture/double-manifest.hap",
      entries: [
        {
          name: "module.json",
          content: JSON.stringify({
            module: { name: "entry-json", type: "entry" },
          }),
        },
        {
          name: "module.json5",
          content: "{ module: { name: 'entry-json5', type: 'entry' } }",
        },
      ],
    },
    {
      name: "HAP 嵌套 manifest",
      artifact: "/private/tmp/fixture/nested-manifest.hap",
      entries: [
        {
          name: "src/main/module.json",
          content: JSON.stringify({
            module: { name: "entry", type: "entry" },
          }),
        },
      ],
    },
    {
      name: "HSP 双根 manifest",
      artifact: "/private/tmp/fixture/double-manifest.hsp",
      entries: [
        {
          name: "module.json",
          content: JSON.stringify({
            module: { name: "shared-json", type: "shared" },
          }),
        },
        {
          name: "module.json5",
          content: "{ module: { name: 'shared-json5', type: 'shared' } }",
        },
      ],
    },
    {
      name: "HSP 嵌套 manifest",
      artifact: "/private/tmp/fixture/nested-manifest.hsp",
      entries: [
        {
          name: "src/main/module.json5",
          content: "{ module: { name: 'shared', type: 'shared' } }",
        },
      ],
    },
  ];

  for (const item of cases) {
    const snapshot = await readHarmonyPackage(item.artifact, {
      fs: new MemoryPackageFileSystem({
        [item.artifact]: zip(item.entries),
      }),
    });
    assert.equal(snapshot.completeness, "INCOMPLETE", item.name);
    assert.match(snapshot.issues.join("\n"), /根目录|唯一/u, item.name);
  }
});

test("HAR 从 gzip tar 的真实 package 目录读取 manifest 且不把 packageName 冒充 Bundle", async () => {
  const artifact = "/private/tmp/fixture/library.har";
  const moduleManifest = JSON.stringify({
    module: {
      name: "library",
      type: "har",
      packageName: "com.hcheck.library",
    },
  });
  const packageManifest = "{ name: '@hcheck/library', version: '1.0.0' }";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: gzipTar([
        {
          name: "package/src/main/module.json",
          content: moduleManifest,
        },
        {
          name: "package/oh-package.json5",
          content: packageManifest,
        },
      ]),
    }),
  });

  assert.equal(snapshot.artifact.type, "har");
  assert.equal(snapshot.bundleName, undefined);
  assert.deepEqual(snapshot.modules, [
    {
      name: "library",
      type: "har",
      packageName: "com.hcheck.library",
      deviceTypes: [],
      requestPermissions: [],
      source: "package/src/main/module.json",
    },
  ]);
  assert.equal(snapshot.version, undefined);
  assert.deepEqual(
    snapshot.entries.map((entry) => ({
      path: entry.path,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      compressionMethod: entry.compressionMethod,
    })),
    [
      {
        path: "package/oh-package.json5",
        compressedSize: Buffer.byteLength(packageManifest),
        uncompressedSize: Buffer.byteLength(packageManifest),
        compressionMethod: "stored",
      },
      {
        path: "package/src/main/module.json",
        compressedSize: Buffer.byteLength(moduleManifest),
        uncompressedSize: Buffer.byteLength(moduleManifest),
        compressionMethod: "stored",
      },
    ],
  );
  assert.equal(snapshot.completeness, "COMPLETE");
});

test("HAR 读取 DevEco 同版 tar@7.5.11 生成的固定 golden", async () => {
  const artifact = "/private/tmp/fixture/tar-7.5.11-golden.har";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: DEV_ECO_TAR_7_5_11_GOLDEN_HAR,
    }),
  });

  assert.equal(snapshot.completeness, "COMPLETE");
  assert.equal(snapshot.bundleName, "com.hcheck.golden");
  assert.equal(snapshot.modules[0]?.name, "golden");
  assert.equal(snapshot.modules[0]?.source, "package/src/main/module.json");
  assert.deepEqual(
    snapshot.entries.map(({ path }) => path),
    ["package/oh-package.json5", "package/src/main/module.json"],
  );
});

test("HAR 精确读取 package/src/main/module.json5 并保留真实 source", async () => {
  const artifact = "/private/tmp/fixture/library-json5.har";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: gzipTar([
        {
          name: "package/src/main/module.json5",
          content: `{
            app: { bundleName: 'com.hcheck.library' },
            module: { name: 'library-json5', type: 'har' },
          }`,
        },
        { name: "package/oh-package.json5", content: "{ name: 'library' }" },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "COMPLETE");
  assert.equal(snapshot.bundleName, "com.hcheck.library");
  assert.equal(snapshot.modules[0]?.name, "library-json5");
  assert.equal(snapshot.modules[0]?.source, "package/src/main/module.json5");
});

test("HAR 规范 module.json/module.json5 清单必须唯一", async () => {
  const artifact = "/private/tmp/fixture/double-manifest.har";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: gzipTar([
        {
          name: "package/src/main/module.json",
          content: JSON.stringify({
            module: { name: "library-json", type: "har" },
          }),
        },
        {
          name: "package/src/main/module.json5",
          content: "{ module: { name: 'library-json5', type: 'har' } }",
        },
        { name: "package/oh-package.json5", content: "{}" },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "INCOMPLETE");
  assert.match(snapshot.issues.join("\n"), /唯一/u);
});

test("HAR 同一规范清单路径的目录与文件记录必须硬拒绝", async () => {
  const artifact = "/private/tmp/fixture/directory-file-manifest.har";
  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: gzipTar([
          {
            name: "package/src/main/module.json",
            content: "",
            typeflag: "5",
          },
          {
            name: "package/src/main/module.json",
            content: JSON.stringify({
              module: { name: "library", type: "har" },
            }),
          },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /重复/u);
      return true;
    },
  );
});

test("HAR 唯一规范清单路径为目录时仍不完整", async () => {
  const artifact = "/private/tmp/fixture/directory-only-manifest.har";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: gzipTar([
        {
          name: "package/src/main/module.json",
          content: "",
          typeflag: "5",
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "INCOMPLETE");
  assert.equal(snapshot.modules.length, 0);
});

test("HAR 接受普通目录条目并按 stored 成员输出", async () => {
  const artifact = "/private/tmp/fixture/directory.har";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: gzipTar([
        { name: "package/", content: "", typeflag: "5" },
        {
          name: "package/src/main/module.json",
          content: JSON.stringify({
            module: { name: "library", type: "har" },
          }),
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "COMPLETE");
  assert.deepEqual(snapshot.entries[0], {
    path: "package/",
    compressedSize: 0,
    uncompressedSize: 0,
    compressionMethod: "stored",
  });
});

test("HAR 拒绝损坏 gzip、tar 校验和、路径、链接、扩展类型和资源超限", async () => {
  const artifact = "/private/tmp/fixture/unsafe.har";
  const moduleEntry: TarEntryInput = {
    name: "package/src/main/module.json",
    content: JSON.stringify({
      module: { name: "library", type: "har" },
    }),
  };
  const validTar = tar([moduleEntry]);
  const badChecksum = Buffer.from(validTar);
  badChecksum[0] ^= 1;
  const badPadding = Buffer.from(validTar);
  badPadding[512 + Buffer.byteLength(moduleEntry.content)] = 1;
  const invalidOctal = Buffer.from(validTar);
  invalidOctal.fill(0, 124, 136);
  invalidOctal.write("00000000008", 124, "ascii");
  refreshTarChecksum(invalidOctal.subarray(0, 512));
  const outOfRange = Buffer.from(validTar);
  writeTarOctal(outOfRange, 124, 12, 4_096);
  refreshTarChecksum(outOfRange.subarray(0, 512));
  const nullPath = Buffer.from(validTar);
  nullPath.fill(0, 0, 100);
  Buffer.from("package\0/src/main/module.json").copy(nullPath, 0);
  refreshTarChecksum(nullPath.subarray(0, 512));
  const invalidUtf8 = Buffer.from(validTar);
  invalidUtf8.fill(0, 0, 100);
  Buffer.from([0xff]).copy(invalidUtf8, 0);
  refreshTarChecksum(invalidUtf8.subarray(0, 512));
  const withoutEndBlocks = validTar.subarray(0, validTar.byteLength - 1_024);
  const withOneEndBlock = validTar.subarray(0, validTar.byteLength - 512);
  const afterEndData = Buffer.concat([validTar, Buffer.alloc(512)]);
  afterEndData[afterEndData.byteLength - 1] = 1;
  const validGzip = gzipSync(validTar);
  const cases = [
    {
      name: "损坏 gzip",
      content: new Uint8Array([1, 2, 3, 4]),
      message: /GZIP/u,
    },
    {
      name: "损坏 tar 校验和",
      content: gzipSync(badChecksum),
      message: /校验和/u,
    },
    {
      name: "路径穿越",
      content: gzipTar([{ name: "../module.json", content: "{}" }]),
      message: /越界/u,
    },
    {
      name: "绝对路径",
      content: gzipTar([{ name: "/package/module.json", content: "{}" }]),
      message: /绝对路径/u,
    },
    {
      name: "反斜线路径",
      content: gzipTar([
        { name: "package\\src\\main\\module.json", content: "{}" },
      ]),
      message: /反斜线/u,
    },
    {
      name: "NUL 路径",
      content: gzipSync(nullPath),
      message: /NUL/u,
    },
    {
      name: "非法 UTF-8 路径",
      content: gzipSync(invalidUtf8),
      message: /UTF-8/u,
    },
    {
      name: "符号链接",
      content: gzipTar([{ name: "package/link", content: "", typeflag: "2" }]),
      message: /链接/u,
    },
    {
      name: "硬链接",
      content: gzipTar([{ name: "package/link", content: "", typeflag: "1" }]),
      message: /链接/u,
    },
    {
      name: "PAX 扩展",
      content: gzipTar([{ name: "package/pax", content: "", typeflag: "x" }]),
      message: /类型/u,
    },
    {
      name: "GNU 长路径扩展",
      content: gzipTar([
        { name: "package/longname", content: "", typeflag: "L" },
      ]),
      message: /类型/u,
    },
    {
      name: "设备条目",
      content: gzipTar([
        { name: "package/device", content: "", typeflag: "3" },
      ]),
      message: /类型/u,
    },
    {
      name: "缺少双零终止块",
      content: gzipSync(withoutEndBlocks),
      message: /结束块/u,
    },
    {
      name: "仅一个零终止块",
      content: gzipSync(withOneEndBlock),
      message: /结束块|越界/u,
    },
    {
      name: "结束块后非零",
      content: gzipSync(afterEndData),
      message: /结束块后/u,
    },
    {
      name: "归一化后重复路径",
      content: gzipTar([
        { name: "package//duplicate.txt", content: "a" },
        { name: "package/duplicate.txt", content: "b" },
      ]),
      message: /重复/u,
    },
    {
      name: "条目数量超限",
      content: gzipTar([
        moduleEntry,
        { name: "package/oh-package.json5", content: "{}" },
      ]),
      options: { maxEntries: 1 },
      message: /条目数量/u,
    },
    {
      name: "单条目超限",
      content: validGzip,
      options: { maxEntryBytes: 1 },
      message: /单条目/u,
    },
    {
      name: "总解压量超限",
      content: validGzip,
      options: { maxTotalUncompressedBytes: validTar.byteLength - 1 },
      message: /总解压量/u,
    },
    {
      name: "压缩比超限",
      content: validGzip,
      options: { maxCompressionRatio: 1 },
      message: /压缩比/u,
    },
    {
      name: "非法八进制 size",
      content: gzipSync(invalidOctal),
      message: /八进制/u,
    },
    {
      name: "条目内容越界",
      content: gzipSync(outOfRange),
      message: /越界/u,
    },
    {
      name: "非零 padding",
      content: gzipSync(badPadding),
      message: /填充/u,
    },
  ];

  for (const item of cases) {
    await assert.rejects(
      readHarmonyPackage(artifact, {
        fs: new MemoryPackageFileSystem({ [artifact]: item.content }),
        ...(item.options ?? {}),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.match(error.message, item.message, item.name);
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  }
});

test("APP 读取 pack.info 并聚合根目录一层 HAP/HSP 模块", async () => {
  const artifact = "/private/tmp/fixture/matrix.app";
  const bundleName = "com.hcheck.p4packagematrix";
  const entryHap = zip([
    {
      name: "module.json",
      content: JSON.stringify({
        app: { bundleName, debug: false },
        module: {
          name: "entry",
          type: "entry",
          packageName: "entry",
          requestPermissions: [{ name: "ohos.permission.INTERNET" }],
        },
      }),
    },
    {
      name: "resources/rawfile/hcheck-debug-marker.txt",
      content: "marker",
    },
  ]);
  const sharedHsp = zip([
    {
      name: "module.json",
      content: JSON.stringify({
        app: { bundleName, debug: true },
        module: {
          name: "shared",
          type: "shared",
          packageName: "shared",
          requestPermissions: [{ name: "ohos.permission.LOCATION" }],
        },
      }),
    },
  ]);
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        { name: "entry-default.hap", content: entryHap },
        {
          name: "pack.info",
          content: JSON.stringify({
            summary: {
              app: {
                bundleName,
                version: { code: 1000000, name: "1.0.0" },
              },
            },
          }),
        },
        { name: "shared-default.hsp", content: sharedHsp },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "COMPLETE");
  assert.equal(snapshot.bundleName, bundleName);
  assert.deepEqual(snapshot.version, { code: 1000000, name: "1.0.0" });
  assert.deepEqual(snapshot.modules, [
    {
      name: "entry",
      type: "entry",
      packageName: "entry",
      deviceTypes: [],
      requestPermissions: ["ohos.permission.INTERNET"],
      debug: false,
      source: "entry-default.hap!/module.json",
    },
    {
      name: "shared",
      type: "shared",
      packageName: "shared",
      deviceTypes: [],
      requestPermissions: ["ohos.permission.LOCATION"],
      debug: true,
      source: "shared-default.hsp!/module.json",
    },
  ]);
  assert.deepEqual(snapshot.permissions, [
    "ohos.permission.INTERNET",
    "ohos.permission.LOCATION",
  ]);
  assert.deepEqual(snapshot.debug.enabledModules, ["shared"]);
  assert.deepEqual(snapshot.debug.markerFiles, [
    "entry-default.hap!/resources/rawfile/hcheck-debug-marker.txt",
  ]);
  assert.deepEqual(
    snapshot.entries.map(({ path }) => path),
    ["entry-default.hap", "pack.info", "shared-default.hsp"],
  );
  assert.ok(!JSON.stringify(snapshot).includes("/private/tmp"));
});

test("APP 缺少有效 pack.info、根目录内包或内包模块时返回不完整证据", async () => {
  const artifactWithoutPack = "/private/tmp/fixture/no-pack.app";
  const artifactWithoutRootPackage = "/private/tmp/fixture/no-package.app";
  const artifactWithoutModule = "/private/tmp/fixture/no-module.app";
  const bundleName = "com.hcheck.p4packagematrix";
  const validHap = zip([
    {
      name: "module.json",
      content: JSON.stringify({
        app: { bundleName },
        module: { name: "entry", type: "entry" },
      }),
    },
  ]);
  const packInfo = JSON.stringify({ summary: { app: { bundleName } } });
  const fs = new MemoryPackageFileSystem({
    [artifactWithoutPack]: zip([
      { name: "entry-default.hap", content: validHap },
    ]),
    [artifactWithoutRootPackage]: zip([
      { name: "pack.info", content: packInfo },
      { name: "nested/entry-default.hap", content: validHap },
    ]),
    [artifactWithoutModule]: zip([
      { name: "pack.info", content: packInfo },
      {
        name: "entry-default.hap",
        content: zip([{ name: "resources/rawfile/readme.txt", content: "ok" }]),
      },
    ]),
  });

  const withoutPack = await readHarmonyPackage(artifactWithoutPack, { fs });
  const withoutRootPackage = await readHarmonyPackage(
    artifactWithoutRootPackage,
    { fs },
  );
  const withoutModule = await readHarmonyPackage(artifactWithoutModule, { fs });

  assert.equal(withoutPack.completeness, "INCOMPLETE");
  assert.equal(withoutPack.bundleName, undefined);
  assert.match(withoutPack.issues.join("\n"), /pack\.info/u);
  assert.equal(withoutRootPackage.completeness, "INCOMPLETE");
  assert.match(withoutRootPackage.issues.join("\n"), /HAP\/HSP/u);
  assert.equal(withoutModule.completeness, "INCOMPLETE");
  assert.match(withoutModule.issues.join("\n"), /模块/u);
  assert.ok(
    !JSON.stringify([
      withoutPack.issues,
      withoutRootPackage.issues,
      withoutModule.issues,
    ]).includes("/private/tmp"),
  );
});

test("APP 重复 pack.info 时返回不完整证据", async () => {
  const artifact = "/private/tmp/fixture/duplicate-pack-info.app";
  const bundleName = "com.hcheck.duplicate-pack";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "pack.info",
          content: JSON.stringify({ summary: { app: { bundleName } } }),
        },
        {
          name: "pack.info",
          content: JSON.stringify({
            summary: { app: { bundleName: "com.hcheck.ambiguous" } },
          }),
        },
        {
          name: "entry-default.hap",
          content: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                app: { bundleName },
                module: { name: "entry", type: "entry" },
              }),
            },
          ]),
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "INCOMPLETE");
  assert.match(snapshot.issues.join("\n"), /pack\.info.*重复/u);
});

test("APP 传播内嵌包的双 manifest 与嵌套 manifest 不完整状态", async () => {
  const bundleName = "com.hcheck.inner-manifest";
  const cases = [
    {
      name: "双根 manifest",
      artifact: "/private/tmp/fixture/inner-double-manifest.app",
      innerEntries: [
        {
          name: "module.json",
          content: JSON.stringify({
            app: { bundleName },
            module: { name: "entry-json", type: "entry" },
          }),
        },
        {
          name: "module.json5",
          content: `{ app: { bundleName: '${bundleName}' }, module: { name: 'entry-json5', type: 'entry' } }`,
        },
      ],
    },
    {
      name: "嵌套 manifest",
      artifact: "/private/tmp/fixture/inner-nested-manifest.app",
      innerEntries: [
        {
          name: "src/main/module.json",
          content: JSON.stringify({
            app: { bundleName },
            module: { name: "entry", type: "entry" },
          }),
        },
      ],
    },
  ];

  for (const item of cases) {
    const snapshot = await readHarmonyPackage(item.artifact, {
      fs: new MemoryPackageFileSystem({
        [item.artifact]: zip([
          {
            name: "pack.info",
            content: JSON.stringify({ summary: { app: { bundleName } } }),
          },
          { name: "entry-default.hap", content: zip(item.innerEntries) },
        ]),
      }),
    });
    assert.equal(snapshot.completeness, "INCOMPLETE", item.name);
    assert.match(snapshot.issues.join("\n"), /内嵌.*清单/u, item.name);
  }
});

test("APP 的 pack.info 与内包 Bundle 冲突时返回明确且脱敏的不完整证据", async () => {
  const artifact = "/private/tmp/fixture/conflict.app";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "pack.info",
          content: JSON.stringify({
            summary: {
              app: { bundleName: "com.hcheck.p4packagematrix" },
            },
          }),
        },
        {
          name: "entry-default.hap",
          content: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                app: { bundleName: "com.hcheck.conflict" },
                module: { name: "entry", type: "entry" },
              }),
            },
          ]),
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "INCOMPLETE");
  assert.equal(snapshot.bundleName, "com.hcheck.p4packagematrix");
  assert.match(snapshot.issues.join("\n"), /Bundle.*不一致/u);
  assert.ok(!JSON.stringify(snapshot.issues).includes("/private/tmp"));
});

test("APP 用 HAP 的兼容 packageName fallback 核对 pack.info Bundle", async () => {
  const artifact = "/private/tmp/fixture/fallback-conflict.app";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "pack.info",
          content: JSON.stringify({
            summary: { app: { bundleName: "com.hcheck.application" } },
          }),
        },
        {
          name: "entry-default.hap",
          content: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                module: {
                  name: "entry",
                  type: "entry",
                  packageName: "com.hcheck.fallback-conflict",
                },
              }),
            },
          ]),
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "INCOMPLETE");
  assert.match(snapshot.issues.join("\n"), /Bundle.*不一致/u);
  assert.ok(!JSON.stringify(snapshot.issues).includes("/private/tmp"));
});

test("APP 的两个内包 Bundle 声明互相冲突时返回不完整证据", async () => {
  const artifact = "/private/tmp/fixture/inner-conflict.app";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "pack.info",
          content: JSON.stringify({
            summary: { app: { bundleName: "com.hcheck.application" } },
          }),
        },
        {
          name: "entry-default.hap",
          content: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                app: { bundleName: "com.hcheck.application" },
                module: { name: "entry", type: "entry" },
              }),
            },
          ]),
        },
        {
          name: "shared-default.hsp",
          content: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                app: { bundleName: "com.hcheck.other" },
                module: { name: "shared", type: "shared" },
              }),
            },
          ]),
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "INCOMPLETE");
  assert.match(snapshot.issues.join("\n"), /互相冲突/u);
});

test("APP 的内嵌 HAP 损坏时抛出脱敏的产物解析错误", async () => {
  const artifact = "/private/tmp/fixture/damaged-inner.app";

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "pack.info",
            content: JSON.stringify({
              summary: {
                app: { bundleName: "com.hcheck.p4packagematrix" },
              },
            }),
          },
          {
            name: "entry-default.hap",
            content: new Uint8Array([1, 2, 3, 4]),
          },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("APP 内外层共享条目数与总解压量安全预算", async () => {
  const artifact = "/private/tmp/fixture/shared-budget.app";
  const moduleContent = JSON.stringify({
    app: { bundleName: "com.hcheck.p4packagematrix" },
    module: { name: "entry", type: "entry" },
  });
  const innerHap = zip([{ name: "module.json", content: moduleContent }]);
  const packInfo = JSON.stringify({
    summary: { app: { bundleName: "com.hcheck.p4packagematrix" } },
  });
  const app = zip([
    { name: "pack.info", content: packInfo },
    { name: "entry-default.hap", content: innerHap },
  ]);
  const fs = new MemoryPackageFileSystem({ [artifact]: app });
  const cases = [
    { name: "条目数", options: { maxEntries: 2 } },
    {
      name: "总解压量",
      options: {
        maxTotalUncompressedBytes:
          Buffer.byteLength(packInfo) + innerHap.byteLength,
      },
    },
  ];

  for (const item of cases) {
    await assert.rejects(
      readHarmonyPackage(artifact, { fs, ...item.options }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        return true;
      },
    );
  }
});

test("APP 内包继续执行路径、符号链接、压缩比和 UTF-8 安全检查", async () => {
  const artifact = "/private/tmp/fixture/unsafe-inner.app";
  const packInfo = JSON.stringify({
    summary: { app: { bundleName: "com.hcheck.p4packagematrix" } },
  });
  const cases = [
    {
      name: "路径穿越",
      inner: zip([{ name: "../module.json", content: "{}" }]),
    },
    {
      name: "符号链接",
      inner: zip([
        {
          name: "module.json",
          content: "{}",
          externalAttributes: (0o120000 << 16) >>> 0,
        },
      ]),
    },
    {
      name: "压缩比",
      inner: zip([
        {
          name: "module.json",
          content: "{}",
          uncompressedSizeOverride: 2_048,
        },
      ]),
    },
    {
      name: "UTF-8",
      inner: zip([
        {
          name: "module.json",
          content: new Uint8Array([0xc3, 0x28]),
        },
      ]),
    },
  ];

  for (const item of cases) {
    const fs = new MemoryPackageFileSystem({
      [artifact]: zip([
        { name: "pack.info", content: packInfo },
        { name: "entry-default.hap", content: item.inner },
      ]),
    });
    await assert.rejects(
      readHarmonyPackage(artifact, { fs }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        return true;
      },
    );
  }
});

test("ZIP 合法 deflate 条目可读且快照标记为 deflated", async () => {
  const artifact = "/private/tmp/fixture/deflated.hap";
  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "module.json",
          content: JSON.stringify({
            app: { bundleName: "com.hcheck.deflated" },
            module: { name: "entry", type: "entry" },
          }),
          compressionMethod: 8,
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "COMPLETE");
  assert.equal(snapshot.bundleName, "com.hcheck.deflated");
  assert.equal(snapshot.entries[0]?.compressionMethod, "deflated");
});

test("ZIP deflate 实际输出超过伪造声明时在解压上限处拒绝", async () => {
  const artifact = "/private/tmp/fixture/deflate-bomb.hap";

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "module.json",
            content: "x".repeat(64 * 1_024),
            compressionMethod: 8,
            uncompressedSizeOverride: 16,
          },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /解压.*上限/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("APP 外层 deflated 内嵌 HAP 的实际输出超过声明时拒绝", async () => {
  const artifact = "/private/tmp/fixture/deflated-inner-bomb.app";
  const innerHap = zip([
    {
      name: "module.json",
      content: JSON.stringify({
        app: { bundleName: "com.hcheck.deflated-inner" },
        module: { name: "entry", type: "entry" },
      }),
    },
  ]);

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "pack.info",
            content: JSON.stringify({
              summary: { app: { bundleName: "com.hcheck.deflated-inner" } },
            }),
          },
          {
            name: "entry-default.hap",
            content: innerHap,
            compressionMethod: 8,
            uncompressedSizeOverride: 16,
          },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /解压.*上限/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("ZIP central 或 local header 设置加密 bit 时均拒绝", async () => {
  const moduleManifest = JSON.stringify({
    module: { name: "entry", type: "entry" },
  });
  const cases = [
    {
      name: "central header 加密位",
      artifact: "/private/tmp/fixture/central-encrypted.hap",
      content: zip([
        { name: "module.json", content: moduleManifest, centralFlags: 1 },
      ]),
    },
    {
      name: "local header 加密位",
      artifact: "/private/tmp/fixture/local-encrypted.hap",
      content: zip([
        { name: "module.json", content: moduleManifest },
        {
          name: "resources/rawfile/encrypted.bin",
          content: "ciphertext",
          localFlags: 1,
        },
      ]),
    },
  ];

  for (const item of cases) {
    await assert.rejects(
      readHarmonyPackage(item.artifact, {
        fs: new MemoryPackageFileSystem({ [item.artifact]: item.content }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.match(error.message, /加密/u);
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  }
});

test("ZIP data descriptor bit3 在 central 与 local header 不一致时拒绝", async () => {
  const moduleManifest = JSON.stringify({
    module: { name: "entry", type: "entry" },
  });
  const cases = [
    {
      name: "仅 central header 启用 bit3",
      artifact: "/private/tmp/fixture/central-data-descriptor-only.hap",
      content: zip([
        {
          name: "module.json",
          content: moduleManifest,
          centralFlags: 1 << 3,
        },
      ]),
    },
    {
      name: "仅 local header 启用 bit3",
      artifact: "/private/tmp/fixture/local-data-descriptor-only.hap",
      content: zip([
        {
          name: "module.json",
          content: moduleManifest,
          localFlags: 1 << 3,
        },
      ]),
    },
  ];

  for (const item of cases) {
    await assert.rejects(
      readHarmonyPackage(item.artifact, {
        fs: new MemoryPackageFileSystem({ [item.artifact]: item.content }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.match(error.message, /data descriptor|bit3/u);
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  }
});

test("ZIP 未启用 data descriptor 时拒绝 local CRC32 或大小与 central 不一致", async () => {
  const moduleManifest = JSON.stringify({
    module: { name: "entry", type: "entry" },
  });
  const cases = [
    {
      name: "CRC32 不一致",
      file: "local-crc32-mismatch.hap",
      entry: { centralCrc32: 0x12345678 },
    },
    {
      name: "压缩大小不一致",
      file: "local-compressed-size-mismatch.hap",
      entry: { localCompressedSizeOverride: 1 },
    },
    {
      name: "未压缩大小不一致",
      file: "local-uncompressed-size-mismatch.hap",
      entry: { localUncompressedSizeOverride: 1 },
    },
  ];

  for (const item of cases) {
    const artifact = `/private/tmp/fixture/${item.file}`;
    await assert.rejects(
      readHarmonyPackage(artifact, {
        fs: new MemoryPackageFileSystem({
          [artifact]: zip([
            {
              name: "module.json",
              content: moduleManifest,
              ...item.entry,
            },
          ]),
        }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.match(error.message, /CRC32|大小/u);
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  }
});

test("ZIP 启用 data descriptor 时允许 local CRC32 与大小为零或等于 central", async () => {
  const moduleManifest = JSON.stringify({
    module: { name: "entry", type: "entry" },
  });
  const manifestSize = Buffer.byteLength(moduleManifest);
  const cases = [
    {
      name: "local 字段均为零",
      file: "data-descriptor-zero-local-fields.hap",
      entry: {
        localCrc32: 0,
        localCompressedSizeOverride: 0,
        localUncompressedSizeOverride: 0,
      },
    },
    {
      name: "local 字段与 central 一致",
      file: "data-descriptor-matching-local-fields.hap",
      entry: {
        localCrc32: 0x12345678,
        localCompressedSizeOverride: manifestSize,
        localUncompressedSizeOverride: manifestSize,
      },
    },
  ];

  for (const item of cases) {
    const artifact = `/private/tmp/fixture/${item.file}`;
    const snapshot = await readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "module.json",
            content: moduleManifest,
            centralFlags: 1 << 3,
            localFlags: 1 << 3,
            centralCrc32: 0x12345678,
            ...item.entry,
          },
        ]),
      }),
    });

    assert.equal(snapshot.completeness, "COMPLETE", item.name);
    assert.equal(snapshot.modules[0]?.name, "entry", item.name);
  }
});

test("ZIP 启用 data descriptor 时拒绝 local CRC32 或大小为非零且不等于 central", async () => {
  const moduleManifest = JSON.stringify({
    module: { name: "entry", type: "entry" },
  });
  const manifestSize = Buffer.byteLength(moduleManifest);
  const cases = [
    {
      name: "CRC32 为其他非零值",
      file: "data-descriptor-crc32-mismatch.hap",
      entry: { localCrc32: 0x87654321 },
    },
    {
      name: "压缩大小为其他非零值",
      file: "data-descriptor-compressed-size-mismatch.hap",
      entry: { localCompressedSizeOverride: manifestSize + 1 },
    },
    {
      name: "未压缩大小为其他非零值",
      file: "data-descriptor-uncompressed-size-mismatch.hap",
      entry: { localUncompressedSizeOverride: manifestSize + 1 },
    },
  ];

  for (const item of cases) {
    const artifact = `/private/tmp/fixture/${item.file}`;
    await assert.rejects(
      readHarmonyPackage(artifact, {
        fs: new MemoryPackageFileSystem({
          [artifact]: zip([
            {
              name: "module.json",
              content: moduleManifest,
              centralFlags: 1 << 3,
              localFlags: 1 << 3,
              centralCrc32: 0x12345678,
              ...item.entry,
            },
          ]),
        }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.match(error.message, /CRC32|大小/u);
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  }
});

test("ZIP64 Locator 与对应 ZIP64 EOCD 存在时拒绝传统字段可表达的归档", async () => {
  const artifact = "/private/tmp/fixture/zip64-end-records.hap";
  const content = withZip64EndRecords(
    zip([
      {
        name: "module.json",
        content: JSON.stringify({ module: { name: "entry", type: "entry" } }),
      },
    ]),
  );

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({ [artifact]: content }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /ZIP64/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("ZIP EOCD 条目数 0xffff 哨兵即使其他传统字段可表达也拒绝", async () => {
  const artifact = "/private/tmp/fixture/zip64-entry-count.hap";
  const content = Buffer.from(
    zip([
      {
        name: "module.json",
        content: JSON.stringify({ module: { name: "entry", type: "entry" } }),
      },
    ]),
  );
  const eocdOffset = content.length - 22;
  content.writeUInt16LE(0xffff, eocdOffset + 8);
  content.writeUInt16LE(0xffff, eocdOffset + 10);

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({ [artifact]: content }),
      maxEntries: 0xffff,
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /ZIP64/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("ZIP 中央目录出现 0x0001 ZIP64 extra field 时拒绝", async () => {
  const artifact = "/private/tmp/fixture/zip64-extra.hap";

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "module.json",
            content: JSON.stringify({
              module: { name: "entry", type: "entry" },
            }),
            centralExtra: Uint8Array.of(0x01, 0x00, 0x00, 0x00),
          },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /ZIP64/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("ZIP 仅 local header 出现 0x0001 ZIP64 extra field 时也拒绝", async () => {
  const artifact = "/private/tmp/fixture/local-zip64-extra.hap";

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "module.json",
            content: JSON.stringify({
              module: { name: "entry", type: "entry" },
            }),
            localExtra: Uint8Array.of(0x01, 0x00, 0x00, 0x00),
          },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /ZIP64/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("ZIP extra field 末尾的 DevEco 零填充不影响 HAP 元数据读取", async () => {
  const artifact = "/private/tmp/fixture/deveco-zero-padding.hap";

  const snapshot = await readHarmonyPackage(artifact, {
    fs: new MemoryPackageFileSystem({
      [artifact]: zip([
        {
          name: "module.json",
          content: JSON.stringify({
            app: {
              bundleName: "com.example.myapplication",
              versionCode: 1000000,
              versionName: "1.0.0",
            },
            module: { name: "entry", type: "entry" },
          }),
          localExtra: Uint8Array.of(0, 0, 0),
          centralExtra: Uint8Array.of(0, 0),
        },
      ]),
    }),
  });

  assert.equal(snapshot.completeness, "COMPLETE");
  assert.equal(snapshot.bundleName, "com.example.myapplication");
  assert.deepEqual(snapshot.version, { code: 1000000, name: "1.0.0" });
});

for (const item of [
  {
    name: "ZIP local header 压缩大小为 ZIP64 哨兵时拒绝",
    file: "local-zip64-compressed-size.hap",
    entry: { localCompressedSizeOverride: 0xffffffff },
  },
  {
    name: "ZIP local header 未压缩大小为 ZIP64 哨兵时拒绝",
    file: "local-zip64-uncompressed-size.hap",
    entry: { localUncompressedSizeOverride: 0xffffffff },
  },
]) {
  test(item.name, async () => {
    const artifact = `/private/tmp/fixture/${item.file}`;
    await assert.rejects(
      readHarmonyPackage(artifact, {
        fs: new MemoryPackageFileSystem({
          [artifact]: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                module: { name: "entry", type: "entry" },
              }),
              ...item.entry,
            },
          ]),
        }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.match(error.message, /ZIP64/u);
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  });
}

for (const item of [
  {
    name: "ZIP local header 路径穿越时拒绝",
    file: "local-traversal.hap",
    entry: { localName: "../module.json" },
  },
  {
    name: "ZIP local header 文件名不是有效 UTF-8 时拒绝",
    file: "local-invalid-utf8.hap",
    entry: { localName: Uint8Array.of(0xff) },
  },
  {
    name: "ZIP local header 文件名与中央目录不一致时拒绝",
    file: "local-name-mismatch.hap",
    entry: { localName: "other.json" },
  },
  {
    name: "ZIP local header 压缩方法与中央目录不一致时拒绝",
    file: "local-compression-mismatch.hap",
    entry: { localCompressionMethod: 8 as const },
  },
]) {
  test(item.name, async () => {
    const artifact = `/private/tmp/fixture/${item.file}`;
    await assert.rejects(
      readHarmonyPackage(artifact, {
        fs: new MemoryPackageFileSystem({
          [artifact]: zip([
            {
              name: "module.json",
              content: JSON.stringify({
                module: { name: "entry", type: "entry" },
              }),
              ...item.entry,
            },
          ]),
        }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.doesNotMatch(error.message, /private|tmp/u);
        return true;
      },
    );
  });
}

test("ZIP 拒绝归一化后重复的普通归档路径", async () => {
  const artifact = "/private/tmp/fixture/duplicate-normalized.hap";

  await assert.rejects(
    readHarmonyPackage(artifact, {
      fs: new MemoryPackageFileSystem({
        [artifact]: zip([
          {
            name: "module.json",
            content: JSON.stringify({
              module: { name: "entry", type: "entry" },
            }),
          },
          { name: "resources//rawfile/value.txt", content: "a" },
          { name: "resources/rawfile/value.txt", content: "b" },
        ]),
      }),
    }),
    (error: unknown) => {
      assert.ok(error instanceof HCheckError);
      assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
      assert.match(error.message, /重复/u);
      assert.doesNotMatch(error.message, /private|tmp/u);
      return true;
    },
  );
});

test("拒绝路径穿越、符号链接、压缩包炸弹、损坏包、超大输入和非预期类型", async () => {
  const validZip = zip([{ name: "module.json", content: "{}" }]);
  const cases = [
    {
      name: "路径穿越",
      file: "/repo/app.hap",
      content: zip([{ name: "../module.json", content: "{}" }]),
    },
    {
      name: "符号链接",
      file: "/repo/app.hap",
      content: zip([
        {
          name: "module.json",
          content: "{}",
          externalAttributes: (0o120000 << 16) >>> 0,
        },
      ]),
    },
    {
      name: "压缩包炸弹",
      file: "/repo/app.hap",
      content: zip([
        {
          name: "module.json",
          content: "{}",
          uncompressedSizeOverride: 64 * 1024 * 1024,
        },
      ]),
    },
    {
      name: "损坏包",
      file: "/repo/app.hap",
      content: new Uint8Array([1, 2, 3, 4]),
    },
    {
      name: "超大输入",
      file: "/repo/app.hap",
      content: validZip,
      maxPackageBytes: 2,
    },
    {
      name: "非预期类型",
      file: "/repo/app.txt",
      content: validZip,
    },
    {
      name: "符号链接文件",
      file: "/repo/app.hap",
      content: { kind: "symlink" as const, content: validZip },
    },
  ];

  for (const item of cases) {
    await assert.rejects(
      readHarmonyPackage(item.file, {
        fs: new MemoryPackageFileSystem({ [item.file]: item.content }),
        ...(item.maxPackageBytes === undefined
          ? {}
          : { maxPackageBytes: item.maxPackageBytes }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof HCheckError, item.name);
        assert.equal(error.code, "ARTIFACT_PARSE_ERROR");
        assert.doesNotMatch(error.message, /\/repo|private|tmp/u);
        return true;
      },
    );
  }
});

interface TarEntryInput {
  readonly name: string;
  readonly content: string | Uint8Array;
  readonly typeflag?: string;
}

function gzipTar(entries: readonly TarEntryInput[]): Uint8Array {
  return gzipSync(tar(entries));
}

function tar(entries: readonly TarEntryInput[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    if (name.byteLength > 100) throw new Error("测试 TAR 路径过长");
    const content =
      typeof entry.content === "string"
        ? Buffer.from(entry.content)
        : Buffer.from(entry.content);
    const header = Buffer.alloc(512);
    name.copy(header, 0);
    writeTarOctal(header, 100, 8, 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, content.byteLength);
    writeTarOctal(header, 136, 12, 0);
    header[156] = (entry.typeflag ?? "0").charCodeAt(0);
    header.write("ustar\0", 257, "ascii");
    header.write("00", 263, "ascii");
    refreshTarChecksum(header);
    const padding = Buffer.alloc((512 - (content.byteLength % 512)) % 512);
    parts.push(header, content, padding);
  }
  parts.push(Buffer.alloc(1_024));
  return Buffer.concat(parts);
}

function writeTarOctal(
  buffer: Buffer,
  offset: number,
  length: number,
  value: number,
): void {
  const encoded = value.toString(8).padStart(length - 1, "0");
  if (encoded.length > length - 1) throw new Error("测试 TAR 数值过大");
  buffer.fill(0, offset, offset + length);
  buffer.write(encoded, offset, length - 1, "ascii");
}

function refreshTarChecksum(header: Buffer): void {
  header.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const encoded = checksum.toString(8).padStart(6, "0");
  if (encoded.length > 6) throw new Error("测试 TAR 校验和过大");
  header.write(encoded, 148, 6, "ascii");
  header[154] = 0;
  header[155] = 0x20;
}

interface ZipEntryInput {
  readonly name: string;
  readonly content: string | Uint8Array;
  readonly compressionMethod?: 0 | 8;
  readonly localCompressionMethod?: 0 | 8;
  readonly localCompressedSizeOverride?: number;
  readonly localUncompressedSizeOverride?: number;
  readonly localName?: string | Uint8Array;
  readonly localExtra?: Uint8Array;
  readonly centralExtra?: Uint8Array;
  readonly centralFlags?: number;
  readonly localFlags?: number;
  readonly centralCrc32?: number;
  readonly localCrc32?: number;
  readonly externalAttributes?: number;
  readonly uncompressedSizeOverride?: number;
}

function zip(entries: readonly ZipEntryInput[]): Uint8Array {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const localName = Buffer.from(entry.localName ?? name);
    const localExtra = Buffer.from(entry.localExtra ?? []);
    const centralExtra = Buffer.from(entry.centralExtra ?? []);
    const rawContent =
      typeof entry.content === "string"
        ? Buffer.from(entry.content)
        : Buffer.from(entry.content);
    const compressionMethod = entry.compressionMethod ?? 0;
    const content =
      compressionMethod === 8 ? deflateRawSync(rawContent) : rawContent;
    const uncompressedSize =
      entry.uncompressedSizeOverride ?? rawContent.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(entry.localFlags ?? 0, 6);
    local.writeUInt16LE(entry.localCompressionMethod ?? compressionMethod, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(entry.localCrc32 ?? 0, 14);
    local.writeUInt32LE(
      entry.localCompressedSizeOverride ?? content.length,
      18,
    );
    local.writeUInt32LE(
      entry.localUncompressedSizeOverride ?? uncompressedSize,
      22,
    );
    local.writeUInt16LE(localName.length, 26);
    local.writeUInt16LE(localExtra.length, 28);
    localParts.push(local, localName, localExtra, content);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(entry.centralFlags ?? 0, 8);
    central.writeUInt16LE(compressionMethod, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(entry.centralCrc32 ?? 0, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(centralExtra.length, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(entry.externalAttributes ?? 0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name, centralExtra);
    offset +=
      local.length + localName.length + localExtra.length + content.length;
  }
  const centralOffset = offset;
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(centralOffset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, ...centralParts, end]);
}

function withZip64EndRecords(archive: Uint8Array): Uint8Array {
  const buffer = Buffer.from(archive);
  const eocdOffset = buffer.length - 22;
  const eocd = buffer.subarray(eocdOffset);
  const zip64Eocd = Buffer.alloc(56);
  zip64Eocd.writeUInt32LE(0x06064b50, 0);
  zip64Eocd.writeBigUInt64LE(44n, 4);
  zip64Eocd.writeUInt16LE(45, 12);
  zip64Eocd.writeUInt16LE(45, 14);
  zip64Eocd.writeBigUInt64LE(BigInt(eocd.readUInt16LE(8)), 24);
  zip64Eocd.writeBigUInt64LE(BigInt(eocd.readUInt16LE(10)), 32);
  zip64Eocd.writeBigUInt64LE(BigInt(eocd.readUInt32LE(12)), 40);
  zip64Eocd.writeBigUInt64LE(BigInt(eocd.readUInt32LE(16)), 48);
  const locator = Buffer.alloc(20);
  locator.writeUInt32LE(0x07064b50, 0);
  locator.writeBigUInt64LE(BigInt(eocdOffset), 8);
  locator.writeUInt32LE(1, 16);
  return Buffer.concat([
    buffer.subarray(0, eocdOffset),
    zip64Eocd,
    locator,
    eocd,
  ]);
}
