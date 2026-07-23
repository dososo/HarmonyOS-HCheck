import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import { gzipSync } from "node:zlib";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";
import {
  parsePackageInspectArguments,
  runPackageInspect,
} from "../src/package-inspect.js";

test("package inspect 参数解析只支持 inspect、产物路径和 terminal/json 输出", () => {
  assert.deepEqual(
    parsePackageInspectArguments(["package", "inspect", "app.hap"]),
    {
      artifact: "app.hap",
      format: "terminal",
    },
  );
  assert.deepEqual(
    parsePackageInspectArguments([
      "package",
      "inspect",
      "app.hap",
      "--format",
      "json",
    ]),
    {
      artifact: "app.hap",
      format: "json",
    },
  );
  assert.throws(
    () => parsePackageInspectArguments(["package", "compare", "app.hap"]),
    /package inspect/u,
  );
  assert.throws(
    () =>
      parsePackageInspectArguments([
        "package",
        "inspect",
        "app.hap",
        "--format",
        "sarif",
      ]),
    /terminal 或 json/u,
  );
});

test("package inspect 读取本地 HAP 元数据且输出不泄露绝对路径", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-package-"));
  const artifact = path.join(directory, "release.hap");
  try {
    await writeFile(
      artifact,
      zip([
        {
          name: "module.json",
          content: JSON.stringify({
            module: {
              name: "entry",
              type: "entry",
              packageName: "com.example.inspect",
              deviceTypes: ["phone"],
              requestPermissions: [
                { name: "ohos.permission.APPROXIMATELY_LOCATION" },
              ],
            },
          }),
        },
      ]),
    );
    let stdout = "",
      stderr = "";
    const code = await runPackageInspect(
      ["package", "inspect", artifact, "--format", "json"],
      {
        fs: new NodeFileSystem(),
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    const report = JSON.parse(stdout) as {
      artifact: { type: string };
      bundleName: string;
      modules: readonly { name: string }[];
      permissions: readonly string[];
    };

    assert.equal(code, 0);
    assert.equal(stderr, "");
    assert.equal(report.artifact.type, "hap");
    assert.equal(report.bundleName, "com.example.inspect");
    assert.deepEqual(
      report.modules.map(({ name }) => name),
      ["entry"],
    );
    assert.deepEqual(report.permissions, [
      "ohos.permission.APPROXIMATELY_LOCATION",
    ]);
    assert.ok(!stdout.includes(directory));
  } finally {
    await unlink(artifact);
    await rmdir(directory);
  }
});

test("package inspect 对 APP/HAP/HSP/HAR 真实容器输出正确类型且不泄露绝对路径", async () => {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-package-matrix-"),
  );
  const bundleName = "com.hcheck.p4packagematrix";
  const entryHap = moduleZip({
    app: {
      bundleName,
      debug: false,
      versionCode: 1000000,
      versionName: "1.0.0",
    },
    module: { name: "entry", type: "entry", packageName: "entry" },
  });
  const artifacts = [
    {
      type: "app",
      file: path.join(directory, "matrix.app"),
      content: zip([
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
      ]),
    },
    { type: "hap", file: path.join(directory, "entry.hap"), content: entryHap },
    {
      type: "hsp",
      file: path.join(directory, "shared.hsp"),
      content: moduleZip({
        app: { bundleName, versionCode: 1000000, versionName: "1.0.0" },
        module: { name: "shared", type: "shared", packageName: "shared" },
      }),
    },
    {
      type: "har",
      file: path.join(directory, "library.har"),
      content: gzipTar([
        {
          name: "package/src/main/module.json",
          content: JSON.stringify({
            module: { name: "library", type: "har", packageName: "library" },
          }),
        },
      ]),
    },
  ] as const;
  const createdArtifacts: string[] = [];

  try {
    for (const artifact of artifacts) {
      await writeFile(artifact.file, artifact.content);
      createdArtifacts.push(artifact.file);
      for (const format of ["json", "terminal"] as const) {
        const { code, stdout, stderr } = await inspectArtifact(
          artifact.file,
          format,
        );

        assert.equal(code, 0, `${artifact.type}/${format}`);
        assert.equal(stderr, "", `${artifact.type}/${format}`);
        if (format === "json") {
          const report = JSON.parse(stdout) as {
            artifact: { type: string };
            completeness: string;
          };
          assert.equal(report.artifact.type, artifact.type);
          assert.equal(report.completeness, "COMPLETE");
        } else {
          assert.match(stdout, new RegExp(`类型：${artifact.type}`, "u"));
          assert.match(stdout, /完整性：COMPLETE/u);
        }
        assert.ok(!stdout.includes(directory), `${artifact.type}/${format}`);
      }
    }
  } finally {
    for (const artifact of createdArtifacts) {
      await unlink(artifact);
    }
    await rmdir(directory);
  }
});

test("package inspect 终端按版本字段真值表显示且保留 code=0", async () => {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-package-version-"),
  );
  const artifact = path.join(directory, "entry.hap");
  const cases = [
    {
      app: { versionCode: 1000000, versionName: "1.0.0" },
      expected: "版本：1000000 / 1.0.0",
    },
    { app: { versionCode: 0 }, expected: "版本：0" },
    { app: { versionName: "1.0.0" }, expected: "版本：1.0.0" },
    { app: {}, expected: "版本：UNKNOWN" },
  ] as const;

  try {
    for (const item of cases) {
      await writeFile(
        artifact,
        moduleZip({
          app: item.app,
          module: { name: "entry", type: "entry", packageName: "entry" },
        }),
      );
      const { code, stdout, stderr } = await inspectArtifact(
        artifact,
        "terminal",
      );

      assert.equal(code, 0, item.expected);
      assert.equal(stderr, "", item.expected);
      assert.equal(
        stdout.split("\n").find((line) => line.startsWith("版本：")),
        item.expected,
      );
      assert.ok(!stdout.includes(directory), item.expected);
    }
  } finally {
    await unlink(artifact);
    await rmdir(directory);
  }
});

test("package inspect 对可读但不完整的快照先输出内容再返回 4", async () => {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-package-incomplete-"),
  );
  const artifact = path.join(directory, "incomplete.hap");
  try {
    await writeFile(
      artifact,
      zip([{ name: "README.txt", content: "fixture" }]),
    );
    for (const format of ["json", "terminal"] as const) {
      const { code, stdout, stderr } = await inspectArtifact(artifact, format);

      assert.equal(code, 4, format);
      assert.equal(stderr, "", format);
      if (format === "json") {
        const report = JSON.parse(stdout) as { completeness: string };
        assert.equal(report.completeness, "INCOMPLETE");
      } else {
        assert.match(stdout, /完整性：INCOMPLETE/u);
        assert.match(stdout, /问题：/u);
      }
      assert.ok(!stdout.includes(directory), format);
    }
  } finally {
    await unlink(artifact);
    await rmdir(directory);
  }
});

test("package inspect 无法读取产物时返回产物解析错误且不泄露路径", async () => {
  const missing = path.join(
    os.tmpdir(),
    "hcheck-package-missing",
    "secret-release.hap",
  );
  let stdout = "",
    stderr = "";
  const code = await runPackageInspect(["package", "inspect", missing], {
    fs: new NodeFileSystem(),
    stdout: (value) => {
      stdout += value;
    },
    stderr: (value) => {
      stderr += value;
    },
  });

  assert.equal(code, 8);
  assert.equal(stdout, "");
  assert.match(stderr, /ARTIFACT_PARSE_ERROR/u);
  assert.ok(!stderr.includes(missing));
});

interface ZipEntryInput {
  readonly name: string;
  readonly content: string | Uint8Array;
}

async function inspectArtifact(
  artifact: string,
  format: "json" | "terminal",
): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = "",
    stderr = "";
  const code = await runPackageInspect(
    ["package", "inspect", artifact, "--format", format],
    {
      fs: new NodeFileSystem(),
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    },
  );
  return { code, stdout, stderr };
}

function moduleZip(manifest: object): Uint8Array {
  return zip([{ name: "module.json", content: JSON.stringify(manifest) }]);
}

interface TarEntryInput {
  readonly name: string;
  readonly content: string | Uint8Array;
}

function gzipTar(entries: readonly TarEntryInput[]): Uint8Array {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    if (name.byteLength > 100) throw new Error("测试 TAR 路径过长");
    const content = Buffer.from(entry.content);
    const header = Buffer.alloc(512);
    name.copy(header, 0);
    writeTarOctal(header, 100, 8, 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, content.byteLength);
    writeTarOctal(header, 136, 12, 0);
    header[156] = "0".charCodeAt(0);
    header.write("ustar\0", 257, "ascii");
    header.write("00", 263, "ascii");
    header.fill(0x20, 148, 156);
    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(checksum.toString(8).padStart(6, "0"), 148, 6, "ascii");
    header[154] = 0;
    header[155] = 0x20;
    parts.push(
      header,
      content,
      Buffer.alloc((512 - (content.byteLength % 512)) % 512),
    );
  }
  parts.push(Buffer.alloc(1_024));
  return gzipSync(Buffer.concat(parts));
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

function zip(entries: readonly ZipEntryInput[]): Uint8Array {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const content = Buffer.from(entry.content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, content);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + content.length;
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
