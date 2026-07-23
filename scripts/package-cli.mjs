#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEFAULT_ENTRYPOINT = "packages/cli/dist/index.js";

export async function createCliPackageManifest({
  root = process.cwd(),
  platform = process.platform,
  arch = process.arch,
  observedVersion = "not-run",
} = {}) {
  const rootPackage = await readJson(path.join(root, "package.json"));
  const cliPackage = await readJson(
    path.join(root, "packages/cli/package.json"),
  );
  const entrypoint = DEFAULT_ENTRYPOINT;
  const entrypointContent = await readFile(path.join(root, entrypoint));
  const version =
    stringValue(cliPackage.version) ?? stringValue(rootPackage.version);
  if (version === undefined) {
    throw new Error("CLI package version is required.");
  }

  return deepFreeze({
    schemaVersion: "1.0.0",
    artifact: {
      name: "hcheck-cli",
      version,
      kind: "node-cli-local-package",
      entrypoint,
      entrypointSha256: `sha256:${sha256(entrypointContent)}`,
    },
    runtime: {
      node: stringValue(rootPackage.engines?.node) ?? "UNKNOWN",
      pnpm: stringValue(rootPackage.engines?.pnpm) ?? "UNKNOWN",
      packageManager: stringValue(rootPackage.packageManager) ?? "UNKNOWN",
    },
    platform: {
      os: platform,
      arch,
      verification: "current-platform-only",
    },
    smoke: {
      command: `node ${entrypoint} --version`,
      expectedVersion: version,
      observedVersion,
      status:
        observedVersion === "not-run"
          ? "not-run"
          : observedVersion === version
            ? "passed"
            : "failed",
    },
    install: {
      mode: "local-workspace",
      commands: ["pnpm install --frozen-lockfile", "pnpm build"],
      boundary:
        "不执行全局安装；只在当前仓库使用 pnpm 安装依赖并构建 packages/cli/dist/index.js。",
    },
    uninstall: {
      mode: "artifact-cleanup",
      commands: [
        "删除本脚本生成的 dist/hcheck-cli-package 目录或 manifest.json",
      ],
      boundary:
        "不删除用户文件、全局命令、账号数据、证书、缓存、node_modules 或仓库源码。",
    },
    externalValidation: {
      currentPlatform: platform,
      status: "local-workspace-only",
      note: "package:cli 只生成本地 Node CLI 清单，不写入全局 PATH，也不声明跨平台安装器验证。公开发布范围见 docs/10-验收与质量标准.md。",
    },
  });
}

export async function packageCli({
  root = process.cwd(),
  outDir = path.join(root, "dist", "hcheck-cli-package"),
  platform = process.platform,
  arch = process.arch,
} = {}) {
  const observedVersion = await runVersionSmoke(root);
  const manifest = await createCliPackageManifest({
    root,
    platform,
    arch,
    observedVersion,
  });
  await mkdir(outDir, { recursive: true });
  const manifestPath = path.join(outDir, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, manifestPath };
}

async function runVersionSmoke(root) {
  const { stdout } = await execFileAsync(
    process.execPath,
    [path.join(root, DEFAULT_ENTRYPOINT), "--version"],
    {
      cwd: root,
      timeout: 10_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    },
  );
  return stdout.trim();
}

async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

function stringValue(value) {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => deepFreeze(item)));
  }
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}

function parseCliArgs(args) {
  let outDir;
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (flag !== "--out") {
      throw new Error("package-cli 仅支持 --out <目录>。");
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error("--out 参数缺少值。");
    }
    outDir = path.resolve(value);
    index += 1;
  }
  return outDir === undefined ? {} : { outDir };
}

if (process.argv[1] !== undefined) {
  const currentFile = fileURLToPath(import.meta.url);
  if (path.resolve(process.argv[1]) === currentFile) {
    try {
      const result = await packageCli(parseCliArgs(process.argv.slice(2)));
      process.stdout.write(
        `${JSON.stringify(
          {
            manifest: result.manifest,
            manifestPath: path.relative(process.cwd(), result.manifestPath),
          },
          null,
          2,
        )}\n`,
      );
    } catch (error) {
      process.stderr.write(
        `${error instanceof Error ? error.message : "package-cli failed"}\n`,
      );
      process.exitCode = 1;
    }
  }
}
