import { constants } from "node:fs";
import { lstat, mkdir, open, unlink } from "node:fs/promises";
import path from "node:path";
import type { RuntimeEvidenceWriterPort } from "@hcheck/core";

const DEFAULT_MAXIMUM_FILES = 16;
const DEFAULT_MAXIMUM_FILE_BYTES = 256 * 1024;
const DEFAULT_MAXIMUM_TOTAL_BYTES = 1024 * 1024;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/u;

export interface NodeRuntimeEvidenceWriterOptions {
  readonly workspaceRoot: string;
  readonly maximumFiles?: number;
  readonly maximumFileBytes?: number;
  readonly maximumTotalBytes?: number;
}

export class NodeRuntimeEvidenceWriter implements RuntimeEvidenceWriterPort {
  private readonly workspaceRoot: string;
  private readonly maximumFiles: number;
  private readonly maximumFileBytes: number;
  private readonly maximumTotalBytes: number;
  private writtenFiles = 0;
  private writtenBytes = 0;

  public constructor(options: NodeRuntimeEvidenceWriterOptions) {
    this.workspaceRoot = path.resolve(options.workspaceRoot);
    this.maximumFiles = requirePositiveInteger(
      options.maximumFiles ?? DEFAULT_MAXIMUM_FILES,
    );
    this.maximumFileBytes = requirePositiveInteger(
      options.maximumFileBytes ?? DEFAULT_MAXIMUM_FILE_BYTES,
    );
    this.maximumTotalBytes = requirePositiveInteger(
      options.maximumTotalBytes ?? DEFAULT_MAXIMUM_TOTAL_BYTES,
    );
  }

  public async write(
    request: Parameters<RuntimeEvidenceWriterPort["write"]>[0],
  ): Promise<void> {
    const archiveSegments = requireArchiveRoot(request.archiveRoot);
    const relativeSegments = requireRelativePath(request.relativePath);
    const bytes = Buffer.from(request.bytes);
    this.assertBudget(bytes.byteLength);

    await requireDirectoryWithoutSymlink(this.workspaceRoot);
    const target = path.resolve(
      this.workspaceRoot,
      ...archiveSegments,
      ...relativeSegments,
    );
    requireWorkspaceChild(this.workspaceRoot, target);

    let currentDirectory = this.workspaceRoot;
    for (const segment of [
      ...archiveSegments,
      ...relativeSegments.slice(0, -1),
    ]) {
      currentDirectory = path.join(currentDirectory, segment);
      await ensureDirectoryWithoutSymlink(currentDirectory);
    }

    await writeNewPrivateFile(target, bytes);
    this.writtenFiles += 1;
    this.writtenBytes += bytes.byteLength;
  }

  private assertBudget(size: number): void {
    if (
      this.writtenFiles >= this.maximumFiles ||
      size > this.maximumFileBytes ||
      this.writtenBytes + size > this.maximumTotalBytes
    ) {
      throw new Error("运行时证据超过安全写入预算。");
    }
  }
}

function requireArchiveRoot(value: string): readonly string[] {
  const segments = value.split("/");
  if (
    segments.length !== 3 ||
    segments[0] !== ".hcheck" ||
    segments[1] !== "evidence" ||
    !SAFE_SEGMENT.test(segments[2] ?? "")
  ) {
    throw new Error("运行时证据归档目录不安全。");
  }
  return segments;
}

function requireRelativePath(value: string): readonly string[] {
  if (
    value.length === 0 ||
    value.includes("\\") ||
    value.includes("\0") ||
    path.posix.isAbsolute(value) ||
    /^[A-Za-z]:\//u.test(value)
  ) {
    throw new Error("运行时证据相对路径不安全。");
  }
  const segments = value.split("/");
  if (segments.some((segment) => !SAFE_SEGMENT.test(segment))) {
    throw new Error("运行时证据相对路径不安全。");
  }
  return segments;
}

function requireWorkspaceChild(workspaceRoot: string, target: string): void {
  const relative = path.relative(workspaceRoot, target);
  if (
    relative.length === 0 ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("运行时证据目标越过工作区边界。");
  }
}

async function requireDirectoryWithoutSymlink(
  directory: string,
): Promise<void> {
  const details = await lstat(directory).catch(() => undefined);
  if (
    details === undefined ||
    details.isSymbolicLink() ||
    !details.isDirectory()
  ) {
    throw new Error("运行时证据目录不安全。");
  }
}

async function ensureDirectoryWithoutSymlink(directory: string): Promise<void> {
  const details = await lstat(directory).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw new Error("运行时证据目录检查失败。");
    },
  );
  if (details !== undefined) {
    if (details.isSymbolicLink() || !details.isDirectory()) {
      throw new Error("运行时证据目录不安全。");
    }
    return;
  }

  await mkdir(directory, { mode: 0o700 }).catch(
    async (error: NodeJS.ErrnoException) => {
      if (error.code !== "EEXIST") {
        throw new Error("运行时证据目录创建失败。");
      }
      await requireDirectoryWithoutSymlink(directory);
    },
  );
  await requireDirectoryWithoutSymlink(directory);
}

async function writeNewPrivateFile(
  target: string,
  bytes: Uint8Array,
): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let created = false;
  let identity:
    | { readonly dev: number | bigint; readonly ino: number | bigint }
    | undefined;
  try {
    handle = await open(
      target,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    created = true;
    const opened = await handle.stat();
    identity = { dev: opened.dev, ino: opened.ino };
    await handle.writeFile(bytes);
    await handle.close();
    handle = undefined;
  } catch {
    await handle?.close().catch(() => undefined);
    if (created) await unlinkOwnedFile(target, identity);
    throw new Error("运行时证据写入失败。");
  }
}

async function unlinkOwnedFile(
  target: string,
  identity:
    | {
        readonly dev: number | bigint;
        readonly ino: number | bigint;
      }
    | undefined,
): Promise<void> {
  if (identity === undefined) return;
  const details = await lstat(target).catch(() => undefined);
  if (
    details !== undefined &&
    !details.isSymbolicLink() &&
    details.isFile() &&
    details.dev === identity.dev &&
    details.ino === identity.ino
  ) {
    await unlink(target).catch(() => undefined);
  }
}

function requirePositiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError("运行时证据预算必须是正整数。");
  }
  return value;
}
