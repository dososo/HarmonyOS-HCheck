import { constants } from "node:fs";
import { lstat, open, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import type { ReadonlyFileSystemPort } from "@hcheck/project-model";

const MAX_READ_BYTES = 1024 * 1024;
const MAX_BINARY_READ_BYTES = 64 * 1024 * 1024;

export class NodeFileSystem implements ReadonlyFileSystemPort {
  public async readText(file: string): Promise<string> {
    const content = await this.readRegularFile(file, MAX_READ_BYTES);
    return new TextDecoder("utf-8", { fatal: true }).decode(content);
  }

  public readFile(file: string): Promise<Uint8Array> {
    return this.readRegularFile(file, MAX_BINARY_READ_BYTES);
  }

  private async readRegularFile(
    file: string,
    maximumBytes: number,
  ): Promise<Uint8Array> {
    const before = await lstat(file);
    if (!isSafelyReadableFile(before, maximumBytes)) {
      throw new Error("文件超过安全读取限制。");
    }
    const handle = await open(
      file,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const opened = await handle.stat();
      if (
        !opened.isFile() ||
        opened.size !== before.size ||
        opened.dev !== before.dev ||
        opened.ino !== before.ino
      )
        throw new Error("文件在读取前发生变化。");
      const buffer = Buffer.allocUnsafe(maximumBytes + 1);
      let total = 0;
      while (total <= maximumBytes) {
        const { bytesRead } = await handle.read(
          buffer,
          total,
          maximumBytes + 1 - total,
          null,
        );
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      const after = await handle.stat();
      if (total > maximumBytes || after.size !== opened.size)
        throw new Error("文件超过安全读取限制。");
      return buffer.subarray(0, total);
    } finally {
      await handle.close();
    }
  }
  public async exists(candidate: string): Promise<boolean> {
    return lstat(candidate).then(
      () => true,
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return false;
        throw error;
      },
    );
  }
  public list(directory: string): Promise<readonly string[]> {
    return readdir(directory);
  }
  public async kind(
    candidate: string,
  ): Promise<"file" | "directory" | "symlink" | "other"> {
    const value = await lstat(candidate);
    if (value.isSymbolicLink()) return "symlink";
    if (value.isFile()) return "file";
    if (value.isDirectory()) return "directory";
    return "other";
  }
  public async size(file: string): Promise<number> {
    return (await stat(file)).size;
  }
  public realpath(candidate: string): Promise<string> {
    return realpath(candidate);
  }
  public parent(candidate: string): string {
    return path.dirname(path.resolve(candidate));
  }
  public resolve(...parts: readonly string[]): string {
    return path.resolve(...parts);
  }
}

function isSafelyReadableFile(
  stats: Awaited<ReturnType<typeof lstat>>,
  maximumBytes: number,
): boolean {
  return (
    Number.isSafeInteger(stats.size) &&
    stats.size >= 0 &&
    stats.size <= maximumBytes &&
    stats.isFile() &&
    !stats.isSymbolicLink()
  );
}

export { MAX_BINARY_READ_BYTES, MAX_READ_BYTES };
