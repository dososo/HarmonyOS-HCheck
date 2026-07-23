import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_IGNORED_DIRS = new Set([
  ".git",
  ".worktrees",
  "node_modules",
  "dist",
  "build",
  "coverage",
]);

export async function validateMarkdownLinks({ root = process.cwd() } = {}) {
  const absoluteRoot = path.resolve(root);
  const files = await collectMarkdownFiles(absoluteRoot);
  const errors = [];

  for (const file of files) {
    const text = await readFile(file, "utf8");
    for (const target of extractMarkdownLinkTargets(text)) {
      const error = validateLocalTarget(absoluteRoot, file, target);
      if (error !== undefined) errors.push(error);
    }
  }

  errors.sort();
  return { ok: errors.length === 0, errors };
}

async function collectMarkdownFiles(root) {
  const files = [];

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!DEFAULT_IGNORED_DIRS.has(entry.name)) await visit(absolute);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith(".md")) files.push(absolute);
    }
  }

  await visit(root);
  return files.sort(compareCodePoints);
}

function extractMarkdownLinkTargets(text) {
  const targets = [];
  let inFence = false;
  for (const line of text.split(/\r?\n/u)) {
    if (/^\s*(```|~~~)/u.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;

    const linkPattern = /!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/gu;
    for (const match of line.matchAll(linkPattern)) {
      targets.push(match[1]);
    }
  }
  return targets;
}

function validateLocalTarget(root, sourceFile, rawTarget) {
  const target = stripAngleBrackets(rawTarget.trim());
  if (isSkippedTarget(target)) return undefined;
  const [withoutHash] = target.split("#", 1);
  const [withoutQuery] = withoutHash.split("?", 1);
  if (withoutQuery.length === 0) return undefined;
  if (target.startsWith("file:")) {
    return `${relative(root, sourceFile)} 使用了禁止的 file URI 链接。`;
  }
  if (
    path.posix.isAbsolute(withoutQuery) ||
    path.win32.isAbsolute(withoutQuery)
  ) {
    return `${relative(root, sourceFile)} 使用了绝对路径链接。`;
  }

  const decoded = decodeURIComponent(withoutQuery);
  const resolved = path.resolve(path.dirname(sourceFile), decoded);
  if (!isInside(root, resolved)) {
    return `${relative(root, sourceFile)} 链接越出仓库边界：${target}`;
  }
  if (!existsSync(resolved)) {
    return `${relative(root, sourceFile)} 链接不存在：${target}`;
  }
  return undefined;
}

function stripAngleBrackets(value) {
  if (value.startsWith("<") && value.endsWith(">")) {
    return value.slice(1, -1);
  }
  return value;
}

function isSkippedTarget(target) {
  return (
    target.startsWith("#") ||
    target.startsWith("http://") ||
    target.startsWith("https://") ||
    target.startsWith("mailto:") ||
    target.startsWith("tel:")
  );
}

function isInside(root, file) {
  const relativePath = path.relative(root, file);
  return (
    relativePath.length === 0 ||
    (!relativePath.startsWith("..") && !path.isAbsolute(relativePath))
  );
}

function relative(root, file) {
  return path.relative(root, file).replaceAll(path.sep, "/");
}

function compareCodePoints(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function main() {
  const result = await validateMarkdownLinks({ root: process.cwd() });
  for (const error of result.errors) console.error(error);
  process.exitCode = result.ok ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
