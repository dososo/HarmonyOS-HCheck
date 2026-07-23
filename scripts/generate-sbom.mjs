import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

export async function generateSbom({ root = process.cwd() } = {}) {
  const lockfile = await readLockfile(root);
  const components = collectComponents(lockfile);
  return deepFreeze({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    metadata: {
      component: {
        type: "application",
        name: "hongjian-hcheck",
      },
    },
    components,
  });
}

async function readLockfile(root) {
  const text = await readFile(path.join(root, "pnpm-lock.yaml"), "utf8");
  return parseYaml(text, { maxAliasCount: 0, uniqueKeys: true });
}

function collectComponents(lockfile) {
  const byIdentity = new Map();
  const importers = asRecord(lockfile?.importers);

  for (const importer of Object.values(importers)) {
    collectDependencyGroup(
      byIdentity,
      asRecord(importer.dependencies),
      "required",
    );
    collectDependencyGroup(
      byIdentity,
      asRecord(importer.optionalDependencies),
      "optional",
    );
    collectDependencyGroup(
      byIdentity,
      asRecord(importer.devDependencies),
      "optional",
    );
  }

  return [...byIdentity.values()].sort((left, right) =>
    compareCodePoints(
      `${left.name}@${left.version}`,
      `${right.name}@${right.version}`,
    ),
  );
}

function collectDependencyGroup(byIdentity, dependencies, scope) {
  for (const [name, descriptor] of Object.entries(dependencies)) {
    const version = normalizeVersion(descriptor);
    if (version === undefined) continue;
    if (isLocalWorkspaceVersion(version)) continue;
    const key = `${name}@${version}`;
    const existing = byIdentity.get(key);
    const next = {
      type: "library",
      name,
      version,
      scope,
      licenses: [{ expression: "UNKNOWN" }],
      purl: packageUrl(name, version),
    };
    if (existing === undefined || existing.scope !== "required") {
      byIdentity.set(key, next);
    }
  }
}

function normalizeVersion(descriptor) {
  const raw = typeof descriptor === "string" ? descriptor : descriptor?.version;
  if (typeof raw !== "string" || raw.length === 0) return undefined;
  return raw.split("(", 1)[0];
}

function isLocalWorkspaceVersion(version) {
  return (
    version.startsWith("link:") ||
    version.startsWith("workspace:") ||
    version.startsWith("file:")
  );
}

function packageUrl(name, version) {
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function asRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
}

function compareCodePoints(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}

async function main() {
  const outputIndex = process.argv.indexOf("--output");
  const output = outputIndex === -1 ? undefined : process.argv[outputIndex + 1];
  const sbom = await generateSbom({ root: process.cwd() });
  const json = `${JSON.stringify(sbom, null, 2)}\n`;
  if (output === undefined) {
    console.log(json.trimEnd());
  } else {
    await writeFile(output, json);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
