import { HCheckError, normalizeRelativeUri } from "@hcheck/core";
import { parseJson5 } from "./json5.js";

export * from "./package-reader.js";

export interface ReadonlyFileSystemPort {
  readText(path: string): Promise<string>;
  exists(path: string): Promise<boolean>;
  list(path: string): Promise<readonly string[]>;
  kind(path: string): Promise<"file" | "directory" | "symlink" | "other">;
  size(path: string): Promise<number>;
  realpath(path: string): Promise<string>;
  parent(path: string): string;
  resolve(...parts: readonly string[]): string;
}

export type SdkVersion = string | number;
export type HarmonyModuleType =
  "entry" | "feature" | "har" | "shared" | "skill";

export interface ProductSnapshot {
  readonly name: string;
  readonly signingConfig?: string;
  readonly compatibleSdkVersion?: SdkVersion;
  readonly targetSdkVersion?: SdkVersion;
  readonly compileSdkVersion?: SdkVersion;
  readonly runtimeOS?: string;
  readonly bundleType?: string;
  readonly versionCode?: SdkVersion;
  readonly versionName?: string;
}

export interface ModuleSnapshot {
  readonly name: string;
  readonly type: HarmonyModuleType;
  readonly root: string;
  readonly relativePath: string;
  readonly isExternal: boolean;
  readonly moduleConfig: string;
  readonly sourceRoots: readonly string[];
  readonly deviceTypes: readonly string[];
  readonly abilities: readonly Readonly<Record<string, unknown>>[];
  readonly extensionAbilities: readonly Readonly<Record<string, unknown>>[];
  readonly requestPermissions: readonly Readonly<Record<string, unknown>>[];
  readonly metadata: readonly Readonly<Record<string, unknown>>[];
  readonly profileRefs: readonly string[];
  readonly configSource: string;
}

export interface ProjectSnapshot {
  readonly schemaVersion: "1.0.0";
  readonly root: string;
  readonly platform: "harmonyos";
  readonly appScope: string;
  readonly bundleName: string;
  readonly bundleType?: string;
  readonly versionCode?: string | number;
  readonly versionName?: string;
  readonly apiReleaseType?: string;
  readonly minCompatibleVersionCode?: string | number;
  readonly products: readonly ProductSnapshot[];
  readonly modules: readonly ModuleSnapshot[];
  readonly minimumApi?: SdkVersion;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly configSources: {
    readonly appScope: string;
    readonly buildProfile: string;
    readonly modules: readonly string[];
  };
}

export type PermissionUseWhen = "inuse" | "always";

export interface PermissionUsedScene {
  readonly abilities: readonly string[];
  readonly when: PermissionUseWhen;
}

export interface PermissionDeclarationSource {
  readonly uri: string;
  readonly logicalPath: string;
}

export interface PermissionDeclaration {
  readonly moduleName: string;
  readonly moduleType: HarmonyModuleType;
  readonly moduleRoot: string;
  readonly moduleConfig: string;
  readonly moduleIsExternal: boolean;
  readonly index: number;
  readonly name: string;
  readonly reason?: string;
  readonly usedScene?: PermissionUsedScene;
  readonly source: PermissionDeclarationSource;
}

export interface ModulePermissionInventory {
  readonly name: string;
  readonly type: HarmonyModuleType;
  readonly root: string;
  readonly configSource: string;
  readonly permissionNames: readonly string[];
  readonly declarations: readonly PermissionDeclaration[];
}

export interface PermissionInventory {
  readonly permissionNames: readonly string[];
  readonly modules: readonly ModulePermissionInventory[];
  readonly declarations: readonly PermissionDeclaration[];
}

export interface ProductIdentitySnapshot {
  readonly name: string;
  readonly signingConfig?: string;
  readonly runtimeOS?: string;
  readonly bundleType?: string;
  readonly versionCode?: SdkVersion;
  readonly versionName?: string;
  readonly effectiveBundleType?: string;
  readonly effectiveVersionCode?: SdkVersion;
  readonly effectiveVersionName?: string;
  readonly compatibleSdkVersion?: SdkVersion;
  readonly targetSdkVersion?: SdkVersion;
  readonly compileSdkVersion?: SdkVersion;
}

export interface ModuleIdentitySnapshot {
  readonly name: string;
  readonly type: HarmonyModuleType;
  readonly root: string;
  readonly configSource: string;
  readonly isExternal: boolean;
}

export interface ProjectIdentitySnapshot {
  readonly bundleName: string;
  readonly bundleType?: string;
  readonly versionCode?: SdkVersion;
  readonly versionName?: string;
  readonly apiReleaseType?: string;
  readonly minCompatibleVersionCode?: SdkVersion;
  readonly source: {
    readonly appScope: string;
    readonly buildProfile: string;
  };
  readonly products: readonly ProductIdentitySnapshot[];
  readonly modules: readonly ModuleIdentitySnapshot[];
}

export interface BuildTargetOptions {
  readonly build: {
    readonly profile: string;
    readonly clean: boolean;
    readonly command: string;
    readonly artifact: {
      readonly include: readonly string[];
      readonly exclude: readonly string[];
    };
  };
  readonly minimumApi?: number;
  readonly runtimeDevice: string;
}

export interface BuildTargetProductApi {
  readonly name: string;
  readonly compatibleSdkVersion?: SdkVersion;
  readonly targetSdkVersion?: SdkVersion;
  readonly compileSdkVersion?: SdkVersion;
}

export interface BuildTargetModule {
  readonly name: string;
  readonly type: HarmonyModuleType;
  readonly deviceTypes: readonly string[];
}

export interface BuildTargetModel {
  readonly schemaVersion: "1.0.0";
  readonly profile: string;
  readonly clean: boolean;
  readonly command: string;
  readonly artifact: {
    readonly include: readonly string[];
    readonly exclude: readonly string[];
  };
  readonly api: {
    readonly minimum: number;
    readonly source: "config" | "project";
    readonly products: readonly BuildTargetProductApi[];
  };
  readonly devices: readonly string[];
  readonly runtimeDevice: string;
  readonly modules: readonly BuildTargetModule[];
  readonly completeness: "COMPLETE" | "INCOMPLETE";
  readonly issues: readonly string[];
}

export type DependencyScope = "runtime" | "development" | "dynamic";

export interface DirectDependency {
  readonly name: string;
  readonly specifier: string;
  readonly scope: DependencyScope;
  readonly source: "oh-package.json5";
  readonly local: boolean;
}

export interface LockfilePackage {
  readonly name: string;
  readonly version: string;
  readonly direct: boolean;
  readonly dependencies: readonly string[];
}

export interface DependencyManifest {
  readonly schemaVersion: "1.0.0";
  readonly packageManager: "ohpm";
  readonly manifestPath: "oh-package.json5";
  readonly lockfilePath: "oh-package-lock.json5";
  readonly completeness: "COMPLETE" | "INCOMPLETE";
  readonly directDependencies: readonly DirectDependency[];
  readonly lockfilePackages: readonly LockfilePackage[];
  readonly issues: readonly string[];
}

export type SdkCandidateConfidence = "PROBABLE" | "POSSIBLE";

export interface DependencyGraphNode {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly direct: boolean;
  readonly scope: DependencyScope;
  readonly source: "oh-package.json5" | "oh-package-lock.json5";
  readonly dependencies: readonly string[];
  readonly paths: readonly (readonly string[])[];
}

export interface SdkCandidate {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly confidence: SdkCandidateConfidence;
  readonly source: "oh-package.json5" | "oh-package-lock.json5";
  readonly dependencyPath: readonly string[];
  readonly fingerprint: string;
  readonly disclosureNames: readonly string[];
}

export interface DependencyGraph {
  readonly schemaVersion: "1.0.0";
  readonly packageManager: "ohpm";
  readonly completeness: "COMPLETE" | "INCOMPLETE";
  readonly nodes: readonly DependencyGraphNode[];
  readonly sdkCandidates: readonly SdkCandidate[];
  readonly issues: readonly string[];
}

export interface PrivacyPolicyEvidenceFile {
  readonly path: string;
  readonly sizeBytes: number;
  readonly disclosedSdkNames: readonly string[];
}

export interface PrivacyPolicyEvidence {
  readonly schemaVersion: "1.0.0";
  readonly completeness: "COMPLETE" | "INCOMPLETE";
  readonly files: readonly PrivacyPolicyEvidenceFile[];
  readonly issues: readonly string[];
}

export interface PrivacyPolicyEvidenceOptions {
  readonly policyFiles: readonly string[];
  readonly policyUrls?: readonly string[];
  readonly offline?: boolean;
  readonly maxBytes?: number;
  readonly expectedDisclosures?: readonly string[];
}

export interface ProjectRootDetector {
  findRoot(startPath: string): Promise<string | undefined>;
}

const APP_SCOPE_PATH = "AppScope/app.json5";
const BUILD_PROFILE_PATH = "build-profile.json5";
const MODULE_CONFIG_PATH = "src/main/module.json5";
const OH_PACKAGE_PATH = "oh-package.json5";
const OH_PACKAGE_LOCK_PATH = "oh-package-lock.json5";
const MODULE_TYPES = new Set<HarmonyModuleType>([
  "entry",
  "feature",
  "har",
  "shared",
  "skill",
]);

export async function findProjectRoot(
  startPath: string,
  fs: ReadonlyFileSystemPort,
): Promise<string> {
  let candidate = await portCall(".", () => fs.resolve(startPath));
  if (
    (await portCall(".", () => fs.exists(candidate))) &&
    (await portCall(".", () => fs.kind(candidate))) === "file"
  ) {
    candidate = await portCall(".", () => fs.parent(candidate));
  }

  while (true) {
    if (await isProjectRoot(candidate, fs)) return candidate;
    const parent = await portCall(".", () => fs.parent(candidate));
    if (parent === candidate) break;
    candidate = parent;
  }

  throw new HCheckError(
    "UNSUPPORTED_PROJECT",
    "未找到合法的 HarmonyOS 工程根目录。",
  );
}

export async function createProjectSnapshot(
  root: string,
  fs: ReadonlyFileSystemPort,
): Promise<ProjectSnapshot> {
  const projectRoot = await portCall(".", () => fs.resolve(root));
  const appDocument = asRecord(
    await readJson5(projectRoot, APP_SCOPE_PATH, fs),
    APP_SCOPE_PATH,
  );
  const app = asRecord(appDocument.app, APP_SCOPE_PATH);
  const bundleName = requiredString(
    app.bundleName,
    "app.bundleName",
    APP_SCOPE_PATH,
  );
  const buildDocument = asRecord(
    await readJson5(projectRoot, BUILD_PROFILE_PATH, fs),
    BUILD_PROFILE_PATH,
  );
  const declaredModules = requireNonEmptyArray(
    buildDocument.modules,
    "modules",
    BUILD_PROFILE_PATH,
  );
  const products = parseProducts(buildDocument);
  const rootRealpath = await portCall(APP_SCOPE_PATH, () =>
    fs.realpath(projectRoot),
  );
  const modules: ModuleSnapshot[] = [];

  for (const [moduleIndex, declarationValue] of declaredModules.entries()) {
    const declaration = asRecord(declarationValue, BUILD_PROFILE_PATH);
    const declaredName = requiredString(
      declaration.name,
      "modules[].name",
      BUILD_PROFILE_PATH,
    );
    const srcPath = requiredString(
      declaration.srcPath,
      "modules[].srcPath",
      BUILD_PROFILE_PATH,
    );
    const declaredDisplayRoot = isAbsolutePath(srcPath)
      ? `@external/module-${moduleIndex + 1}`
      : normalizeModulePath(srcPath);
    const moduleAccessSource = joinRelative(
      declaredDisplayRoot,
      MODULE_CONFIG_PATH,
    );
    const moduleRoot = await portCall(moduleAccessSource, () =>
      fs.resolve(projectRoot, srcPath),
    );
    const moduleRootRealpath = await portCall(moduleAccessSource, () =>
      fs.realpath(moduleRoot),
    );
    const projectRelativePath = relativePathWithin(
      rootRealpath,
      moduleRootRealpath,
    );
    const isExternal = projectRelativePath === undefined;
    const relativePath = isExternal ? declaredDisplayRoot : projectRelativePath;
    const moduleConfig = joinRelative(relativePath, MODULE_CONFIG_PATH);
    const absoluteModuleConfig = await portCall(moduleConfig, () =>
      fs.resolve(moduleRoot, MODULE_CONFIG_PATH),
    );
    const moduleDocument = asRecord(
      await readJson5At(absoluteModuleConfig, moduleConfig, fs),
      moduleConfig,
    );
    const moduleConfigValue = asRecord(moduleDocument.module, moduleConfig);
    const moduleName = requiredString(
      moduleConfigValue.name,
      "module.name",
      moduleConfig,
    );
    if (moduleName !== declaredName) {
      throw unsupported(
        `模块声明名与 module.name 不一致：${normalizePath(moduleConfig)}。`,
        moduleConfig,
      );
    }

    const moduleType = requiredString(
      moduleConfigValue.type,
      "module.type",
      moduleConfig,
    );
    if (!MODULE_TYPES.has(moduleType as HarmonyModuleType)) {
      throw unsupported(
        `module.type 不受支持：${normalizePath(moduleConfig)}。`,
        moduleConfig,
      );
    }

    const configSource = normalizePath(moduleConfig);
    modules.push({
      name: moduleName,
      type: moduleType as HarmonyModuleType,
      root: relativePath,
      relativePath,
      isExternal,
      moduleConfig: configSource,
      sourceRoots: [joinRelative(relativePath, "src/main")],
      deviceTypes: stringArray(
        moduleConfigValue.deviceTypes,
        "module.deviceTypes",
        moduleConfig,
      ),
      abilities: recordArray(
        moduleConfigValue.abilities,
        "module.abilities",
        moduleConfig,
      ),
      extensionAbilities: recordArray(
        moduleConfigValue.extensionAbilities,
        "module.extensionAbilities",
        moduleConfig,
      ),
      requestPermissions: recordArray(
        moduleConfigValue.requestPermissions,
        "module.requestPermissions",
        moduleConfig,
      ),
      metadata: recordArray(
        moduleConfigValue.metadata,
        "module.metadata",
        moduleConfig,
      ),
      profileRefs: collectProfileReferences(moduleConfigValue),
      configSource,
    });
  }

  const minimumApi = inferMinimumApi(products);
  return {
    schemaVersion: "1.0.0",
    root: ".",
    platform: "harmonyos",
    appScope: APP_SCOPE_PATH,
    bundleName,
    ...(typeof app.bundleType === "string"
      ? { bundleType: app.bundleType }
      : {}),
    ...(isStringOrNumber(app.versionCode)
      ? { versionCode: app.versionCode }
      : {}),
    ...(typeof app.versionName === "string"
      ? { versionName: app.versionName }
      : {}),
    ...(typeof app.apiReleaseType === "string"
      ? { apiReleaseType: app.apiReleaseType }
      : {}),
    ...(isStringOrNumber(app.minCompatibleVersionCode)
      ? { minCompatibleVersionCode: app.minCompatibleVersionCode }
      : {}),
    products,
    modules,
    ...(minimumApi === undefined ? {} : { minimumApi }),
    metadata: {},
    configSources: {
      appScope: APP_SCOPE_PATH,
      buildProfile: BUILD_PROFILE_PATH,
      modules: modules.map((module) => module.configSource),
    },
  };
}

export function collectProjectIdentity(
  project: ProjectSnapshot,
): ProjectIdentitySnapshot {
  const products = project.products.map((product) => {
    const effectiveBundleType = product.bundleType ?? project.bundleType;
    const effectiveVersionCode = product.versionCode ?? project.versionCode;
    const effectiveVersionName = product.versionName ?? project.versionName;
    return {
      name: product.name,
      ...(product.signingConfig === undefined
        ? {}
        : { signingConfig: product.signingConfig }),
      ...(product.runtimeOS === undefined
        ? {}
        : { runtimeOS: product.runtimeOS }),
      ...(product.bundleType === undefined
        ? {}
        : { bundleType: product.bundleType }),
      ...(product.versionCode === undefined
        ? {}
        : { versionCode: product.versionCode }),
      ...(product.versionName === undefined
        ? {}
        : { versionName: product.versionName }),
      ...(effectiveBundleType === undefined ? {} : { effectiveBundleType }),
      ...(effectiveVersionCode === undefined ? {} : { effectiveVersionCode }),
      ...(effectiveVersionName === undefined ? {} : { effectiveVersionName }),
      ...(product.compatibleSdkVersion === undefined
        ? {}
        : { compatibleSdkVersion: product.compatibleSdkVersion }),
      ...(product.targetSdkVersion === undefined
        ? {}
        : { targetSdkVersion: product.targetSdkVersion }),
      ...(product.compileSdkVersion === undefined
        ? {}
        : { compileSdkVersion: product.compileSdkVersion }),
    };
  });
  return deepFreeze({
    bundleName: project.bundleName,
    ...(project.bundleType === undefined
      ? {}
      : { bundleType: project.bundleType }),
    ...(project.versionCode === undefined
      ? {}
      : { versionCode: project.versionCode }),
    ...(project.versionName === undefined
      ? {}
      : { versionName: project.versionName }),
    ...(project.apiReleaseType === undefined
      ? {}
      : { apiReleaseType: project.apiReleaseType }),
    ...(project.minCompatibleVersionCode === undefined
      ? {}
      : { minCompatibleVersionCode: project.minCompatibleVersionCode }),
    source: {
      appScope: project.configSources.appScope,
      buildProfile: project.configSources.buildProfile,
    },
    products,
    modules: project.modules.map((module) => ({
      name: module.name,
      type: module.type,
      root: module.root,
      configSource: module.configSource,
      isExternal: module.isExternal,
    })),
  });
}

export function createBuildTargetModel(
  project: ProjectSnapshot,
  options: BuildTargetOptions,
): BuildTargetModel {
  const minimumApi = options.minimumApi ?? project.minimumApi;
  if (
    typeof minimumApi !== "number" ||
    !Number.isInteger(minimumApi) ||
    minimumApi < 1
  ) {
    throw new HCheckError(
      "CONFIGURATION_ERROR",
      "缺少有效 project.minimum_api，无法建立构建/API 目标模型。",
    );
  }

  const devices = uniqueSorted(
    project.modules.flatMap((module) => module.deviceTypes),
  );
  const issues =
    devices.length === 0 ? ["未在模块配置中声明 deviceTypes。"] : [];

  return deepFreeze({
    schemaVersion: "1.0.0",
    profile: options.build.profile,
    clean: options.build.clean,
    command: options.build.command,
    artifact: {
      include: [...options.build.artifact.include],
      exclude: [...options.build.artifact.exclude],
    },
    api: {
      minimum: minimumApi,
      source: options.minimumApi === undefined ? "project" : "config",
      products: project.products.map((product) => ({
        name: product.name,
        ...(product.compatibleSdkVersion === undefined
          ? {}
          : { compatibleSdkVersion: product.compatibleSdkVersion }),
        ...(product.targetSdkVersion === undefined
          ? {}
          : { targetSdkVersion: product.targetSdkVersion }),
        ...(product.compileSdkVersion === undefined
          ? {}
          : { compileSdkVersion: product.compileSdkVersion }),
      })),
    },
    devices,
    runtimeDevice: options.runtimeDevice,
    modules: project.modules.map((module) => ({
      name: module.name,
      type: module.type,
      deviceTypes: [...module.deviceTypes].sort(codePointCompare),
    })),
    completeness: issues.length === 0 ? "COMPLETE" : "INCOMPLETE",
    issues,
  });
}

export async function collectDependencyManifest(
  root: string,
  fs: ReadonlyFileSystemPort,
): Promise<DependencyManifest> {
  const projectRoot = await portCall(".", () => fs.resolve(root));
  const issues: string[] = [];
  let directDependencies: readonly DirectDependency[] = [];
  let lockfilePackages: readonly LockfilePackage[] = [];

  const manifest = await readOptionalJson5(projectRoot, OH_PACKAGE_PATH, fs);
  if (manifest === undefined) {
    issues.push("缺少 oh-package.json5，无法收集直接依赖。");
  } else {
    directDependencies = collectDirectDependencies(
      asRecord(manifest, OH_PACKAGE_PATH),
    );
  }

  const lockfile = await readOptionalJson5(
    projectRoot,
    OH_PACKAGE_LOCK_PATH,
    fs,
  );
  if (lockfile === undefined) {
    issues.push("缺少 oh-package-lock.json5，无法确认间接依赖。");
  } else {
    lockfilePackages = collectLockfilePackages(
      asRecord(lockfile, OH_PACKAGE_LOCK_PATH),
      directDependencies,
    );
  }

  return deepFreeze({
    schemaVersion: "1.0.0",
    packageManager: "ohpm",
    manifestPath: OH_PACKAGE_PATH,
    lockfilePath: OH_PACKAGE_LOCK_PATH,
    completeness: issues.length === 0 ? "COMPLETE" : "INCOMPLETE",
    directDependencies,
    lockfilePackages,
    issues,
  });
}

export function createDependencyGraph(
  manifest: DependencyManifest,
): DependencyGraph {
  const directByName = new Map(
    manifest.directDependencies.map((dependency) => [
      dependency.name,
      dependency,
    ]),
  );
  const nodes = new Map<string, MutableDependencyGraphNode>();

  for (const dependency of manifest.directDependencies) {
    if (dependency.scope === "development") continue;
    const id = directDependencyId(dependency);
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        name: dependency.name,
        version: directDependencyVersion(dependency),
        direct: true,
        scope: dependency.scope,
        source: "oh-package.json5",
        dependencies: [],
        paths: [[id]],
      });
    }
  }

  for (const packageEntry of manifest.lockfilePackages) {
    const direct = directByName.get(packageEntry.name);
    const existing = nodes.get(
      packageId(packageEntry.name, packageEntry.version),
    );
    nodes.set(packageId(packageEntry.name, packageEntry.version), {
      id: packageId(packageEntry.name, packageEntry.version),
      name: packageEntry.name,
      version: packageEntry.version,
      direct: packageEntry.direct,
      scope: direct?.scope ?? "runtime",
      source: "oh-package-lock.json5",
      dependencies: [...packageEntry.dependencies],
      paths: existing?.paths ?? [],
    });
  }

  propagateDependencyPaths(nodes);
  const orderedNodes = [...nodes.values()]
    .map((node) => ({
      ...node,
      dependencies: [...node.dependencies].sort(codePointCompare),
      paths: sortPaths(node.paths),
    }))
    .sort((left, right) => codePointCompare(left.id, right.id));
  const sdkCandidates: SdkCandidate[] = orderedNodes
    .filter((node) => isSdkCandidateName(node.name) && node.paths.length > 0)
    .map((node): SdkCandidate => ({
      id: node.id,
      name: node.name,
      version: node.version,
      confidence: node.direct ? "PROBABLE" : "POSSIBLE",
      source: node.source,
      dependencyPath: node.paths[0] ?? [node.id],
      fingerprint: `sdk:${node.name}@${node.version}`,
      disclosureNames: disclosureNamesForPackage(node.name),
    }))
    .sort((left, right) => {
      const byPath = left.dependencyPath.length - right.dependencyPath.length;
      return byPath === 0 ? codePointCompare(left.id, right.id) : byPath;
    });

  return deepFreeze({
    schemaVersion: "1.0.0",
    packageManager: manifest.packageManager,
    completeness: manifest.completeness,
    nodes: orderedNodes,
    sdkCandidates,
    issues: [...manifest.issues],
  });
}

export async function collectPrivacyPolicyEvidence(
  root: string,
  fs: ReadonlyFileSystemPort,
  options: PrivacyPolicyEvidenceOptions,
): Promise<PrivacyPolicyEvidence> {
  const projectRoot = await portCall(".", () => fs.resolve(root));
  const limit = options.maxBytes ?? 256 * 1024;
  const expected = uniqueSorted(options.expectedDisclosures ?? []);
  const files: PrivacyPolicyEvidenceFile[] = [];
  const issues: string[] = [];

  for (const policyFile of options.policyFiles) {
    if (!isSafeRelativePath(policyFile)) {
      issues.push("隐私政策文件路径无效。");
      continue;
    }
    const absolutePath = await portCall(policyFile, () =>
      fs.resolve(projectRoot, policyFile),
    );
    if (
      !(await portCall(policyFile, () => fs.exists(absolutePath))) ||
      (await portCall(policyFile, () => fs.kind(absolutePath))) !== "file"
    ) {
      issues.push(`缺少隐私政策文件：${normalizePath(policyFile)}。`);
      continue;
    }
    const sizeBytes = await portCall(policyFile, () => fs.size(absolutePath));
    if (
      !Number.isSafeInteger(sizeBytes) ||
      sizeBytes < 0 ||
      sizeBytes > limit
    ) {
      issues.push(`隐私政策文件超过大小限制：${normalizePath(policyFile)}。`);
      continue;
    }
    const content = await portCall(policyFile, () => fs.readText(absolutePath));
    const actualBytes = new TextEncoder().encode(content).byteLength;
    if (actualBytes > limit) {
      issues.push(`隐私政策文件超过大小限制：${normalizePath(policyFile)}。`);
      continue;
    }
    files.push({
      path: normalizePath(policyFile),
      sizeBytes: actualBytes,
      disclosedSdkNames: expected.filter((name) =>
        content.toLocaleLowerCase().includes(name.toLocaleLowerCase()),
      ),
    });
  }

  if ((options.policyUrls?.length ?? 0) > 0 && options.offline === true) {
    issues.push("隐私政策链接处于离线状态，未联网验证。");
  }

  return deepFreeze({
    schemaVersion: "1.0.0",
    completeness: issues.length === 0 ? "COMPLETE" : "INCOMPLETE",
    files,
    issues,
  });
}

export function collectPermissionDeclarations(
  project: ProjectSnapshot,
): PermissionInventory {
  const declarations: PermissionDeclaration[] = [];
  const modules: ModulePermissionInventory[] = [];
  const permissionNames = new Set<string>();

  for (const module of project.modules) {
    const moduleDeclarations: PermissionDeclaration[] = [];
    const modulePermissionNames = new Set<string>();
    for (const [index, raw] of module.requestPermissions.entries()) {
      const logicalPath = `module.requestPermissions[${index}]`;
      const name = permissionName(
        Reflect.get(raw, "name"),
        module.configSource,
        `${logicalPath}.name`,
      );
      const reason = optionalPermissionString(
        Reflect.get(raw, "reason"),
        module.configSource,
        `${logicalPath}.reason`,
      );
      const usedScene = optionalUsedScene(
        Reflect.get(raw, "usedScene"),
        module.configSource,
        `${logicalPath}.usedScene`,
      );
      const declaration: PermissionDeclaration = {
        moduleName: module.name,
        moduleType: module.type,
        moduleRoot: module.relativePath,
        moduleConfig: module.configSource,
        moduleIsExternal: module.isExternal,
        index,
        name,
        ...(reason === undefined ? {} : { reason }),
        ...(usedScene === undefined ? {} : { usedScene }),
        source: {
          uri: module.configSource,
          logicalPath,
        },
      };
      declarations.push(declaration);
      moduleDeclarations.push(declaration);
      permissionNames.add(name);
      modulePermissionNames.add(name);
    }
    modules.push({
      name: module.name,
      type: module.type,
      root: module.relativePath,
      configSource: module.configSource,
      permissionNames: [...modulePermissionNames].sort(codePointCompare),
      declarations: moduleDeclarations,
    });
  }

  return deepFreeze({
    permissionNames: [...permissionNames].sort(codePointCompare),
    modules,
    declarations,
  });
}

export function hasDeclaredPermission(
  inventory: PermissionInventory,
  moduleName: string,
  permissionNameValue: string,
): boolean {
  return inventory.modules.some(
    (module) =>
      module.name === moduleName &&
      module.permissionNames.includes(permissionNameValue),
  );
}

async function isProjectRoot(
  candidate: string,
  fs: ReadonlyFileSystemPort,
): Promise<boolean> {
  const appPath = await portCall(APP_SCOPE_PATH, () =>
    fs.resolve(candidate, APP_SCOPE_PATH),
  );
  const buildPath = await portCall(BUILD_PROFILE_PATH, () =>
    fs.resolve(candidate, BUILD_PROFILE_PATH),
  );
  if (
    !(await isFile(appPath, APP_SCOPE_PATH, fs)) ||
    !(await isFile(buildPath, BUILD_PROFILE_PATH, fs))
  )
    return false;

  try {
    const document = asRecord(
      parseJson5(
        await portCall(BUILD_PROFILE_PATH, () => fs.readText(buildPath)),
        BUILD_PROFILE_PATH,
      ),
      BUILD_PROFILE_PATH,
    );
    return Array.isArray(document.modules) && document.modules.length > 0;
  } catch (error) {
    if (
      error instanceof HCheckError &&
      error.details.reason === "FILE_SYSTEM_ACCESS"
    ) {
      throw error;
    }
    if (
      error instanceof HCheckError &&
      (error.code === "ARTIFACT_PARSE_ERROR" ||
        error.code === "UNSUPPORTED_PROJECT")
    ) {
      return false;
    }
    throw error;
  }
}

async function isFile(
  path: string,
  sourcePath: string,
  fs: ReadonlyFileSystemPort,
): Promise<boolean> {
  return (
    (await portCall(sourcePath, () => fs.exists(path))) &&
    (await portCall(sourcePath, () => fs.kind(path))) === "file"
  );
}

async function readJson5(
  root: string,
  relativePath: string,
  fs: ReadonlyFileSystemPort,
): Promise<unknown> {
  const absolutePath = await portCall(relativePath, () =>
    fs.resolve(root, relativePath),
  );
  return readJson5At(absolutePath, relativePath, fs);
}

async function readJson5At(
  absolutePath: string,
  sourcePath: string,
  fs: ReadonlyFileSystemPort,
): Promise<unknown> {
  if (!(await isFile(absolutePath, sourcePath, fs))) {
    throw unsupported(
      `缺少必需配置：${normalizePath(sourcePath)}。`,
      sourcePath,
    );
  }
  return parseJson5(
    await portCall(sourcePath, () => fs.readText(absolutePath)),
    normalizePath(sourcePath),
  );
}

async function readOptionalJson5(
  root: string,
  relativePath: string,
  fs: ReadonlyFileSystemPort,
): Promise<unknown | undefined> {
  const absolutePath = await portCall(relativePath, () =>
    fs.resolve(root, relativePath),
  );
  if (!(await isFile(absolutePath, relativePath, fs))) return undefined;
  return readJson5At(absolutePath, relativePath, fs);
}

async function portCall<T>(
  sourcePath: string,
  operation: () => T | Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch {
    throw new HCheckError(
      "UNSUPPORTED_PROJECT",
      `无法访问工程配置：${normalizePath(sourcePath)}。`,
      {
        path: normalizePath(sourcePath),
        reason: "FILE_SYSTEM_ACCESS",
      },
    );
  }
}

function collectDirectDependencies(
  manifest: Readonly<Record<string, unknown>>,
): readonly DirectDependency[] {
  return [
    ...dependencyGroup(manifest.dependencies, "runtime"),
    ...dependencyGroup(manifest.dynamicDependencies, "dynamic"),
    ...dependencyGroup(manifest.devDependencies, "development"),
  ].sort((left, right) => codePointCompare(left.name, right.name));
}

function dependencyGroup(
  value: unknown,
  scope: DependencyScope,
): readonly DirectDependency[] {
  if (value === undefined) return [];
  const dependencies = asRecord(value, OH_PACKAGE_PATH);
  return Object.entries(dependencies).map(([name, rawSpecifier]) => {
    const specifier = dependencySpecifier(rawSpecifier);
    const local = isLocalDependencySpecifier(specifier);
    return {
      name,
      specifier: local ? redactLocalSpecifier(specifier) : specifier,
      scope,
      source: OH_PACKAGE_PATH,
      local,
    };
  });
}

function dependencySpecifier(value: unknown): string {
  if (typeof value === "string" && value.length > 0) return value;
  if (isRecord(value)) {
    const version = Reflect.get(value, "version");
    if (typeof version === "string" && version.length > 0) return version;
  }
  throw unsupported("依赖版本必须是非空字符串。", OH_PACKAGE_PATH);
}

function isLocalDependencySpecifier(value: string): boolean {
  return (
    value.startsWith("file:") ||
    value.startsWith("link:") ||
    value.startsWith("workspace:")
  );
}

function redactLocalSpecifier(value: string): string {
  const separator = value.indexOf(":");
  return `${value.slice(0, separator + 1)}[REDACTED_LOCAL_PATH]`;
}

function collectLockfilePackages(
  lockfile: Readonly<Record<string, unknown>>,
  directDependencies: readonly DirectDependency[],
): readonly LockfilePackage[] {
  const rawPackages = optionalRecord(lockfile.packages) ?? {};
  const directNames = new Set(
    directDependencies
      .filter((dependency) => !dependency.local)
      .map((dependency) => dependency.name),
  );
  return Object.entries(rawPackages)
    .map(([key, value]) =>
      lockfilePackage(key, asRecord(value, OH_PACKAGE_LOCK_PATH), directNames),
    )
    .sort((left, right) =>
      codePointCompare(
        `${left.name}@${left.version}`,
        `${right.name}@${right.version}`,
      ),
    );
}

interface MutableDependencyGraphNode {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly direct: boolean;
  readonly scope: DependencyScope;
  readonly source: "oh-package.json5" | "oh-package-lock.json5";
  readonly dependencies: readonly string[];
  paths: readonly (readonly string[])[];
}

function directDependencyId(dependency: DirectDependency): string {
  return packageId(dependency.name, directDependencyVersion(dependency));
}

function directDependencyVersion(dependency: DirectDependency): string {
  return dependency.local ? "local" : dependency.specifier;
}

function packageId(name: string, version: string): string {
  return `${name}@${version}`;
}

function propagateDependencyPaths(
  nodes: Map<string, MutableDependencyGraphNode>,
): void {
  const queue = [...nodes.values()]
    .filter((node) => node.direct && node.scope !== "development")
    .flatMap((node) => node.paths.map((path) => ({ node, path })));

  while (queue.length > 0) {
    const item = queue.shift();
    if (item === undefined) break;
    for (const dependencyId of item.node.dependencies) {
      const dependency = nodes.get(dependencyId);
      if (dependency === undefined || item.path.includes(dependency.id)) {
        continue;
      }
      const nextPath = [...item.path, dependency.id];
      if (!hasPath(dependency.paths, nextPath)) {
        dependency.paths = [...dependency.paths, nextPath];
        queue.push({ node: dependency, path: nextPath });
      }
    }
  }
}

function hasPath(
  existing: readonly (readonly string[])[],
  candidate: readonly string[],
): boolean {
  return existing.some(
    (path) =>
      path.length === candidate.length &&
      path.every((item, index) => item === candidate[index]),
  );
}

function sortPaths(
  paths: readonly (readonly string[])[],
): readonly (readonly string[])[] {
  return [...paths].sort((left, right) => {
    const byLength = left.length - right.length;
    if (byLength !== 0) return byLength;
    return codePointCompare(left.join("\0"), right.join("\0"));
  });
}

function isSdkCandidateName(name: string): boolean {
  const normalized = name.toLocaleLowerCase();
  return /(?:^|[-_/])(sdk|analytics|ad|ads|push|crash)(?:$|[-_/])/u.test(
    normalized,
  );
}

function disclosureNamesForPackage(name: string): readonly string[] {
  const packageLeaf = name.includes("/")
    ? (name.split("/").pop() ?? name)
    : name;
  const humanName = packageLeaf.replace(/[-_.]+/gu, " ").trim();
  return uniqueSorted([name, humanName].filter((item) => item.length > 0));
}

function isSafeRelativePath(value: string): boolean {
  return (
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.includes("\0") &&
    !/^[A-Za-z]:/u.test(value) &&
    !value.split("/").includes("..")
  );
}

function lockfilePackage(
  key: string,
  value: Readonly<Record<string, unknown>>,
  directNames: ReadonlySet<string>,
): LockfilePackage {
  const identity = parsePackageIdentity(key, value);
  return {
    name: identity.name,
    version: identity.version,
    direct: directNames.has(identity.name),
    dependencies: lockfileDependencyIdentities(value.dependencies),
  };
}

function parsePackageIdentity(
  key: string,
  value: Readonly<Record<string, unknown>>,
): { readonly name: string; readonly version: string } {
  const separator = key.lastIndexOf("@");
  const name = separator > 0 ? key.slice(0, separator) : key;
  const versionFromKey = separator > 0 ? key.slice(separator + 1) : undefined;
  const rawVersion = Reflect.get(value, "version");
  const version =
    typeof rawVersion === "string" && rawVersion.length > 0
      ? rawVersion
      : versionFromKey;
  if (name.length === 0 || version === undefined || version.length === 0) {
    throw unsupported("lockfile package identity 无效。", OH_PACKAGE_LOCK_PATH);
  }
  return { name, version };
}

function lockfileDependencyIdentities(value: unknown): readonly string[] {
  if (value === undefined) return [];
  return Object.entries(asRecord(value, OH_PACKAGE_LOCK_PATH))
    .map(([name, version]) => `${name}@${dependencySpecifier(version)}`)
    .sort(codePointCompare);
}

function parseProducts(
  buildDocument: Readonly<Record<string, unknown>>,
): readonly ProductSnapshot[] {
  const app = optionalRecord(buildDocument.app);
  const rawProducts = app?.products;
  if (rawProducts === undefined) return [];
  if (!Array.isArray(rawProducts))
    throw unsupported("app.products 必须是数组。", BUILD_PROFILE_PATH);

  return rawProducts.map((value) => {
    const product = asRecord(value, BUILD_PROFILE_PATH);
    return {
      name: requiredString(
        product.name,
        "app.products[].name",
        BUILD_PROFILE_PATH,
      ),
      ...(typeof product.signingConfig === "string"
        ? { signingConfig: product.signingConfig }
        : {}),
      ...(isStringOrNumber(product.compatibleSdkVersion)
        ? { compatibleSdkVersion: product.compatibleSdkVersion }
        : {}),
      ...(isStringOrNumber(product.targetSdkVersion)
        ? { targetSdkVersion: product.targetSdkVersion }
        : {}),
      ...(isStringOrNumber(product.compileSdkVersion)
        ? { compileSdkVersion: product.compileSdkVersion }
        : {}),
      ...(typeof product.runtimeOS === "string"
        ? { runtimeOS: product.runtimeOS }
        : {}),
      ...(typeof product.bundleType === "string"
        ? { bundleType: product.bundleType }
        : {}),
      ...(isStringOrNumber(product.versionCode)
        ? { versionCode: product.versionCode }
        : {}),
      ...(typeof product.versionName === "string"
        ? { versionName: product.versionName }
        : {}),
    };
  });
}

function inferMinimumApi(
  products: readonly ProductSnapshot[],
): SdkVersion | undefined {
  return (
    products.find((product) => product.compatibleSdkVersion !== undefined)
      ?.compatibleSdkVersion ??
    products.find((product) => product.targetSdkVersion !== undefined)
      ?.targetSdkVersion
  );
}

function collectProfileReferences(value: unknown): readonly string[] {
  const references = new Set<string>();
  const visit = (current: unknown): void => {
    if (typeof current === "string") {
      if (current.startsWith("$profile:")) references.add(current);
      return;
    }
    if (Array.isArray(current)) {
      for (const item of current) visit(item);
      return;
    }
    if (isRecord(current)) {
      for (const item of Object.values(current)) visit(item);
    }
  };
  visit(value);
  return [...references].sort(codePointCompare);
}

function stringArray(
  value: unknown,
  field: string,
  sourcePath: string,
): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw unsupported(`${field} 必须是字符串数组。`, sourcePath);
  }
  return [...value] as string[];
}

function recordArray(
  value: unknown,
  field: string,
  sourcePath: string,
): readonly Readonly<Record<string, unknown>>[] {
  if (value === undefined) return [];
  if (!Array.isArray(value))
    throw unsupported(`${field} 必须是数组。`, sourcePath);
  return value.map((item) => ({ ...asRecord(item, sourcePath) }));
}

function requireNonEmptyArray(
  value: unknown,
  field: string,
  sourcePath: string,
): readonly unknown[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw unsupported(`${field} 必须是非空数组。`, sourcePath);
  }
  return value;
}

function requiredString(
  value: unknown,
  field: string,
  sourcePath: string,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw unsupported(`${field} 必须是非空字符串。`, sourcePath);
  }
  return value;
}

function permissionName(value: unknown, path: string, field: string): string {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 255
  ) {
    throw invalidPermissionDeclaration(path, field);
  }
  return value;
}

function optionalPermissionString(
  value: unknown,
  path: string,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 512
  ) {
    throw invalidPermissionDeclaration(path, field);
  }
  return value;
}

function optionalUsedScene(
  value: unknown,
  path: string,
  field: string,
): PermissionUsedScene | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw invalidPermissionDeclaration(path, field);
  const record = value;
  const abilities = Reflect.get(record, "abilities");
  const when = Reflect.get(record, "when");
  if (
    !Array.isArray(abilities) ||
    abilities.length === 0 ||
    abilities.length > 64 ||
    abilities.some(
      (item) =>
        typeof item !== "string" ||
        item.trim() !== item ||
        item.length === 0 ||
        item.length > 127,
    )
  ) {
    throw invalidPermissionDeclaration(path, `${field}.abilities`);
  }
  if (when !== "inuse" && when !== "always") {
    throw invalidPermissionDeclaration(path, `${field}.when`);
  }
  return deepFreeze({
    abilities: [...abilities],
    when,
  });
}

function asRecord(
  value: unknown,
  sourcePath: string,
): Readonly<Record<string, unknown>> {
  if (!isRecord(value))
    throw unsupported(`配置结构不受支持：${sourcePath}。`, sourcePath);
  return value;
}

function optionalRecord(
  value: unknown,
): Readonly<Record<string, unknown>> | undefined {
  return isRecord(value) ? value : undefined;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringOrNumber(value: unknown): value is string | number {
  return (
    typeof value === "string" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}

function relativePathWithin(
  root: string,
  candidate: string,
): string | undefined {
  const normalizedRoot = trimTrailingSlash(normalizeResolvedPath(root));
  const normalizedCandidate = trimTrailingSlash(
    normalizeResolvedPath(candidate),
  );
  const comparisonRoot = pathComparisonKey(normalizedRoot);
  const comparisonCandidate = pathComparisonKey(normalizedCandidate);
  if (comparisonCandidate === comparisonRoot) return ".";
  if (!comparisonCandidate.startsWith(`${comparisonRoot}/`)) return undefined;
  return normalizedCandidate.slice(normalizedRoot.length + 1);
}

function normalizeResolvedPath(value: string): string {
  return value.replaceAll("\\", "/");
}

function pathComparisonKey(value: string): string {
  return /^[A-Za-z]:\//u.test(value) || value.startsWith("//")
    ? value.toLowerCase()
    : value;
}

function isAbsolutePath(value: string): boolean {
  return (
    value.startsWith("/") ||
    value.startsWith("\\") ||
    /^[A-Za-z]:[\\/]/u.test(value)
  );
}

function trimTrailingSlash(value: string): string {
  return value.length > 1 ? value.replace(/\/+$/u, "") : value;
}

function normalizeModulePath(value: string): string {
  const normalized = normalizePath(value)
    .replace(/^\.\//u, "")
    .replace(/\/$/u, "");
  return normalized || ".";
}

function joinRelative(...parts: readonly string[]): string {
  return normalizePath(parts.filter((part) => part !== ".").join("/"));
}

function normalizePath(value: string): string {
  return normalizeRelativeUri(value).replace(/\/{2,}/gu, "/");
}

function codePointCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(codePointCompare);
}

function unsupported(message: string, path: string): HCheckError {
  return new HCheckError("UNSUPPORTED_PROJECT", message, {
    path: normalizePath(path),
  });
}

function invalidPermissionDeclaration(
  path: string,
  field: string,
): HCheckError {
  return new HCheckError("UNSUPPORTED_PROJECT", "权限声明结构无效。", {
    path: normalizePath(path),
    field,
  });
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  const stack: object[] = [value];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined || seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === "object") stack.push(child);
    }
    Object.freeze(current);
  }
  return value;
}
