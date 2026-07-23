import type { Confidence, SourceLocation } from "@hcheck/core";
import ts from "typescript";

export interface ArkTsSourceUnit {
  readonly uri: string;
  readonly source: string;
}

export interface ArkTsImportBinding {
  readonly uri: string;
  readonly module: string;
  readonly imported: string;
  readonly local: string;
  readonly location: SourceLocation;
}

export interface ArkTsDeclaration {
  readonly uri: string;
  readonly name: string;
  readonly kind: "function" | "variable" | "class";
  readonly exported: boolean;
  readonly location: SourceLocation;
}

export interface ArkTsCallSite {
  readonly uri: string;
  readonly callee: string;
  readonly receiver?: string;
  readonly member?: string;
  readonly importModule?: string;
  readonly importName?: string;
  readonly enclosingFunction?: string;
  readonly location: SourceLocation;
  readonly index: number;
}

export interface ArkTsSymbolIndex {
  readonly imports: readonly ArkTsImportBinding[];
  readonly declarations: readonly ArkTsDeclaration[];
  readonly callSites: readonly ArkTsCallSite[];
}

export interface CallGraphEdge {
  readonly from: string;
  readonly to: string;
  readonly kind: "imported-api" | "local-call";
  readonly location: SourceLocation;
}

export interface CallGraphBudget {
  readonly maxEdges?: number;
}

export interface BuildCallGraphOptions {
  readonly budget?: CallGraphBudget;
}

export interface CallGraphIncompleteReason {
  readonly code: "resource_budget";
  readonly limit: number;
  readonly observedAtLeast: number;
}

export interface CallGraph {
  readonly edges: readonly CallGraphEdge[];
  readonly completeness: "COMPLETE" | "INCOMPLETE";
  readonly incompleteReason?: CallGraphIncompleteReason;
}

export interface SensitiveApiDescriptor {
  readonly importModule: string;
  readonly importName: string;
  readonly member: string;
  readonly permission: string;
}

export interface ConsentGateCandidate {
  readonly api: string;
  readonly permission: string;
  readonly confidence: Confidence;
  readonly runtimeConfirmed: false;
  readonly hasPriorConsentCandidate: boolean;
  readonly location: SourceLocation;
  readonly consentLocation?: SourceLocation;
}

export function buildArkTsSymbolIndex(
  units: readonly ArkTsSourceUnit[],
): ArkTsSymbolIndex {
  const imports: ArkTsImportBinding[] = [];
  const declarations: ArkTsDeclaration[] = [];
  const callSites: ArkTsCallSite[] = [];

  for (const unit of [...units].sort((left, right) =>
    compareCodePoints(left.uri, right.uri),
  )) {
    const sourceFile = ts.createSourceFile(
      unit.uri,
      unit.source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );
    const importByLocal = new Map<string, ArkTsImportBinding>();
    collectImports(unit.uri, sourceFile, imports, importByLocal);
    collectDeclarationsAndCalls({
      uri: unit.uri,
      sourceFile,
      importByLocal,
      declarations,
      callSites,
    });
  }

  return deepFreeze({
    imports: imports.sort(compareByLocation),
    declarations: declarations.sort(compareByLocation),
    callSites: callSites
      .sort(compareByLocation)
      .map((call, index) => ({ ...call, index })),
  });
}

export function buildCallGraph(
  index: ArkTsSymbolIndex,
  options: BuildCallGraphOptions = {},
): CallGraph {
  const declarations = new Set(
    index.declarations.map(
      (declaration) => `${declaration.uri}#${declaration.name}`,
    ),
  );
  const edges: CallGraphEdge[] = [];
  const maxEdges = options.budget?.maxEdges ?? Number.POSITIVE_INFINITY;
  let incompleteReason: CallGraphIncompleteReason | undefined;

  for (const call of index.callSites) {
    if (call.enclosingFunction === undefined) continue;
    const from = `${call.uri}#${call.enclosingFunction}`;
    if (
      call.importModule !== undefined &&
      call.importName !== undefined &&
      call.member !== undefined
    ) {
      addEdge(edges, {
        from,
        to: `${call.importModule}#${call.importName}.${call.member}`,
        kind: "imported-api",
        location: call.location,
      });
      continue;
    }
    if (declarations.has(`${call.uri}#${call.callee}`)) {
      addEdge(edges, {
        from,
        to: `${call.uri}#${call.callee}`,
        kind: "local-call",
        location: call.location,
      });
    }
  }

  return deepFreeze({
    edges: edges.sort(compareEdges),
    completeness: incompleteReason === undefined ? "COMPLETE" : "INCOMPLETE",
    ...(incompleteReason === undefined ? {} : { incompleteReason }),
  });

  function addEdge(output: CallGraphEdge[], edge: CallGraphEdge): void {
    if (output.length >= maxEdges) {
      incompleteReason ??= {
        code: "resource_budget",
        limit: maxEdges,
        observedAtLeast: output.length + 1,
      };
      return;
    }
    output.push(edge);
  }
}

export function findConsentGateCandidates(
  index: ArkTsSymbolIndex,
  sensitiveApis: readonly SensitiveApiDescriptor[],
): readonly ConsentGateCandidate[] {
  const candidates: ConsentGateCandidate[] = [];

  for (const call of index.callSites) {
    const api = sensitiveApis.find(
      (item) =>
        item.importModule === call.importModule &&
        item.importName === call.importName &&
        item.member === call.member,
    );
    if (api === undefined) continue;
    const consentCall = index.callSites.find(
      (candidate) =>
        candidate.uri === call.uri &&
        candidate.enclosingFunction === call.enclosingFunction &&
        isBefore(candidate, call) &&
        candidate.member === "requestPermissionsFromUser",
    );
    candidates.push({
      api: `${api.importModule}#${api.importName}.${api.member}`,
      permission: api.permission,
      confidence: "PROBABLE",
      runtimeConfirmed: false,
      hasPriorConsentCandidate: consentCall !== undefined,
      location: call.location,
      ...(consentCall === undefined
        ? {}
        : { consentLocation: consentCall.location }),
    });
  }

  return deepFreeze(candidates.sort(compareCandidate));
}

function collectImports(
  uri: string,
  sourceFile: ts.SourceFile,
  output: ArkTsImportBinding[],
  importByLocal: Map<string, ArkTsImportBinding>,
): void {
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    if (!ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const module = statement.moduleSpecifier.text;
    const namedBindings = statement.importClause?.namedBindings;
    if (namedBindings === undefined) continue;
    if (ts.isNamedImports(namedBindings)) {
      for (const element of namedBindings.elements) {
        const binding = {
          uri,
          module,
          imported: element.propertyName?.text ?? element.name.text,
          local: element.name.text,
          location: locationOf(uri, sourceFile, element),
        };
        output.push(binding);
        importByLocal.set(binding.local, binding);
      }
    } else if (ts.isNamespaceImport(namedBindings)) {
      const binding = {
        uri,
        module,
        imported: "*",
        local: namedBindings.name.text,
        location: locationOf(uri, sourceFile, namedBindings),
      };
      output.push(binding);
      importByLocal.set(binding.local, binding);
    }
  }
}

function collectDeclarationsAndCalls(options: {
  readonly uri: string;
  readonly sourceFile: ts.SourceFile;
  readonly importByLocal: ReadonlyMap<string, ArkTsImportBinding>;
  readonly declarations: ArkTsDeclaration[];
  readonly callSites: ArkTsCallSite[];
}): void {
  const visit = (node: ts.Node, enclosingFunction?: string): void => {
    if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
      const name = node.name.text;
      options.declarations.push({
        uri: options.uri,
        name,
        kind: "function",
        exported: hasExportModifier(node),
        location: locationOf(options.uri, options.sourceFile, node.name),
      });
      ts.forEachChild(node, (child) => visit(child, name));
      return;
    }
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        options.declarations.push({
          uri: options.uri,
          name: declaration.name.text,
          kind: "variable",
          exported: hasExportModifier(node),
          location: locationOf(
            options.uri,
            options.sourceFile,
            declaration.name,
          ),
        });
      }
    }
    if (ts.isClassDeclaration(node) && node.name !== undefined) {
      options.declarations.push({
        uri: options.uri,
        name: node.name.text,
        kind: "class",
        exported: hasExportModifier(node),
        location: locationOf(options.uri, options.sourceFile, node.name),
      });
    }
    if (ts.isCallExpression(node)) {
      options.callSites.push(
        createCallSite(
          options.uri,
          options.sourceFile,
          node,
          options.importByLocal,
          enclosingFunction,
        ),
      );
    }
    ts.forEachChild(node, (child) => visit(child, enclosingFunction));
  };
  visit(options.sourceFile);
}

function createCallSite(
  uri: string,
  sourceFile: ts.SourceFile,
  node: ts.CallExpression,
  importByLocal: ReadonlyMap<string, ArkTsImportBinding>,
  enclosingFunction: string | undefined,
): ArkTsCallSite {
  if (ts.isPropertyAccessExpression(node.expression)) {
    const receiver = node.expression.expression.getText(sourceFile);
    const member = node.expression.name.text;
    const imported = ts.isIdentifier(node.expression.expression)
      ? importByLocal.get(node.expression.expression.text)
      : undefined;
    return {
      uri,
      callee: `${receiver}.${member}`,
      receiver,
      member,
      ...(imported === undefined
        ? {}
        : { importModule: imported.module, importName: imported.imported }),
      ...(enclosingFunction === undefined ? {} : { enclosingFunction }),
      location: locationOf(uri, sourceFile, node.expression.name),
      index: 0,
    };
  }
  return {
    uri,
    callee: node.expression.getText(sourceFile),
    ...(enclosingFunction === undefined ? {} : { enclosingFunction }),
    location: locationOf(uri, sourceFile, node.expression),
    index: 0,
  };
}

function hasExportModifier(node: ts.Node): boolean {
  return (
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some(
      (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
    )
  );
}

function locationOf(
  uri: string,
  sourceFile: ts.SourceFile,
  node: ts.Node,
): SourceLocation {
  const position = sourceFile.getLineAndCharacterOfPosition(
    node.getStart(sourceFile),
  );
  return {
    uri,
    line: position.line + 1,
    column: position.character + 1,
  };
}

function isBefore(left: ArkTsCallSite, right: ArkTsCallSite): boolean {
  if ((left.location.line ?? 0) !== (right.location.line ?? 0)) {
    return (left.location.line ?? 0) < (right.location.line ?? 0);
  }
  return (left.location.column ?? 0) < (right.location.column ?? 0);
}

function compareByLocation(
  left: { readonly uri: string; readonly location: SourceLocation },
  right: { readonly uri: string; readonly location: SourceLocation },
): number {
  return (
    compareCodePoints(left.uri, right.uri) ||
    (left.location.line ?? 0) - (right.location.line ?? 0) ||
    (left.location.column ?? 0) - (right.location.column ?? 0)
  );
}

function compareEdges(left: CallGraphEdge, right: CallGraphEdge): number {
  return (
    compareCodePoints(left.from, right.from) ||
    compareCodePoints(left.to, right.to) ||
    compareBySourceLocation(left.location, right.location)
  );
}

function compareCandidate(
  left: ConsentGateCandidate,
  right: ConsentGateCandidate,
): number {
  return (
    compareCodePoints(left.api, right.api) ||
    compareBySourceLocation(left.location, right.location)
  );
}

function compareBySourceLocation(
  left: SourceLocation,
  right: SourceLocation,
): number {
  return (
    compareCodePoints(left.uri, right.uri) ||
    (left.line ?? 0) - (right.line ?? 0) ||
    (left.column ?? 0) - (right.column ?? 0)
  );
}

function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => deepFreeze(item))) as T;
  }
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}
