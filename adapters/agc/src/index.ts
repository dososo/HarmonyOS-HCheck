export interface AgcAdapterCapability {
  readonly available: boolean;
  readonly version?: string;
  readonly reason?: string;
}

export interface AgcCredentialLookup {
  readonly status: "available" | "unavailable";
  readonly name: string;
  readonly secret?: string;
  readonly reason?: string;
}

export interface AgcCredentialPort {
  resolve(name: string): Promise<AgcCredentialLookup>;
}

export interface AgcSnapshot {
  readonly schemaVersion: "0.1.0";
  readonly capturedAt: string;
  readonly source: "official-connect-api" | "recorded-sample";
  readonly application: {
    readonly appId: string;
    readonly bundleName?: string;
    readonly name?: string;
  };
  readonly release?: {
    readonly versionName?: string;
    readonly versionCode?: number;
  };
  readonly capabilities?: {
    readonly unsupported?: readonly string[];
  };
  readonly privacyDeclaration?: {
    readonly status: "configured" | "missing";
    readonly url?: string;
  };
  readonly reviewAccount?: {
    readonly required: boolean;
    readonly configured: boolean;
    readonly username?: string;
  };
  readonly redacted: true;
}

export interface CachedAgcSnapshot {
  readonly snapshot: AgcSnapshot;
  readonly cachedAt: string;
  readonly expiresAt: string;
}

export interface AgcSnapshotCachePort {
  read(appId: string): Promise<CachedAgcSnapshot | undefined>;
  write(snapshot: CachedAgcSnapshot): Promise<void>;
}

export type AgcClientResponse =
  | { readonly status: "success"; readonly snapshot: AgcSnapshot }
  | {
      readonly status: "http_error";
      readonly statusCode: number;
      readonly code?: string;
    }
  | { readonly status: "network_error" };

export interface AgcReadOnlyClient {
  fetch(request: {
    readonly appId: string;
    readonly clientId: string;
    readonly clientSecret: string;
  }): Promise<AgcClientResponse>;
}

export type AgcSnapshotLoadStatus =
  | "available"
  | "stale"
  | "unavailable"
  | "unauthorized"
  | "forbidden"
  | "expired"
  | "network_error"
  | "failed";

export interface AgcSnapshotLoadResult {
  readonly status: AgcSnapshotLoadStatus;
  readonly snapshot?: AgcSnapshot;
  readonly offline?: boolean;
  readonly reason?: string;
}

export interface LoadAgcSnapshotOptions {
  readonly appId: string;
  readonly credentialNames: {
    readonly clientId: string;
    readonly clientSecret: string;
  };
  readonly credentials: AgcCredentialPort;
  readonly client: AgcReadOnlyClient;
  readonly cache: AgcSnapshotCachePort;
  readonly now: Date;
  readonly ttlMs: number;
  readonly offline: boolean;
}

export type AgcCompareStatus = "MATCH" | "MISMATCH" | "UNKNOWN";

export type AgcCompareField =
  | {
      readonly status: "MATCH" | "MISMATCH";
      readonly local: string | number;
      readonly remote: string | number;
    }
  | {
      readonly status: "UNKNOWN";
      readonly reason: string;
    };

export interface LocalAgcComparableApplication {
  readonly bundleName: string;
  readonly versionName: string;
  readonly versionCode: number;
}

export interface AgcApplicationComparison {
  readonly bundleName: AgcCompareField;
  readonly versionName: AgcCompareField;
  readonly versionCode: AgcCompareField;
}

export interface LocalAgcPrivacyDeclaration {
  readonly required: boolean;
  readonly privacyPolicyUrl?: string;
}

export type AgcPrivacyDeclarationComparison =
  | {
      readonly status: "MATCH" | "MISMATCH";
      readonly local?: string;
      readonly remote?: string;
    }
  | {
      readonly status: "UNKNOWN";
      readonly reason: string;
    };

export interface LocalAgcReviewAccount {
  readonly requiresLogin: boolean;
}

export type AgcReviewAccountComparison =
  | {
      readonly status: "MATCH" | "MISMATCH";
      readonly localRequired: boolean;
      readonly remoteConfigured: boolean;
      readonly usernamePresent: boolean;
    }
  | {
      readonly status: "UNKNOWN";
      readonly reason: string;
    };

export const adapterStatus = "P1 只读 DTO、凭证和缓存合同已接入" as const;

export async function loadAgcSnapshot({
  appId,
  credentialNames,
  credentials,
  client,
  cache,
  now,
  ttlMs,
  offline,
}: LoadAgcSnapshotOptions): Promise<AgcSnapshotLoadResult> {
  const cached = await cache.read(appId);
  if (offline) {
    if (cached === undefined) {
      return { status: "unavailable", offline: true, reason: "无 AGC 缓存。" };
    }
    return {
      status:
        now.getTime() > Date.parse(cached.expiresAt) ? "stale" : "available",
      snapshot: cached.snapshot,
      offline: true,
    };
  }

  const clientId = await credentials.resolve(credentialNames.clientId);
  const clientSecret = await credentials.resolve(credentialNames.clientSecret);
  if (
    clientId.status !== "available" ||
    clientSecret.status !== "available" ||
    clientId.secret === undefined ||
    clientSecret.secret === undefined
  ) {
    return { status: "unavailable", reason: "AGC 凭证不可用。" };
  }

  const response = await client.fetch({
    appId,
    clientId: clientId.secret,
    clientSecret: clientSecret.secret,
  });
  if (response.status === "success") {
    const cachedSnapshot = {
      snapshot: response.snapshot,
      cachedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    };
    await cache.write(cachedSnapshot);
    return { status: "available", snapshot: response.snapshot };
  }
  if (response.status === "network_error") {
    return { status: "network_error", reason: "AGC 网络失败。" };
  }
  if (response.statusCode === 401 && response.code === "TOKEN_EXPIRED") {
    return { status: "expired", reason: "AGC 凭证已过期。" };
  }
  if (response.statusCode === 401) {
    return { status: "unauthorized", reason: "AGC 认证失败。" };
  }
  if (response.statusCode === 403) {
    return { status: "forbidden", reason: "AGC 权限不足。" };
  }
  return { status: "failed", reason: "AGC 只读请求失败。" };
}

export function compareAgcApplication(
  local: LocalAgcComparableApplication,
  remote: AgcSnapshot,
): AgcApplicationComparison {
  const unsupported = new Set(remote.capabilities?.unsupported ?? []);
  return {
    bundleName: compareField(
      local.bundleName,
      remote.application.bundleName,
      unsupported.has("application.bundleName"),
    ),
    versionName: compareField(
      local.versionName,
      remote.release?.versionName,
      unsupported.has("release.versionName"),
    ),
    versionCode: compareField(
      local.versionCode,
      remote.release?.versionCode,
      unsupported.has("release.versionCode"),
    ),
  };
}

export function compareAgcPrivacyDeclaration(
  local: LocalAgcPrivacyDeclaration,
  remote: AgcSnapshot,
): AgcPrivacyDeclarationComparison {
  const unsupported = new Set(remote.capabilities?.unsupported ?? []);
  if (
    unsupported.has("privacyDeclaration") ||
    remote.privacyDeclaration === undefined
  ) {
    return { status: "UNKNOWN", reason: "AGC 未返回或不支持该字段。" };
  }
  if (!local.required) {
    return remote.privacyDeclaration.status === "missing"
      ? privacyComparison("MATCH")
      : privacyComparison("MISMATCH", undefined, remote.privacyDeclaration.url);
  }
  const remoteUrl = remote.privacyDeclaration.url;
  if (local.privacyPolicyUrl === undefined || remoteUrl === undefined) {
    return privacyComparison("MISMATCH", local.privacyPolicyUrl, remoteUrl);
  }
  return privacyComparison(
    local.privacyPolicyUrl === remoteUrl ? "MATCH" : "MISMATCH",
    local.privacyPolicyUrl,
    remoteUrl,
  );
}

export function compareAgcReviewAccount(
  local: LocalAgcReviewAccount,
  remote: AgcSnapshot,
): AgcReviewAccountComparison {
  const unsupported = new Set(remote.capabilities?.unsupported ?? []);
  if (unsupported.has("reviewAccount") || remote.reviewAccount === undefined) {
    return { status: "UNKNOWN", reason: "AGC 未返回或不支持该字段。" };
  }
  if (hasPasswordField(remote.reviewAccount)) {
    throw new TypeError("审核账号快照不得包含密码。");
  }
  const matches = local.requiresLogin
    ? remote.reviewAccount.configured
    : !remote.reviewAccount.required;
  return {
    status: matches ? "MATCH" : "MISMATCH",
    localRequired: local.requiresLogin,
    remoteConfigured: remote.reviewAccount.configured,
    usernamePresent: remote.reviewAccount.username !== undefined,
  };
}

function compareField(
  local: string | number,
  remote: string | number | undefined,
  unsupported: boolean,
): AgcCompareField {
  if (unsupported || remote === undefined) {
    return { status: "UNKNOWN", reason: "AGC 未返回或不支持该字段。" };
  }
  return local === remote
    ? { status: "MATCH", local, remote }
    : { status: "MISMATCH", local, remote };
}

function privacyComparison(
  status: "MATCH" | "MISMATCH",
  local?: string,
  remote?: string,
): AgcPrivacyDeclarationComparison {
  return {
    status,
    ...(local === undefined ? {} : { local }),
    ...(remote === undefined ? {} : { remote }),
  };
}

function hasPasswordField(value: object): boolean {
  return Object.hasOwn(value, "password");
}
