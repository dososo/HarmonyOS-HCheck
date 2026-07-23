import assert from "node:assert/strict";
import test from "node:test";
import {
  compareAgcApplication,
  compareAgcPrivacyDeclaration,
  compareAgcReviewAccount,
  loadAgcSnapshot,
  type AgcCredentialPort,
  type AgcReadOnlyClient,
  type AgcSnapshotCachePort,
  type CachedAgcSnapshot,
} from "../src/index.js";

class FakeCredentialPort implements AgcCredentialPort {
  public constructor(
    private readonly values: Readonly<Record<string, string | undefined>>,
  ) {}

  public async resolve(name: string) {
    const value = this.values[name];
    return value === undefined
      ? { status: "unavailable" as const, name, reason: "凭证不存在。" }
      : { status: "available" as const, name, secret: value };
  }
}

class FakeAgcClient implements AgcReadOnlyClient {
  public calls = 0;

  public constructor(
    private readonly response: Awaited<ReturnType<AgcReadOnlyClient["fetch"]>>,
  ) {}

  public async fetch() {
    this.calls += 1;
    return this.response;
  }
}

class MemoryCache implements AgcSnapshotCachePort {
  public written: CachedAgcSnapshot | undefined;

  public constructor(private readonly cached: CachedAgcSnapshot | undefined) {}

  public async read() {
    return this.cached;
  }

  public async write(snapshot: CachedAgcSnapshot) {
    this.written = snapshot;
  }
}

const snapshot = {
  schemaVersion: "0.1.0",
  capturedAt: "2026-07-10T00:00:00Z",
  source: "official-connect-api" as const,
  application: {
    appId: "REDACTED_APP_ID",
    bundleName: "com.example.app",
    name: "示例应用",
  },
  release: { versionName: "1.0.0", versionCode: 1 },
  capabilities: { unsupported: [] as string[] },
  redacted: true,
};

test("loadAgcSnapshot 无凭证时返回 unavailable 且不访问客户端", async () => {
  const client = new FakeAgcClient({ status: "success", snapshot });

  const result = await loadAgcSnapshot({
    appId: "app",
    credentialNames: {
      clientId: "HCHECK_AGC_CLIENT_ID",
      clientSecret: "HCHECK_AGC_CLIENT_SECRET",
    },
    credentials: new FakeCredentialPort({}),
    client,
    cache: new MemoryCache(undefined),
    now: new Date("2026-07-10T00:00:00Z"),
    ttlMs: 60_000,
    offline: false,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(client.calls, 0);
  assert.ok(!JSON.stringify(result).includes("SECRET"));
});

test("loadAgcSnapshot 明确区分 401、403、过期和网络失败", async () => {
  const cases = [
    [{ status: "http_error" as const, statusCode: 401 }, "unauthorized"],
    [{ status: "http_error" as const, statusCode: 403 }, "forbidden"],
    [
      { status: "http_error" as const, statusCode: 401, code: "TOKEN_EXPIRED" },
      "expired",
    ],
    [{ status: "network_error" as const }, "network_error"],
  ] as const;

  for (const [response, expected] of cases) {
    const result = await loadAgcSnapshot({
      appId: "app",
      credentialNames: {
        clientId: "HCHECK_AGC_CLIENT_ID",
        clientSecret: "HCHECK_AGC_CLIENT_SECRET",
      },
      credentials: new FakeCredentialPort({
        HCHECK_AGC_CLIENT_ID: "CLIENT",
        HCHECK_AGC_CLIENT_SECRET: "SECRET",
      }),
      client: new FakeAgcClient(response),
      cache: new MemoryCache(undefined),
      now: new Date("2026-07-10T00:00:00Z"),
      ttlMs: 60_000,
      offline: false,
    });

    assert.equal(result.status, expected);
    assert.ok(!JSON.stringify(result).includes("SECRET"));
  }
});

test("loadAgcSnapshot 离线时使用缓存并标记 TTL 过期状态", async () => {
  const result = await loadAgcSnapshot({
    appId: "app",
    credentialNames: {
      clientId: "HCHECK_AGC_CLIENT_ID",
      clientSecret: "HCHECK_AGC_CLIENT_SECRET",
    },
    credentials: new FakeCredentialPort({}),
    client: new FakeAgcClient({ status: "success", snapshot }),
    cache: new MemoryCache({
      snapshot,
      cachedAt: "2026-07-10T00:00:00Z",
      expiresAt: "2026-07-10T00:01:00Z",
    }),
    now: new Date("2026-07-10T00:02:00Z"),
    ttlMs: 60_000,
    offline: true,
  });

  assert.equal(result.status, "stale");
  assert.equal(result.offline, true);
  assert.equal(result.snapshot?.application.bundleName, "com.example.app");
});

test("compareAgcApplication 对不一致和不支持字段输出 MISMATCH/UNKNOWN", () => {
  const result = compareAgcApplication(
    { bundleName: "com.example.local", versionName: "1.0.0", versionCode: 1 },
    {
      ...snapshot,
      application: {
        ...snapshot.application,
        bundleName: "com.example.remote",
      },
      release: { versionCode: 1 },
      capabilities: { unsupported: ["release.versionName"] },
    },
  );

  assert.deepEqual(result, {
    bundleName: {
      status: "MISMATCH",
      local: "com.example.local",
      remote: "com.example.remote",
    },
    versionName: { status: "UNKNOWN", reason: "AGC 未返回或不支持该字段。" },
    versionCode: { status: "MATCH", local: 1, remote: 1 },
  });
});

test("compareAgcPrivacyDeclaration 对隐私声明 URL 输出 MATCH/MISMATCH/UNKNOWN", () => {
  const matched = compareAgcPrivacyDeclaration(
    { required: true, privacyPolicyUrl: "https://example.com/privacy" },
    {
      ...snapshot,
      privacyDeclaration: {
        status: "configured",
        url: "https://example.com/privacy",
      },
    },
  );
  assert.deepEqual(matched, {
    status: "MATCH",
    local: "https://example.com/privacy",
    remote: "https://example.com/privacy",
  });

  const mismatched = compareAgcPrivacyDeclaration(
    { required: true, privacyPolicyUrl: "https://example.com/privacy" },
    {
      ...snapshot,
      privacyDeclaration: {
        status: "configured",
        url: "https://example.com/other",
      },
    },
  );
  assert.equal(mismatched.status, "MISMATCH");

  const unknown = compareAgcPrivacyDeclaration(
    { required: true, privacyPolicyUrl: "https://example.com/privacy" },
    {
      ...snapshot,
      capabilities: { unsupported: ["privacyDeclaration"] },
    },
  );
  assert.deepEqual(unknown, {
    status: "UNKNOWN",
    reason: "AGC 未返回或不支持该字段。",
  });
});

test("compareAgcReviewAccount 只比较审核账号配置状态且不保存账号密码", () => {
  const configured = compareAgcReviewAccount(
    { requiresLogin: true },
    {
      ...snapshot,
      reviewAccount: {
        required: true,
        configured: true,
        username: "reviewer@example.com",
      },
    },
  );
  assert.deepEqual(configured, {
    status: "MATCH",
    localRequired: true,
    remoteConfigured: true,
    usernamePresent: true,
  });
  assert.ok(!JSON.stringify(configured).includes("reviewer@example.com"));

  const missing = compareAgcReviewAccount(
    { requiresLogin: true },
    {
      ...snapshot,
      reviewAccount: { required: true, configured: false },
    },
  );
  assert.equal(missing.status, "MISMATCH");

  assert.throws(
    () =>
      compareAgcReviewAccount({ requiresLogin: true }, {
        ...snapshot,
        reviewAccount: {
          required: true,
          configured: true,
          username: "reviewer@example.com",
          password: "raw-password",
        },
      } as never),
    /不得包含密码/u,
  );
});
