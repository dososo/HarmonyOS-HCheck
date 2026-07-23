import { createHash } from "node:crypto";
import type { ProcessRunResult, ProcessRunnerPort } from "@hcheck/core";

export * from "./runtime-device.js";

export interface HdcAdapterCapability {
  readonly available: boolean;
  readonly version?: string;
  readonly reason?: string;
}

export type HdcDeviceState =
  "connected" | "offline" | "unauthorized" | "unknown";

export type HdcDeviceProbeStatus =
  | "available"
  | "unavailable"
  | "no_devices"
  | "multiple_devices"
  | "offline"
  | "unauthorized"
  | "failed"
  | "timed_out";

export interface HdcDeviceSummary {
  readonly id: string;
  readonly state: HdcDeviceState;
}

export interface HdcDeviceProbeResult {
  readonly available: boolean;
  readonly status: HdcDeviceProbeStatus;
  readonly devices: readonly HdcDeviceSummary[];
  readonly command: {
    readonly args: readonly string[];
  };
  readonly reason?: string;
  readonly exitCode?: number;
  readonly stdoutSummary?: string;
  readonly stderrSummary?: string;
}

export interface HdcDetailedDeviceProbeResult extends HdcDeviceProbeResult {
  readonly displayOnly: true;
}

export interface ProbeHdcDevicesOptions {
  readonly runner: ProcessRunnerPort;
  readonly executable?: string;
  readonly cwd?: string;
  readonly timeoutMs?: number;
}

export type HdcVersionProbeStatus =
  "available" | "unavailable" | "timed_out" | "failed";

export type HdcVersionProbeResult =
  | {
      readonly available: true;
      readonly status: "available";
      readonly version: string;
      readonly command: { readonly args: readonly string[] };
    }
  | {
      readonly available: false;
      readonly status: Exclude<HdcVersionProbeStatus, "available">;
      readonly reason: string;
      readonly command: { readonly args: readonly string[] };
    };

export const adapterStatus = "P2 Fake runner 设备探测合同已接入" as const;

export async function probeHdcVersion({
  runner,
  executable = "hdc",
  cwd,
  timeoutMs = 10_000,
}: ProbeHdcDevicesOptions): Promise<HdcVersionProbeResult> {
  const args = ["-v"] as const;
  const command = { args };
  let result: ProcessRunResult;
  try {
    result = await runner.run({
      executable,
      args,
      ...(cwd === undefined ? {} : { cwd }),
      timeoutMs,
      maxStdoutBytes: 8 * 1024,
      maxStderrBytes: 8 * 1024,
    });
  } catch {
    return {
      available: false,
      status: "unavailable",
      reason: "hdc 不可用。",
      command,
    };
  }

  if (result.status === "start_failed") {
    return {
      available: false,
      status: "unavailable",
      reason: "hdc 不可用。",
      command,
    };
  }
  if (result.status === "timed_out" || result.timedOut) {
    return {
      available: false,
      status: "timed_out",
      reason: "HDC 版本探测超时。",
      command,
    };
  }
  if (
    result.status !== "completed" ||
    result.exitCode !== 0 ||
    result.stdoutTruncated ||
    result.stderrTruncated ||
    result.signal !== undefined ||
    result.errorMessage !== undefined ||
    result.stderr.length > 0 ||
    containsHdcFailure(result.stdout)
  ) {
    return {
      available: false,
      status: "failed",
      reason: "HDC 版本探测失败。",
      command,
    };
  }

  const match =
    /^Ver: ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)[A-Za-z])(?:\r?\n)?$/u.exec(
      result.stdout,
    );
  if (match?.[1] === undefined) {
    return {
      available: false,
      status: "failed",
      reason: "HDC 版本输出格式无效。",
      command,
    };
  }
  return {
    available: true,
    status: "available",
    version: match[1],
    command,
  };
}

export async function probeHdcDevices(
  options: ProbeHdcDevicesOptions,
): Promise<HdcDeviceProbeResult> {
  return runDeviceProbe(options, ["list", "targets"], "plain");
}

export async function probeHdcDeviceDetails(
  options: ProbeHdcDevicesOptions,
): Promise<HdcDetailedDeviceProbeResult> {
  const result = await runDeviceProbe(
    options,
    ["list", "targets", "-v"],
    "detail",
  );
  return { ...result, displayOnly: true };
}

type TargetOutputFormat = "plain" | "detail";

async function runDeviceProbe(
  {
    runner,
    executable = "hdc",
    cwd,
    timeoutMs = 10_000,
  }: ProbeHdcDevicesOptions,
  args: readonly string[],
  outputFormat: TargetOutputFormat,
): Promise<HdcDeviceProbeResult> {
  const command = { args };
  let result: ProcessRunResult;
  try {
    result = await runner.run({
      executable,
      args: command.args,
      ...(cwd === undefined ? {} : { cwd }),
      timeoutMs,
      maxStdoutBytes: 8 * 1024,
      maxStderrBytes: 8 * 1024,
    });
  } catch {
    return {
      available: false,
      status: "unavailable",
      devices: [],
      command,
      reason: "hdc 不可用。",
    };
  }

  if (result.stdoutTruncated || result.stderrTruncated) {
    return {
      available: false,
      status: "failed",
      devices: [],
      command,
      reason: "HDC 设备探测输出被截断。",
    };
  }
  if (result.status === "start_failed") {
    return {
      available: false,
      status: "unavailable",
      devices: [],
      command,
      reason: "hdc 不可用。",
    };
  }
  if (result.status === "timed_out" || result.timedOut) {
    return {
      available: false,
      status: "timed_out",
      devices: [],
      command,
      reason: "hdc list targets 执行超时。",
    };
  }
  if (
    result.exitCode !== 0 ||
    result.signal !== undefined ||
    result.errorMessage !== undefined ||
    result.stderr.length > 0 ||
    containsHdcFailure(result.stdout) ||
    containsHdcFailure(result.stderr)
  ) {
    return {
      available: false,
      status: "failed",
      devices: [],
      command,
      ...(typeof result.exitCode === "number"
        ? { exitCode: result.exitCode }
        : {}),
      reason: "HDC 设备探测返回失败。",
    };
  }

  const parsed = parseTargets(result.stdout, outputFormat);
  if (!parsed.ok) {
    return {
      available: false,
      status: "failed",
      devices: [],
      command,
      reason: "HDC 设备枚举输出格式无效。",
    };
  }
  const { devices } = parsed;
  if (devices.length === 0) {
    return {
      available: true,
      status: "no_devices",
      devices,
      command,
      reason: "未发现 HDC 设备。",
    };
  }
  if (devices.some((device) => device.state === "unknown")) {
    return {
      available: false,
      status: "failed",
      devices: [],
      command,
      reason: "HDC 返回 Unknown 设备状态。",
    };
  }
  if (devices.some((device) => device.state === "unauthorized")) {
    return { available: true, status: "unauthorized", devices, command };
  }
  if (devices.some((device) => device.state === "offline")) {
    return { available: true, status: "offline", devices, command };
  }
  if (devices.length > 1) {
    return { available: true, status: "multiple_devices", devices, command };
  }
  return { available: true, status: "available", devices, command };
}

type ParseTargetsResult =
  | { readonly ok: true; readonly devices: readonly HdcDeviceSummary[] }
  | { readonly ok: false };

function parseTargets(
  stdout: string,
  outputFormat: TargetOutputFormat,
): ParseTargetsResult {
  const lines = stdout
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length === 1 && lines[0] === "[Empty]") {
    return { ok: true, devices: [] };
  }
  if (lines.length === 0) return { ok: false };

  const devices: HdcDeviceSummary[] = [];
  const connectKeys = new Set<string>();
  for (const line of lines) {
    const tokens = line.split(/\s+/u);
    const parsed =
      outputFormat === "plain"
        ? parsePlainTarget(tokens)
        : parseDetailedTarget(tokens);
    if (parsed === undefined || connectKeys.has(parsed.connectKey)) {
      return { ok: false };
    }
    connectKeys.add(parsed.connectKey);
    devices.push({
      id: hashConnectKey(parsed.connectKey),
      state: parsed.state,
    });
  }
  return { ok: true, devices };
}

interface ParsedTarget {
  readonly connectKey: string;
  readonly state: HdcDeviceState;
}

function parsePlainTarget(tokens: readonly string[]): ParsedTarget | undefined {
  if (tokens.length !== 1 && tokens.length !== 2) return undefined;
  const connectKey = tokens[0];
  if (connectKey === undefined || connectKey.length === 0) return undefined;
  const state = tokens.length === 1 ? "connected" : normalizeState(tokens[1]);
  if (state === undefined) return undefined;
  return { connectKey, state };
}

function parseDetailedTarget(
  tokens: readonly string[],
): ParsedTarget | undefined {
  if (tokens.length !== 5) return undefined;
  const [connectKey, rawTransport, rawState] = tokens;
  if (
    connectKey === undefined ||
    connectKey.length === 0 ||
    rawTransport === undefined ||
    !["usb", "tcp"].includes(rawTransport.toLowerCase())
  ) {
    return undefined;
  }
  const state = normalizeState(rawState);
  if (state === undefined) return undefined;
  return { connectKey, state };
}

function normalizeState(value: string | undefined): HdcDeviceState | undefined {
  switch (value?.toLowerCase()) {
    case "ready":
    case "connected":
      return "connected";
    case "offline":
      return "offline";
    case "unauthorized":
      return "unauthorized";
    case "unknown":
      return "unknown";
    default:
      return undefined;
  }
}

function hashConnectKey(connectKey: string): string {
  return `device:sha256:${createHash("sha256").update(connectKey).digest("hex")}`;
}

function containsHdcFailure(value: string): boolean {
  return /\[E\d{6}\]/u.test(value) || /\[fail\]/iu.test(value);
}
