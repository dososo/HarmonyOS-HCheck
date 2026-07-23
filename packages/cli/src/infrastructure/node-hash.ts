import { createHash } from "node:crypto";
import type { HashPort } from "@hcheck/core";

export class NodeHash implements HashPort {
  public async sha256(
    content: string | Uint8Array,
  ): Promise<`sha256:${string}`> {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  }
}
