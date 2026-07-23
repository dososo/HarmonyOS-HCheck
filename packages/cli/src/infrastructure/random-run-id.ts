import { randomUUID } from "node:crypto";
import type { RunIdPort } from "@hcheck/reporters";
export class RandomRunId implements RunIdPort {
  public next(): string {
    return `run-${randomUUID()}`;
  }
}
