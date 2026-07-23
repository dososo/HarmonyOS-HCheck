import type { ClockPort } from "@hcheck/reporters";
export class SystemClock implements ClockPort {
  public now(): Date {
    return new Date();
  }
}
