import { VM_MARKER_BYTES, VM_MARKER_LIMIT } from "./vm-options.ts";

export class RegistryMarkers {
  readonly values: string[] = [];
  private failed = false;
  constructor(initial: string[]) { for (const value of initial) this.add(value); }
  private add(value: string) {
    if (this.values.includes(value)) return;
    if (value.length === 0 || value.length > 4096 || this.values.length >= VM_MARKER_LIMIT || Buffer.byteLength(JSON.stringify([...this.values, value])) > VM_MARKER_BYTES) {
      this.failed = true; throw Error("private registry marker plan exceeded its bounds");
    }
    this.values.push(value);
  }
  location(value: string) {
    try { for (const marker of new URL(value, "https://localhost").searchParams.getAll("_state")) this.add(marker); }
    catch { this.failed = true; throw Error("invalid private registry marker plan"); }
  }
  assertValid() { if (this.failed) throw Error("private registry marker plan failed"); }
}
