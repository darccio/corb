import { createHash } from "node:crypto";

export class LayerValidationError extends Error {
  constructor(detail: string) {
    super(`corb layer: ${detail}`);
    this.name = "LayerValidationError";
  }
}

export function fail(detail: string): never {
  throw new LayerValidationError(detail);
}

export function table(value: unknown, location: string, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${location} must be a table`);
  const result = value as Record<string, unknown>;
  for (const key of Object.keys(result)) {
    if (!keys.includes(key)) fail(`unknown key '${location}.${key}'`);
  }
  return result;
}

export function string(value: unknown, location: string, pattern?: RegExp): string {
  if (typeof value !== "string" || (pattern !== undefined && !pattern.test(value))) fail(`invalid ${location}`);
  return value;
}

export function array(value: unknown, location: string): unknown[] {
  if (!Array.isArray(value)) fail(`${location} must be an array`);
  return value;
}

export function integer(value: unknown, location: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) fail(`invalid ${location}`);
  return value;
}

export const SHA256 = /^[a-f0-9]{64}$/;
export const PACKAGE_NAME = /^[a-z0-9][a-z0-9+_.-]*$/;
export const ARCHES = ["x86_64", "aarch64"] as const;
export type LayerArch = typeof ARCHES[number];

export function architecture(value: unknown): LayerArch {
  if (value !== "x86_64" && value !== "aarch64") fail(`unsupported target architecture '${String(value)}'`);
  return value;
}

export function nativeLayerArch(value: string = process.arch): LayerArch {
  return architecture(value === "x64" ? "x86_64" : value === "arm64" ? "aarch64" : value);
}

export function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
