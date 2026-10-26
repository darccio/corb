export function cleanVmOptions(value: unknown, markers: readonly string[], limits = { nodes: 200_000, depth: 64, text: 16 * 1024 ** 2, bytes: 512 * 1024 ** 2 }): boolean {
  if (markers.length === 0 || markers.length > 32 || markers.some((marker) => marker.length === 0 || marker.length > 4096)) throw Error("invalid private marker plan");
  const needles = markers.map((marker) => Buffer.from(marker)); const seen = new WeakSet<object>();
  let nodes = 0; let text = 0; let bytes = 0;
  const bounded = (ok: boolean) => { if (!ok) throw Error("VM options inspection exceeded its bounds"); };
  const string = (value: string) => { text += Buffer.byteLength(value); bounded(text <= limits.text); return markers.every((marker) => !value.includes(marker)); };
  function inspect(value: unknown, depth: number): boolean {
    bounded(++nodes <= limits.nodes && depth <= limits.depth);
    if (typeof value === "string") return string(value);
    if (typeof value === "symbol") return value.description === undefined || string(value.description);
    if (value === null || (typeof value !== "object" && typeof value !== "function")) return true;
    if (seen.has(value)) return true; seen.add(value);
    if (value instanceof ArrayBuffer || value instanceof SharedArrayBuffer || ArrayBuffer.isView(value)) {
      const view = ArrayBuffer.isView(value) ? Buffer.from(value.buffer, value.byteOffset, value.byteLength) : Buffer.from(value);
      bytes += view.byteLength; bounded(bytes <= limits.bytes);
      return needles.every((needle) => view.indexOf(needle) === -1);
    }
    if (value instanceof Map) { for (const [key, item] of value) if (!inspect(key, depth + 1) || !inspect(item, depth + 1)) return false; }
    if (value instanceof Set) { for (const item of value) if (!inspect(item, depth + 1)) return false; }
    const keys = Reflect.ownKeys(value); bounded(keys.length <= limits.nodes - nodes);
    for (const key of keys) {
      if (!inspect(key, depth + 1)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
      if (!Object.hasOwn(descriptor, "value")) throw Error("VM options inspection encountered an accessor");
      if (!inspect(descriptor.value, depth + 1)) return false;
    }
    return true;
  }
  return inspect(value, 0);
}

export function observeOptionsCall<T extends (...args: never[]) => unknown>(original: T, observe: (options: unknown) => void): T {
  return function (this: unknown, ...args: unknown[]) { observe(args[0]); return Reflect.apply(original, this, args); } as unknown as T;
}
