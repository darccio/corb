import { expect, it } from "vitest";
import { isQemuVersionProbe } from "../../../e2e/helpers/qemu.ts";

it("recognizes the SDK version probe without classifying it as a guest", () => {
  expect(isQemuVersionProbe(["qemu-system-x86_64", "--version"])).toBe(true);
  expect(isQemuVersionProbe(["/usr/bin/qemu-system-x86_64", "--version"])).toBe(true);
});
it("keeps actual guests and other QEMU invocations subject to strict guest checks", () => {
  for (const argv of [
    ["qemu-system-x86_64", "-m", "1G", "-smp", "2", "-drive", "file=/tmp/owned.qcow2,format=qcow2"],
    ["qemu-system-x86_64", "--version", "-m", "1G"],
    ["qemu-system-x86_64", "-m", "1G", "--version"],
    ["qemu-system-x86_64", "--help"],
    ["other-qemu-system-x86_64", "--version"],
    ["qemu-system-aarch64", "--version"],
  ]) expect(isQemuVersionProbe(argv)).toBe(false);
});
