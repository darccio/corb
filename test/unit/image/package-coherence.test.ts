import { describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { REQUIRED_PACKAGES, archiveIdentity, assertFile, assertIdentity, assertRequired, gzipMembers, parseInstalled, validateReport } from "../../../image/helpers/package-coherence.mjs";

const checksum = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
function records() {
  return REQUIRED_PACKAGES.map((P: string) => ({ P, V: "1-r0", C: "Q1control", A: "x86_64", p: P === "openssh-client-krb5" ? "cmd:ssh=1-r0" : "", files: [] }));
}
describe("base package coherence", () => {
  it("parses real installed control fields and package ownership", () => {
    expect(parseInstalled("P:libssl3\nV:3.5.4-r0\nC:Q1old\nA:x86_64\nF:usr/lib\nR:libssl.so.3\np:so:libssl.so.3=3\n\n"))
      .toEqual([{ P: "libssl3", V: "3.5.4-r0", C: "Q1old", A: "x86_64", p: "so:libssl.so.3=3", files: ["/usr/lib/libssl.so.3"] }]);
  });
  it("rejects stale OpenSSL records even when current library bytes match a current signed archive", () => {
    const record = { P: "libssl3", V: "3.5.4-r0", C: "Q1old", A: "x86_64" };
    const archive = { name: "libssl3", version: "3.5.9-r0", checksum: "Q1current", arch: "x86_64" };
    expect(assertFile(record, "/usr/lib/libssl.so.3", Buffer.from("current"), Buffer.from("current"))).toBe(checksum("current"));
    expect(() => assertIdentity(record, archive)).toThrow(/libssl3: recorded version 3.5.4-r0, V=3.5.4-r0 differs from signed archive 3.5.9-r0/);
  });
  it("accepts APK's target architecture record for a signed noarch package", () => {
    assertIdentity({ P: "alpine-baselayout", V: "3.7.2-r0", C: "Q1control", A: "x86_64" },
      { name: "alpine-baselayout", version: "3.7.2-r0", checksum: "Q1control", arch: "noarch" });
    expect(() => assertIdentity({ P: "libssl3", V: "3.5.9-r0", C: "Q1control", A: "x86_64" },
      { name: "libssl3", version: "3.5.9-r0", checksum: "Q1control", arch: "aarch64" })).toThrow(/A=x86_64/);
  });
  it("rejects a control checksum mismatch at the same version", () => {
    expect(() => assertIdentity({ P: "libssl3", V: "3.5.9-r0", C: "Q1old", A: "x86_64" },
      { name: "libssl3", version: "3.5.9-r0", checksum: "Q1current", arch: "x86_64" })).toThrow(/C=Q1old/);
  });
  it("rejects altered library bytes and identifies their package and version", () => {
    expect(() => assertFile({ P: "libcrypto3", V: "3.5.9-r0" }, "/usr/lib/libcrypto.so.3", Buffer.from("signed"), Buffer.from("altered")))
      .toThrow(/libcrypto3: recorded version 3.5.9-r0.*bytes.*differ from signed archive/);
  });
  it("requires every declared package record", () => {
    expect(() => assertRequired(records().filter((record: {P: string}) => record.P !== "nodejs"))).toThrow(/nodejs.*missing/);
  });
  it("requires exactly the capability-preserving SSH provider", () => {
    assertRequired(records());
    expect(() => assertRequired([...records(), { P: "openssh-client-default", V: "1-r0" }])).toThrow(/conflicts/);
    const noProvider = records();
    noProvider.find((record: {P: string}) => record.P === "openssh-client-krb5").p = "";
    expect(() => assertRequired(noProvider)).toThrow(/missing cmd:ssh/);
  });
  it("separates all gzip members without treating the package payload as control", () => {
    const first = gzipSync("signature");
    const second = gzipSync("control");
    const third = gzipSync("payload");
    const members = gzipMembers(Buffer.concat([first, second, third]));
    expect(members.map((member: {data: Buffer}) => member.data.toString())).toEqual(["signature", "control", "payload"]);
    expect(members[1].compressed).toEqual(second);
    expect(() => archiveIdentity(Buffer.concat([first, second, third]))).toThrow(/no .PKGINFO/);
  });
  it("rechecks native bytes from signed build evidence before publication", () => {
    const entries = records();
    const database = Buffer.from(entries.map((record: {P: string; V: string; C: string; A: string; p: string}) => `P:${record.P}\nV:${record.V}\nC:${record.C}\nA:${record.A}\np:${record.p}`).join("\n\n"));
    const report = { packages: entries.map((entry: {P: string; V: string; A: string; C: string}) => ({ name: entry.P, version: entry.V, arch: entry.A, checksum: entry.C })), databaseSha256: checksum(database), files: [{ package: "libssl3", version: "1-r0", checksum: "Q1control", path: "/usr/lib/libssl.so.3", sha256: checksum("signed") }] };
    expect(validateReport(report, database, () => Buffer.from("signed"))).toBe(report);
    expect(() => validateReport(report, database, () => Buffer.from("changed"))).toThrow(/libssl3: recorded version 1-r0/);
  });
});
