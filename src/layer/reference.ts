import { isIP } from "node:net";
import { fail, string } from "./validate.ts";

export function validateArtifactReference(value: unknown): string {
  const reference = string(value, "artifact");
  const match = /^([^/@?#\s]+)\/([^@?#\s]+)@sha256:([a-f0-9]{64})$/.exec(reference);
  if (match === null) fail("artifact must be REGISTRY/REPOSITORY@sha256:<lowercase digest>");
  const registry = match[1]!;
  const repository = match[2]!;
  if (repository.length > 255 || !repository.split("/").every((part) => /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/.test(part))) fail("invalid OCI repository syntax");
  const authority = /^(\[[a-fA-F0-9:]+\]|[a-z0-9.-]+)(?::([0-9]+))?$/.exec(registry);
  if (authority === null) fail("invalid artifact registry");
  const host = authority[1]!;
  if (host.startsWith("[")) {
    if (isIP(host.slice(1, -1)) !== 6) fail("invalid artifact registry IPv6 address");
  } else if ((!host.includes(".") && host !== "localhost" && authority[2] === undefined)
    || host.split(".").some((part) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))) fail("artifact registry must be explicit and valid");
  if (authority[2] !== undefined && (!/^[1-9][0-9]*$/.test(authority[2]) || Number(authority[2]) > 65535)) fail("invalid artifact registry port");
  return reference;
}
