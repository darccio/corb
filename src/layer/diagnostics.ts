function redactToken(token: string, final: boolean): string {
  return token.replace(/(?:https?:)?\/\/[^\s"'<>\\]+|\/[^\s"'<>\\]*[?#][^\s"'<>\\]*/gi, (value) => {
    const boundary = value.search(/[?#]/);
    let safe = boundary < 0 ? value : `${value.slice(0, boundary)}${value[boundary]}[REDACTED]`;
    safe = safe.replace(/^((?:https?:)?\/\/)([^/?#]*)(.*)$/i, (_match, scheme: string, authority: string, rest: string) => {
      const at = authority.lastIndexOf("@");
      const incomplete = at < 0 && (final && rest === "" || authority.includes(":") && !/:\d+$/.test(authority) && !/^\[[a-f\d:]+\](?::\d+)?$/i.test(authority));
      return `${scheme}${incomplete ? "[REDACTED]" : authority.slice(at + 1)}${rest}`;
    });
    return safe;
  });
}

/** Scrub complete diagnostic tokens before retaining a bounded output tail. */
export class RegistryDiagnosticRedactor {
  private token = "";
  private dropped = false;
  write(text: string): string {
    let result = "";
    for (const character of text) {
      if (/[\s"'<>\\]/.test(character)) {
        result += this.flush(false) + character;
      } else if (!this.dropped) {
        this.token += character;
        if (this.token.length > 4096) { this.token = ""; this.dropped = true; result += "[REDACTED]"; }
      }
    }
    return result;
  }
  flush(final = true): string {
    const result = redactToken(this.token, final);
    this.token = ""; this.dropped = false;
    return result;
  }
}

export function redactRegistryDiagnostics(text: string): string {
  const redactor = new RegistryDiagnosticRedactor();
  return redactor.write(text) + redactor.flush();
}
