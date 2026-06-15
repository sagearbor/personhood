// Minimal RFC 8785 (JSON Canonicalization Scheme) implementation.
//
// Why hand-rolled: to verify the issuer's Ed25519 signature we must reproduce
// the EXACT bytes the Go issuer canonicalized and signed. The credential
// carries integer values (notably freshness_lifetime in nanoseconds) that can
// exceed Number.MAX_SAFE_INTEGER, so we cannot round-trip through JSON.parse
// without risking precision loss. This parser preserves number literals as
// strings and re-serializes integers exactly via BigInt.
//
// Scope: supports the value space Personhood credentials actually use — objects,
// arrays, strings, integers, booleans, null. Non-integer numbers fall back to
// ECMAScript Number formatting (not used by signed credentials).

type JNum = { __num: string };
type JVal = null | boolean | string | JNum | JVal[] | { [k: string]: JVal };

function isNum(v: JVal): v is JNum {
  return typeof v === "object" && v !== null && "__num" in (v as object);
}

class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  parse(): JVal {
    this.ws();
    const v = this.value();
    this.ws();
    if (this.i !== this.s.length) {
      throw new Error(`jcs: trailing data at offset ${this.i}`);
    }
    return v;
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else break;
    }
  }

  private value(): JVal {
    const c = this.s[this.i];
    if (c === undefined) throw new Error("jcs: unexpected end of input");
    switch (c) {
      case "{":
        return this.object();
      case "[":
        return this.array();
      case '"':
        return this.string();
      case "t":
      case "f":
        return this.bool();
      case "n":
        return this.nullLit();
      default:
        if (c === "-" || (c >= "0" && c <= "9")) return this.number();
        throw new Error(`jcs: unexpected character ${JSON.stringify(c)} at ${this.i}`);
    }
  }

  private object(): { [k: string]: JVal } {
    this.expect("{");
    const out: { [k: string]: JVal } = {};
    this.ws();
    if (this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      const key = this.string();
      this.ws();
      this.expect(":");
      this.ws();
      out[key] = this.value();
      this.ws();
      const ch = this.s[this.i++];
      if (ch === "}") break;
      if (ch !== ",") throw new Error(`jcs: expected ',' or '}' at ${this.i - 1}`);
    }
    return out;
  }

  private array(): JVal[] {
    this.expect("[");
    const out: JVal[] = [];
    this.ws();
    if (this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      this.ws();
      const ch = this.s[this.i++];
      if (ch === "]") break;
      if (ch !== ",") throw new Error(`jcs: expected ',' or ']' at ${this.i - 1}`);
    }
    return out;
  }

  private string(): string {
    this.expect('"');
    let out = "";
    for (;;) {
      const c = this.s[this.i++];
      if (c === undefined) throw new Error("jcs: unterminated string");
      if (c === '"') break;
      if (c === "\\") {
        const e = this.s[this.i++];
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = this.s.slice(this.i, this.i + 4);
            this.i += 4;
            out += String.fromCharCode(parseInt(hex, 16));
            break;
          }
          default:
            throw new Error(`jcs: bad escape \\${e}`);
        }
      } else {
        out += c;
      }
    }
    return out;
  }

  private number(): JNum {
    const start = this.i;
    if (this.s[this.i] === "-") this.i++;
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === undefined) break;
      if ((c >= "0" && c <= "9") || c === "." || c === "e" || c === "E" || c === "+" || c === "-") {
        this.i++;
      } else break;
    }
    return { __num: this.s.slice(start, this.i) };
  }

  private bool(): boolean {
    if (this.s.startsWith("true", this.i)) {
      this.i += 4;
      return true;
    }
    if (this.s.startsWith("false", this.i)) {
      this.i += 5;
      return false;
    }
    throw new Error(`jcs: invalid literal at ${this.i}`);
  }

  private nullLit(): null {
    if (this.s.startsWith("null", this.i)) {
      this.i += 4;
      return null;
    }
    throw new Error(`jcs: invalid literal at ${this.i}`);
  }

  private expect(ch: string): void {
    if (this.s[this.i] !== ch) {
      throw new Error(`jcs: expected ${JSON.stringify(ch)} at ${this.i}`);
    }
    this.i++;
  }
}

// RFC 8785 string escaping: escape only ", \, and control chars U+0000..U+001F.
function escapeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    switch (ch) {
      case '"': out += '\\"'; break;
      case "\\": out += "\\\\"; break;
      case "\b": out += "\\b"; break;
      case "\f": out += "\\f"; break;
      case "\n": out += "\\n"; break;
      case "\r": out += "\\r"; break;
      case "\t": out += "\\t"; break;
      default:
        if (code < 0x20) {
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

function serializeNumber(n: JNum): string {
  const raw = n.__num;
  // Integer fast path: exact via BigInt, matching Go's minimal decimal form.
  if (/^-?\d+$/.test(raw)) {
    return BigInt(raw).toString();
  }
  // Non-integer: ECMAScript Number formatting (not used by signed credentials).
  return Number(raw).toString();
}

function serialize(v: JVal): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return escapeString(v);
  if (isNum(v)) return serializeNumber(v);
  if (Array.isArray(v)) {
    return "[" + v.map(serialize).join(",") + "]";
  }
  const obj = v as { [k: string]: JVal };
  // Sort keys by UTF-16 code unit (default JS string comparison).
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => escapeString(k) + ":" + serialize(obj[k]!)).join(",") + "}";
}

/**
 * canonicalize returns the RFC 8785 canonical form of the given JSON text.
 */
export function canonicalize(text: string): string {
  return serialize(new Parser(text).parse());
}

/**
 * canonicalizeWithoutProof parses the credential JSON, removes the top-level
 * "proof" member, and returns the canonical bytes the issuer signed over.
 */
export function canonicalizeWithoutProof(text: string): Uint8Array {
  const v = new Parser(text).parse();
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new Error("jcs: credential must be a JSON object");
  }
  delete (v as { [k: string]: JVal })["proof"];
  return new TextEncoder().encode(serialize(v));
}
