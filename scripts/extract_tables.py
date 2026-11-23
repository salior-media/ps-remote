"""Pull every `static const uint8_t NAME[...] = { ... };` table out of a chiaki-ng C file.

Prints each table's name, start line, length and SHA-256, and with --rust OUT writes the
unique tables as Rust consts named <FN>_<NAME>, where FN is the enclosing function.
"""
import hashlib
import re
import sys

ARRAY = re.compile(r"static const uint8_t (\w+)\[[^\]]*\]\s*=\s*\{(.*?)\};", re.S)
FUNC = re.compile(r"^(?:CHIAKI_EXPORT |static )?\w[\w\s\*]*?\b(\w+)\s*\([^;]*\)\s*$", re.M)


def parse_c_bytes(body: str) -> list[int]:
    """C integer literals in an initializer: hex (0x1f), octal (00, 017) and decimal (42)."""
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.S)
    values = []
    for tok in (t.strip() for t in body.split(",")):
        if not tok:
            continue
        if tok.lower().startswith("0x"):
            v = int(tok, 16)
        elif tok.startswith("0") and len(tok) > 1:
            v = int(tok, 8)
        else:
            v = int(tok, 10)
        if not 0 <= v <= 0xFF:
            raise ValueError(f"not a byte: {tok}")
        values.append(v)
    return values


def enclosing_function(src: str, pos: int) -> str:
    best = "file"
    for m in FUNC.finditer(src, 0, pos):
        best = m.group(1)
    return best


def main() -> None:
    path = sys.argv[1]
    src = open(path, encoding="utf-8").read()
    tables = []
    for m in ARRAY.finditer(src):
        values = parse_c_bytes(m.group(2))
        line = src.count("\n", 0, m.start()) + 1
        fn = enclosing_function(src, m.start())
        digest = hashlib.sha256(bytes(values)).hexdigest()[:16]
        tables.append((fn, m.group(1), line, values, digest))
        print(f"{fn:40} {m.group(1):22} line {line:5} len {len(values):5} sha256 {digest}")
    if "--rust" in sys.argv:
        out = sys.argv[sys.argv.index("--rust") + 1]
        seen = {}
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write("// SPDX-License-Identifier: AGPL-3.0-only\n")
            f.write(f"// Generated from chiaki-ng `{sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else path}`\n")
            f.write("// by scripts/extract_tables.py. Do not edit by hand: regenerate.\n\n")
            for fn, name, line, values, digest in tables:
                const = f"{fn.upper()}_{name.upper()}"
                if digest in seen:
                    f.write(f"// chiaki-ng line {line} ({fn}::{name}) repeats `{seen[digest]}` byte for byte.\n\n")
                    continue
                seen[digest] = const
                f.write(f"/// chiaki-ng line {line}, sha256 prefix {digest}.\n")
                f.write(f"pub const {const}: &[u8; {len(values)}] = &[\n")
                for i in range(0, len(values), 16):
                    f.write("    " + ", ".join(f"0x{v:02x}" for v in values[i:i + 16]) + ",\n")
                f.write("];\n\n")


if __name__ == "__main__":
    main()
