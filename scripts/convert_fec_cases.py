"""Convert chiaki-ng's test/fec_test_cases.inl into one case per line:
`k m erasures unit_size base64`, where erasures is comma-separated."""
import re
import sys

CASE = re.compile(r"\{\s*(\d+)\s*,\s*(\d+)\s*,\s*\{([^}]*)\}\s*,\s*((?:\"[^\"]*\"\s*)+),\s*(\d+)\s*\}", re.S)


def main() -> None:
    src = open(sys.argv[1], encoding="utf-8").read()
    out = open(sys.argv[2], "w", encoding="utf-8", newline="\n")
    out.write("# Converted from chiaki-ng test/fec_test_cases.inl by scripts/convert_fec_cases.py. Do not edit.\n")
    n = 0
    for m in CASE.finditer(src):
        k, mm, erasures, strings, unit = m.groups()
        es = [int(e) for e in erasures.split(",") if e.strip()]
        assert es and es[-1] == -1, f"case {n}: erasure list must end with -1"
        b64 = "".join(re.findall(r"\"([^\"]*)\"", strings))
        out.write(f"{k} {mm} {','.join(map(str, es[:-1]))} {unit} {b64}\n")
        n += 1
    print(n, "cases")


if __name__ == "__main__":
    main()
