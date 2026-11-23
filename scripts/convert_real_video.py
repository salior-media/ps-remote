"""Convert chiaki-ng's test/takion_av_packet_parse_real_video.inl into:
  key <handshake_key hex> <ecdh_secret hex> <crypt_index>
  <n> <packet base64> <nalu base64> <nalu size>"""
import re
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
from extract_tables import parse_c_bytes  # noqa: E402


def main() -> None:
    src = open(sys.argv[1], encoding="utf-8").read()
    arr = lambda name: bytes(parse_c_bytes(re.search(name + r"\[\]\s*=\s*\{(.*?)\};", src, re.S).group(1)))
    index = int(re.search(r"crypt_index\s*=\s*(\d+)", src).group(1))
    decode = re.compile(r"uint8_t (packet|nalu)_(\d+)\[(\d+)\];.*?chiaki_base64_decode\(\"([^\"]*)\"", re.S)
    found = {}
    for kind, n, size, b64 in decode.findall(src):
        found.setdefault(int(n), {})[kind] = (int(size), b64)
    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as out:
        out.write("# Converted from chiaki-ng test/takion_av_packet_parse_real_video.inl by scripts/convert_real_video.py.\n")
        out.write(f"key {arr('handshake_key').hex()} {arr('ecdh_secret').hex()} {index}\n")
        for n in sorted(found):
            (psize, pb64), (nsize, nb64) = found[n]["packet"], found[n]["nalu"]
            out.write(f"{n} {psize} {pb64} {nsize} {nb64}\n")
    print(len(found), "packets")


if __name__ == "__main__":
    main()
