#!/usr/bin/env bash
# Regenerate crates/psr-crypto/src/rpcrypt_tables.rs from a chiaki-ng checkout.
# Usage: scripts/gen-rpcrypt-tables.sh path/to/chiaki-ng
set -euo pipefail
src="$1/lib/src/rpcrypt.c"
out="$(dirname "$0")/../crates/psr-crypto/src/rpcrypt_tables.rs"
python -I "$(dirname "$0")/extract_tables.py" "$src" lib/src/rpcrypt.c --rust "$out" > /dev/null
# chiaki-ng declares the HMAC keys at file scope after init_regist_psn; name them plainly.
sed -i -e 's/CHIAKI_RPCRYPT_INIT_REGIST_PSN_HMAC_KEY/HMAC_KEY/g' -e 's/CHIAKI_RPCRYPT_//g' \
    -e 's/FILE_ECHO_B/ECHO_B/' -e 's/BRIGHT_AMBASSADOR_PS4_PRE10_ECHO_A/ECHO_A/' "$out"
sed -i '1a //! Key tables from chiaki-ng `lib/src/rpcrypt.c`. Regenerate with `scripts/gen-rpcrypt-tables.sh`.' "$out"
