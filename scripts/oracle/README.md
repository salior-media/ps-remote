# Test oracle: chiaki-ng's own C code

chiaki-ng's tests don't cover every path the port has, for example PS5 `bright_ambassador`. This oracle compiles
chiaki-ng's code locally and prints vectors for those paths. The vectors become the Rust tests'
`tests/vectors/*_oracle.txt` files. The oracle is a local tool: it is never built into ps-remote.

To regenerate the rpcrypt vectors:

```bash
# chiaki-ng's lib/src/rpcrypt.c, lines 17..2099: the table code, without OpenSSL and without init_regist_psn
awk 'NR>=17 && NR<=2099' path/to/chiaki-ng/lib/src/rpcrypt.c > rpcrypt_part.c
gcc -O1 -Wno-unused-function -I. oracle.c -o oracle
./oracle > ../../crates/psr-crypto/tests/vectors/rpcrypt_oracle.txt   # then add the header line back
```

`chiaki/rpcrypt.h` is a minimal shim of chiaki-ng's headers, just enough to compile that part of the file.
`rpcrypt_part.c` is not committed. Take it from chiaki-ng at the commit you are checking against.
