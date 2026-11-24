# Launch spec oracle

Prints chiaki-ng's launch spec JSON for three profiles, from chiaki-ng's own `lib/src/launchspec.c`
compiled with these minimal header shims. The output is `crates/psr-lan/tests/vectors/launchspec_oracle.txt`.

```bash
cp path/to/chiaki-ng/lib/src/launchspec.c .   # not committed: take it at the commit you check against
gcc -O1 -I. main.c launchspec.c -o oracle
./oracle   # then add the header line back
```

`chiaki/base64.h` is a plain RFC 4648 encoder standing in for chiaki-ng's OpenSSL one; the handshake key is
the only base64 in the output.
