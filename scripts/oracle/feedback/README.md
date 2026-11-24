# Feedback oracle

Prints the controller feedback that chiaki-ng's own `lib/src/feedback.c` and `lib/src/controller.c` produce:
motion and stick state packets (protocol 9 and 12), every button event, touchpad events, and the history
packets recorded for a set of state changes. The output is `crates/psr-input/tests/vectors/feedback_oracle.txt`.

```bash
cp path/to/chiaki-ng/lib/src/feedback.c path/to/chiaki-ng/lib/src/controller.c .
cp path/to/chiaki-ng/lib/include/chiaki/feedback.h path/to/chiaki-ng/lib/include/chiaki/controller.h chiaki/
gcc -O1 -I. main.c feedback.c controller.c -lm -lws2_32 -o oracle   # -lws2_32 for htons on Windows only
./oracle > ../../../crates/psr-input/tests/vectors/feedback_oracle.txt   # then add the header line back
```

The chiaki-ng files are not committed: take them at the commit you check against. `chiaki/common.h` and
`chiaki/log.h` are minimal stand-ins (no logging). The vectors were made at chiaki-ng
`43728af2e639fecb8a7af1cd68c29820a40de973`, with WinLibs gcc on x86-64.
