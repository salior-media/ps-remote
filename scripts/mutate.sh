#!/usr/bin/env bash
# Usage: scripts/mutate.sh <crate> <file> <sed expression>
# Applies one deliberate break, runs the crate's tests, and restores the file with a fresh timestamp
# (restoring with `mv` keeps an older mtime, and cargo then reuses the broken build).
set -u
crate="$1"; file="$2"; expr="$3"
backup="$(mktemp)"
cp "$file" "$backup"
sed -i "$expr" "$file"
if cmp -s "$file" "$backup"; then
  echo "NOT APPLIED  $expr"
else
  out=$(cargo test -q -p "$crate" 2>&1)
  if grep -q "^error\[" <<<"$out"; then echo "DOES NOT BUILD $expr"
  elif grep -q "test result: FAILED" <<<"$out"; then echo "caught       $expr"
  else echo "NOT CAUGHT   $expr"; fi
fi
cat "$backup" > "$file"   # rewrite in place: new mtime
rm -f "$backup"
touch "$file"
