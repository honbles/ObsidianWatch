#!/bin/sh
# Rebuilds proc_bpfel.o from proc.bpf.c. Needs clang (12 or later) and the
# kernel UAPI headers (linux-libc-dev). Commit the object: the agent embeds it
# so ordinary builds need no clang.
set -eu
cd "$(dirname "$0")"
arch_inc="/usr/include/$(uname -m)-linux-gnu"
clang -O2 -g -target bpf -Wall -I"$arch_inc" -c proc.bpf.c -o proc_bpfel.o
echo "built $(pwd)/proc_bpfel.o"
