#!/bin/sh
# Rebuilds block_bpfel.o from block.bpf.c (needs clang and kernel UAPI
# headers). Commit the object: the agent embeds it.
set -eu
cd "$(dirname "$0")"
clang -O2 -g -target bpf -Wall -I"/usr/include/$(uname -m)-linux-gnu" -c block.bpf.c -o block_bpfel.o
echo "built $(pwd)/block_bpfel.o"
