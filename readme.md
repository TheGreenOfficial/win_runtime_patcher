# Eternal Runtime Patcher

Tiny 64-bit runtime patcher that applies single-byte patches from a `patches.1337` file to a running 64-bit executable. Built for reverse-engineering...
research on binaries you control...

## Build
```bash
# Build (64-bit)
gcc -m64 c.c -o eternalPatcher x64.exe -lpsapi
