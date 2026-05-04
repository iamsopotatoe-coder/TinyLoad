# TinyLoad V3
![Custom VM](https://img.shields.io/badge/Custom%20VM-live-brightgreen) ![Better Compression](https://img.shields.io/badge/Better%20Compression-coming%20soon-blue) ![Actively Maintained](https://img.shields.io/badge/Actively%20Maintained-success?style=flat-square)

simple PE packer for Windows. compresses and encrypts executables with a custom virtual machine into a self-extracting stub.

## how it works

TinyLoad appends your compressed payload to a copy of itself. when the packed exe runs it spins up a custom VM interpreter, executes the decryption bytecode against the payload, then loads and runs it directly in RAM.

every time you pack a file the VM opcodes are randomly shuffled and baked into the stub — so every packed file speaks a different instruction set. standard disassemblers can't auto-trace the decryption without reversing the interpreter first.

everything is in one .cpp file, no dependencies.

## download

grab a precompiled binary from [releases](https://github.com/iamsopotatoe-coder/tinyload/releases) or build it yourself.

## building from source

you need MinGW (g++) installed. just run:

```
g++ -o TinyLoad.exe TinyLoad.cpp -static -O2 -s
```

or use the included `build.bat`.

## usage

```
TinyLoad.exe --i <input> [--o <output>] [--vm] [--c]
```

| flag | description |
|------|-------------|
| `--i <file>` | input exe to pack |
| `--o <file>` | output path (default: `input_packed.exe`) |
| `--vm` | custom VM encryption with randomized ISA |
| `--c` | LZ77 compression |

### examples

```
TinyLoad.exe --i myapp.exe --c
TinyLoad.exe --i myapp.exe --o packed.exe --vm --c
TinyLoad.exe --i myapp.exe --vm
```

you need at least one of `--vm` or `--c`.

## compression

custom LZ77 with hash-chain matching, 64KB sliding window, and lazy evaluation. typically gets decent ratios on PE files since they have a lot of repeated structure. compression runs on the raw input first, then VM encryption is applied on top so patterns in the compressed stream are also hidden. (we wanna improve this in v4)

## vm encryption

v3 replaces XOR with a custom 20-opcode virtual machine. the opcode table is randomly shuffled at pack time — every packed file gets a different ISA. the decryption logic is stored as bytecode with the keys embedded as immediates directly in the program. an analyst has to reverse the interpreter before they can even start on the payload.

the cipher itself is a 128-bit stream cipher using rotl/rotr key mixing, run entirely through the VM so there's no native decryption loop to fingerprint.

Graph:

<img width="1977" height="1178" alt="compression_graph" src="https://github.com/user-attachments/assets/061a34a8-bb27-4afa-b94f-1d2410ab2c29" />

## license

MIT

## Sidenotes

- This works on all files i tested it on, if it breaks on some of your files please open an issue to let me know.
- If you want to suggest any improvements or future updates please open an issue.
- if you use it, a star helps a lot <3
