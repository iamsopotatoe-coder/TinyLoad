# TinyLoad

simple PE packer for Windows. compresses and optionally XOR-encrypts executables into a self-extracting stub.

## how it works

TinyLoad appends your compressed payload to a copy of itself. when the packed exe runs it extracts the original to a temp folder, runs it, waits for it to finish, then deletes it.

everything is in one .cpp file, no dependencies.

## download

grab a precompiled binary from [releases](https://github.com/user/tinyload/releases) or build it yourself.

## building from source

you need MinGW (g++) installed. just run:

```
g++ -o TinyLoad.exe TinyLoad.cpp -static -O2 -s
```

or use the included `build.bat`.

## usage

```
TinyLoad.exe --i <input> [--o <output>] [--xor] [--c]
```

| flag | description |
|------|-------------|
| `--i <file>` | input exe to pack |
| `--o <file>` | output path (default: `input_packed.exe`) |
| `--xor` | rolling XOR encryption on the payload |
| `--c` | LZ77 compression |

### examples

```
TinyLoad.exe --i myapp.exe --c
TinyLoad.exe --i myapp.exe --o packed.exe --xor --c
TinyLoad.exe --i myapp.exe --xor
```

you need at least one of `--xor` or `--c`.

## compression

custom LZ77 with hash-chain matching, 64KB sliding window, and lazy evaluation. typically gets decent ratios on PE files since they have a lot of repeated structure. compression runs on the raw input first, then XOR is applied on top so patterns in the compressed stream are also hidden.

## license

MIT
