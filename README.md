<img src="https://github.com/user-attachments/assets/ada41458-c6f8-4916-b09d-39d37dcacfd1" alt="github-social-preview" width="70%" />

# TinyLoad V7.0
![Version](https://img.shields.io/badge/version-v7.0-e84393?style=flat&logo=cplusplus&logoColor=white&labelColor=0d0d0d)
![Actively Maintained](https://img.shields.io/badge/Actively%20Maintained-2ed573?style=flat&logo=checkmarx&logoColor=white)
[![Awesome](https://awesome.re/mentioned-badge.svg)](https://github.com/gmh5225/awesome-game-security)

simple PE/crypter for Windows. compresses and encrypts executables with a custom virtual machine into a self-extracting stub.

## how it works

TinyLoad appends your compressed payload to a copy of itself. when the packed exe runs it uses a custom VM interpreter, executes the decryption bytecode against the payload, then loads and runs it directly in RAM. every time you pack a file the VM opcodes are randomly changed and put into 4 independently keyed tables. Everything is in one c++ file and has no dependencies!

Workflow:

<img width="720" height="1454" alt="workflow!" src="https://github.com/user-attachments/assets/e51e3556-edb9-43f2-a85e-de5323b0403f" />

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
TinyLoad.exe --i <input> [--o <output>] [--vm] [--c] [--veh]
```

| flag | description |
|------|-------------|
| `--i <file>` | input exe to pack |
| `--o <file>` | output path (default: `input_packed.exe`) |
| `--vm` | VM encryption |
| `--c` | LZ77 compression |
| `--veh` | VEH page fault decryption |

### examples

<img width="800" height="111" alt="demo" src="https://github.com/user-attachments/assets/f6e9f863-27ef-4398-9450-d060af753931" />



```
TinyLoad.exe --i myapp.exe --c
TinyLoad.exe --i myapp.exe --o packed.exe --vm --c
TinyLoad.exe --i myapp.exe --vm --c --veh
```

you need at least one of `--vm`, `--c`, or `--veh`.

## compression

custom LZ77 with hash-chain matching, 64KB sliding window, and lazy evaluation. typically gets decent ratios on PE files since they have a lot of repeated structure. compression runs on the raw input first, then VM encryption is applied on top so patterns in the compressed stream are also hidden.

## vm encryption

v7 uses a custom 28-opcode virtual machine. the opcode table is split into four 8-entry subtables at pack time — each XOR-encrypted with an independent key derived from different parts of the payload and VM bytecode.

the cipher itself is a 128-bit stream cipher using rotl/rotr key mixing, run entirely through the VM so there's no native decryption loop to fingerprint.

## control flow obfuscation

v7 flattens every major function through indirect dispatch tables. the self-extraction entry point is broken into 6 stages called through a function pointer array. the PE loader is split into 5 stages using the same pattern.

string decryption noise is scattered throughout: all encrypted strings are pre-decrypted once at startup, then `noiseDecrypt()` fires at random points.

the VM dispatch table itself is never plaintext in the packed binary. pack time reads live label offsets from the running stub process, encrypts them with a random key, and stores them in the appended tail. the packed stub decrypts and recomputes the dispatch at runtime.

## anti dump

v7 redirects critical payload imports (GetModuleHandleA, GetProcAddress, ExitProcess, VirtualAlloc) through stub resident wrappers. after loading, the import directory is wiped.

## veh page-fault decryption

`--veh` maps all PE section pages as PAGE_NOACCESS. a vectored exception handler decrypts pages on first access and restores their original section protection (PAGE_EXECUTE_READ for .text, PAGE_READONLY for .rdata, etc.). a watchdog thread re-encrypts pages after 200ms of inactivity with a 256-slot LRU cache. memory dumps capture only recently-accessed pages.

Graph:

<img width="1977" height="1178" alt="compression_graph" src="https://github.com/user-attachments/assets/e07c1f38-1063-4564-8d7c-d75275d2125f" />

## license

MIT

## Sidenotes

- This works on all files i tested it on, if it breaks on some of your files please open an issue to let me know.
- If you want to suggest any improvements or future updates please open an issue.
- if you use it, a star helps a lot <3
- Check out our blog at https://iamsopotatoe-coder.github.io/TinyLoad/#blog for future updates and changelogs!
- Please do not use this tool to pack any malicious software or malware, it is intended to be used for legitimate purposes.
- Star History:

[![Star History Chart](https://api.star-history.com/svg?repos=iamsopotatoe-coder/TinyLoad&type=Date)](https://star-history.com/#iamsopotatoe-coder/TinyLoad&Date)
