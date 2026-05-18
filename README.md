
<img src="https://github.com/user-attachments/assets/ada41458-c6f8-4916-b09d-39d37dcacfd1" alt="github-social-preview" width="70%" />

# TinyLoad V5.0
![Custom VM](https://img.shields.io/badge/Custom%20VM-Live-7c3aed?style=flat&logo=ghost&logoColor=white&labelColor=0d0d0d)
![Version](https://img.shields.io/badge/version-v5.0-e84393?style=flat&logo=cplusplus&logoColor=white&labelColor=0d0d0d)
![Actively Maintained](https://img.shields.io/badge/Actively%20Maintained-2ed573?style=flat&logo=checkmarx&logoColor=white)

simple PE packer for Windows. compresses and encrypts executables with a custom virtual machine into a self-extracting stub.

## how it works

TinyLoad appends your compressed payload to a copy of itself. when the packed exe runs it uses a custom VM interpreter, executes the decryption bytecode against the payload, then loads and runs it directly in RAM.

every time you pack a file the VM opcodes are randomly shuffled and baked into the stub. So every packed file speaks a different instruction set. standard disassemblers can't auto-trace the decryption without reversing the interpreter first.

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
| `--vm` | custom VM encryption |
| `--c` | LZ77 compression |

### examples

<img width="800" height="111" alt="demo" src="https://github.com/user-attachments/assets/f6e9f863-27ef-4398-9450-d060af753931" />



```
TinyLoad.exe --i myapp.exe --c
TinyLoad.exe --i myapp.exe --o packed.exe --vm --c
TinyLoad.exe --i myapp.exe --vm
```

you need at least one of `--vm` or `--c`.

## compression

custom LZ77 with hash-chain matching, 64KB sliding window, and lazy evaluation. typically gets decent ratios on PE files since they have a lot of repeated structure. compression runs on the raw input first, then VM encryption is applied on top so patterns in the compressed stream are also hidden.

## vm encryption

v5 uses a custom 32-opcode virtual machine. the opcode table is randomly shuffled at pack time — every packed file gets a different ISA. the opmap decode table is encrypted with a per-file key, and junk instructions are scattered through the bytecode to break pattern matching.

the cipher itself is a 128-bit stream cipher using rotl/rotr key mixing, run entirely through the VM so there's no native decryption loop to fingerprint.

## anti dump

v5 redirects critical payload imports (GetModuleHandleA, GetProcAddress, ExitProcess, VirtualAlloc) through stub resident wrappers. after loading, the import directory is wiped. OriginalFirstThunk, DLL names, and the import DataDirectory are all zeroed. a dumped payload has no import table and IAT entries pointing into dead addresses. automated reconstruction is impossible.

internal strings (signature, DLL names, API names) are XOR-encrypted in the stub binary. 

Graph:

<img width="1977" height="1178" alt="compression_graph" src="https://github.com/user-attachments/assets/cbdf9b29-12ce-4742-901a-acb18b546832" />


## license

MIT

## Sidenotes

- This works on all files i tested it on, if it breaks on some of your files please open an issue to let me know.
- If you want to suggest any improvements or future updates please open an issue.
- if you use it, a star helps a lot <3
- Check out our blog at https://iamsopotatoe-coder.github.io/TinyLoad/#blog for future updates and changelogs!
- Tinyload v5.0 adds anti-dump IAT hooking, import directory wiping, encrypted opmap, junk instructions, and dead code insertion.
- Please do not use this tool to pack any malicious software or malware, it is intended to be used for legitimate purposes.

