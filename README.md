<img src="https://github.com/user-attachments/assets/ada41458-c6f8-4916-b09d-39d37dcacfd1" alt="github-social-preview" width="70%" />

# TinyLoad V6.0, The "More Obfuscation" update
![Custom VM](https://img.shields.io/badge/Custom%20VM-Live-7c3aed?style=flat&logo=ghost&logoColor=white&labelColor=0d0d0d)
![Version](https://img.shields.io/badge/version-v6.0-e84393?style=flat&logo=cplusplus&logoColor=white&labelColor=0d0d0d)
![Actively Maintained](https://img.shields.io/badge/Actively%20Maintained-2ed573?style=flat&logo=checkmarx&logoColor=white)

simple PE packer for Windows. compresses and encrypts executables with a custom virtual machine into a self-extracting stub.

## how it works

TinyLoad appends your compressed payload to a copy of itself. when the packed exe runs it uses a custom VM interpreter, executes the decryption bytecode against the payload, then loads and runs it directly in RAM.
every time you pack a file the VM opcodes are randomly changed and put into 4 independently keyed tables.
Everything is in one c++ file and has no dependencies!

Workflow:

<img width="720" height="1453" alt="image" src="https://github.com/user-attachments/assets/a9953596-aed7-4dfa-8052-2c03c6f8f39f" />

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

v6 uses a custom 28-opcode virtual machine. the opcode table is split into four 8-entry subtables at pack time, each XOR-encrypted with an independent key derived from different slices of the payload and VM bytecode. every packed file gets a different ISA spread across multiple decode layers.

the cipher itself is a 128-bit stream cipher using rotl/rotr key mixing, run entirely through the VM so there's no native decryption loop to fingerprint.

## control flow obfuscation

v6 flattens every major function through indirect dispatch tables. the self extraction entry point is broken into 6 stages called through a function pointer array. the PE loader is split into 5 stages using the same pattern.

the VM dispatch table itself is never plaintext in the packed binary. pack time reads live label offsets from the running stub process, encrypts them with a random key, and stores them in the appended tail. the packed stub decrypts and recomputes the dispatch at runtime.

## anti dump

v6 redirects critical payload imports (GetModuleHandleA, GetProcAddress, ExitProcess, VirtualAlloc) through stub resident wrappers. after loading, the import directory is wiped. OriginalFirstThunk, DLL names, and the import DataDirectory are all zeroed. a dumped payload has no import table and IAT entries pointing into dead addresses.
internal strings (signature, DLL names, API names) are XOR'ed in the stub binary. 

Graph:

<img width="1977" height="1178" alt="compression_graph" src="https://github.com/user-attachments/assets/44a4528d-12cd-467d-ab23-9375f456be53" />

## license

MIT

## Sidenotes

- This works on all files i tested it on, if it breaks on some of your files please open an issue to let me know.
- If you want to suggest any improvements or future updates please open an issue.
- if you use it, a star helps a lot <3
- Check out our blog at https://iamsopotatoe-coder.github.io/TinyLoad/#blog for future updates and changelogs!
- Tinyload v6.0 adds control flow flattening, split opcode decoder, encrypted dispatch table, staged function dispatch, string decryption noise, full resource cloning, and a compression fix.
- Please do not use this tool to pack any malicious software or malware, it is intended to be used for legitimate purposes.
- Star History:

[![Star History Chart](https://api.star-history.com/svg?repos=iamsopotatoe-coder/TinyLoad&type=Date)](https://star-history.com/#iamsopotatoe-coder/TinyLoad&Date)
