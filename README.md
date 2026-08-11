<img src="https://github.com/user-attachments/assets/ada41458-c6f8-4916-b09d-39d37dcacfd1" alt="github-social-preview" width="70%" />

## *TinyLoad v7.3 - PE packer for windows* 
<p align=”left">
  <img alt="Version" src="https://img.shields.io/badge/version-v7.2-e84393?style=plastic&logo=cplusplus&logoColor=white&labelColor=0d0d0d">
  <img alt="Actively Maintained" src="https://img.shields.io/badge/Actively%20Maintained-2ed573?style=plastic&logo=checkmarx&logoColor=white">
  <a href="https://github.com/gmh5225/awesome-game-security"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome" height="18"></a>
</p>


TinyLoad is an pe crypter/packer for x64 executables it packs an input exe with varying protection layers to prevent it from being reverse engineered. Its 1 single .cpp file and does not have any external dependencies.

## *how it works*

TinyLoad appends your payload to a copy of itself. when the packed exe runs it extracts the payload, decrypts it, and executes it directly in memory without ever writing the original to disk. every time you pack something the VM opcodes are randomly changed and put into 4 independently keyed subtables so no 2 builds are the same.

## *download*

grab a precompiled binary from [releases](https://github.com/iamsopotatoe-coder/tinyload/releases) or build it yourself.

## *building from source*

you need MinGW (g++). just run:

```cmd
g++ -o TinyLoad.exe TinyLoad.cpp -static -O2 -s
```

or use `build.bat`.

## *usage*

```cmd
TinyLoad.exe --i <input> [--o <output>] [--vm] [--c] [--veh]
```

| flag | what it does |
|------|-------------|
| `--i <file>` | input exe to pack |
| `--o <file>` | output path (default: `input_packed.exe`) |
| `--vm` | VM encryption |
| `--c` | LZ77 compression |
| `--veh` | VEH page fault decryption |
| `--noconsole` | GUI subsystem |

you need at least 1 of `--vm`, `--c`, or `--veh`.

### examples

<img width="800" height="103" alt="2026-08-1118-55-14-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/a72391e1-aa90-4921-ad8c-840095cd2c1c" />

## *DIE images*

<p align="center">
  <img src="https://github.com/user-attachments/assets/b78e57fd-24c0-472d-8ceb-9b67636f3e6e" alt="die-gui-packed" height="300" style="max-width: 48%; border-radius: 6px;" />
  <img src="https://github.com/user-attachments/assets/aaaf44fb-37f0-459d-a72a-608a40132d0c" alt="die-gui-entropy" height="300" style="max-width: 48%; border-radius: 6px;" />
</p>

## *compression*

custom LZ77 compression with hash chain matching and a 64KB sliding window. compression runs first, then VM encryption goes on top so any patterns in the compressed data get hidden too.

## *vm encryption*

custom 28 opcode virtual machine that runs inside the stub. the opcodes get randomly placed into 4 subtables of 8 each and every subtable is XOR encrypted with a different key derived from the payload data. cracking 1 subtable reveals at most 8 opcodes out of 28. the cipher itself is a 128 bit stream cipher using rotl and rotr key mixing run entirely inside the VM interpreter. The payload is encrypted using XXTEA.


## *veh page fault decryption*

with `--veh` enabled, all PE section pages get mapped as PAGE_NOACCESS. when the program tries to access a page it triggers an exception, a vectored exception handler decrypts just that 1 page and sets the correct protection. a watchdog thread runs in the background and re-encrypts any page that hasnt been touched in 200ms. at any given moment most of your program is still encrypted in memory so memory dumps only capture whatever was recently accessed.


## *anti dump*

the 4 most critical APIs (GetModuleHandleA, GetProcAddress, ExitProcess, VirtualAlloc) get redirected through wrapper functions inside the stub. after the payload is loaded the entire import directory gets zeroed so memory dumps cannot reconstruct the import table.


### Graph:

<img width="2100" height="1200" alt="631688071-324a4b82-29fb-40cf-9b01-15687aba7cae-mh" src="https://github.com/user-attachments/assets/f6e2818e-82d9-4437-a8d3-fe364cf33bec" />

## *license*

MIT

## *sidenotes*

- There are alot of features that i didnt put into the readme, you can read the code yourself or look at [changelog.md](docs/CHANGELOG.md)
- this works on most files ive tested, if it breaks on yours open an issue and ill look into it
- suggestions and feature ideas go in issues too
- if you use it a star helps alot <3 
- check the blog at https://iamsopotatoe-coder.github.io/TinyLoad/#blog for future updates
- yes AVs flag packers, thats expected. (Currently has 9 detections on virustotal, any file you pack with it gets 9 detections, the content doesnt matter)
- please dont pack malware with this, its intended for legitimate purposes 
