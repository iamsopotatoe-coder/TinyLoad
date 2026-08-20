
# Changelog

##TinyLoad v7.4
* VM cipher keys are derived at runtime now instead of sitting in the bytecode as immediates
* VM bytecode is different every build
* opaque predicates and light CFF on the native x64 stub itself.
* key schedule split into pieces with no constants in them (the old one had 14 golden ratio constants in one function)
* the internal hash is officially shax256 now, it never was real sha256 anyway
* Better compression beacuse i thinkered with settings

(Note: the unpacker is 17kb fatter because of the new compression)

## v7.3
* bypassed "XEmulUnpacker" https://github.com/horsicq/XEmulUnpacker OEP unpacking by changing call rax in sp_go() to callq*(%reg) (memory indirect FF 10)
* new anti debugging syscall in the SSN table
* SHA 256 integrity hash of the payload stored in Tail overlay.
* I added terminal colors so the output of the builder/packer is colorful! (mostly for fun and so you can read better)

## v7.2
* added --noconsole flag for when you do not want a console
* Fixed a XXTEA bug which would make it break on previously packed executables with RustPacker.
* Added direct syscalls for stub apis

## v7.1

* XXTEA overlay encryption payload encryption upgraded from XOR to XXTEA (Corrected Block TEA).
* dual thread key recombination: 128-bit XXTEA key split across two threads. Thread A owns k0,k1; Thread B owns k2,k3. Full key only exists transiently inside a WaitForSingleObject fence, then destroyed.
* Tail field randomization: overlay Tail serialized field by field in Fisher Yates shuffled order per build. Guard marker bracketed serialization with field IDs.
* Anti debug improvements: PEB BeingDebugged (offset +2) and NtGlobalFlag (offset +0xBC, 0x70 mask) checked before Win32 APIs. Catches ring 3 debuggers that patch IsDebuggerPresent.
* PE compatibility improvements: Section bounds integer overflow guards. Import Name/FirstThunk/OriginalFirstThunk validated against SizeOfImage. DLL count capped at 256.

## v7.0

* Encrypted product strings: help text, CLI flags, and version strings XOR-encrypted at rest.
* Hidden overlay signature: "TINYLD60" marker XOR'ed with per file stubKey.
* Encrypted overlay metadata: origSz, packSz, flags, dispKey, vmCodeSz, canary fields individually XOR'ed with stubKey derived keys.
* Encrypted VM bytecode: VM program blob XOR-encrypted with stubKey stream.
* Encrypted tail offset: 4-byte EOF pointer XOR'ed with stubKey, overlay start not readable from hex dump.
* Zero-filler interleave: overlay interleaved with zero bytes at 3:1 ratio, entropy \~6.73 bits/byte blending with normal PE sections.
* Canary corridor: 8 chained integrity checks embedded in VM bytecode. Failures escalate a corruption mask (1→8 bits) XOR'ed into plaintext.
* VEH page-fault decryption: sections mapped PAGE\_NOACCESS, decrypted on-demand via vectored exception handler. Watchdog re encrypts cold pages after 200ms idle. LRU cache (256 slots) with thread safe eviction.
* Overlay chunk splitting: payload split into 4 chunks with random junk gaps (128–640 bytes).
* Bug fixes: LDB\_I/STB\_I bounds checks, SizeOfImage==0 rejection, NumberOfSections cap, readVarInt UB fix, relocation type validation, import truncation detection, vmCodeSz/origSz key de-duplication, keystream seed hardening.

## v6.0

* Control Flow Flattening on vmRun: switch statement replaced by computed-goto dispatch table built from encrypted label offsets. No recognisable interpreter structure survives in the binary.
* Split opcode decoder: 28 opcodes scattered across four 8-entry subtables, each XOR-encrypted with an independent key derived from different slices of payload and VM bytecode. Cracking one subtable reveals at most 8 opcodes.
* Staged entry point: tryRun broken into 6 stages dispatched through a function pointer table. PE loader (runInMem) split into 5 stages using the same pattern — no linear code paths.
* String decryption noise: all encrypted strings pre-decrypted once at startup, then noiseDecrypt() fires at scattered points (every stage transition, every 64 VM iterations). Real sdec2 calls indistinguishable from decoys in dynamic traces.
* Encrypted dispatch table: VM dispatch offsets never plaintext in the packed binary. Packer reads live label offsets from its own process, encrypts with random key, stores in tail. Packed stub decrypts and recomputes dispatch at runtime.
* Full resource cloning: EnumResourceTypesA replaces hardcoded RT\_ICON/RT\_VERSION/RT\_MANIFEST — all resource types (RT\_RCDATA, bitmaps, dialogs, string tables, fonts, accelerators) now survive packing.
* Compression improvement: fixed hash-chain self-loop in LZ compressor from double-insert bug. Compression ratios improved \~2% across tested files.
* PE loader hardening: SizeOfBlock underflow guard, relocation target bounds validation, negative e\_lfanew rejection, 32-bit PE explicit rejection, LoadLibraryA failure handling, import thunk iteration cap, lzUnpack error propagation on corrupted data, truncated decompression detection.
* vmRun g\_off stale fix: offset table moved to file scope, recomputed every call — no stale dispatch on nested unpack scenarios.

## v5.0 Bug Fixes

* LZ compressor WINDOW=0x10000 overflowed 16-bit distance field to 0, causing decompression corruption and access violation crash on packed executables. Reduced to 0xFFFF.
* \--i and --o now auto-append .exe if missing (e.g. --i calc works)
* 32 bit PE detection (as tinyload only supports 64 bit)
* Better error messages for invalid PE files and stub load failures
* PE loader bounds checks on headers, section copies, reloc/import directory walks to prevent crashes on malformed input.

## v5.0

* opmap is now derived from file content via FNV hash, no longer plaintext in the binary
* API and DLL name strings are XOR-encrypted, not visible in static analysis
* IAT wiped post-load, OriginalFirstThunk, import names, and import directory zeroed after mapping, making dumps harder to reconstruct
* 4 opaque predicates in the VM bytecode instead of 1, scattered through the program
* junk NOP and self-mov instructions inserted between real VM ops
* stub wrapper functions for key Win32 APIs routed through encrypted string resolution
* dead code functions added to inflate and confuse disassembly

## v4.0

* VM opaque predicates
* anti-debug checks (IsDebuggerPresent and CheckRemoteDebuggerPresent)
* PE section name obfuscation

## v3.1

* added 8 new VM instructions (ROL, ROR, NOT, MULI, ROLI, RORI, CALL, RET)
* 3-key encryption system with k1, k2, k3 (golden ratio seed) using rotation-based key evolution
* enhanced keystream generation with 192-bit state using rotations, multiplication, and NOT operations
* expanded opmap from 20 to 32 bytes to accommodate new instruction set

## v3.0

* replaced rolling XOR with custom VM encryption
* randomised opcode table per build, every packed file gets a different ISA
* improved in-memory protection

## v2.0

* in-memory execution, decrypted payload never written to disk
* icon, description, and version info now persist to output file

## v1.0

* initial release
