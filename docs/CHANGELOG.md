# Changelog

## v5.0
- opmap is now derived from file content via FNV hash, no longer plaintext in the binary
- API and DLL name strings are XOR-encrypted, not visible in static analysis
- IAT wiped post-load, OriginalFirstThunk, import names, and import directory zeroed after mapping, making dumps harder to reconstruct
- 4 opaque predicates in the VM bytecode instead of 1, scattered through the program
- junk NOP and self-mov instructions inserted between real VM ops
- stub wrapper functions for key Win32 APIs routed through encrypted string resolution
- dead code functions added to inflate and confuse disassembly

## v4.0
- VM opaque predicates
- anti-debug checks (IsDebuggerPresent and CheckRemoteDebuggerPresent)
- PE section name obfuscation

## v3.1
- added 8 new VM instructions (ROL, ROR, NOT, MULI, ROLI, RORI, CALL, RET)
- 3-key encryption system with k1, k2, k3 (golden ratio seed) using rotation-based key evolution
- enhanced keystream generation with 192-bit state using rotations, multiplication, and NOT operations
- expanded opmap from 20 to 32 bytes to accommodate new instruction set

## v3.0
- replaced rolling XOR with custom VM encryption
- randomised opcode table per build, every packed file gets a different ISA
- improved in-memory protection

## v2.0
- in-memory execution, decrypted payload never written to disk
- icon, description, and version info now persist to output file

## v1.0
- initial release
