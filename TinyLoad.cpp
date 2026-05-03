#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <random>
#include <numeric>

using Bytes = std::vector<BYTE>;

#pragma pack(push, 1)
struct Tail {
    char sig[8];
    DWORD origSz;
    DWORD packSz;
    BYTE flags;
    BYTE opmap[20];
    DWORD vmCodeSz;
};
#pragma pack(pop)

enum {
    HLT_I, NOP_I, LDI_I, MOV_I, ADD_I, SUB_I, MUL_I,
    XOR_I, AND_I, OR_I, SHL_I, SHR_I,
    ADDI_I, XORI_I, ANDI_I,
    LDB_I, STB_I, CMP_I, JMP_I, JNZ_I,
    NUM_OPS
};

Bytes loadFile(const std::string& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return {};
    Bytes b((size_t)f.tellg());
    f.seekg(0);
    f.read((char*)b.data(), b.size());
    return b;
}

bool saveFile(const std::string& p, const Bytes& d) {
    std::ofstream f(p, std::ios::binary);
    f.write((char*)d.data(), d.size());
    return f.good();
}

Bytes lzPack(const Bytes& in) {
    if (in.empty()) return {0, 0, 0, 0};
    const int WINDOW = 0x10000;
    const int MAXCHAIN = 512;
    const int MAXMATCH = 258;
    const int MINMATCH = 3;
    const int HSIZE = 1 << 16;
    std::vector<int> head(HSIZE, -1);
    std::vector<int> prev(in.size(), -1);
    auto hash4 = [&](size_t p) -> int {
        if (p + 3 >= in.size()) {
            if (p + 2 >= in.size()) return 0;
            return ((in[p] * 0x1000193u) ^ (in[p+1] * 0x100) ^ in[p+2]) & (HSIZE - 1);
        }
        unsigned h = in[p];
        h = (h * 0x1000193u) ^ in[p+1];
        h = (h * 0x1000193u) ^ in[p+2];
        h = (h * 0x1000193u) ^ in[p+3];
        return h & (HSIZE - 1);
    };
    auto insert = [&](size_t p) {
        if (p + 2 >= in.size()) return;
        int h = hash4(p);
        prev[p] = head[h];
        head[h] = (int)p;
    };
    auto findMatch = [&](size_t p, int& ml, int& md) {
        ml = 0; md = 0;
        if (p + MINMATCH > in.size()) return;
        int h = hash4(p);
        int cur = head[h];
        int lo = std::max(0, (int)p - WINDOW);
        int cap = std::min(MAXMATCH, (int)(in.size() - p));
        for (int c = 0; c < MAXCHAIN && cur >= lo; c++) {
            if (in[cur] == in[p] && in[cur + ml] == in[p + ml]) {
                int l = 1;
                while (l < cap && in[cur + l] == in[p + l]) l++;
                if (l > ml) { ml = l; md = (int)(p - cur); if (l >= cap) return; }
            }
            cur = prev[cur];
            if (cur < 0) return;
        }
    };
    struct Tok { bool match; BYTE lit; int dist, len; };
    std::vector<Tok> toks;
    toks.reserve(in.size() / 2);
    size_t pos = 0;
    while (pos < in.size()) {
        int ml, md;
        findMatch(pos, ml, md);
        if (ml >= MINMATCH) {
            insert(pos);
            if (pos + 1 + MINMATCH <= in.size()) {
                int ml2, md2;
                findMatch(pos + 1, ml2, md2);
                if (ml2 > ml + 1) {
                    toks.push_back({false, in[pos], 0, 0});
                    insert(pos + 1);
                    pos++;
                    ml = ml2; md = md2;
                }
            }
            toks.push_back({true, 0, md, ml});
            for (int j = 0; j < ml; j++) insert(pos + j);
            pos += ml;
        } else {
            insert(pos);
            toks.push_back({false, in[pos], 0, 0});
            pos++;
        }
    }
    Bytes out;
    DWORD sz = (DWORD)in.size();
    for (int i = 0; i < 4; i++) out.push_back((sz >> (i * 8)) & 0xFF);
    size_t ti = 0;
    while (ti < toks.size()) {
        BYTE flag = 0;
        size_t fp = out.size();
        out.push_back(0);
        for (int bit = 0; bit < 8 && ti < toks.size(); bit++, ti++) {
            auto& t = toks[ti];
            if (t.match) {
                flag |= (1 << bit);
                out.push_back(t.dist & 0xFF);
                out.push_back((t.dist >> 8) & 0xFF);
                out.push_back((BYTE)(t.len - MINMATCH));
            } else { out.push_back(t.lit); }
        }
        out[fp] = flag;
    }
    return out;
}

Bytes lzUnpack(const Bytes& in) {
    if (in.size() < 4) return {};
    DWORD sz = in[0] | (in[1] << 8) | (in[2] << 16) | (in[3] << 24);
    Bytes out;
    out.reserve(sz);
    size_t p = 4;
    while (p < in.size() && out.size() < sz) {
        BYTE flag = in[p++];
        for (int bit = 0; bit < 8 && p < in.size() && out.size() < sz; bit++) {
            if (flag & (1 << bit)) {
                int dist = in[p] | (in[p + 1] << 8);
                int len = (int)in[p + 2] + 3;
                p += 3;
                size_t src = out.size() - dist;
                for (int i = 0; i < len; i++) out.push_back(out[src + i]);
            } else { out.push_back(in[p++]); }
        }
    }
    return out;
}

void vmRun(BYTE* data, uint64_t dataSz, const BYTE* code, size_t codesz, const BYTE* dec) {
    uint64_t r[8] = {};
    r[0] = (uint64_t)(uintptr_t)data;
    r[1] = dataSz;
    size_t ip = 0;
    while (ip < codesz) {
        uint8_t op = dec[code[ip++]];
        switch (op) {
        case HLT_I: return;
        case NOP_I: break;
        case LDI_I: { uint8_t reg = code[ip++]; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip+i] << (i*8); ip += 8; r[reg] = v; break; }
        case MOV_I: { uint8_t d = code[ip++], s = code[ip++]; r[d] = r[s]; break; }
        case ADD_I: { uint8_t d = code[ip++], s = code[ip++]; r[d] += r[s]; break; }
        case SUB_I: { uint8_t d = code[ip++], s = code[ip++]; r[d] -= r[s]; break; }
        case MUL_I: { uint8_t d = code[ip++], s = code[ip++]; r[d] *= r[s]; break; }
        case XOR_I: { uint8_t d = code[ip++], s = code[ip++]; r[d] ^= r[s]; break; }
        case AND_I: { uint8_t d = code[ip++], s = code[ip++]; r[d] &= r[s]; break; }
        case OR_I:  { uint8_t d = code[ip++], s = code[ip++]; r[d] |= r[s]; break; }
        case SHL_I: { uint8_t reg = code[ip++], n = code[ip++]; r[reg] <<= n; break; }
        case SHR_I: { uint8_t reg = code[ip++], n = code[ip++]; r[reg] >>= n; break; }
        case ADDI_I: { uint8_t reg = code[ip++]; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip+i] << (i*8); ip += 8; r[reg] += v; break; }
        case XORI_I: { uint8_t reg = code[ip++]; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip+i] << (i*8); ip += 8; r[reg] ^= v; break; }
        case ANDI_I: { uint8_t reg = code[ip++]; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip+i] << (i*8); ip += 8; r[reg] &= v; break; }
        case LDB_I: { uint8_t d = code[ip++], b = code[ip++], idx = code[ip++]; r[d] = ((BYTE*)(uintptr_t)r[b])[r[idx]]; break; }
        case STB_I: { uint8_t b = code[ip++], idx = code[ip++], s = code[ip++]; ((BYTE*)(uintptr_t)r[b])[r[idx]] = (BYTE)r[s]; break; }
        case CMP_I: { uint8_t d = code[ip++], a = code[ip++], b2 = code[ip++]; r[d] = r[a] < r[b2] ? 1 : 0; break; }
        case JMP_I: { int32_t off = 0; memcpy(&off, &code[ip], 4); ip = (size_t)((int64_t)(ip + 4) + off); break; }
        case JNZ_I: { uint8_t reg = code[ip++]; int32_t off = 0; memcpy(&off, &code[ip], 4); ip += 4; if (r[reg]) ip = (size_t)((int64_t)ip + off); break; }
        }
    }
}

static void eOp(Bytes& bc, const BYTE* enc, int op) { bc.push_back(enc[op]); }
static void eR(Bytes& bc, uint8_t r) { bc.push_back(r); }
static void e64(Bytes& bc, uint64_t v) { for (int i = 0; i < 8; i++) bc.push_back((v >> (i*8)) & 0xFF); }
static void e32(Bytes& bc, int32_t v) { uint32_t u = (uint32_t)v; for (int i = 0; i < 4; i++) bc.push_back((u >> (i*8)) & 0xFF); }

Bytes makeVmProgram(const BYTE* enc, uint64_t key1, uint64_t key2) {
    Bytes bc;

    eOp(bc,enc,LDI_I); eR(bc,2); e64(bc,0);
    eOp(bc,enc,LDI_I); eR(bc,3); e64(bc,key1);
    eOp(bc,enc,LDI_I); eR(bc,4); e64(bc,key2);

    int loopPos = (int)bc.size();

    eOp(bc,enc,CMP_I); eR(bc,7); eR(bc,2); eR(bc,1);
    eOp(bc,enc,JNZ_I); eR(bc,7);
    int jnzPatch = (int)bc.size(); e32(bc, 0);
    eOp(bc,enc,HLT_I);

    int bodyPos = (int)bc.size();
    { int32_t off = bodyPos - (jnzPatch + 4); memcpy(&bc[jnzPatch], &off, 4); }

    eOp(bc,enc,MOV_I);  eR(bc,5); eR(bc,3);
    eOp(bc,enc,XOR_I);  eR(bc,5); eR(bc,4);
    eOp(bc,enc,ANDI_I); eR(bc,5); e64(bc,0xFF);

    eOp(bc,enc,LDB_I); eR(bc,6); eR(bc,0); eR(bc,2);
    eOp(bc,enc,XOR_I);  eR(bc,6); eR(bc,5);
    eOp(bc,enc,STB_I); eR(bc,0); eR(bc,2); eR(bc,6);

    eOp(bc,enc,MOV_I); eR(bc,5); eR(bc,3);
    eOp(bc,enc,SHL_I); eR(bc,5); eR(bc,13);
    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,3);
    eOp(bc,enc,SHR_I); eR(bc,6); eR(bc,51);
    eOp(bc,enc,OR_I);  eR(bc,5); eR(bc,6);
    eOp(bc,enc,XOR_I); eR(bc,5); eR(bc,4);

    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,4);
    eOp(bc,enc,SHR_I); eR(bc,6); eR(bc,7);
    eOp(bc,enc,MOV_I); eR(bc,7); eR(bc,4);
    eOp(bc,enc,SHL_I); eR(bc,7); eR(bc,57);
    eOp(bc,enc,OR_I);  eR(bc,6); eR(bc,7);
    eOp(bc,enc,ADD_I); eR(bc,6); eR(bc,3);

    eOp(bc,enc,MOV_I); eR(bc,3); eR(bc,5);
    eOp(bc,enc,MOV_I); eR(bc,4); eR(bc,6);

    eOp(bc,enc,ADDI_I); eR(bc,2); e64(bc,1);

    eOp(bc,enc,JMP_I);
    int32_t back = loopPos - ((int)bc.size() + 4);
    e32(bc, back);

    return bc;
}

void vmEncryptPayload(Bytes& pay, uint64_t k1, uint64_t k2) {
    for (size_t i = 0; i < pay.size(); i++) {
        uint8_t ks = (uint8_t)(k1 ^ k2);
        pay[i] ^= ks;
        uint64_t nk1 = ((k1 << 13) | (k1 >> 51)) ^ k2;
        uint64_t nk2 = ((k2 >> 7)  | (k2 << 57)) + k1;
        k1 = nk1; k2 = nk2;
    }
}

bool runInMem(const Bytes& data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    void* base = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return false;
    memcpy(base, data.data(), nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sect[i].SizeOfRawData > 0)
            memcpy((BYTE*)base + sect[i].VirtualAddress, data.data() + sect[i].PointerToRawData, sect[i].SizeOfRawData);
    }
    size_t delta = (size_t)base - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto* relDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relDir->Size > 0) {
            auto* rel = (IMAGE_BASE_RELOCATION*)((BYTE*)base + relDir->VirtualAddress);
            while (rel->VirtualAddress > 0) {
                DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)(rel + 1);
                for (DWORD i = 0; i < count; i++) {
                    if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        size_t* p = (size_t*)((BYTE*)base + rel->VirtualAddress + (list[i] & 0xFFF));
                        *p += delta;
                    }
                }
                rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rel + rel->SizeOfBlock);
            }
        }
    }
    auto* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->Size > 0) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base + impDir->VirtualAddress);
        while (imp->Name) {
            HMODULE mod = LoadLibraryA((char*)((BYTE*)base + imp->Name));
            if (mod) {
                auto* thunk = (IMAGE_THUNK_DATA64*)((BYTE*)base + imp->FirstThunk);
                auto* orig = (IMAGE_THUNK_DATA64*)((BYTE*)base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                while (orig->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal)) {
                        thunk->u1.Function = (size_t)GetProcAddress(mod, (char*)(orig->u1.Ordinal & 0xFFFF));
                    } else {
                        auto* name = (IMAGE_IMPORT_BY_NAME*)((BYTE*)base + orig->u1.AddressOfData);
                        thunk->u1.Function = (size_t)GetProcAddress(mod, name->Name);
                    }
                    thunk++;
                    orig++;
                }
            }
            imp++;
        }
    }
    using EntryPoint = void(WINAPI*)();
    EntryPoint entry = (EntryPoint)((BYTE*)base + nt->OptionalHeader.AddressOfEntryPoint);
    entry();
    return true;
}

bool tryRun() {
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    Bytes blob = loadFile(self);
    if (blob.size() < sizeof(Tail) + 4) return false;
    DWORD off = *(DWORD*)&blob[blob.size() - 4];
    if (off + sizeof(Tail) > blob.size()) return false;
    Tail* t = (Tail*)&blob[off];
    if (memcmp(t->sig, "TINYLD3!", 8)) return false;
    if (off + sizeof(Tail) + t->vmCodeSz + t->packSz + 4 != blob.size()) return false;

    BYTE* vmCodePtr = (BYTE*)(t + 1);
    BYTE* payPtr = vmCodePtr + t->vmCodeSz;

    Bytes pay(payPtr, payPtr + t->packSz);

    if (t->flags & 2) {
        vmRun(pay.data(), pay.size(), vmCodePtr, t->vmCodeSz, t->opmap);
    }
    if (t->flags & 1) {
        pay = lzUnpack(pay);
        if (pay.empty()) return false;
    }

    return runInMem(pay);
}

struct ResCtx { HANDLE dst; };
BOOL CALLBACK resCbk(HMODULE mod, LPCSTR type, LPSTR name, LONG_PTR ctx) {
    ResCtx* c = (ResCtx*)ctx;
    HRSRC res = FindResourceA(mod, name, type);
    if (!res) return TRUE;
    HGLOBAL glob = LoadResource(mod, res);
    UpdateResourceA(c->dst, type, name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), LockResource(glob), SizeofResource(mod, res));
    return TRUE;
}

void cloneRes(const std::string& src, const std::string& dst) {
    HMODULE mod = LoadLibraryExA(src.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!mod) return;
    HANDLE h = BeginUpdateResourceA(dst.c_str(), FALSE);
    if (h) {
        ResCtx c = {h};
        EnumResourceNamesA(mod, RT_ICON, resCbk, (LONG_PTR)&c);
        EnumResourceNamesA(mod, RT_GROUP_ICON, resCbk, (LONG_PTR)&c);
        EnumResourceNamesA(mod, RT_VERSION, resCbk, (LONG_PTR)&c);
        EnumResourceNamesA(mod, RT_MANIFEST, resCbk, (LONG_PTR)&c);
        EndUpdateResourceA(h, FALSE);
    }
    FreeLibrary(mod);
}

bool pack(const std::string& in, const std::string& out, bool vm, bool comp) {
    Bytes orig = loadFile(in);
    if (orig.size() < 2 || orig[0] != 'M' || orig[1] != 'Z') return false;
    printf("input: %zu bytes\n", orig.size());

    BYTE flags = 0;
    Bytes pay = orig;

    if (comp) {
        flags |= 1;
        Bytes packed = lzPack(pay);
        printf("compressed: %zu -> %zu bytes (%d%%)\n", pay.size(), packed.size(), (int)(100.0 * packed.size() / orig.size()));
        pay = packed;
    }

    BYTE opmap_enc[NUM_OPS] = {}, opmap_dec[NUM_OPS] = {};
    Bytes vmCode;

    if (vm) {
        flags |= 2;
        std::mt19937 rng((uint32_t)GetTickCount() ^ (uint32_t)(uintptr_t)&rng);
        uint8_t perm[NUM_OPS];
        std::iota(perm, perm + NUM_OPS, 0);
        std::shuffle(perm, perm + NUM_OPS, rng);
        for (int i = 0; i < NUM_OPS; i++) { opmap_enc[i] = perm[i]; opmap_dec[perm[i]] = i; }

        std::mt19937_64 rng2(GetTickCount64() ^ (uint64_t)(uintptr_t)&rng2);
        uint64_t key1 = rng2(), key2 = rng2();

        vmCode = makeVmProgram(opmap_enc, key1, key2);
        vmEncryptPayload(pay, key1, key2);
        printf("vm encrypted: custom ISA, %zu bytes of bytecode\n", vmCode.size());
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    Bytes stub = loadFile(self);
    if (stub.empty()) return false;

    if (!saveFile(out, stub)) return false;
    cloneRes(in, out);
    Bytes result = loadFile(out);
    if (result.empty()) return false;

    DWORD tailOff = (DWORD)result.size();

    Tail t;
    memcpy(t.sig, "TINYLD3!", 8);
    t.origSz = (DWORD)orig.size();
    t.packSz = (DWORD)pay.size();
    t.flags = flags;
    memcpy(t.opmap, opmap_dec, NUM_OPS);
    t.vmCodeSz = (DWORD)vmCode.size();

    result.insert(result.end(), (BYTE*)&t, (BYTE*)&t + sizeof(t));
    if (!vmCode.empty()) result.insert(result.end(), vmCode.begin(), vmCode.end());
    result.insert(result.end(), pay.begin(), pay.end());
    result.push_back(tailOff & 0xFF);
    result.push_back((tailOff >> 8) & 0xFF);
    result.push_back((tailOff >> 16) & 0xFF);
    result.push_back((tailOff >> 24) & 0xFF);

    if (!saveFile(out, result)) return false;
    printf("-> %s (%zu bytes)\n", out.c_str(), result.size());
    return true;
}

int main(int argc, char* argv[]) {
    if (tryRun()) return 0;
    std::string in, out;
    bool vm = false, comp = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--i" && i + 1 < argc) in = argv[++i];
        else if (a == "--o" && i + 1 < argc) out = argv[++i];
        else if (a == "--vm") vm = true;
        else if (a == "--c") comp = true;
    }
    if (in.empty()) {
        puts("TinyLoad v3\n  --i <file>  --o <file>  --vm  --c");
        return 1;
    }
    if (out.empty()) {
        auto d = in.rfind('.');
        out = d != std::string::npos ? in.substr(0, d) + "_packed" + in.substr(d) : in + "_packed.exe";
    }
    if (!vm && !comp) { puts("need --vm and/or --c"); return 1; }
    return pack(in, out, vm, comp) ? 0 : 1;
}
