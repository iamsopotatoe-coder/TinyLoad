// Tinyload v6.0, MIT license, https://github.com/iamsopotatoe-coder/TinyLoad/
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

// stub wrappers
static FARPROC g_Real_GetModuleHandleA;
static FARPROC g_Real_GetProcAddress;
static FARPROC g_Real_ExitProcess;
static FARPROC g_Real_VirtualAlloc;

static HMODULE WINAPI Stub_GetModuleHandleA(LPCSTR n) {
    return ((decltype(&GetModuleHandleA))g_Real_GetModuleHandleA)(n);
}
static FARPROC WINAPI Stub_GetProcAddress(HMODULE m, LPCSTR n) {
    return ((decltype(&GetProcAddress))g_Real_GetProcAddress)(m, n);
}
static void WINAPI Stub_ExitProcess(UINT c) {
    ((decltype(&ExitProcess))g_Real_ExitProcess)(c);
}
static LPVOID WINAPI Stub_VirtualAlloc(LPVOID a, SIZE_T s, DWORD t, DWORD p) {
    return ((decltype(&VirtualAlloc))g_Real_VirtualAlloc)(a, s, t, p);
}

// API strings are XOR'ed to avoid appearing as plaintext in the
// packed binary's string table. decrypted at runtime by sdec2().
// key is per-string, rolling XOR: buf[i] = enc[i] ^ (key + i)
//
// _ed_k32 = "kernel32.dll"
// _ed_gmha = "GetModuleHandleA"
// _ed_gpa = "GetProcAddress"
// _ed_ep = "ExitProcess"
// _ed_va = "VirtualAlloc"
// _ed_sig = "TINYLD50"
struct StubHook { const BYTE* dll; uint8_t dllLen; const BYTE* name; uint8_t nameLen; uint8_t key; FARPROC* realStore; FARPROC wrapper; };
static const BYTE _ed_k32[] = {0x3A,0x37,0x21,0x3A,0x30,0x3A,0x64,0x6A,0x77,0x3E,0x37,0x30};
static const BYTE _ed_gmha[] = {0x70,0x5D,0x4D,0x77,0x54,0x58,0x48,0x52,0x5A,0x08,0x20,0x2C,0x27,0x28,0x20,0x07};
static const BYTE _ed_gpa[] = {0x06,0x27,0x37,0x14,0x37,0x29,0x24,0x09,0x2D,0x2E,0x39,0x29,0x3E,0x3D};
static const BYTE _ed_ep[] = {0x66,0x5C,0x4C,0x52,0x77,0x5A,0x46,0x49,0x4E,0x5F,0x5E};
static const BYTE _ed_va[] = {0x4F,0x73,0x69,0x68,0x68,0x7F,0x73,0x61,0x4D,0x4E,0x4C,0x47};
static const BYTE _ed_sig[] = {0x02,0x1E,0x16,0x00,0x16,0x1F,0x6A,0x6D};
static StubHook g_hooks[] = {
    {_ed_k32,12, _ed_gmha,16, 0x37, &g_Real_GetModuleHandleA, (FARPROC)Stub_GetModuleHandleA},
    {_ed_k32,12, _ed_gpa, 14, 0x41, &g_Real_GetProcAddress,    (FARPROC)Stub_GetProcAddress},
    {_ed_k32,12, _ed_ep,   11, 0x23, &g_Real_ExitProcess,       (FARPROC)Stub_ExitProcess},
    {_ed_k32,12, _ed_va,   12, 0x19, &g_Real_VirtualAlloc,      (FARPROC)Stub_VirtualAlloc},
};
static int g_hookCount = sizeof(g_hooks) / sizeof(g_hooks[0]);

// pre-decrypted
static char _pd_sig[9];
static char _pd_k32[13];

// noise table
struct NoiseEnt { const BYTE* enc; size_t n; uint8_t k; };
static NoiseEnt g_noise[] = {
    {_ed_sig, 8, 0x56},
    {_ed_k32, 12, 0x37},
    {_ed_gmha, 16, 0x37},
    {_ed_gpa, 14, 0x41},
    {_ed_ep, 11, 0x23},
    {_ed_va, 12, 0x19},
};

// xor decrypt
static char* sdec2(char* buf, const BYTE* enc, size_t n, uint8_t k) {
    for (size_t i = 0; i < n; i++) buf[i] = enc[i] ^ (uint8_t)(k + i);
    buf[n] = 0; return buf;
}

static void initStrings() {
    sdec2(_pd_sig, _ed_sig, 8, 0x56);
    sdec2(_pd_k32, _ed_k32, 12, 0x37);
}

__attribute__((noinline)) __attribute__((used)) static void noiseDecrypt() {
    volatile char junk[64];
    int n = sizeof(g_noise)/sizeof(g_noise[0]);
    int idx = (int)(((uintptr_t)&junk * 2654435761u) >> 5) % n;
    sdec2((char*)junk, g_noise[idx].enc, g_noise[idx].n, g_noise[idx].k);
}

bool isDebugged() {
    // go away windbg
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) return true;
    return false;
}

enum {
    HLT_I, NOP_I, LDI_I, MOV_I, ADD_I, SUB_I, MUL_I,
    XOR_I, AND_I, OR_I, SHL_I, SHR_I, ROL_I, ROR_I, NOT_I,
    ADDI_I, XORI_I, ANDI_I, MULI_I, ROLI_I, RORI_I,
    LDB_I, STB_I, CMP_I, JMP_I, JNZ_I, CALL_I, RET_I,
    NUM_OPS
};

#pragma pack(push, 1)
struct Tail {
    char sig[8];
    DWORD origSz;
    DWORD packSz;
    BYTE flags;
    uint64_t dispOff[NUM_OPS];
    BYTE subtables[4][8];
    DWORD vmCodeSz;
    uint64_t dispKey;
};
#pragma pack(pop)

// per-subtable keys
static void xorOpmap(BYTE* sub, const Tail& t, const BYTE* vmCode, const BYTE* pay) {
    uint32_t baseH = 0x811C9DC5u;
    auto feedBase = [&](uint8_t b) { baseH ^= b; baseH *= 0x01000193u; };
    for (int i = 0; i < 4; i++) {
        feedBase((uint8_t)(t.origSz >> (i * 8)));
        feedBase((uint8_t)(t.packSz >> (i * 8)));
        feedBase((uint8_t)(t.vmCodeSz >> (i * 8)));
    }
    for (int tbl = 0; tbl < 4; tbl++) {
        uint32_t h = baseH;
        auto feed = [&](uint8_t b) { h ^= b; h *= 0x01000193u; };
        feed((uint8_t)tbl);
        DWORD vmLim = t.vmCodeSz < 32 ? t.vmCodeSz : 32;
        DWORD payLim = t.packSz < 32 ? t.packSz : 32;
        DWORD vmOff = vmLim ? (tbl * 8) % vmLim : 0;
        DWORD payOff = payLim ? (tbl * 8) % payLim : 0;
        if (vmCode) for (DWORD i = 0; i < 8 && (vmOff + i) < vmLim; i++) feed(vmCode[vmOff + i]);
        else for (int i = 0; i < 8; i++) feed((uint8_t)(tbl ^ i));
        if (pay) for (DWORD i = 0; i < 8 && (payOff + i) < payLim; i++) feed(pay[payOff + i]);
        else for (int i = 0; i < 8; i++) feed((uint8_t)(~tbl ^ i));
        for (int i = 0; i < 8; i++) {
            feed((uint8_t)i);
            sub[tbl * 8 + i] ^= (uint8_t)((h >> 24) ^ (h >> 16) ^ (h >> 8) ^ h);
        }
    }
}

// dead code
__attribute__((used)) static DWORD dead_crc32(const BYTE* d, size_t n) {
    DWORD c = 0xFFFFFFFF;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & -(c & 1));
    }
    return ~c;
}
__attribute__((used)) static bool dead_checkBP() {
    // alt debug check
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    return peb && *(peb + 2);
}
__attribute__((used)) static void dead_scramble(char* b, size_t n, DWORD s) {
    for (size_t i = 0; i < n; i++) {
        s = s * 1103515245 + 12345;
        b[i] ^= (char)(s >> 16);
    }
}
__attribute__((used)) static int dead_strlen_safe(const char* s, int max) {
    int i = 0;
    while (s && i < max && s[i]) i++;
    return i;
}
__attribute__((used)) static bool dead_isPe(const BYTE* d, size_t n) {
    if (n < 64) return false;
    if (d[0] != 'M' || d[1] != 'Z') return false;
    DWORD pe = *(DWORD*)(d + 0x3C);
    return pe < n && *(DWORD*)(d + pe) == 0x00004550;
}

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
    const int WINDOW = 0xFFFF;
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
            // lazy matching: try 1 byte ahead, pick the better match
            if (pos + 1 + MINMATCH <= in.size()) {
                int ml2, md2;
                findMatch(pos + 1, ml2, md2);
                if (ml2 > ml + 1) {
                    toks.push_back({false, in[pos], 0, 0});
                    insert(pos);
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
                if (p + 2 >= in.size()) break;
                int dist = in[p] | (in[p + 1] << 8);
                int len = (int)in[p + 2] + 3;
                p += 3;
                if (dist <= 0 || (size_t)dist > out.size()) return {};
                size_t src = out.size() - dist;
                for (int i = 0; i < len; i++) out.push_back(out[src + i]);
            } else { out.push_back(in[p++]); }
        }
    }
    if (out.size() < sz) return {};
    return out;
}

// packer reads live offsets via this
__attribute__((used)) static intptr_t g_off[NUM_OPS];
__attribute__((used)) static intptr_t* g_vmOffPtr = g_off;

void vmRun(BYTE* data, uint64_t dataSz, const BYTE* code, size_t codesz, const BYTE* dec, const uint64_t* dispOff, uint64_t dispKey) {
    // r0=data, r1=sz, r2=i, r3/4=key, r5=const, r6-8=tmp
    uint64_t r[9] = {};
    r[0] = (uint64_t)(uintptr_t)data;
    r[1] = dataSz;
    size_t ip = 0;

    // populate offset table each call
    if (dispKey) {
        for (int i = 0; i < NUM_OPS; i++)
            g_off[i] = (intptr_t)(dispOff[i] ^ dispKey);
    } else {
            g_off[0] = (intptr_t)(uintptr_t)&&hlt_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[1] = (intptr_t)(uintptr_t)&&nop_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[2] = (intptr_t)(uintptr_t)&&ldi_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[3] = (intptr_t)(uintptr_t)&&mov_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[4] = (intptr_t)(uintptr_t)&&add_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[5] = (intptr_t)(uintptr_t)&&sub_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[6] = (intptr_t)(uintptr_t)&&mul_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[7] = (intptr_t)(uintptr_t)&&xor_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[8] = (intptr_t)(uintptr_t)&&and_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[9] = (intptr_t)(uintptr_t)&&or_l  - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[10] = (intptr_t)(uintptr_t)&&shl_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[11] = (intptr_t)(uintptr_t)&&shr_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[12] = (intptr_t)(uintptr_t)&&rol_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[13] = (intptr_t)(uintptr_t)&&ror_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[14] = (intptr_t)(uintptr_t)&&not_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[15] = (intptr_t)(uintptr_t)&&addi_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[16] = (intptr_t)(uintptr_t)&&xori_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[17] = (intptr_t)(uintptr_t)&&andi_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[18] = (intptr_t)(uintptr_t)&&muli_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[19] = (intptr_t)(uintptr_t)&&roli_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[20] = (intptr_t)(uintptr_t)&&rori_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[21] = (intptr_t)(uintptr_t)&&ldb_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[22] = (intptr_t)(uintptr_t)&&stb_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[23] = (intptr_t)(uintptr_t)&&cmp_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[24] = (intptr_t)(uintptr_t)&&jmp_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[25] = (intptr_t)(uintptr_t)&&jnz_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[26] = (intptr_t)(uintptr_t)&&call_l - (intptr_t)(uintptr_t)&&hlt_l;
            g_off[27] = (intptr_t)(uintptr_t)&&ret_l - (intptr_t)(uintptr_t)&&hlt_l;
    }

    // build dispatch from offsets
    void* dispatch[NUM_OPS];
    {
        intptr_t base = (intptr_t)(uintptr_t)&&hlt_l;
        for (int i = 0; i < NUM_OPS; i++)
            dispatch[i] = (void*)(base + g_off[i]);
    }

dispatch:;
    if (ip >= codesz) return;
    { static size_t _nc = 0;
    if ((++_nc & 63) == 0) noiseDecrypt();
    uint8_t b = code[ip++];
    uint8_t op = dec[((b >> 6) & 3) * 8 + (b & 7)];
    if (op >= NUM_OPS) return;
    goto *dispatch[op]; }

hlt_l:
    return;
nop_l:
    goto dispatch;
ldi_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        ip += 8;
        if (ip > codesz) goto dispatch;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip - 8 + i] << (i*8);
        r[reg] = v;
    }
    goto dispatch;
mov_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] = r[s];
    }
    goto dispatch;
add_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] += r[s];
    }
    goto dispatch;
sub_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] -= r[s];
    }
    goto dispatch;
mul_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] *= r[s];
    }
    goto dispatch;
xor_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] ^= r[s];
    }
    goto dispatch;
and_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] &= r[s];
    }
    goto dispatch;
or_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t d = code[ip++], s = code[ip++];
        if (d >= 9 || s >= 9) return;
        r[d] |= r[s];
    }
    goto dispatch;
shl_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t reg = code[ip++], n = code[ip++] & 63;
        if (reg >= 9) return;
        r[reg] <<= n;
    }
    goto dispatch;
shr_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t reg = code[ip++], n = code[ip++] & 63;
        if (reg >= 9) return;
        r[reg] >>= n;
    }
    goto dispatch;
rol_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t reg = code[ip++], n = code[ip++] & 63;
        if (reg >= 9) return;
        if (n) r[reg] = (r[reg] << n) | (r[reg] >> (64 - n));
    }
    goto dispatch;
ror_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t reg = code[ip++], n = code[ip++] & 63;
        if (reg >= 9) return;
        if (n) r[reg] = (r[reg] >> n) | (r[reg] << (64 - n));
    }
    goto dispatch;
not_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        r[reg] = ~r[reg];
    }
    goto dispatch;
addi_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        ip += 8;
        if (ip > codesz) goto dispatch;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip - 8 + i] << (i*8);
        r[reg] += v;
    }
    goto dispatch;
xori_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        ip += 8;
        if (ip > codesz) goto dispatch;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip - 8 + i] << (i*8);
        r[reg] ^= v;
    }
    goto dispatch;
andi_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        ip += 8;
        if (ip > codesz) goto dispatch;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip - 8 + i] << (i*8);
        r[reg] &= v;
    }
    goto dispatch;
muli_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        ip += 8;
        if (ip > codesz) goto dispatch;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)code[ip - 8 + i] << (i*8);
        r[reg] *= v;
    }
    goto dispatch;
roli_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t reg = code[ip++], n = code[ip++] & 63;
        if (reg >= 9) return;
        if (n) r[reg] = (r[reg] << n) | (r[reg] >> (64 - n));
    }
    goto dispatch;
rori_l:
    {
        if (ip + 1 >= codesz) goto dispatch;
        uint8_t reg = code[ip++], n = code[ip++] & 63;
        if (reg >= 9) return;
        if (n) r[reg] = (r[reg] >> n) | (r[reg] << (64 - n));
    }
    goto dispatch;
ldb_l:
    {
        if (ip + 2 >= codesz) goto dispatch;
        uint8_t d = code[ip++], b = code[ip++], idx = code[ip++];
        if (d >= 9 || b >= 9 || idx >= 9) return;
        r[d] = ((BYTE*)(uintptr_t)r[b])[r[idx]];
    }
    goto dispatch;
stb_l:
    {
        if (ip + 2 >= codesz) goto dispatch;
        uint8_t b = code[ip++], idx = code[ip++], s = code[ip++];
        if (b >= 9 || idx >= 9 || s >= 9) return;
        ((BYTE*)(uintptr_t)r[b])[r[idx]] = (BYTE)r[s];
    }
    goto dispatch;
cmp_l:
    {
        if (ip + 2 >= codesz) goto dispatch;
        uint8_t d = code[ip++], a = code[ip++], b2 = code[ip++];
        if (d >= 9 || a >= 9 || b2 >= 9) return;
        r[d] = r[a] < r[b2] ? 1 : 0;
    }
    goto dispatch;
jmp_l:
    {
        if (ip + 4 > codesz) goto dispatch;
        int32_t off = 0;
        memcpy(&off, &code[ip], 4);
        ip = (size_t)((int64_t)(ip + 4) + off);
    }
    goto dispatch;
jnz_l:
    {
        if (ip >= codesz) goto dispatch;
        uint8_t reg = code[ip++];
        if (reg >= 9) return;
        if (ip + 4 > codesz) goto dispatch;
        int32_t off = 0;
        memcpy(&off, &code[ip], 4);
        ip += 4;
        if (r[reg]) ip = (size_t)((int64_t)ip + off);
    }
    goto dispatch;
call_l:
    {
        if (ip + 4 > codesz) goto dispatch;
        int32_t off = 0;
        memcpy(&off, &code[ip], 4);
        r[7] = ip + 4;
        ip = (size_t)((int64_t)(ip + 4) + off);
    }
    goto dispatch;
ret_l:
    {
        ip = (size_t)r[7];
    }
    goto dispatch;
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
    eOp(bc,enc,LDI_I); eR(bc,5); e64(bc,0x9E3779B97F4A7C15ull); // φ
    eOp(bc,enc,NOP_I); // junk
    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,6); // junk

    // coffee before cream
    eOp(bc,enc,LDI_I); eR(bc,6); e64(bc,0xCAFE);
    eOp(bc,enc,LDI_I); eR(bc,7); e64(bc,0xCAFF);
    eOp(bc,enc,CMP_I); eR(bc,8); eR(bc,6); eR(bc,7);
    eOp(bc,enc,JNZ_I); eR(bc,8);
    int opqPatch = (int)bc.size(); e32(bc, 0); // Jumps over if true
    eOp(bc,enc,HLT_I); // Trap if jumped
    int opqEnd = (int)bc.size();
    { int32_t off = opqEnd - (opqPatch + 4); memcpy(&bc[opqPatch], &off, 4); }

    // xor-self → 0
    eOp(bc,enc,LDI_I); eR(bc,6); e64(bc,0xDEADBEEFCAFEBABEull);
    eOp(bc,enc,XOR_I); eR(bc,6); eR(bc,6);
    eOp(bc,enc,LDI_I); eR(bc,7); e64(bc,1);
    eOp(bc,enc,CMP_I); eR(bc,8); eR(bc,6); eR(bc,7);
    eOp(bc,enc,JNZ_I); eR(bc,8);
    int opq2Patch = (int)bc.size(); e32(bc, 0);
    eOp(bc,enc,HLT_I);
    int opq2End = (int)bc.size();
    { int32_t off = opq2End - (opq2Patch + 4); memcpy(&bc[opq2Patch], &off, 4); }

    // 0x1337 < 0xBEEF
    eOp(bc,enc,LDI_I); eR(bc,6); e64(bc,0x1337);
    eOp(bc,enc,LDI_I); eR(bc,7); e64(bc,0xBEEF);
    eOp(bc,enc,CMP_I); eR(bc,8); eR(bc,6); eR(bc,7);
    eOp(bc,enc,JNZ_I); eR(bc,8);
    int opq3Patch = (int)bc.size(); e32(bc, 0);
    eOp(bc,enc,HLT_I);
    int opq3End = (int)bc.size();
    { int32_t off = opq3End - (opq3Patch + 4); memcpy(&bc[opq3Patch], &off, 4); }

    int loopPos = (int)bc.size();

    eOp(bc,enc,CMP_I); eR(bc,7); eR(bc,2); eR(bc,1);
    eOp(bc,enc,JNZ_I); eR(bc,7);
    int jnzPatch = (int)bc.size(); e32(bc, 0);
    eOp(bc,enc,HLT_I);

    int bodyPos = (int)bc.size();
    { int32_t off = bodyPos - (jnzPatch + 4); memcpy(&bc[jnzPatch], &off, 4); }

    // 0 < ~0
    eOp(bc,enc,LDI_I); eR(bc,6); e64(bc,0);
    eOp(bc,enc,LDI_I); eR(bc,7); e64(bc,0xFFFFFFFFFFFFFFFFull);
    eOp(bc,enc,CMP_I); eR(bc,8); eR(bc,6); eR(bc,7);
    eOp(bc,enc,JNZ_I); eR(bc,8);
    int opq4Patch = (int)bc.size(); e32(bc, 0);
    eOp(bc,enc,HLT_I);
    int opq4End = (int)bc.size();
    { int32_t off = opq4End - (opq4Patch + 4); memcpy(&bc[opq4Patch], &off, 4); }

    // keystream
    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,3);
    eOp(bc,enc,XOR_I); eR(bc,6); eR(bc,4);
    eOp(bc,enc,ADD_I); eR(bc,6); eR(bc,5);
    eOp(bc,enc,ANDI_I); eR(bc,6); e64(bc,0xFF);
    eOp(bc,enc,NOP_I); // junk

    eOp(bc,enc,LDB_I); eR(bc,8); eR(bc,0); eR(bc,2);
    eOp(bc,enc,XOR_I); eR(bc,8); eR(bc,6);
    eOp(bc,enc,NOT_I); eR(bc,8);
    eOp(bc,enc,STB_I); eR(bc,0); eR(bc,2); eR(bc,8);
    eOp(bc,enc,MOV_I); eR(bc,8); eR(bc,8); // junk

    // key mixing
    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,3);
    eOp(bc,enc,ROL_I); eR(bc,6); eR(bc,11);
    eOp(bc,enc,XOR_I); eR(bc,6); eR(bc,4);
    eOp(bc,enc,MOV_I); eR(bc,7); eR(bc,6);
    eOp(bc,enc,ROL_I); eR(bc,8); eR(bc,0); // junk

    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,4);
    eOp(bc,enc,ROR_I); eR(bc,6); eR(bc,19);
    eOp(bc,enc,ADD_I); eR(bc,6); eR(bc,3);
    eOp(bc,enc,ADD_I); eR(bc,6); eR(bc,5);
    eOp(bc,enc,MOV_I); eR(bc,4); eR(bc,6);

    eOp(bc,enc,MULI_I); eR(bc,5); e64(bc,0x9E3779B97F4A7C15ull);
    eOp(bc,enc,XOR_I); eR(bc,5); eR(bc,7);
    eOp(bc,enc,ADDI_I); eR(bc,6); e64(bc,0); // junk

    eOp(bc,enc,MOV_I); eR(bc,3); eR(bc,7);

    eOp(bc,enc,ADDI_I); eR(bc,2); e64(bc,1);

    eOp(bc,enc,JMP_I);
    int32_t back = loopPos - ((int)bc.size() + 4);
    e32(bc, back);

    return bc;
}

void vmEncryptPayload(Bytes& pay, uint64_t k1, uint64_t k2) {
    // stream cipher: xor + NOT (cuz 1 layer is boring)
    uint64_t k3 = 0x9E3779B97F4A7C15ull;
    for (size_t i = 0; i < pay.size(); i++) {
        uint8_t b = pay[i];
        uint8_t ks = (uint8_t)(((k1 ^ k2) + k3) & 0xFF);
        b ^= ks;
        b = ~b;
        pay[i] = b;
        uint64_t nk1 = ((k1 << 11) | (k1 >> 53)) ^ k2;
        uint64_t nk2 = ((k2 >> 19) | (k2 << 45)) + k1 + k3;
        k1 = nk1; k2 = nk2;
        k3 = (k3 * 0x9E3779B97F4A7C15ull) ^ k1;
    }
}

// pe loader stages
typedef int (*PEStageFn)();

static struct {
    const Bytes* data;
    void* base;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    size_t delta;
} g_pe;

static int sp_hdr() {
    if (g_pe.data->size() < sizeof(IMAGE_DOS_HEADER)) return -2;
    g_pe.dos = (IMAGE_DOS_HEADER*)g_pe.data->data();
    if (g_pe.dos->e_magic != IMAGE_DOS_SIGNATURE) return -2;
    if (g_pe.dos->e_lfanew <= 0) return -2;
    if ((DWORD)g_pe.dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > g_pe.data->size()) return -2;
    g_pe.nt = (IMAGE_NT_HEADERS64*)(g_pe.data->data() + g_pe.dos->e_lfanew);
    if (g_pe.nt->Signature != IMAGE_NT_SIGNATURE) return -2;
    if (g_pe.nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return -2;
    if (g_pe.nt->OptionalHeader.SizeOfImage > 0x40000000) return -2;
    return 1;
}
static int sp_map() {
    g_pe.base = VirtualAlloc(NULL, g_pe.nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_pe.base) return -2;
    size_t hdrSize = g_pe.nt->OptionalHeader.SizeOfHeaders;
    if (hdrSize > g_pe.data->size()) hdrSize = g_pe.data->size();
    memcpy(g_pe.base, g_pe.data->data(), hdrSize);
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(g_pe.nt);
    for (int i = 0; i < g_pe.nt->FileHeader.NumberOfSections; i++) {
        if (sect[i].SizeOfRawData > 0) {
            size_t srcOff = sect[i].PointerToRawData;
            size_t dstOff = sect[i].VirtualAddress;
            if (srcOff + sect[i].SizeOfRawData <= g_pe.data->size() && dstOff + sect[i].SizeOfRawData <= g_pe.nt->OptionalHeader.SizeOfImage)
                memcpy((BYTE*)g_pe.base + dstOff, g_pe.data->data() + srcOff, sect[i].SizeOfRawData);
        }
    }
    return 2;
}
static int sp_reloc() {
    g_pe.delta = (size_t)g_pe.base - g_pe.nt->OptionalHeader.ImageBase;
    if (g_pe.delta != 0) {
        auto* relDir = &g_pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relDir->Size > 0 && relDir->VirtualAddress < g_pe.nt->OptionalHeader.SizeOfImage) {
            auto* rel = (IMAGE_BASE_RELOCATION*)((BYTE*)g_pe.base + relDir->VirtualAddress);
            BYTE* relEnd = (BYTE*)g_pe.base + relDir->VirtualAddress + relDir->Size;
            while ((BYTE*)rel + sizeof(IMAGE_BASE_RELOCATION) <= relEnd && rel->VirtualAddress > 0) {
                if (rel->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)(rel + 1);
                for (DWORD i = 0; i < count; i++) {
                    if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        size_t target = (size_t)rel->VirtualAddress + (list[i] & 0xFFF);
                        if (target + sizeof(size_t) <= g_pe.nt->OptionalHeader.SizeOfImage) {
                            size_t* p = (size_t*)((BYTE*)g_pe.base + target);
                            *p += g_pe.delta;
                        }
                    }
                }
                rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rel + rel->SizeOfBlock);
            }
        }
    }
    return 3;
}
static int sp_import() {
    auto* impDir = &g_pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->Size > 0 && impDir->VirtualAddress < g_pe.nt->OptionalHeader.SizeOfImage) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)g_pe.base + impDir->VirtualAddress);
        BYTE* impEnd = (BYTE*)g_pe.base + impDir->VirtualAddress + impDir->Size;
        while ((BYTE*)(imp + 1) <= impEnd && imp->Name) {
            HMODULE mod = LoadLibraryA((char*)((BYTE*)g_pe.base + imp->Name));
            if (mod) {
                auto* thunk = (IMAGE_THUNK_DATA64*)((BYTE*)g_pe.base + imp->FirstThunk);
                auto* orig = (IMAGE_THUNK_DATA64*)((BYTE*)g_pe.base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                int impLimit = 10000;
                while (orig->u1.AddressOfData && impLimit-- > 0) {
                    if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal)) {
                        thunk->u1.Function = (size_t)GetProcAddress(mod, (char*)(orig->u1.Ordinal & 0xFFFF));
                    } else {
                        auto* name = (IMAGE_IMPORT_BY_NAME*)((BYTE*)g_pe.base + orig->u1.AddressOfData);
                        FARPROC real = GetProcAddress(mod, name->Name);
                        const char* dllName = (const char*)((BYTE*)g_pe.base + imp->Name);
                        FARPROC hook = nullptr;
                        char dbuf[32], nbuf[64];
                        for (int h = 0; h < g_hookCount; h++) {
                            sdec2(dbuf, g_hooks[h].dll, g_hooks[h].dllLen, g_hooks[h].key);
                            sdec2(nbuf, g_hooks[h].name, g_hooks[h].nameLen, g_hooks[h].key);
                            if (!_stricmp(dllName, dbuf) && !strcmp(name->Name, nbuf)) {
                                *g_hooks[h].realStore = real;
                                hook = g_hooks[h].wrapper;
                                break;
                            }
                        }
                        thunk->u1.Function = hook ? (size_t)hook : (size_t)real;
                    }
                    thunk++;
                    orig++;
                }
                imp->OriginalFirstThunk = 0;
                imp->Name = 0;
            }
            imp++;
        }
        g_pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
        g_pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
    }
    return 4;
}
static int sp_go() {
    using EntryPoint = void(WINAPI*)();
    EntryPoint entry = (EntryPoint)((BYTE*)g_pe.base + g_pe.nt->OptionalHeader.AddressOfEntryPoint);
    entry();
    return -1;
}

bool runInMem(const Bytes& data) {
    static PEStageFn stages[] = {
        sp_hdr, sp_map, sp_reloc, sp_import, sp_go
    };
    g_pe.data = &data;
    g_pe.base = nullptr;
    int stage = 0;
    while (stage >= 0) {
        if (stage >= (int)(sizeof(stages)/sizeof(stages[0]))) return false;
        noiseDecrypt();
        stage = stages[stage]();
    }
    return stage == -1;
}

// stage dispatch
typedef int (*StageFn)();

static struct {
    char self[MAX_PATH];
    Bytes blob;
    DWORD off;
    Tail* t;
    BYTE* vmCodePtr;
    BYTE* payPtr;
    Bytes pay;
} g_st;

static int s_chk() {
    initStrings();
    if (isDebugged()) return -2;
    noiseDecrypt();
    GetModuleFileNameA(NULL, g_st.self, MAX_PATH);
    return 1;
}
static int s_ld() {
    noiseDecrypt();
    g_st.blob = loadFile(g_st.self);
    if (g_st.blob.size() < sizeof(Tail) + 4) return -2;
    g_st.off = *(DWORD*)&g_st.blob[g_st.blob.size() - 4];
    if (g_st.off + sizeof(Tail) > g_st.blob.size()) return -2;
    return 2;
}
static int s_prs() {
    noiseDecrypt();
    g_st.t = (Tail*)&g_st.blob[g_st.off];
    if (memcmp(g_st.t->sig, _pd_sig, 8)) return -2;
    if ((uint64_t)g_st.off + sizeof(Tail) + (uint64_t)g_st.t->vmCodeSz + (uint64_t)g_st.t->packSz + 4 != g_st.blob.size()) return -2;
    g_st.vmCodePtr = (BYTE*)(g_st.t + 1);
    g_st.payPtr = g_st.vmCodePtr + g_st.t->vmCodeSz;
    g_st.pay = Bytes(g_st.payPtr, g_st.payPtr + g_st.t->packSz);
    return 3;
}
static int s_vm() {
    noiseDecrypt();
    if (g_st.t->flags & 2) {
        xorOpmap((BYTE*)g_st.t->subtables, *g_st.t, g_st.vmCodePtr, g_st.payPtr);
        vmRun(g_st.pay.data(), g_st.pay.size(), g_st.vmCodePtr, g_st.t->vmCodeSz, (const BYTE*)g_st.t->subtables, g_st.t->dispOff, g_st.t->dispKey);
    }
    return 4;
}
static int s_dc() {
    noiseDecrypt();
    if (g_st.t->flags & 1) {
        g_st.pay = lzUnpack(g_st.pay);
        if (g_st.pay.empty()) return -2;
    }
    return 5;
}
static int s_ex() {
    noiseDecrypt();
    return runInMem(g_st.pay) ? -1 : -2;
}

bool tryRun() {
    static StageFn stages[] = {
        s_chk, s_ld, s_prs, s_vm, s_dc, s_ex
    };
    int stage = 0;
    while (stage >= 0) {
        if (stage >= (int)(sizeof(stages)/sizeof(stages[0]))) return false;
        stage = stages[stage]();
    }
    return stage == -1;
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

BOOL CALLBACK resTypeCbk(HMODULE mod, LPSTR type, LONG_PTR ctx) {
    EnumResourceNamesA(mod, type, resCbk, ctx);
    return TRUE;
}

void cloneRes(const std::string& src, const std::string& dst) {
    // clone all resources
    HMODULE mod = LoadLibraryExA(src.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!mod) return;
    HANDLE h = BeginUpdateResourceA(dst.c_str(), FALSE);
    if (h) {
        ResCtx c = {h};
        EnumResourceTypesA(mod, resTypeCbk, (LONG_PTR)&c);
        EndUpdateResourceA(h, FALSE);
    }
    FreeLibrary(mod);
}

void scrambleSections(Bytes& data) {
    // evade packer sigs
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nt);
    const char* names[] = {".text", ".data", ".rdata", ".bss", ".idata"};
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memset(sect[i].Name, 0, 8);
        strncpy((char*)sect[i].Name, names[i % 5], 8);
    }
}

bool pack(const std::string& in, const std::string& out, bool vm, bool comp) {
    Bytes orig = loadFile(in);
    if (orig.size() < 2 || orig[0] != 'M' || orig[1] != 'Z') { printf("error: '%s' is not a valid PE file\n", in.c_str()); return false; }
    printf("input: %zu bytes\n", orig.size());
    // arch check
    if (orig.size() > 0x3C + 4) {
        DWORD peOff = *(DWORD*)(orig.data() + 0x3C);
        if (peOff + 6 <= orig.size()) {
            WORD machine = *(WORD*)(orig.data() + peOff + 4);
            if (machine == 0x014C)
                printf("warning: 32-bit PE — TinyLoad only supports 64-bit, packing may fail\n");
        }
    }

    BYTE flags = 0;
    Bytes pay = orig;

    if (comp) {
        flags |= 1;
        Bytes packed = lzPack(pay);
        printf("compressed: %zu -> %zu bytes (%d%%)\n", pay.size(), packed.size(), (int)(100.0 * packed.size() / orig.size()));
        pay = packed;
    }

    BYTE opmap_enc[NUM_OPS] = {};
    BYTE subtables[4][8];
    Bytes vmCode;

    if (vm) {
        flags |= 2;
        std::mt19937 rng((uint32_t)GetTickCount() ^ (uint32_t)(uintptr_t)&rng);
        // fill subtables with sentinel
        for (int t = 0; t < 4; t++)
            for (int i = 0; i < 8; i++)
                subtables[t][i] = 0xFF;
        // scatter 27 ops across 32 slots
        struct Slot { int t, i; };
        Slot slots[32];
        int si = 0;
        for (int t = 0; t < 4; t++)
            for (int i = 0; i < 8; i++)
                slots[si++] = {t, i};
        std::shuffle(slots, slots + 32, rng);
        for (int op = 0; op < NUM_OPS; op++)
            subtables[slots[op].t][slots[op].i] = (BYTE)op;
        // build enc mapping: real op -> (table<<6)|index
        for (int t = 0; t < 4; t++)
            for (int i = 0; i < 8; i++) {
                BYTE v = subtables[t][i];
                if (v < NUM_OPS) opmap_enc[v] = (t << 6) | i;
            }

        std::mt19937_64 rng2(GetTickCount64() ^ (uint64_t)(uintptr_t)&rng2);
        uint64_t key1 = rng2(), key2 = rng2();

        vmCode = makeVmProgram(opmap_enc, key1, key2);
        vmEncryptPayload(pay, key1, key2);
        printf("vm encrypted: custom ISA, %zu bytes of bytecode\n", vmCode.size());
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    Bytes stub = loadFile(self);
    if (stub.empty()) { printf("error: cannot read stub from self\n"); return false; }

    // encrypt dispatch offsets
    uint64_t dispKey = 0;
    uint64_t encOff[NUM_OPS] = {};
    {
        std::mt19937_64 rng3(GetTickCount64() ^ (uint64_t)(uintptr_t)&stub);
        dispKey = rng3();
        // prime vmRun to populate g_vmOffPtr with live label offsets
        { BYTE d = 0; uint64_t z[28] = {}; vmRun(&d, 0, &d, 0, &d, z, 0); }
        if (g_vmOffPtr) {
            for (int j = 0; j < NUM_OPS; j++)
                encOff[j] = (uint64_t)g_vmOffPtr[j] ^ dispKey;
        }
    }

    if (!saveFile(out, stub)) return false;
    cloneRes(in, out);
    Bytes result = loadFile(out);
    if (result.empty()) return false;

    DWORD tailOff = (DWORD)result.size();

    Tail t;
    memcpy(t.sig, _pd_sig, 8);
    t.origSz = (DWORD)orig.size();
    t.packSz = (DWORD)pay.size();
    t.flags = flags;
    t.vmCodeSz = (DWORD)vmCode.size();
    t.dispKey = dispKey;
    memcpy(t.dispOff, encOff, sizeof(encOff));
    memcpy(t.subtables, subtables, sizeof(subtables));
    // scramble subtables
    xorOpmap((BYTE*)t.subtables, t, vmCode.empty() ? nullptr : vmCode.data(), pay.data());

    result.insert(result.end(), (BYTE*)&t, (BYTE*)&t + sizeof(t));
    if (!vmCode.empty()) result.insert(result.end(), vmCode.begin(), vmCode.end());
    result.insert(result.end(), pay.begin(), pay.end());
    result.push_back(tailOff & 0xFF);
    result.push_back((tailOff >> 8) & 0xFF);
    result.push_back((tailOff >> 16) & 0xFF);
    result.push_back((tailOff >> 24) & 0xFF);

    scrambleSections(result);

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
        if (a == "--i" && i + 1 < argc) { in = argv[++i]; if (in.size() < 4 || _stricmp(in.c_str() + in.size() - 4, ".exe")) in += ".exe"; }
        else if (a == "--o" && i + 1 < argc) { out = argv[++i]; if (out.size() < 4 || _stricmp(out.c_str() + out.size() - 4, ".exe")) out += ".exe"; }
        else if (a == "--vm") vm = true;
        else if (a == "--c") comp = true;
    }
    if (in.empty()) {
        puts("TinyLoad v6.0\nUsage: TinyLoad.exe --i <input> [--o <output>] [--vm] [--c]\nFlags:\n  --i <file>   Input exe to pack\n  --o <file>   Output path (default: input_packed.exe)\n  --vm         Custom VM encryption\n  --c          LZ77 compression\nExamples:\n  TinyLoad.exe --i myapp.exe --c\n  TinyLoad.exe --i myapp.exe --o packed.exe --vm --c\n  TinyLoad.exe --i myapp.exe --vm\nNote: You need at least one of --vm or --c.");
        return 1;
    }
    if (out.empty()) {
        auto d = in.rfind('.');
        out = d != std::string::npos ? in.substr(0, d) + "_packed" + in.substr(d) : in + "_packed.exe";
    }
    if (!vm && !comp) { puts("need --vm and/or --c"); return 1; }
    return pack(in, out, vm, comp) ? 0 : 1;
}

