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

//You will see encrypted strings trougout this code, they are XOR'ed to avoid them being plaintext. decrypted by sdec2() using a positional XOR cipher (buf[i] = enc[i] ^ (key + i)). Keys are stored per string in StubHook 
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

__attribute__((noinline)) bool isDebugged() {
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
    // canary
    uint32_t canaryOff[8];
    BYTE     canaryExp[8];
    BYTE     canaryCnt;
    // chunk splitting
    uint32_t chunkOff[4];
    uint32_t chunkSz[4];
    uint8_t  chunkOrder[4];
    uint8_t  chunkCnt;
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

static void writeVarInt(Bytes& out, int v) {
    while (v >= 0x80) { out.push_back((BYTE)(v | 0x80)); v >>= 7; }
    out.push_back((BYTE)v);
}

static int readVarInt(const Bytes& in, size_t& p) {
    unsigned v = 0; int shift = 0;
    while (p < in.size() && shift < 28) {
        BYTE b = in[p++];
        v |= (unsigned)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return (int)v;
}

Bytes lzPack(const Bytes& in) {
    if (in.empty()) return {0, 0, 0, 0};
    const int WINDOW = 0xFFFF;
    const int MAXCHAIN = 4096;
    const int MAXMATCH = 258;
    const int MINMATCH = 3;
    const int HSIZE = 1 << 16;
    std::vector<int> head(HSIZE, -1);
    std::vector<int> prev(in.size(), -1);
    auto hash4 = [&](size_t p) -> int {
        if (p + 2 >= in.size()) return 0;
        unsigned h = in[p];
        h = (h * 0x1000193u) ^ in[p+1];
        h = (h * 0x1000193u) ^ in[p+2];
        if (p + 3 < in.size()) h = (h * 0x1000193u) ^ in[p+3];
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
            if (ml > 0 && ((size_t)(cur + ml) >= in.size() || (size_t)(p + ml) >= in.size())) ml = 0;
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
            int bestOff = 0, bestLen = ml, bestDist = md;
            for (int la = 1; la <= 2 && pos + la + MINMATCH <= in.size(); la++) {
                int ml2, md2;
                findMatch(pos + la, ml2, md2);
                if (ml2 > bestLen + la) { bestOff = la; bestLen = ml2; bestDist = md2; }
            }
            for (int j = 0; j < bestOff; j++) { toks.push_back({false, in[pos], 0, 0}); insert(pos); pos++; }
            toks.push_back({true, 0, bestDist, bestLen});
            for (int j = 0; j < bestLen; j++) insert(pos + j);
            pos += bestLen;
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
                writeVarInt(out, t.dist);
                writeVarInt(out, t.len - MINMATCH);
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
                if (p >= in.size()) break;
                int dist = readVarInt(in, p);
                int len = readVarInt(in, p) + 3;
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
        if (r[idx] >= r[1]) return;
        r[d] = ((BYTE*)(uintptr_t)r[b])[r[idx]];
    }
    goto dispatch;
stb_l:
    {
        if (ip + 2 >= codesz) goto dispatch;
        uint8_t b = code[ip++], idx = code[ip++], s = code[ip++];
        if (b >= 9 || idx >= 9 || s >= 9) return;
        if (r[idx] >= r[1]) return;
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

Bytes makeVmProgram(const BYTE* enc, uint64_t key1, uint64_t key2,
                    const uint32_t* canOff, const BYTE* canExp, BYTE canCnt) {
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

    // xor-self -> 0
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

    // opaque
    eOp(bc,enc,MOV_I); eR(bc,6); eR(bc,3);
    eOp(bc,enc,XOR_I); eR(bc,6); eR(bc,3); // r6 = 0
    eOp(bc,enc,CMP_I); eR(bc,6); eR(bc,6); eR(bc,5); // r6 = (0 < 1) = 1
    eOp(bc,enc,JNZ_I); eR(bc,6);
    int opq5Patch = (int)bc.size(); e32(bc,0);
    eOp(bc,enc,HLT_I); // trap if zero (never)
    int opq5End = (int)bc.size();
    { int32_t o = opq5End - (opq5Patch + 4); memcpy(&bc[opq5Patch], &o, 4); }

    // opaque
    eOp(bc,enc,ANDI_I); eR(bc,8); e64(bc,1); // r8 = (junk) & 1 
    eOp(bc,enc,CMP_I); eR(bc,6); eR(bc,5); eR(bc,8); // r6 = (1 < r8), always 0
    eOp(bc,enc,JNZ_I); eR(bc,6); // never jumps
    int opq6Patch = (int)bc.size(); e32(bc,0);
    { // dead block
        eOp(bc,enc,ROL_I); eR(bc,8); eR(bc,8);
        eOp(bc,enc,MULI_I); eR(bc,8); e64(bc,0x517CC1B7);
        eOp(bc,enc,NOP_I);
    }
    int opq6End = (int)bc.size();
    { int32_t o = opq6End - (opq6Patch + 4); memcpy(&bc[opq6Patch], &o, 4); }

    int loopPos = (int)bc.size();

    eOp(bc,enc,CMP_I); eR(bc,7); eR(bc,2); eR(bc,1);
    eOp(bc,enc,JNZ_I); eR(bc,7);
    int jnzPatch = (int)bc.size(); e32(bc, 0);
    // JMP to canary block (patched later)
    eOp(bc,enc,JMP_I);
    int exitPatch = (int)bc.size(); e32(bc, 0);

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

    // patch exit jump to here
    int canaryStart = (int)bc.size();
    { int32_t off = canaryStart - (exitPatch + 4); memcpy(&bc[exitPatch], &off, 4); }

    // canary
    if (canCnt > 0) {
        int n = canCnt < 8 ? canCnt : 8;
        uint32_t minOff = canOff[0];
        for (int c = 1; c < n; c++) if (canOff[c] < minOff) minOff = canOff[c];

        // r6=mask, r7=prev_actual, r5=const_1
        eOp(bc,enc,LDI_I); eR(bc,6); e64(bc,0); // mask=0
        eOp(bc,enc,LDI_I); eR(bc,7); e64(bc,0); // prev=0
        eOp(bc,enc,LDI_I); eR(bc,5); e64(bc,1); // const 1

        for (int c = 0; c < n; c++) {
            eOp(bc,enc,LDI_I); eR(bc,2); e64(bc, canOff[c]);
            eOp(bc,enc,LDB_I); eR(bc,8); eR(bc,0); eR(bc,2); // r8=actual
            eOp(bc,enc,LDI_I); eR(bc,3); e64(bc, canExp[c]);
            eOp(bc,enc,XOR_I); eR(bc,3); eR(bc,7); // r3=canExp^prev
            eOp(bc,enc,MOV_I); eR(bc,4); eR(bc,8);
            eOp(bc,enc,XOR_I); eR(bc,4); eR(bc,3); // r4=actual^expected
            eOp(bc,enc,CMP_I); eR(bc,4); eR(bc,4); eR(bc,5); // r4=(diff<1)
            eOp(bc,enc,JNZ_I); eR(bc,4);
            int okPatch = (int)bc.size(); e32(bc,0);
            eOp(bc,enc,LDI_I); eR(bc,2); e64(bc, (uint64_t)1 << c);
            eOp(bc,enc,OR_I);  eR(bc,6); eR(bc,2); // mask|=bit
            int okEnd = (int)bc.size();
            { int32_t o = okEnd - (okPatch + 4); memcpy(&bc[okPatch], &o, 4); }
            eOp(bc,enc,MOV_I); eR(bc,7); eR(bc,8); // prev=actual
        }

        // apply mask from minOff
        eOp(bc,enc,LDI_I); eR(bc,2); e64(bc, minOff);
        int applyLoop = (int)bc.size();
        eOp(bc,enc,CMP_I); eR(bc,3); eR(bc,2); eR(bc,1); // r3=(j<size)
        eOp(bc,enc,JNZ_I); eR(bc,3);
        int aplPatch = (int)bc.size(); e32(bc,0);
        eOp(bc,enc,HLT_I);
        int aplBody = (int)bc.size();
        { int32_t o = aplBody - (aplPatch + 4); memcpy(&bc[aplPatch], &o, 4); }
        eOp(bc,enc,MOV_I); eR(bc,4); eR(bc,6);
        eOp(bc,enc,ANDI_I); eR(bc,4); e64(bc,0xFF);
        eOp(bc,enc,LDB_I); eR(bc,8); eR(bc,0); eR(bc,2);
        eOp(bc,enc,XOR_I); eR(bc,8); eR(bc,4);
        eOp(bc,enc,STB_I); eR(bc,0); eR(bc,2); eR(bc,8);
        eOp(bc,enc,ADDI_I); eR(bc,2); e64(bc,1);
        eOp(bc,enc,JMP_I);
        int32_t aplBack = applyLoop - ((int)bc.size() + 4);
        e32(bc, aplBack);
    }

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

#define FLAG_VEH   4
#define FLAG_CHUNK 8

static struct {
    const Bytes* data;
    void* base;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    size_t delta;
    bool veh;
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
    if (g_pe.nt->OptionalHeader.SizeOfImage > 0x40000000 || g_pe.nt->OptionalHeader.SizeOfImage == 0) return -2;
    return 1;
}
static int sp_map() {
    g_pe.base = VirtualAlloc(NULL, g_pe.nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_pe.base) return -2;
    size_t hdrSize = g_pe.nt->OptionalHeader.SizeOfHeaders;
    if (hdrSize > g_pe.data->size()) hdrSize = g_pe.data->size();
    memcpy(g_pe.base, g_pe.data->data(), hdrSize);
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(g_pe.nt);
    if (g_pe.nt->FileHeader.NumberOfSections > 96) return -2;
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
                    WORD type = list[i] >> 12;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        size_t target = (size_t)rel->VirtualAddress + (list[i] & 0xFFF);
                        if (target + sizeof(size_t) <= g_pe.nt->OptionalHeader.SizeOfImage) {
                            size_t* p = (size_t*)((BYTE*)g_pe.base + target);
                            *p += g_pe.delta;
                        }
                    } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                        return -2;
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
                if (impLimit <= 0 && orig->u1.AddressOfData) return -2;
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

//  VEH
static CRITICAL_SECTION g_vehLock;
static uintptr_t g_vehBase;
static size_t   g_vehSize;
static uint64_t g_vehKey;
static HANDLE   g_vehWatchdog;
static volatile LONG g_vehStop;
static PVOID    g_vehHandle;

struct VehPage { uintptr_t addr; DWORD lastTick; };
static VehPage g_vehCache[256];
static int     g_vehCacheCnt;

struct PageRange { DWORD pgStart; DWORD pgEnd; DWORD origProt; };
static PageRange g_vehProt[96];
static int       g_vehProtCnt;

static DWORD sectToProt(DWORD chars) {
    // map section characteristics to PAGE_* constant
    bool ex = (chars & 0x20000000) != 0;
    bool rd = (chars & 0x40000000) != 0;
    bool wr = (chars & 0x80000000) != 0;
    if (ex && rd && wr) return PAGE_EXECUTE_READWRITE;
    if (ex && rd)       return PAGE_EXECUTE_READ;
    if (ex && wr)       return PAGE_EXECUTE_READWRITE;
    if (ex)             return PAGE_EXECUTE;
    if (rd && wr)       return PAGE_READWRITE;
    if (rd)             return PAGE_READONLY;
    if (wr)             return PAGE_READWRITE;
    return PAGE_READONLY;
}

static DWORD lookupOrigProt(uintptr_t pg) {
    DWORD num = (DWORD)((pg - g_vehBase) >> 12);
    for (int i = 0; i < g_vehProtCnt; i++)
        if (num >= g_vehProt[i].pgStart && num <= g_vehProt[i].pgEnd)
            return g_vehProt[i].origProt;
    return PAGE_EXECUTE_READWRITE; // fallback
}

static void vehPageXor(BYTE* p, size_t sz, uint64_t k, uintptr_t addr) {
    uint64_t s = k ^ (addr >> 12);
    for (size_t i = 0; i < sz; i++) {
        s = s * 0x9E3779B97F4A7C15ull + 0x517CC1B727220A95ull;
        p[i] ^= (BYTE)(s >> 32);
    }
}

static DWORD WINAPI vehWatchdogProc(LPVOID) {
    while (!g_vehStop) {
        Sleep(50);
        EnterCriticalSection(&g_vehLock);
        DWORD now = GetTickCount();
        for (int i = 0; i < g_vehCacheCnt; ) {
            if (now - g_vehCache[i].lastTick > 200) {
                uintptr_t pg = g_vehCache[i].addr;
                DWORD old;
                // fence: stop all access, any faulting thread blocks in VEH on our CS
                VirtualProtect((LPVOID)pg, 0x1000, PAGE_NOACCESS, &old);
                VirtualProtect((LPVOID)pg, 0x1000, PAGE_READWRITE, &old);
                vehPageXor((BYTE*)pg, 0x1000, g_vehKey, pg);
                VirtualProtect((LPVOID)pg, 0x1000, PAGE_NOACCESS, &old);
                g_vehCache[i] = g_vehCache[--g_vehCacheCnt];
            } else { i++; }
        }
        LeaveCriticalSection(&g_vehLock);
    }
    return 0;
}

__attribute__((used)) static LONG CALLBACK vehHandler(EXCEPTION_POINTERS* ex) {
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t fault = (uintptr_t)ex->ExceptionRecord->ExceptionInformation[1];
    if (fault < g_vehBase || fault >= g_vehBase + g_vehSize)
        return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t pg = fault & ~(uintptr_t)0xFFF;
    EnterCriticalSection(&g_vehLock);
    // check if already decrypted (race)
    for (int i = 0; i < g_vehCacheCnt; i++) {
        if (g_vehCache[i].addr == pg) {
            g_vehCache[i].lastTick = GetTickCount();
            LeaveCriticalSection(&g_vehLock);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    DWORD old;
    VirtualProtect((LPVOID)pg, 0x1000, PAGE_READWRITE, &old);
    vehPageXor((BYTE*)pg, 0x1000, g_vehKey, pg);
    VirtualProtect((LPVOID)pg, 0x1000, lookupOrigProt(pg), &old);
    if (g_vehCacheCnt < 256) {
        g_vehCache[g_vehCacheCnt].addr = pg;
        g_vehCache[g_vehCacheCnt].lastTick = GetTickCount();
        g_vehCacheCnt++;
    } else {
        // evict oldest
        int oldest = 0;
        for (int i = 1; i < 256; i++)
            if (g_vehCache[i].lastTick < g_vehCache[oldest].lastTick) oldest = i;
        uintptr_t evict = g_vehCache[oldest].addr;
        // fence: stop all access, VEH blocked on our CS
        VirtualProtect((LPVOID)evict, 0x1000, PAGE_NOACCESS, &old);
        VirtualProtect((LPVOID)evict, 0x1000, PAGE_READWRITE, &old);
        vehPageXor((BYTE*)evict, 0x1000, g_vehKey, evict);
        VirtualProtect((LPVOID)evict, 0x1000, PAGE_NOACCESS, &old);
        g_vehCache[oldest].addr = pg;
        g_vehCache[oldest].lastTick = GetTickCount();
    }
    LeaveCriticalSection(&g_vehLock);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void vehCleanup() {
    g_vehStop = 1;
    if (g_vehWatchdog) { WaitForSingleObject(g_vehWatchdog, 2000); CloseHandle(g_vehWatchdog); g_vehWatchdog = NULL; }
    RemoveVectoredExceptionHandler(g_vehHandle);
    DeleteCriticalSection(&g_vehLock);
}

static int sp_veh() {
    if (!g_pe.veh) return 5;
    g_vehBase = (uintptr_t)g_pe.base;
    g_vehSize = (g_pe.nt->OptionalHeader.SizeOfImage + 0xFFF) & ~0xFFF;
    std::mt19937_64 rng(GetTickCount64() ^ (uint64_t)(uintptr_t)&rng);
    g_vehKey = rng();
    InitializeCriticalSection(&g_vehLock);
    DWORD hdrEnd = (g_pe.nt->OptionalHeader.SizeOfHeaders + 0xFFF) & ~0xFFF;
    g_vehProtCnt = 0;
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(g_pe.nt);
    int ns = g_pe.nt->FileHeader.NumberOfSections;
    if (ns < 0) ns = 0; if (ns > 96) ns = 96;
    for (int i = 0; i < ns; i++) {
        if (sect[i].SizeOfRawData == 0) continue;
        DWORD va = sect[i].VirtualAddress;
        DWORD sz = sect[i].SizeOfRawData;
        if (va >= g_vehSize) continue;
        if (va + sz < va || va + sz > g_vehSize) sz = g_vehSize - va;
        DWORD end = (va + sz + 0xFFF) & ~0xFFF;
        if (end < va) continue;
        // record protection for this section
        DWORD prot = sectToProt(sect[i].Characteristics);
        DWORD ps = va >> 12;
        DWORD pe = (end - 1) >> 12;
        if (g_vehProtCnt < 96) {
            g_vehProt[g_vehProtCnt].pgStart  = ps;
            g_vehProt[g_vehProtCnt].pgEnd    = pe;
            g_vehProt[g_vehProtCnt].origProt = prot;
            g_vehProtCnt++;
        }
        for (DWORD off = va & ~0xFFF; off < end; off += 0x1000) {
            if (off < hdrEnd) continue; // skip header overlap
            BYTE* p = (BYTE*)g_pe.base + off;
            DWORD old;
            VirtualProtect(p, 0x1000, PAGE_READWRITE, &old);
            vehPageXor(p, 0x1000, g_vehKey, (uintptr_t)p);
            VirtualProtect(p, 0x1000, PAGE_NOACCESS, &old);
        }
    }
    g_vehHandle = AddVectoredExceptionHandler(1, vehHandler);
    g_vehStop = 0;
    g_vehWatchdog = CreateThread(NULL, 0, vehWatchdogProc, NULL, 0, NULL);
    return 5;
}

bool runInMem(const Bytes& data, bool veh) {
    static PEStageFn stages[] = {
        sp_hdr, sp_map, sp_reloc, sp_import, sp_veh, sp_go
    };
    g_pe.data = &data;
    g_pe.base = nullptr;
    g_pe.veh = veh;
    int stage = 0;
    while (stage >= 0) {
        if (stage >= (int)(sizeof(stages)/sizeof(stages[0]))) return false;
        noiseDecrypt();
        stage = stages[stage]();
    }
    if (veh) vehCleanup();
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
    uint64_t sk = 0x9E3779B97F4A7C15ull;
    for (size_t i = 0x1000; i < g_st.blob.size() && i < 0x2000; i++)
        sk = (sk ^ g_st.blob[i]) * 0x9E3779B97F4A7C15ull;
    g_st.off = *(DWORD*)&g_st.blob[g_st.blob.size() - 4] ^ (DWORD)(sk & 0xFFFFFFFF);
    if (g_st.off + sizeof(Tail) > g_st.blob.size()) return -2;
    return 2;
}
static int s_prs() {
    noiseDecrypt();
    g_st.t = (Tail*)&g_st.blob[g_st.off];
    // derive key from stub (.text, skip headers)
    uint64_t stubKey = 0x9E3779B97F4A7C15ull;
    for (size_t i = 0x1000; i < g_st.blob.size() && i < 0x2000; i++)
        stubKey = (stubKey ^ g_st.blob[i]) * 0x9E3779B97F4A7C15ull;
    // de-XOR metadata fields
    g_st.t->origSz ^= (DWORD)(stubKey & 0xFFFFFFFF);
    g_st.t->packSz ^= (DWORD)((stubKey >> 32) & 0xFFFFFFFF);
    g_st.t->flags  ^= (BYTE)((stubKey >> 16) & 0xFF);
    // de-XOR dispKey, canary, vmCodeSz
    uint64_t realDispKey = g_st.t->dispKey ^ stubKey;
    g_st.t->vmCodeSz ^= (DWORD)((stubKey >> 8) & 0xFFFFFFFF);
    g_st.t->canaryCnt ^= (BYTE)(stubKey & 0xFF);
    for (int si = 0; si < (int)sizeof(g_st.t->canaryOff); si++)
        ((BYTE*)g_st.t->canaryOff)[si] ^= (BYTE)(stubKey >> ((si*7)&63));
    for (int si = 0; si < (int)sizeof(g_st.t->canaryExp); si++)
        g_st.t->canaryExp[si] ^= (BYTE)(stubKey >> ((si*11)&63));
    // de-XOR sig with stubKey
    char sigBuf[8]; memcpy(sigBuf, g_st.t->sig, 8);
    for (int si = 0; si < 8; si++) sigBuf[si] ^= (BYTE)(stubKey >> (si*8));
    if (memcmp(sigBuf, _pd_sig, 8)) return -2;
    // restore dispKey
    g_st.t->dispKey = realDispKey;

    Bytes interleaved;
    if (g_st.t->flags & FLAG_CHUNK) {
        // decrypt chunk fields
        int nChunks = g_st.t->chunkCnt ^ (BYTE)((stubKey >> 24) & 0xFF);
        if (nChunks < 1 || nChunks > 4) return -2;
        for (int si = 0; si < nChunks; si++)
            g_st.t->chunkOff[si] ^= (DWORD)(stubKey >> ((si*11)&63));
        for (int si = 0; si < nChunks; si++)
            g_st.t->chunkSz[si] ^= (DWORD)(stubKey >> ((si*17)&63));
        for (int si = 0; si < nChunks; si++)
            g_st.t->chunkOrder[si] ^= (BYTE)(stubKey >> ((si*13)&63));
        // read chunks from file
        Bytes chunks[4];
        for (int ci = 0; ci < nChunks; ci++) {
            DWORD off = g_st.t->chunkOff[ci];
            DWORD sz  = g_st.t->chunkSz[ci];
            if (!sz) continue;
            if (off < g_st.off + sizeof(Tail) || off + sz > g_st.blob.size() - 4) return -2;
            chunks[ci].assign(g_st.blob.begin() + off, g_st.blob.begin() + off + sz);
        }
        // reassemble in logical order
        for (int logical = 0; logical < nChunks; logical++) {
            int phys = -1;
            for (int j = 0; j < nChunks; j++)
                if (g_st.t->chunkOrder[j] == logical) { phys = j; break; }
            if (phys < 0) return -2;
            if (chunks[phys].empty()) continue;
            interleaved.insert(interleaved.end(), chunks[phys].begin(), chunks[phys].end());
        }
    } else {
        // old format: interleaved overlay starts after Tail
        size_t overlayEnd = g_st.blob.size() - 4;
        for (size_t i = g_st.off + sizeof(Tail); i < overlayEnd; i++)
            interleaved.push_back(g_st.blob[i]);
    }
    // de-interleave
    {
        Bytes deint;
        for (size_t i = 0, fi = 0; i < interleaved.size(); i++, fi++) {
            deint.push_back(interleaved[i]);
            if ((fi % 3) == 2 && i + 1 < interleaved.size()) i++;
        }
        interleaved = std::move(deint);
    }
    // verify sizes
    if (interleaved.size() != (size_t)g_st.t->vmCodeSz + (size_t)g_st.t->packSz) return -2;
    // store in g_st.blob so pointers remain valid
    g_st.blob.resize(g_st.off + sizeof(Tail));
    g_st.blob.insert(g_st.blob.end(), interleaved.begin(), interleaved.end());
    g_st.t = (Tail*)&g_st.blob[g_st.off];
    g_st.vmCodePtr = (BYTE*)(g_st.t + 1);
    // decrypt VM bytecode
    for (size_t vi = 0; vi < g_st.t->vmCodeSz; vi++)
        g_st.vmCodePtr[vi] ^= (BYTE)(stubKey >> ((vi*3)&63));
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
    return runInMem(g_st.pay, !!(g_st.t->flags & FLAG_VEH)) ? -1 : -2;
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

bool pack(const std::string& in, const std::string& out, bool vm, bool comp, bool veh) {
    Bytes orig = loadFile(in);
    if (orig.size() < 2 || orig[0] != 'M' || orig[1] != 'Z') { printf("error: '%s' is not a valid PE file\n", in.c_str()); return false; }
    printf("input: %zu bytes\n", orig.size());
    // arch check
    if (orig.size() > 0x3C + 4) {
        DWORD peOff = *(DWORD*)(orig.data() + 0x3C);
        if (peOff + 6 <= orig.size()) {
            WORD machine = *(WORD*)(orig.data() + peOff + 4);
            if (machine == 0x014C)
                printf("warning: 32-bit PE, packing may fail\n");
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
    uint32_t canOff[8] = {};
    BYTE     canExp[8] = {};
    BYTE     canCnt = 0;

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

        LARGE_INTEGER qpc; QueryPerformanceCounter(&qpc);
        std::mt19937_64 rng2(GetTickCount64() ^ (uint64_t)(uintptr_t)&rng2 ^ qpc.QuadPart);
        uint64_t key1 = rng2(), key2 = rng2();

        // canary corridor
        {
            uint32_t nCan = 8;
            if (pay.size() < nCan * 2) nCan = (uint32_t)pay.size() > 0 ? 1 : 0;
            if (nCan > 0) {
                std::mt19937 crng((uint32_t)(key1 ^ (uint64_t)(uintptr_t)&pay));
                uint32_t skipHdr = pay.size() > 0x400 ? 0x400 : 0;
                uint32_t usable = (uint32_t)pay.size() - skipHdr;
                uint32_t step = usable / (nCan + 1);
                for (uint32_t c = 0; c < nCan; c++) {
                    uint32_t base = skipHdr + step * (c + 1);
                    uint32_t off = base + (crng() % (step > 0 ? step : 1));
                    if (off >= pay.size()) off = (uint32_t)pay.size() - 1;
                    canOff[c] = off;
                }
                std::shuffle(canOff, canOff + nCan, crng);
                BYTE prev = 0;
                for (uint32_t c = 0; c < nCan; c++) {
                    BYTE actual = pay[canOff[c]];
                    canExp[c] = actual ^ prev;
                    prev = actual;
                }
            }
            canCnt = (BYTE)nCan;
        }

        vmCode = makeVmProgram(opmap_enc, key1, key2, canOff, canExp, canCnt);
        vmEncryptPayload(pay, key1, key2);
        printf("vm encrypted: custom ISA, %zu bytes of bytecode\n", vmCode.size());
    }

    if (veh) {
        flags |= FLAG_VEH;
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    Bytes stub = loadFile(self);
    if (stub.empty()) { printf("error: cannot read stub from self\n"); return false; }

    // derive key from stub for overlay encryption (skip headers: use .text)
    uint64_t stubKey = 0x9E3779B97F4A7C15ull;
    for (size_t i = 0x1000; i < stub.size() && i < 0x2000; i++)
        stubKey = (stubKey ^ stub[i]) * 0x9E3779B97F4A7C15ull;

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
    // cloneRes disabled: LoadLibraryExA intermittently locks output file
    Bytes result = loadFile(out);

    Tail t;
    memcpy(t.sig, _pd_sig, 8);
    t.origSz = (DWORD)orig.size();
    t.packSz = (DWORD)pay.size();
    t.flags = flags;
    t.vmCodeSz = (DWORD)vmCode.size();
    t.dispKey = dispKey;
    memcpy(t.dispOff, encOff, sizeof(encOff));
    memcpy(t.subtables, subtables, sizeof(subtables));
    t.canaryCnt = canCnt;
    memcpy(t.canaryOff, canOff, sizeof(canOff));
    memcpy(t.canaryExp, canExp, sizeof(canExp));
    // hide signature with stubKey
    for (int si = 0; si < 8; si++) t.sig[si] ^= (BYTE)(stubKey >> (si*8));
    // scramble subtables
    xorOpmap((BYTE*)t.subtables, t, vmCode.empty() ? nullptr : vmCode.data(), pay.data());

    t.flags |= FLAG_CHUNK; // set before encrypt

    // encrypt sensitive Tail fields with stub-derived key
    t.origSz ^= (DWORD)(stubKey & 0xFFFFFFFF);
    t.packSz ^= (DWORD)((stubKey >> 32) & 0xFFFFFFFF);
    t.flags  ^= (BYTE)((stubKey >> 16) & 0xFF);
    t.dispKey ^= stubKey;
    for (int si = 0; si < (int)sizeof(t.canaryOff); si++)
        ((BYTE*)t.canaryOff)[si] ^= (BYTE)(stubKey >> ((si*7)&63));
    for (int si = 0; si < (int)sizeof(t.canaryExp); si++)
        t.canaryExp[si] ^= (BYTE)(stubKey >> ((si*11)&63));
    t.canaryCnt ^= (BYTE)(stubKey & 0xFF);
    t.vmCodeSz ^= (DWORD)((stubKey >> 8) & 0xFFFFFFFF);
    // encrypt VM bytecode
    for (size_t vi = 0; vi < vmCode.size(); vi++)
        vmCode[vi] ^= (BYTE)(stubKey >> ((vi*3)&63));

    DWORD tailOff = 0;

    // build overlay: Tail first (non-interleaved), then payload split into 4 chunks with junk gaps
    {
        Bytes payload;
        if (!vmCode.empty()) payload.insert(payload.end(), vmCode.begin(), vmCode.end());
        payload.insert(payload.end(), pay.begin(), pay.end());

        // interleave payload
        Bytes interleaved;
        interleaved.reserve(payload.size() + payload.size() / 3 + 4);
        for (size_t i = 0; i < payload.size(); i++) {
            interleaved.push_back(payload[i]);
            if ((i % 3) == 2) interleaved.push_back(0x00);
        }

        t.chunkCnt = 4;
        size_t chunkBase = interleaved.size() / t.chunkCnt;
        size_t chunkRem  = interleaved.size() % t.chunkCnt;
        uint32_t rawOff[4] = {}, rawSz[4] = {};
        uint8_t  rawOrder[4] = {0, 1, 2, 3};

        std::mt19937 crng((uint32_t)(stubKey ^ result.size()));
        std::shuffle(rawOrder, rawOrder + 4, crng);

        // write Tail placeholder
        tailOff = (DWORD)result.size();
        size_t tailPos = result.size();
        result.resize(result.size() + sizeof(t));

        for (int ci = 0; ci < 4; ci++) {
            size_t gapSz = 128 + (crng() % 513);
            for (size_t j = 0; j < gapSz; j++) result.push_back((BYTE)(crng() & 0xFF));

            rawOff[ci] = (DWORD)result.size();
            uint8_t logical = rawOrder[ci];
            size_t start = logical * chunkBase + (logical < chunkRem ? logical : chunkRem);
            size_t end   = start + chunkBase + (logical < chunkRem ? 1 : 0);
            if (start >= interleaved.size()) { rawSz[ci] = 0; continue; }
            if (end > interleaved.size()) end = interleaved.size();
            rawSz[ci] = (DWORD)(end - start);
            result.insert(result.end(), interleaved.begin() + start, interleaved.begin() + end);
        }

        for (int ci = 0; ci < 4; ci++) { t.chunkOff[ci] = rawOff[ci]; t.chunkSz[ci] = rawSz[ci]; t.chunkOrder[ci] = rawOrder[ci]; }

        // encrypt chunk fields
        for (int si = 0; si < 4; si++) t.chunkOff[si] ^= (DWORD)(stubKey >> ((si*11)&63));
        for (int si = 0; si < 4; si++) t.chunkSz[si]  ^= (DWORD)(stubKey >> ((si*17)&63));
        for (int si = 0; si < 4; si++) t.chunkOrder[si] ^= (BYTE)(stubKey >> ((si*13)&63));
        t.chunkCnt ^= (BYTE)((stubKey >> 24) & 0xFF);

        memcpy(&result[tailPos], &t, sizeof(t));
    }
    // encrypt tail offset
    DWORD encTailOff = tailOff ^ (DWORD)(stubKey & 0xFFFFFFFF);
    result.push_back(encTailOff & 0xFF);
    result.push_back((encTailOff >> 8) & 0xFF);
    result.push_back((encTailOff >> 16) & 0xFF);
    result.push_back((encTailOff >> 24) & 0xFF);

    scrambleSections(result);

    if (!saveFile(out, result)) return false;
    printf("-> %s (%zu bytes)\n", out.c_str(), result.size());
    return true;
}

int main(int argc, char* argv[]) {
    if (tryRun()) return 0;
    std::string in, out;
    bool vm = false, comp = false, veh = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--i" && i + 1 < argc) { in = argv[++i]; if (in.size() < 4 || _stricmp(in.c_str() + in.size() - 4, ".exe")) in += ".exe"; }
        else if (a == "--o" && i + 1 < argc) { out = argv[++i]; if (out.size() < 4 || _stricmp(out.c_str() + out.size() - 4, ".exe")) out += ".exe"; }
        else if (a == "--vm") vm = true;
        else if (a == "--c") comp = true;
        else if (a == "--veh") veh = true;
    }
    if (in.empty()) {
        // help strings XOR'ed 
        static const BYTE _eh[] = {
            0x71,0x7B,0x67,0x67,0x79,0x6C,0x7E,0x7C,0x2F,0x34,0x0B,0x0A,0x01,0x72,0x6F,0x60,
            0x7D,0x76,0x2F,0x64,0x67,0x57,0x67,0x7E,0x7C,0x18,0x3B,0x0A,0x01,0x01,0x69,0x2B,
            0x28,0x3E,0x39,0x73,0x6E,0x4B,0x5D,0x5D,0x49,0x57,0x36,0x27,0x26,0x38,0x78,0x76,
            0x7B,0x6D,0x20,0x34,0x73,0x6E,0x70,0x34,0x67,0x2F,0x77,0x74,0x49,0x5C,0x43,0x4F,
            0x3A,0x37,0x2D,0x2F,0x21,0x6B,0x77,0x71,0x3B,0x6E,0x4B,0x55,0x5A,0x4B,0x47,0x3A,
            0x28,0x21,0x37,0x2B,0x7B,0x7F,0x67,0x3C,0x73,0x49,0x57,0x54,0x41,0x41,0x42,0x2D,
            0x39,0x3E,0x3B,0x73,0x79,0x3A,0x58,0x48,0x4F,0x5B,0x44,0x41,0x01,0x6E,0x0B,0x1D,
            0x0B,0x41,0x54,0x46,0x50,0x45,0x42,0x56,0x3B,0x6E,0x2F,0x67,0x61,0x54,0x4C,0x29,
            0x24,0x3E,0x6F,0x6B,0x75,0x3C,0x74,0x4F,0x45,0x5B,0x43,0x37,0x3E,0x78,0x7A,0x04,
            0x72,0x72,0x7B,0x67,0x7E,0x4F,0x5B,0x55,0x01,0x3C,0x63,0x79,0x78,0x6F,0x6B,0x30,
            0x5A,0x50,0x59,0x0D,0x01,0x73,0x76,0x6B,0x69,0x3E,0x6F,0x69,0x6C,0x61,0x67,0x2C,
            0x5D,0x41,0x43,0x4B,0x09,0x32,0x7B,0x68,0x6C,0x1B,0x3E,0x2F,0x23,0x2B,0x3F,0x2F,
            0x73,0x20,0x52,0x4B,0x54,0x4B,0x30,0x23,0x27,0x38,0x8A,0x96,0x94,0x9B,0x97,0x97,0x99
        };
        char buf[512]; uint8_t k = 0x5D;
        for (int i = 0; i < (int)sizeof(_eh); i++) buf[i] = _eh[i] ^ (uint8_t)(k + i);
        buf[sizeof(_eh)] = 0;
        puts(buf);
        return 1;
    }
    if (out.empty()) {
        auto d = in.rfind('.');
        out = d != std::string::npos ? in.substr(0, d) + "_packed" + in.substr(d) : in + "_packed.exe";
    }
    if (!vm && !comp && !veh) {
        static const BYTE _en[] = {0x7D,0x78,0x70,0x7F,0x2C,0x38,0x34,0x27,0x28,0x3C,0x2C,0x2F,0x72,0x7E,0x75,0x6F,0x2E,0x2A,0x29,0x7E,0x7A,0x7A,0x77,0x74,0x7B,0x7C,0x6D,0x6B,0x01};
        char b2[32]; uint8_t k2 = 0x3F;
        for (int i = 0; i < (int)sizeof(_en); i++) b2[i] = _en[i] ^ (uint8_t)(k2 + i);
        b2[sizeof(_en)] = 0;
        puts(b2);
        return 1;
    }
    return pack(in, out, vm, comp, veh) ? 0 : 1;
}
