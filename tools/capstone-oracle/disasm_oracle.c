/* Capstone disassembly oracle — links the exact capstone 5.0 static lib
 * vendored in upstream DIE-engine (dep/XCapstone/3rdparty/Capstone).
 * Replicates XCapstone::openHandle's DM->(arch,mode) mapping so Rust
 * output can be diffed instruction-for-instruction.
 *
 * Usage: disasm_oracle <dm> <base_hex> <binfile>
 * Output: one line per instruction "addr<TAB>hexbytes<TAB>mnemonic op_str"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

typedef struct {
    const char *name;
    cs_arch arch;
    cs_mode mode;
} dm_entry;

/* Mirror of XCapstone::openHandle branches — the full DM table except
 * the x86/arm variants routed to other Rust backends (DM_8086/X86/ARM
 * LE/AARCH64 LE yaxpeax paths are covered by their own parity tests). */
static const dm_entry DM_TABLE[] = {
    {"mips32le",  CS_ARCH_MIPS,   (cs_mode)(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)},
    {"mips32be",  CS_ARCH_MIPS,   (cs_mode)(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)},
    {"mips64le",  CS_ARCH_MIPS,   (cs_mode)(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)},
    {"mips64be",  CS_ARCH_MIPS,   (cs_mode)(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)},
    {"ppc32le",   CS_ARCH_PPC,    (cs_mode)(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN)},
    {"ppc32be",   CS_ARCH_PPC,    (cs_mode)(CS_MODE_32 | CS_MODE_BIG_ENDIAN)},
    {"ppc64le",   CS_ARCH_PPC,    (cs_mode)(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)},
    {"ppc64be",   CS_ARCH_PPC,    (cs_mode)(CS_MODE_64 | CS_MODE_BIG_ENDIAN)},
    {"riscv32",   CS_ARCH_RISCV,  (cs_mode)(CS_MODE_RISCV32)},
    {"riscv64",   CS_ARCH_RISCV,  (cs_mode)(CS_MODE_RISCV64)},
    {"riscvc",    CS_ARCH_RISCV,  (cs_mode)(CS_MODE_RISCVC)},
    {"armbe",     CS_ARCH_ARM,    (cs_mode)(CS_MODE_ARM | CS_MODE_BIG_ENDIAN)},
    {"aarch64le", CS_ARCH_ARM64,  (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)},
    {"aarch64be", CS_ARCH_ARM64,  (cs_mode)(CS_MODE_ARM | CS_MODE_BIG_ENDIAN)},
    {"cortexm",   CS_ARCH_ARM,    (cs_mode)(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS)},
    {"thumble",   CS_ARCH_ARM,    (cs_mode)(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)},
    {"thumbbe",   CS_ARCH_ARM,    (cs_mode)(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)},
    {"sparc",     CS_ARCH_SPARC,  (cs_mode)(CS_MODE_BIG_ENDIAN)},
    {"sparcv9",   CS_ARCH_SPARC,  (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_V9)},
    {"s390x",     CS_ARCH_SYSZ,   (cs_mode)(CS_MODE_BIG_ENDIAN)},
    {"xcore",     CS_ARCH_XCORE,  (cs_mode)(CS_MODE_BIG_ENDIAN)},
    {"m68k",      CS_ARCH_M68K,   (cs_mode)(CS_MODE_BIG_ENDIAN)},
    {"m68k00",    CS_ARCH_M68K,   (cs_mode)(CS_MODE_M68K_000)},
    {"m68k10",    CS_ARCH_M68K,   (cs_mode)(CS_MODE_M68K_010)},
    {"m68k20",    CS_ARCH_M68K,   (cs_mode)(CS_MODE_M68K_020)},
    {"m68k30",    CS_ARCH_M68K,   (cs_mode)(CS_MODE_M68K_030)},
    {"m68k40",    CS_ARCH_M68K,   (cs_mode)(CS_MODE_M68K_040)},
    {"m68k60",    CS_ARCH_M68K,   (cs_mode)(CS_MODE_M68K_060)},
    {"tms320c64x",CS_ARCH_TMS320C64X, (cs_mode)(CS_MODE_BIG_ENDIAN)},
    {"m6800",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6800)},
    {"m6801",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6801)},
    {"m6805",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6805)},
    {"m6808",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6808)},
    {"m6809",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6809)},
    {"m6811",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6811)},
    {"cpu12",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_CPU12)},
    {"hd6301",    CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6301)},
    {"hd6309",    CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_6309)},
    {"hcs08",     CS_ARCH_M680X,  (cs_mode)(CS_MODE_M680X_HCS08)},
    {"evm",       CS_ARCH_EVM,    (cs_mode)(0)},
    {"mos65xx",   CS_ARCH_MOS65XX,(cs_mode)(0)},
    {"wasm",      CS_ARCH_WASM,   (cs_mode)(0)},
    {"bpfle",     CS_ARCH_BPF,    (cs_mode)(CS_MODE_BPF_CLASSIC | CS_MODE_LITTLE_ENDIAN)},
    {"bpfbe",     CS_ARCH_BPF,    (cs_mode)(CS_MODE_BPF_CLASSIC | CS_MODE_BIG_ENDIAN)},
    {NULL, 0, 0}
};

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <dm> <base_hex> <binfile>\n", argv[0]);
        return 2;
    }
    const dm_entry *e = NULL;
    for (const dm_entry *it = DM_TABLE; it->name; ++it) {
        if (strcmp(it->name, argv[1]) == 0) { e = it; break; }
    }
    if (!e) { fprintf(stderr, "unknown dm %s\n", argv[1]); return 2; }

    uint64_t base = strtoull(argv[2], NULL, 16);
    FILE *f = fopen(argv[3], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("fread"); return 2; }
    fclose(f);

    csh handle;
    if (cs_open(e->arch, e->mode, &handle) != CS_ERR_OK) {
        fprintf(stderr, "cs_open failed\n");
        return 2;
    }
    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, (size_t)n, base, 0, &insn);
    for (size_t i = 0; i < count; ++i) {
        printf("%llx\t", (unsigned long long)insn[i].address);
        for (size_t b = 0; b < insn[i].size; ++b) printf("%02x", insn[i].bytes[b]);
        printf("\t%s %s\n", insn[i].mnemonic, insn[i].op_str);
    }
    cs_free(insn, count);
    cs_close(&handle);
    free(buf);
    return 0;
}
