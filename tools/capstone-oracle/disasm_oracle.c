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

/* Mirror of XCapstone::openHandle branches (subset: MIPS/PPC/RISCV + x86/arm anchors). */
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
