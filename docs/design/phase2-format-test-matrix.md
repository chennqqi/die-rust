# Phase 2 格式测试覆盖矩阵

本文档追踪每个已实现格式的测试覆盖情况，确保满足 Phase 2 退出条件：
"每个实现格式有 positive/truncated/malformed/fuzz/differential cases"。

## 测试类别说明

| 类别 | 说明 |
|------|------|
| Positive | 有效 magic/header 输入，probe 返回正确格式 |
| Truncated | 输入过短，probe 返回 None（不 panic） |
| Malformed | magic 正确但 header 字段无效，probe 返回 error 或 None |
| Boundary | 恰好最小字节数 / 差一字节 |
| Empty | 零长度输入 |
| Fuzz | cargo-fuzz target + property test |
| Differential | corpus 样本差分验证 |

## 覆盖矩阵

| 格式 | Probe | Positive | Truncated | Malformed | Boundary | Empty | Fuzz | Differential |
|------|-------|----------|-----------|-----------|----------|-------|------|--------------|
| MSDOS | MsdosProbe | ✅ mz_magic_matches | ✅ too_short | ✅ non_mz | ✅ exact_2/1_byte | ✅ | ✅ property | ✅ (PE 副产物) |
| PE32 | PeProbe | ✅ pe32_matches | ✅ too_short | ✅ unknown_opt_magic, mz_without_pe_sig | ✅ exact_min/one_short | ✅ | ✅ property | ✅ corpus |
| PE64 | PeProbe | ✅ pe64_matches | (shared) | (shared) | (shared) | (shared) | (shared) | ✅ corpus |
| ELF32 | ElfProbe | ✅ elf32_matches | ✅ too_short | ✅ unknown_class, class_zero | ✅ exact_5/4_bytes | ✅ | ✅ property | ✅ corpus |
| ELF64 | ElfProbe | ✅ elf64_matches | (shared) | (shared) | (shared) | (shared) | (shared) | ✅ corpus |
| Mach-O 32 | MachOProbe | ✅ macho_32_be/le | ✅ too_short | ✅ partial_magic | ✅ exact_4/3_bytes | ✅ | ✅ property | ✅ corpus |
| Mach-O 64 | MachOProbe | ✅ macho_64_be/le | (shared) | (shared) | (shared) | (shared) | (shared) | ✅ corpus |
| Mach-O FAT | MachOProbe | ✅ fat_matches | (shared) | ✅ fat_wrong_suffix | ✅ exact_4_bytes | (shared) | (shared) | ✅ corpus |
| Mach-O FAT64 | MachOProbe | ✅ fat64_matches | (shared) | (shared) | (shared) | (shared) | (shared) | — |
| DEX | DexProbe | ✅ dex_matches + multi_version | ✅ too_short | ✅ bad_version | — | — | ✅ property | ✅ corpus |
| Java Class | JavaClassProbe | ✅ java_class_matches | ✅ too_short | ✅ too_low_major | — | — | ✅ property | ✅ corpus |
| PYC | PycProbe | ✅ pyc_matches | ✅ too_short | ✅ no_crlf, zero_magic | — | — | ✅ property | ✅ corpus |
| PDF | PdfProbe | ✅ pdf_matches | ✅ too_short | ✅ non_pdf, partial_magic | ✅ exact_5/4_bytes | ✅ | ✅ property | ✅ corpus |
| CFBF | CfbfProbe | ✅ cfbf_matches | ✅ too_short | ✅ non_cfbf, partial_magic | ✅ exact_8/7_bytes | ✅ | ✅ property | ✅ corpus |
| ZIP | ZipProbe | ✅ zip_matches | ✅ too_short | ✅ non_zip | ✅ exact_4/3_bytes | ✅ | ✅ property | ✅ corpus |
| RAR4 | RarProbe | ✅ rar4_matches | ✅ too_short | ✅ non_rar | ✅ exact_7_bytes | ✅ | ✅ property | ✅ corpus |
| RAR5 | RarProbe | ✅ rar5_matches | (shared) | (shared) | ✅ exact_8_bytes | (shared) | (shared) | — |
| 7Z | SevenZProbe | ✅ sevenz_matches | ✅ too_short | ✅ non_sevenz | ✅ exact_6_bytes | ✅ | ✅ property | — |
| GZIP | GzipProbe | ✅ gzip_matches | ✅ too_short | ✅ non_gzip | ✅ exact_2_bytes | ✅ | ✅ property | ✅ corpus |
| TAR | TarProbe | ✅ tar_matches | ✅ too_short | ✅ non_ustar | ✅ exact_262/261_bytes | ✅ | ✅ property | ✅ corpus |
| ISO9660 | Iso9660Probe | ✅ iso9660_matches | ✅ too_short | ✅ non_iso | ✅ exact_magic_end/one_short | ✅ | ✅ property | ✅ corpus |
| CAB | CabProbe | ✅ cab_matches | ✅ too_short | ✅ non_cab | ✅ exact_4_bytes | ✅ | ✅ property | — |
| JPEG | JpegProbe | ✅ jpeg_matches | ✅ too_short | ✅ non_jpeg | ✅ exact_3/2_bytes | ✅ | ✅ property | ✅ corpus |
| PNG | PngProbe | ✅ png_matches | ✅ too_short | ✅ non_png | ✅ exact_8/7_bytes | ✅ | ✅ property | ✅ corpus |
| BMP | BmpProbe | ✅ bmp_matches | ✅ too_short | ✅ non_bmp | ✅ exact_2/1_bytes | ✅ | ✅ property | ✅ corpus |
| WAV | WavProbe | ✅ wav_matches | ✅ too_short | ✅ non_riff, riff_not_wave | ✅ exact_12/11_bytes | ✅ | ✅ property | ✅ corpus |

## Header 字段提取

| 格式 | 提取字段 |
|------|---------|
| PE | COFF machine, number_of_sections, opt magic, entry_point, size_of_code |
| ELF | EI_CLASS, EI_DATA, EI_OSABI, e_type (endian-aware) |
| Mach-O | cputype, cpusubtype, filetype (endian-aware) |

## Fuzz Targets

| Target | 覆盖 | 不变量 |
|--------|------|--------|
| fuzz_byte_source | ByteSource read_at/read_exact_at | 无 panic/越界 |
| fuzz_byte_view_subview | ByteView subview/read/typed reads | view 边界不被越过 |
| fuzz_format_probe | ProbeTable 20 个 probe | 无 panic/hang/Io error |

## Property Tests

| Crate | 测试数 | 覆盖 |
|-------|--------|------|
| die-core | 7 | memory_source, read_exact_at, byte_view, chunked, typed_reads, empty_source |
| die-formats | 4 | random_input, deterministic, all_zeros, single_byte |

## Corpus Differential

| 样本数 | 覆盖格式 |
|--------|---------|
| 24 | ELF32/64, PE32/64, Mach-O 32/64/FAT, DEX, Java Class, PYC, PNG, JPEG, BMP, WAV, PDF, CFBF, ZIP, APK, JAR, IPA, RAR, ISO9660, TAR, GZIP |
| 2 | empty, text (no match) |

## 统计

- ProbeTable 注册 probe 数：20
- die-formats 单元测试：156
- die-formats 集成测试（corpus differential）：5
- die-core property tests：7
- die-formats property tests：4
- Fuzz targets：3
- 总测试数：161 + 7 = 168
