//! Benchmarks for format probing.
//!
//! Measures the time to run all format probes against corpus samples.
//! This isolates the format detection layer from rule execution.
//!
//! Run with: cargo bench -p die-formats

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use die_core::input::{ByteRange, ByteSource, ByteView, MemorySource};
use die_formats::ProbeTable;
use std::path::PathBuf;

/// Resolve the corpus directory.
fn corpus_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("corpus")
}

/// Create a ByteView from a data buffer.
fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
    ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
}

/// Benchmark format probing on corpus files.
fn bench_probe_corpus(c: &mut Criterion) {
    let table = ProbeTable::default_phase2();
    let corpus = corpus_dir();

    let samples = [
        ("minimal.elf", "ELF64"),
        ("minimal.exe", "PE32"),
        ("minimal.macho", "Mach-O 64"),
        ("payload.zip", "Zip"),
        ("payload.tar", "tar"),
        ("minimal.pdf", "PDF"),
        ("pixel.png", "PNG"),
        ("pixel.jpg", "JPEG"),
        ("Minimal.class", "Java Class"),
        ("minimal.dex", "DEX"),
        ("minimal.iso", "ISO 9660"),
        ("empty.bin", "empty"),
        ("plain.txt", "text"),
    ];

    let mut group = c.benchmark_group("probe_corpus");
    group.sample_size(50);

    for (filename, label) in &samples {
        let path = corpus.join(filename);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        group.bench_with_input(BenchmarkId::new("probe_all", label), &data, |b, data| {
            b.iter(|| {
                let source = MemorySource::new(data);
                let view = view_of(&source);
                let _ = table.probe_all(&view);
            });
        });
    }

    group.finish();
}

/// Benchmark probe table construction.
fn bench_probe_table_new(c: &mut Criterion) {
    c.bench_function("probe_table_default_phase2", |b| {
        b.iter(ProbeTable::default_phase2);
    });
}

criterion_group!(benches, bench_probe_corpus, bench_probe_table_new);
criterion_main!(benches);
