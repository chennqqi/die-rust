fn main() {
    for p in std::env::args().skip(1) {
        let d = std::fs::read(&p).unwrap();
        let ft = diec_nfd::sniff_ft(&d);
        println!("== {} ft={}", p, diec_nfd::ft_name(ft));
        for r in diec_nfd::scan(
            &d,
            ft,
            diec_nfd::ScanOptions {
                deep_scan: true,
                heuristic_scan: true,
                verbose: true,
                all_types: false,
                archives_scan: true,
                recursive_scan: true,
                resources_scan: true,
                overlay_scan: true,
                aggressive_scan: false,
            },
        ) {
            println!(
                "  {}: {} {} {}",
                r.record_type, r.record_name, r.version, r.info
            );
        }
    }
}
