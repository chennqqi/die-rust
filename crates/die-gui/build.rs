fn main() {
    tauri_build::build();

    // The Tauri app manifest (Common-Controls v6, DPI awareness) is emitted
    // via `cargo:rustc-link-arg-bins`, which only covers the bin target.
    // Integration test executables that transitively keep `rfd`/`windows`
    // imports (e.g. `TaskDialogIndirect`, exported only by comctl32 v6 in
    // WinSxS) then crash at load time with STATUS_ENTRYPOINT_NOT_FOUND.
    // Link the same resource into test targets so they get the manifest too.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let resource =
            std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("resource.lib");
        if resource.exists() {
            println!("cargo:rustc-link-arg-tests={}", resource.display());
        }
    }
}
