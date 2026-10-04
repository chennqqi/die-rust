# C static-link spike

This is an isolated Phase 0 experiment, not the public `die-rust` ABI or a
scanner implementation.

It builds a Rust `staticlib`, links it into a real C11 executable, and checks
the ABI version, structured result access, Rust-owned result lifetime, invalid
arguments, explicit resource limits, and panic containment.

On Windows x64:

```cmd
run-windows-msvc.cmd
run-windows-msvc.cmd --static-crt
```

The script locates Visual Studio with `vswhere`, initializes the x64 MSVC
environment, builds the `.lib`, compiles `c/smoke.c`, links all required native
system libraries, and runs the resulting executable. The default uses the
dynamic MSVC CRT (`/MD`); `--static-crt` pairs Rust
`-C target-feature=+crt-static` with C `/MT`.

On Linux GNU:

```sh
./run-linux-gnu.sh
```

This builds `libdiec_c_static_link_spike.a`, links the same C11 fixture with
the native libraries reported by rustc, and runs it.
