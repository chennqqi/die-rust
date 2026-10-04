# died (die daemon) Packaging Guide

This document describes how to build platform-specific packages for `died`,
the diec scan service daemon.

## Prerequisites

- Rust 1.88+ with cargo
- The diec rule database (`upstream/Detect-It-Easy/db` or custom path)

## Windows

### MSI Installer (cargo-wix)

```powershell
# Install cargo-wix (one-time)
cargo install cargo-wix

# Install WiX Toolset v3.14+ from https://wixtoolset.org/

# Build the MSI
cargo wix --package diec-server
# Output: target/wix/died-<version>-x86_64-install.msi
```

### Windows Service

After installing the MSI (or using the binary directly):

```powershell
# Run as Administrator
died install --db "C:\Program Files\died\db" --bind 127.0.0.1:18080

# Start the service
sc start died

# Stop the service
sc stop died

# Uninstall the service
died uninstall
```

## Linux

### DEB Package (cargo-deb)

```bash
# Install cargo-deb (one-time)
cargo install cargo-deb

# Build the DEB
cargo deb --package diec-server
# Output: target/debian/died_<version>_<arch>.deb

# Install
sudo dpkg -i target/debian/died_*.deb

# The systemd service is automatically enabled and started
```

### RPM Package

```bash
# Build the binary
cargo build --release --package diec-server

# Build the RPM (requires rpmbuild)
rpmbuild -ba crates/diec-server/packaging/died.spec
# Output: ~/rpmbuild/RPMS/<arch>/died-<version>-<release>.<arch>.rpm

# Install
sudo rpm -i died-*.rpm

# Enable and start the service
sudo systemctl enable --now died
```

### Manual systemd setup

If using a pre-built binary without a package:

```bash
# Generate a systemd unit template
died install --db /usr/share/diec/db --bind 127.0.0.1:18080 > /tmp/died.service

# Install and start
sudo cp /tmp/died.service /etc/systemd/system/died.service
sudo systemctl daemon-reload
sudo systemctl enable --now died
```

## Configuration

The service looks for the database in this order:
1. `--db <path>` command-line argument
2. `DIEC_DB_PATH` environment variable
3. `db/` directory adjacent to the executable
4. Development paths (`upstream/Detect-It-Easy/db`, etc.)

## Security Notes

- Default bind address is `127.0.0.1:0` (localhost only, random port)
- Use `--bind 127.0.0.1:18080` for a fixed port
- Use `--allow-root <dir>` to restrict `/scan/path` to a specific directory
- Use `--max-file-size` and `--max-request-size` to limit resource usage
- Use `--scan-timeout` to prevent long-running scans from blocking
- For remote access, use a reverse proxy (nginx, caddy) with TLS
