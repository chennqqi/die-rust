#!/bin/bash
# Wrapper: run the pinned upstream DIE oracle (podman image) as a host-compatible CLI.
# Keeps a long-lived container so per-sample overhead stays low (podman exec).
# Translates repo DB paths for -D/-C and mounts the corpus read-only.
# Qt variant is selectable: the qt5 engine uses QtScript (methods are
# assignable, `_init` wrappers work), while qt6's V4 engine makes QObject
# methods read-only so `_init` aborts early at this baseline and most
# db/Binary rules die with ReferenceError. Default qt5-arc matches upstream
# release builds (qmake `XCONFIG += use_archive` -> -DUSE_ARCHIVE): the
# plain cmake qt5 image lacks XRar/XSevenZip probes, so RAR/7Z files fall
# back to Binary there. Set UPSTREAM_ORACLE_QT=qt5 for the archive-less
# variant or qt6 for the V4 build.
QT_VARIANT="${UPSTREAM_ORACLE_QT:-qt5-arc}"
IMAGE="die-rust/upstream-oracle-${QT_VARIANT}:23fec32"
CONTAINER="die-oracle-${QT_VARIANT}-23fec32"
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DIE_DB="${REPO_ROOT}/upstream/Detect-It-Easy"

args=()
for a in "$@"; do
    case "$a" in
        "${DIE_DB}"*) args+=("/opt/die-db${a#"$DIE_DB"}") ;;
        *) args+=("$a") ;;
    esac
done

if ! podman inspect --format '{{.State.Running}}' "${CONTAINER}" 2>/dev/null | grep -q true; then
    podman rm -f "${CONTAINER}" >/dev/null 2>&1
    podman run -d --name "${CONTAINER}" --network=none \
        -v /data/virus:/data/virus:ro,z \
        -v "${DIE_DB}:/opt/die-db:ro,z" \
        "${IMAGE}" sleep infinity >/dev/null
fi

exec podman exec "${CONTAINER}" /opt/die-build/src/console/diec "${args[@]}"
