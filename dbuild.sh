#!/usr/bin/env sh
# D-OS cross-platform host tool bootstrapper (Linux / POSIX).
# Compiles tools/dbuild on demand and forwards all arguments to dbuild.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CRATE="$ROOT/tools/dbuild"
BIN="$CRATE/target/release/dbuild"

if ! command -v cargo >/dev/null 2>&1; then
    echo "dbuild: Rust toolchain (cargo) not found on PATH. See docs/building.md." >&2
    exit 1
fi

NEED_BUILD=0
if [ ! -x "$BIN" ]; then
    NEED_BUILD=1
elif [ -n "$(find "$CRATE/src" "$CRATE/Cargo.toml" "$ROOT/user/lib/fs/src" "$ROOT/user/lib/crypto/src" "$ROOT/user/lib/net/src" "$ROOT/user/lib/font/src" "$ROOT/user/lib/app/src" "$ROOT/user/lib/identity/src" \
        -type f -newer "$BIN" 2>/dev/null | head -n 1)" ]; then
    NEED_BUILD=1
fi

if [ "$NEED_BUILD" -eq 1 ]; then
    LOCK_FLAG=""
    if [ -f "$CRATE/Cargo.lock" ]; then
        LOCK_FLAG="--locked"
    fi
    (cd "$CRATE" && cargo build --release $LOCK_FLAG --quiet)
fi

exec "$BIN" "$@"
