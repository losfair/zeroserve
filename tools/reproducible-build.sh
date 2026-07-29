#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <zig-target> <output-binary>" >&2
  exit 2
fi

zig_target=$1
output_binary=$2
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cargo_target_dir=${CARGO_TARGET_DIR:-"$repo_root/target/reproducible"}

if [[ $cargo_target_dir != /* ]]; then
  cargo_target_dir="$repo_root/$cargo_target_dir"
fi
if [[ $output_binary != /* ]]; then
  output_binary="$repo_root/$output_binary"
fi

case "$zig_target" in
  *-unknown-linux-gnu.[0-9]*)
    rust_target=${zig_target%%.[0-9]*}
    ;;
  *)
    echo "unsupported target: $zig_target" >&2
    exit 2
    ;;
esac

if [[ -z ${SOURCE_DATE_EPOCH:-} ]]; then
  SOURCE_DATE_EPOCH=$(git -C "$repo_root" show -s --format=%ct HEAD)
fi

mkdir -p "$cargo_target_dir" "$(dirname "$output_binary")"

repro_rustflags=(
  "--remap-path-prefix=$cargo_target_dir=./target"
  "--remap-path-prefix=$repo_root=."
  "-C"
  "link-arg=-Wl,--build-id=none"
)
printf -v joined_rustflags ' %q' "${repro_rustflags[@]}"

# Do NOT set ARFLAGS here: cc-rs prepends $ARFLAGS to its archiver command but
# always appends its own "cq" operation, so e.g. ARFLAGS=crsD makes ar parse
# "cq" as the archive name and fail. Deterministic archives don't need it:
# zig's ar (llvm-ar) is deterministic by default, and ZERO_AR_DATE covers
# Apple ar.
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$cargo_target_dir"
export LC_ALL=C
export SOURCE_DATE_EPOCH
export TZ=UTC
export ZERO_AR_DATE=1
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${joined_rustflags:1}"
# CXXFLAGS matters too: BoringSSL (via boring-sys) is C++, and its
# OPENSSL_PUT_ERROR macro embeds __FILE__ paths from the cargo target dir
# into .rodata. Without the C++ remap the two builds differ.
prefix_map_flags="-ffile-prefix-map=$cargo_target_dir=./target -ffile-prefix-map=$repo_root=."
export CFLAGS="${CFLAGS:+$CFLAGS }$prefix_map_flags"
export CXXFLAGS="${CXXFLAGS:+$CXXFLAGS }$prefix_map_flags"

umask 022
cargo zigbuild --release --locked --target "$zig_target"

install -m 0755 \
  "$cargo_target_dir/$rust_target/release/zeroserve" \
  "$output_binary"
sha256sum "$output_binary"
