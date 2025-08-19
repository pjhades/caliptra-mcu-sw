#!/bin/bash

set -eux

docker run --rm -v$PWD:/work-dir -w/work-dir -v$HOME/.cargo/registry:/root/.cargo/registry -v$HOME/.cargo/git:/root/.cargo/git ghcr.io/chipsalliance/caliptra-build-image:latest /bin/bash -c "(cd /work-dir && echo 'Cross compiling xtask' && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build -p xtask --features=fpga_realtime --target=aarch64-unknown-linux-gnu --target-dir cross-target/)"

echo "Copying xtask"
rsync -avxz cross-target/aarch64-unknown-linux-gnu/debug/xtask ocp-host:.

