
#!/bin/bash

set -eux
# ssh ocp-host -t '(cd caliptra-mcu-sw && tar -xvf ../caliptra-test-binaries.tar.zst)'

echo "Running tests"

# Clear old logs
ssh ocp-host -t '(sudo rm /tmp/junit.xml || true)'
ssh ocp-host -t '(cd caliptra-mcu-sw && \
    sudo CPTRA_FIRMWARE_BUNDLE="${HOME}/all-fw.zip" cargo-nextest nextest run \
      --workspace-remap=. \
      --archive-file $HOME/caliptra-test-binaries.tar.zst \
      -E "package(mcu-hw-model) - test(model_emulated::test::test_new_unbooted)" \
      --test-threads=1 --no-fail-fast --profile=nightly)'
rsync ocp-host:/tmp/junit.xml .
