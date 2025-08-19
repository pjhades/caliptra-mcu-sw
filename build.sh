#!/bin/bash

set -ux

cargo xtask all-build --platform fpga
rsync -avxz target/all-fw.zip ocp-host:.
