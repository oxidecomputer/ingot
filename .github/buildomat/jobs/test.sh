#!/bin/bash
#:
#: name = "lint"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = true
#:

set -o errexit
set -o pipefail
set -o xtrace

function header {
	echo "# ==== $* ==== #"
}

header "run tests (stable)"
cargo test
