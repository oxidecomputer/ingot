#!/bin/bash
#:
#: name = "test-miri"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = "nightly"
#:

set -o errexit
set -o pipefail
set -o xtrace

function header {
	echo "# ==== $* ==== #"
}

header "install miri components"
rustup +nightly component add miri

header "run tests (miri)"
cargo +nightly miri test
