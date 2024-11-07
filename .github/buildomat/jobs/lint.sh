#!/bin/bash
#:
#: name = "lint"
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

header "check style"
cargo +nightly fmt --check

header "clippy compile"
cargo +nightly clippy -- -Dwarnings
