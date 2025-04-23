#!/usr/bin/env bash

set -eou pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd $SCRIPT_DIR/../

OS_TYPE=ubuntu go test -tags=integration ./test/integration -timeout=15m -count=1 -parallel=2 -v

popd
