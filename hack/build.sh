#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -eou pipefail

pushd $SCRIPT_DIR/../

GO_VERSION=${GO_VERSION:-"1.24.2"}

mkdir -p .cache
mkdir -p .mod-cache

docker run --rm \
    -v "$PWD":/data/ \
    -w /data \
    --user=$(id -u):$(id -g) \
    -v ${PWD}/.cache:/.cache \
    -v ${PWD}/.mod-cache:/go/pkg/mod \
    golang:${GO_VERSION}-alpine \
    go build -v -o opkssh

chmod u+x opkssh

popd
