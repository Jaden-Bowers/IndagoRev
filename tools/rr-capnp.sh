#!/usr/bin/env bash
# Upstream invokes capnp by name. Supply its private schema include directory.
set -euo pipefail
sdk=/home/jaden/.cache/indago/rr-source-sdk/root
if [[ ${1:-} == compile ]];then
  shift
  exec "$sdk/usr/bin/capnp" compile -I "$sdk/usr/include" "$@"
fi
exec "$sdk/usr/bin/capnp" "$@"
