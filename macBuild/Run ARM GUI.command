#!/bin/zsh
# Double-click in Finder. A failed setup/build stops before an old app launches.
set -e
cd -- "$(dirname -- "$0")/.."
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
bash macBuild/setup.sh
cmake -S macBuild -B out/macBuild/build -DCMAKE_BUILD_TYPE=Release
cmake --build out/macBuild/build --parallel 4
open out/macBuild/build/IndagoRev-ARM64.app
