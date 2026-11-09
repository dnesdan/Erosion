#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
xcrun --sdk macosx clang -fobjc-arc -fblocks -Wall -Wextra \
    tests/CacheCleanerTests.m -framework Foundation -o build/cache-cleaner-tests
build/cache-cleaner-tests
